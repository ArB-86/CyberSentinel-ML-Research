#!/usr/bin/env python3
"""Reproducible CICIDS2017 anomaly-detector comparison.

Primary comparison:
  * Isolation Forest (benign-only)
  * Local Outlier Factor in novelty mode (benign-only)
  * RBF One-Class SVM (benign-only)
  * Random Forest (labelled supervised reference; reported separately)

Higher returned scores always mean "more anomalous". Unsupervised thresholds
are calibrated only on a held-out BENIGN calibration subset to target a fixed
nominal false-positive rate. Test labels are used only for final evaluation.
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, help="Path to cleaned CICIDS2017 Parquet")
    parser.add_argument("--outdir", default="experiments/results")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--folds", type=int, default=7,
                        help="Number of duplicate-group folds; fold 0=validation, fold 1=test")
    parser.add_argument("--train-benign", type=int, default=5000,
                        help="Equal benign training cap for the three unsupervised models")
    parser.add_argument("--calibration-rows", type=int, default=5000,
                        help="Held-out BENIGN rows used to set each model's threshold")
    parser.add_argument("--evaluation-rows", type=int, default=15000,
                        help="Shared, binary-stratified test sample scored by every model")
    parser.add_argument("--target-fpr", type=float, default=0.05,
                        help="Nominal false-positive target from benign-only calibration (0 < value < 0.5)")
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--lof-neighbors", type=int, default=35)
    parser.add_argument("--svm-nu", type=float, default=0.05)
    parser.add_argument("--svm-cache-mb", type=float, default=512)
    parser.add_argument("--rf-train-rows", type=int, default=50000,
                        help="Maximum labelled training rows for the separate supervised RF reference")
    parser.add_argument("--rf-trees", type=int, default=300)
    parser.add_argument("--skip-supervised", action="store_true")
    return parser.parse_args()


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}. Download the processed Parquet listed in DATASET_SOURCES.md."
        )
    frame = pd.read_parquet(path)
    label_col = next((c for c in frame.columns if str(c).strip().casefold() == "label"), None)
    if label_col is None:
        raise ValueError("Expected a CICIDS2017 label column named 'Label'.")

    labels = frame[label_col].astype(str).str.strip()
    keep = labels.notna() & labels.ne("") & labels.str.casefold().ne("nan")
    frame = frame.loc[keep].reset_index(drop=True)
    labels = labels.loc[keep].reset_index(drop=True)

    binary = labels.str.casefold().ne("benign").astype(np.int8)
    excluded = {str(label_col).strip().casefold(), "is_attack"}
    feature_frame = frame.drop(
        columns=[c for c in frame.columns if str(c).strip().casefold() in excluded],
        errors="ignore",
    )
    features = feature_frame.select_dtypes(include=[np.number]).copy()
    if features.empty:
        raise ValueError("No numeric model features found after excluding label columns.")

    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.dropna(axis=1, how="all")
    non_constant = features.nunique(dropna=False) > 1
    features = features.loc[:, non_constant]
    if features.empty:
        raise ValueError("No usable numeric features remain after cleaning.")

    # Labels are never included in this hash. Identical feature vectors are
    # kept in a single split to reduce exact-duplicate train/test leakage.
    return features, labels, binary


def duplicate_group_split(
    features: pd.DataFrame,
    binary: pd.Series,
    n_splits: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if n_splits < 4:
        raise ValueError("--folds must be at least 4.")
    groups = pd.util.hash_pandas_object(features, index=False).to_numpy(dtype=np.uint64)
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    fold_indices: list[np.ndarray] = []
    dummy_x = np.zeros((len(binary), 1), dtype=np.uint8)
    for _, held_out in splitter.split(dummy_x, binary.to_numpy(), groups=groups):
        fold_indices.append(held_out)

    val_idx = np.sort(fold_indices[0])
    test_idx = np.sort(fold_indices[1])
    held_out_all = np.concatenate([val_idx, test_idx])
    train_idx = np.setdiff1d(np.arange(len(binary)), held_out_all, assume_unique=False)

    # A collision-free SHA hash is not assumed; we explicitly verify that
    # identical numeric feature hashes do not cross any split boundary.
    g_train = np.unique(groups[train_idx])
    g_val = np.unique(groups[val_idx])
    g_test = np.unique(groups[test_idx])
    overlap = np.intersect1d(g_train, g_val).size + np.intersect1d(g_train, g_test).size
    overlap += np.intersect1d(g_val, g_test).size
    if overlap:
        raise RuntimeError(f"Exact-feature duplicate groups cross split boundaries: {overlap}")
    return train_idx, val_idx, test_idx, groups


def stratified_sample_indices(
    indices: np.ndarray,
    y: np.ndarray,
    n_rows: int,
    seed: int,
) -> np.ndarray:
    if n_rows <= 0 or n_rows >= len(indices):
        return np.asarray(indices, dtype=np.int64)
    _, sampled = train_test_split(
        indices,
        test_size=n_rows,
        random_state=seed,
        stratify=y[indices],
    )
    return np.sort(sampled)


def sample_benign(
    indices: np.ndarray,
    y: np.ndarray,
    n_rows: int,
    seed: int,
) -> np.ndarray:
    benign_indices = indices[y[indices] == 0]
    if len(benign_indices) == 0:
        raise ValueError("No benign observations are available in the requested split.")
    n = min(n_rows, len(benign_indices))
    rng = np.random.default_rng(seed)
    return np.sort(rng.choice(benign_indices, size=n, replace=False))


def make_unsupervised_models(args: argparse.Namespace, n_train: int) -> dict[str, Pipeline]:
    n_neighbors = min(args.lof_neighbors, max(2, n_train - 1))
    return {
        "IsolationForest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("detector", IsolationForest(
                n_estimators=args.trees,
                max_samples=min(1024, n_train),
                contamination="auto",
                random_state=args.seed,
                n_jobs=-1,
            )),
        ]),
        "LOF_novelty": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("detector", LocalOutlierFactor(
                n_neighbors=n_neighbors,
                novelty=True,
                contamination="auto",
                n_jobs=-1,
            )),
        ]),
        "RBF_OneClassSVM": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("detector", OneClassSVM(
                kernel="rbf",
                nu=args.svm_nu,
                gamma="scale",
                cache_size=args.svm_cache_mb,
            )),
        ]),
    }


def anomaly_scores(name: str, model: Pipeline, x: pd.DataFrame) -> np.ndarray:
    steps = model.named_steps
    transformed = steps["imputer"].transform(x)
    if "scaler" in steps:
        transformed = steps["scaler"].transform(transformed)
    detector = steps["detector"]
    if name == "RBF_OneClassSVM":
        # One-Class SVM decision_function is positive for inliers.
        return -np.asarray(detector.decision_function(transformed)).reshape(-1)
    # IsolationForest and novelty-LOF score_samples are larger for inliers.
    return -np.asarray(detector.score_samples(transformed)).reshape(-1)


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray,
) -> dict[str, float | int]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = np.unique(y_true).size == 2
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else float("nan"),
        "pr_auc_average_precision": float(average_precision_score(y_true, scores)),
        "attack_precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "attack_recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "attack_f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else float("nan"),
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else float("nan"),
        "matthews_corrcoef": float(matthews_corrcoef(y_true, y_pred)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "alert_rate": float(np.mean(y_pred)),
    }


def main() -> None:
    args = parse_args()
    if not (0.0 < args.target_fpr < 0.5):
        raise ValueError("--target-fpr must be between 0 and 0.5.")
    data_path = Path(args.data)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    features, labels, binary_series = load_dataset(data_path)
    y = binary_series.to_numpy(dtype=np.int8)
    label_values = labels.to_numpy()
    train_idx, val_idx, test_idx, groups = duplicate_group_split(
        features, binary_series, args.folds, args.seed
    )

    # The validation fold supplies only benign calibration observations.
    # Validation attack labels are not used for model selection or thresholding.
    calibration_idx = sample_benign(val_idx, y, args.calibration_rows, args.seed + 1)
    test_eval_idx = stratified_sample_indices(
        test_idx, y, args.evaluation_rows, args.seed + 2
    )
    benign_train_idx = sample_benign(train_idx, y, args.train_benign, args.seed + 3)

    x_train_benign = features.iloc[benign_train_idx]
    x_cal = features.iloc[calibration_idx]
    x_test = features.iloc[test_eval_idx]
    y_test = y[test_eval_idx]
    y_test_labels = label_values[test_eval_idx]

    metric_rows: list[dict[str, object]] = []
    per_attack_rows: list[dict[str, object]] = []
    prediction_frames: list[pd.DataFrame] = []
    saved_scores: dict[str, np.ndarray] = {}

    models = make_unsupervised_models(args, len(benign_train_idx))
    for name, model in models.items():
        print(f"Training {name} on {len(benign_train_idx):,} benign-only flows...")
        start = time.perf_counter()
        model.fit(x_train_benign)
        fit_seconds = time.perf_counter() - start

        start = time.perf_counter()
        calibration_scores = anomaly_scores(name, model, x_cal)
        calibration_seconds = time.perf_counter() - start
        threshold = float(np.quantile(calibration_scores, 1.0 - args.target_fpr))

        start = time.perf_counter()
        test_scores = anomaly_scores(name, model, x_test)
        inference_seconds = time.perf_counter() - start
        predictions = (test_scores >= threshold).astype(np.int8)

        metrics = compute_metrics(y_test, predictions, test_scores)
        metrics.update({
            "model": name,
            "learning_paradigm": "unsupervised_benign_only",
            "train_rows": int(len(benign_train_idx)),
            "calibration_benign_rows": int(len(calibration_idx)),
            "test_rows": int(len(test_eval_idx)),
            "threshold": threshold,
            "target_calibration_fpr": float(args.target_fpr),
            "measured_calibration_fpr": float(np.mean(calibration_scores >= threshold)),
            "fit_seconds": float(fit_seconds),
            "calibration_seconds": float(calibration_seconds),
            "test_scoring_seconds": float(inference_seconds),
            "test_rows_per_second": float(len(test_eval_idx) / inference_seconds)
                if inference_seconds > 0 else float("inf"),
        })
        metric_rows.append(metrics)
        saved_scores[name] = test_scores
        prediction_frames.append(pd.DataFrame({
            "model": name,
            "Label": y_test_labels,
            "y_attack": y_test,
            "anomaly_score": test_scores,
            "predicted_attack": predictions,
        }))

        for attack_name in pd.unique(y_test_labels):
            if str(attack_name).casefold() == "benign":
                continue
            mask = y_test_labels == attack_name
            per_attack_rows.append({
                "model": name,
                "attack_type": str(attack_name),
                "test_support": int(mask.sum()),
                "detected": int(predictions[mask].sum()),
                "detection_recall": float(predictions[mask].mean()),
            })

    # Supervised reference is intentionally separate: unlike the first three
    # detectors, it is allowed to use attack labels during fitting.
    if not args.skip_supervised:
        rf_train_idx = stratified_sample_indices(
            train_idx, y, args.rf_train_rows, args.seed + 4
        )
        rf = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=args.rf_trees,
                class_weight="balanced_subsample",
                max_features="sqrt",
                random_state=args.seed,
                n_jobs=-1,
            )),
        ])
        print(f"Training supervised RandomForest on {len(rf_train_idx):,} labelled flows...")
        start = time.perf_counter()
        rf.fit(features.iloc[rf_train_idx], y[rf_train_idx])
        fit_seconds = time.perf_counter() - start

        start = time.perf_counter()
        cal_scores = rf.predict_proba(x_cal)[:, 1]
        calibration_seconds = time.perf_counter() - start
        threshold = float(np.quantile(cal_scores, 1.0 - args.target_fpr))

        start = time.perf_counter()
        test_scores = rf.predict_proba(x_test)[:, 1]
        inference_seconds = time.perf_counter() - start
        predictions = (test_scores >= threshold).astype(np.int8)
        metrics = compute_metrics(y_test, predictions, test_scores)
        metrics.update({
            "model": "RandomForest_supervised_reference",
            "learning_paradigm": "supervised_labelled_reference",
            "train_rows": int(len(rf_train_idx)),
            "calibration_benign_rows": int(len(calibration_idx)),
            "test_rows": int(len(test_eval_idx)),
            "threshold": threshold,
            "target_calibration_fpr": float(args.target_fpr),
            "measured_calibration_fpr": float(np.mean(cal_scores >= threshold)),
            "fit_seconds": float(fit_seconds),
            "calibration_seconds": float(calibration_seconds),
            "test_scoring_seconds": float(inference_seconds),
            "test_rows_per_second": float(len(test_eval_idx) / inference_seconds)
                if inference_seconds > 0 else float("inf"),
        })
        metric_rows.append(metrics)
        saved_scores["RandomForest_supervised_reference"] = test_scores
        prediction_frames.append(pd.DataFrame({
            "model": "RandomForest_supervised_reference",
            "Label": y_test_labels,
            "y_attack": y_test,
            "anomaly_score": test_scores,
            "predicted_attack": predictions,
        }))
        for attack_name in pd.unique(y_test_labels):
            if str(attack_name).casefold() == "benign":
                continue
            mask = y_test_labels == attack_name
            per_attack_rows.append({
                "model": "RandomForest_supervised_reference",
                "attack_type": str(attack_name),
                "test_support": int(mask.sum()),
                "detected": int(predictions[mask].sum()),
                "detection_recall": float(predictions[mask].mean()),
            })

    metrics_df = pd.DataFrame(metric_rows).sort_values(
        ["learning_paradigm", "pr_auc_average_precision"],
        ascending=[True, False],
    )
    metrics_df.to_csv(outdir / "metrics.csv", index=False)
    pd.DataFrame(per_attack_rows).sort_values(
        ["attack_type", "model"]
    ).to_csv(outdir / "per_attack_recall.csv", index=False)
    pd.concat(prediction_frames, ignore_index=True).to_csv(
        outdir / "predictions.csv", index=False
    )

    metadata = {
        "dataset": str(data_path),
        "rows_after_label_filter": int(len(features)),
        "numeric_features": int(features.shape[1]),
        "label_distribution": {str(k): int(v) for k, v in labels.value_counts().items()},
        "binary_distribution": {"benign": int((y == 0).sum()), "attack": int((y == 1).sum())},
        "split": "StratifiedGroupKFold on exact numeric-feature hashes; fold 0 validation, fold 1 test",
        "folds": int(args.folds),
        "seed": int(args.seed),
        "train_rows_all_classes": int(len(train_idx)),
        "train_benign_rows_used_by_unsupervised_models": int(len(benign_train_idx)),
        "validation_fold_rows": int(len(val_idx)),
        "benign_calibration_rows": int(len(calibration_idx)),
        "test_fold_rows": int(len(test_idx)),
        "shared_test_evaluation_rows": int(len(test_eval_idx)),
        "unique_feature_hash_groups": int(pd.Series(groups).nunique()),
        "exact_duplicate_hash_overlap_between_splits": 0,
        "threshold_rule": f"upper {args.target_fpr:.1%} tail of held-out benign calibration scores",
        "warning": "This split prevents exact numeric-feature duplicates crossing splits; it does not group by five-tuple because the cleaned Parquet has no connection identifiers.",
        "software": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "arguments": vars(args),
    }
    (outdir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, default=str), encoding="utf-8"
    )

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import precision_recall_curve, roc_curve

        fig, axes = plt.subplots(1, 2, figsize=(13, 5))
        for name, scores in saved_scores.items():
            fpr, tpr, _ = roc_curve(y_test, scores)
            precision, recall, _ = precision_recall_curve(y_test, scores)
            axes[0].plot(fpr, tpr, label=name)
            axes[1].plot(recall, precision, label=name)
        axes[0].plot([0, 1], [0, 1], linestyle="--", linewidth=1)
        axes[0].set(title="ROC curve", xlabel="False-positive rate", ylabel="True-positive rate")
        axes[1].set(title="Precision-recall curve", xlabel="Recall", ylabel="Precision")
        axes[0].legend(fontsize=8)
        axes[1].legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(outdir / "roc_pr_curves.png", dpi=160)
        plt.close(fig)
    except ImportError:
        print("matplotlib not installed; skipping optional ROC/PR plot.")

    print("\nComparison finished.")
    print(metrics_df[[
        "model", "learning_paradigm", "roc_auc", "pr_auc_average_precision",
        "attack_precision", "attack_recall", "attack_f1", "false_positive_rate",
        "fit_seconds", "test_rows_per_second",
    ]].to_string(index=False))
    print(f"Results written to: {outdir.resolve()}")


if __name__ == "__main__":
    main()
