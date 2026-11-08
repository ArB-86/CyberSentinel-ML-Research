#!/usr/bin/env python3
"""Paired, nested-sample scalability study for CICIDS2017 anomaly detectors.

The duplicate-grouped train/validation/test partition is created once. Every
model and every training-size configuration uses the same benign calibration
rows and the same held-out test rows. For each repetition, benign training
subsets are nested: the 5k rows are a subset of 25k, which are a subset of 50k.

Isolation Forest, novelty-LOF and exact RBF One-Class SVM are all fitted on
benign flows only. Thresholds use a held-out benign-only calibration sample.
No test labels are used in model selection or threshold selection.
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, average_precision_score, balanced_accuracy_score,
    confusion_matrix, f1_score, matthews_corrcoef, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


def parse_int_list(value: str, name: str) -> list[int]:
    try:
        values = sorted({int(x.strip()) for x in value.split(",") if x.strip()})
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be comma-separated integers") from exc
    if not values or any(x <= 0 for x in values):
        raise argparse.ArgumentTypeError(f"{name} must contain positive integers")
    return values


def args_parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", required=True)
    p.add_argument("--outdir", default="experiments/results/scaling-validation-v1")
    p.add_argument("--seeds", default="42,43,44")
    p.add_argument("--train-sizes", default="5000,25000,50000")
    p.add_argument("--folds", type=int, default=7)
    p.add_argument("--split-seed", type=int, default=42,
                   help="One fixed duplicate-group split shared by all repetitions.")
    p.add_argument("--calibration-rows", type=int, default=5000)
    p.add_argument("--evaluation-rows", type=int, default=15000)
    p.add_argument("--target-fpr", type=float, default=0.05)
    p.add_argument("--trees", type=int, default=200)
    p.add_argument("--max-samples", type=int, default=1024)
    p.add_argument("--lof-neighbors", type=int, default=35)
    p.add_argument("--svm-nu", type=float, default=0.05)
    p.add_argument("--svm-cache-mb", type=float, default=512)
    return p.parse_args()


def load_dataset(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    frame = pd.read_parquet(path)
    label_col = next((c for c in frame.columns if str(c).strip().casefold() == "label"), None)
    if label_col is None:
        raise ValueError("Expected CICIDS2017 Label column.")
    labels = frame[label_col].astype(str).str.strip()
    keep = labels.notna() & labels.ne("") & labels.str.casefold().ne("nan")
    frame = frame.loc[keep].reset_index(drop=True)
    labels = labels.loc[keep].reset_index(drop=True)
    y = labels.str.casefold().ne("benign").astype(np.int8).to_numpy()
    feature_frame = frame.drop(
        columns=[c for c in frame.columns if str(c).strip().casefold() in
                 {str(label_col).strip().casefold(), "is_attack"}],
        errors="ignore",
    )
    x = feature_frame.select_dtypes(include=[np.number]).copy()
    x = x.replace([np.inf, -np.inf], np.nan).dropna(axis=1, how="all")
    x = x.loc[:, x.nunique(dropna=False) > 1]
    if x.empty:
        raise ValueError("No numeric modelling features remain.")
    return x, labels, y


def duplicate_group_split(x: pd.DataFrame, y: np.ndarray, n_splits: int, seed: int):
    if n_splits < 4:
        raise ValueError("At least 4 folds are required.")
    groups = pd.util.hash_pandas_object(x, index=False).to_numpy(dtype=np.uint64)
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    dummy = np.zeros((len(y), 1), dtype=np.uint8)
    folds = [held for _, held in splitter.split(dummy, y, groups=groups)]
    val_idx, test_idx = np.sort(folds[0]), np.sort(folds[1])
    train_idx = np.setdiff1d(np.arange(len(y)), np.concatenate([val_idx, test_idx]))
    group_sets = [np.unique(groups[idx]) for idx in (train_idx, val_idx, test_idx)]
    overlap = sum(np.intersect1d(group_sets[i], group_sets[j]).size
                  for i in range(3) for j in range(i + 1, 3))
    if overlap:
        raise RuntimeError(f"Exact duplicate groups cross split boundaries: {overlap}")
    return train_idx, val_idx, test_idx, groups, int(overlap)


def sample_rows(indices: np.ndarray, y: np.ndarray, n: int, seed: int) -> np.ndarray:
    if n >= len(indices):
        return np.asarray(indices, dtype=np.int64)
    _, picked = train_test_split(indices, test_size=n, random_state=seed, stratify=y[indices])
    return np.sort(picked)


def benign_permutation(indices: np.ndarray, y: np.ndarray, max_n: int, seed: int) -> np.ndarray:
    pool = indices[y[indices] == 0]
    if len(pool) < max_n:
        raise ValueError(f"Training partition has {len(pool)} benign rows, fewer than requested {max_n}.")
    rng = np.random.default_rng(seed)
    return rng.permutation(pool)[:max_n]


def score_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both = np.unique(y_true).size == 2
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if both else float("nan"),
        "pr_auc_average_precision": float(average_precision_score(y_true, scores)),
        "attack_precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "attack_recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "attack_f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else float("nan"),
        "false_negative_rate": float(fn / (fn + tp)) if tp + fn else float("nan"),
        "matthews_corrcoef": float(matthews_corrcoef(y_true, y_pred)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "alert_rate": float(np.mean(y_pred)),
    }


def fit_and_score(name: str, x_train: pd.DataFrame, x_cal: pd.DataFrame,
                  x_test: pd.DataFrame, args, seed: int):
    imputer = SimpleImputer(strategy="median")
    xtr = imputer.fit_transform(x_train)
    xcal = imputer.transform(x_cal)
    xtest = imputer.transform(x_test)

    scaler = None
    if name in {"LOF_novelty", "RBF_OneClassSVM"}:
        scaler = StandardScaler()
        xtr = scaler.fit_transform(xtr)
        xcal = scaler.transform(xcal)
        xtest = scaler.transform(xtest)

    if name == "IsolationForest":
        model = IsolationForest(
            n_estimators=args.trees,
            max_samples=min(args.max_samples, len(x_train)),
            contamination="auto",
            random_state=seed,
            n_jobs=-1,
        )
    elif name == "LOF_novelty":
        model = LocalOutlierFactor(
            n_neighbors=min(args.lof_neighbors, len(x_train) - 1),
            novelty=True,
            contamination="auto",
            n_jobs=-1,
        )
    elif name == "RBF_OneClassSVM":
        model = OneClassSVM(
            kernel="rbf", nu=args.svm_nu, gamma="scale",
            cache_size=args.svm_cache_mb,
        )
    else:
        raise ValueError(name)

    start = time.perf_counter()
    model.fit(xtr)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    if name == "RBF_OneClassSVM":
        cal_scores = -np.asarray(model.decision_function(xcal)).reshape(-1)
    else:
        cal_scores = -np.asarray(model.score_samples(xcal)).reshape(-1)
    calibration_seconds = time.perf_counter() - start
    threshold = float(np.quantile(cal_scores, 1.0 - args.target_fpr))
    calibration_fpr = float(np.mean(cal_scores >= threshold))

    start = time.perf_counter()
    if name == "RBF_OneClassSVM":
        test_scores = -np.asarray(model.decision_function(xtest)).reshape(-1)
    else:
        test_scores = -np.asarray(model.score_samples(xtest)).reshape(-1)
    test_seconds = time.perf_counter() - start
    pred = (test_scores >= threshold).astype(np.int8)
    return pred, test_scores, threshold, calibration_fpr, fit_seconds, calibration_seconds, test_seconds


def main():
    args = args_parse()
    seeds = parse_int_list(args.seeds, "seeds")
    sizes = parse_int_list(args.train_sizes, "train-sizes")
    if not 0 < args.target_fpr < 0.5:
        raise ValueError("target-fpr must lie between 0 and 0.5.")
    if args.evaluation_rows <= 0 or args.calibration_rows <= 0:
        raise ValueError("Calibration and evaluation sample sizes must be positive.")
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    x, labels, y = load_dataset(Path(args.data))
    print(f"Loaded {len(x):,} rows and {x.shape[1]} numeric features.")
    print(f"Creating one fixed duplicate-grouped split (seed={args.split_seed})...")
    train_idx, val_idx, test_idx, groups, overlap = duplicate_group_split(
        x, y, args.folds, args.split_seed
    )
    rng_cal = np.random.default_rng(args.split_seed + 10)
    val_benign = val_idx[y[val_idx] == 0]
    if len(val_benign) < args.calibration_rows:
        raise ValueError("Not enough benign validation rows for calibration.")
    cal_idx = np.sort(rng_cal.choice(val_benign, size=args.calibration_rows, replace=False))
    test_idx_eval = sample_rows(test_idx, y, args.evaluation_rows, args.split_seed + 20)
    x_cal = x.iloc[cal_idx]
    x_test = x.iloc[test_idx_eval]
    y_test = y[test_idx_eval]
    labels_test = labels.to_numpy()[test_idx_eval]

    print(f"Train pool benign rows: {(y[train_idx] == 0).sum():,}")
    print(f"Calibration benign rows: {len(cal_idx):,}; shared test rows: {len(test_idx_eval):,}")
    max_size = max(sizes)
    model_names = ["IsolationForest", "LOF_novelty", "RBF_OneClassSVM"]
    rows, per_attack = [], []
    config_meta = []

    for repetition_seed in seeds:
        train_order = benign_permutation(train_idx, y, max_size, repetition_seed + 1000)
        for train_size in sizes:
            chosen = train_order[:train_size]
            x_train = x.iloc[chosen]
            print(f"\nSeed={repetition_seed} | benign_train={train_size:,}")
            for name in model_names:
                print(f"  Fitting {name}...")
                pred, scores, threshold, cal_fpr, fit_s, cal_s, test_s = fit_and_score(
                    name, x_train, x_cal, x_test, args, repetition_seed
                )
                metric = score_metrics(y_test, pred, scores)
                metric.update({
                    "model": name,
                    "seed": repetition_seed,
                    "train_rows": train_size,
                    "calibration_benign_rows": len(cal_idx),
                    "test_rows": len(test_idx_eval),
                    "threshold": threshold,
                    "target_calibration_fpr": args.target_fpr,
                    "measured_calibration_fpr": cal_fpr,
                    "fit_seconds": fit_s,
                    "calibration_seconds": cal_s,
                    "test_scoring_seconds": test_s,
                    "test_rows_per_second": len(test_idx_eval) / test_s if test_s > 0 else float("inf"),
                })
                rows.append(metric)
                for attack in pd.unique(labels_test):
                    if str(attack).casefold() == "benign":
                        continue
                    mask = labels_test == attack
                    per_attack.append({
                        "model": name, "seed": repetition_seed,
                        "train_rows": train_size, "attack_type": str(attack),
                        "test_support": int(mask.sum()),
                        "detected": int(pred[mask].sum()),
                        "detection_recall": float(pred[mask].mean()),
                    })
                config_meta.append({
                    "seed": repetition_seed, "train_rows": train_size,
                    "model": name, "fit_seconds": fit_s,
                    "test_scoring_seconds": test_s,
                })
                del pred, scores

    metrics_df = pd.DataFrame(rows)
    metrics_df.to_csv(out / "metrics_by_seed.csv", index=False)
    pd.DataFrame(per_attack).to_csv(out / "per_attack_by_seed.csv", index=False)

    metric_cols = [
        "roc_auc", "pr_auc_average_precision", "attack_precision",
        "attack_recall", "attack_f1", "false_positive_rate",
        "fit_seconds", "test_scoring_seconds",
    ]
    summary = metrics_df.groupby(["model", "train_rows"])[metric_cols].agg(["mean", "std"])
    summary.columns = [f"{metric}_{stat}" for metric, stat in summary.columns]
    summary = summary.reset_index()
    summary.to_csv(out / "summary_mean_std.csv", index=False)

    pooled = (pd.DataFrame(per_attack)
              .groupby(["model", "train_rows", "attack_type"], as_index=False)
              .agg(test_support=("test_support", "sum"), detected=("detected", "sum")))
    pooled["detection_recall"] = pooled["detected"] / pooled["test_support"]
    pooled.to_csv(out / "per_attack_pooled.csv", index=False)

    metadata = {
        "dataset": str(Path(args.data)),
        "rows": int(len(x)),
        "numeric_features": int(x.shape[1]),
        "label_distribution": {str(k): int(v) for k, v in labels.value_counts().items()},
        "split_method": "StratifiedGroupKFold on exact numeric-feature hashes",
        "split_seed": args.split_seed,
        "folds": args.folds,
        "train_rows": int(len(train_idx)),
        "validation_rows": int(len(val_idx)),
        "test_fold_rows": int(len(test_idx)),
        "calibration_indices_fixed_across_all_runs": True,
        "test_indices_fixed_across_all_runs": True,
        "benign_train_subsets_nested_within_each_seed": True,
        "seeds": seeds,
        "train_sizes": sizes,
        "calibration_rows": len(cal_idx),
        "evaluation_rows": len(test_idx_eval),
        "target_fpr": args.target_fpr,
        "exact_duplicate_group_overlap": overlap,
        "threshold_rule": "upper target-FPR tail of fixed held-out benign calibration scores",
        "models": model_names,
        "software": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "arguments": vars(args),
        "interpretation": (
            "Seeds change the benign training permutation and Isolation Forest random_state. "
            "Calibration and test rows are fixed across all sizes and seeds, enabling paired comparisons."
        ),
        "limitations": (
            "Exact duplicate feature groups are separated; temporal and five-tuple grouping are not "
            "possible from this cleaned Parquet because flow identifiers and timestamps are absent."
        ),
    }
    (out / "run_metadata.json").write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        for metric, ylabel, filename in [
            ("pr_auc_average_precision", "Average Precision", "scaling_pr_auc.png"),
            ("attack_f1", "Attack F1", "scaling_f1.png"),
            ("fit_seconds", "Fit time (seconds)", "scaling_fit_time.png"),
        ]:
            fig, ax = plt.subplots(figsize=(8, 5))
            for model in model_names:
                subset = summary[summary["model"] == model].sort_values("train_rows")
                mean_col = f"{metric}_mean"
                std_col = f"{metric}_std"
                ax.errorbar(
                    subset["train_rows"], subset[mean_col],
                    yerr=subset[std_col], marker="o", capsize=3, label=model,
                )
            ax.set_xlabel("Benign training rows")
            ax.set_ylabel(ylabel)
            ax.set_xscale("log")
            ax.set_title(f"{ylabel} vs training sample size")
            ax.legend()
            fig.tight_layout()
            fig.savefig(out / filename, dpi=160)
            plt.close(fig)
    except ImportError:
        print("Matplotlib unavailable; scaling plots skipped.")

    print("\nSCALING SUMMARY")
    print(summary.to_string(index=False))
    print(f"\nResults: {out.resolve()}")


if __name__ == "__main__":
    main()
