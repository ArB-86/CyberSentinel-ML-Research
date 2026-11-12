#!/usr/bin/env python3
"""Controlled Isolation Forest ablation for CICIDS2017 temporal folds.

Compares the current raw-feature baseline with signed-log and train-fitted
quantile transforms. Hyperparameters are selected on validation labels at a
threshold calibrated from validation-benign scores only. The later test day is
scored once after the candidate and threshold have been frozen.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import QuantileTransformer

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.temporal_threshold_optimization import (
    binary_metrics,
    first_position_per_hash,
    load_temporal_csvs,
    rolling_forward_splits,
    sample_binary_stratified,
    threshold_at_fpr,
)


TRANSFORMS = ("raw", "signed_log1p", "quantile_uniform", "quantile_normal")
CONFIGS = (
    {"n_estimators": 200, "max_samples": 256, "max_features": 1.0},
    {"n_estimators": 200, "max_samples": 1024, "max_features": 1.0},
    {"n_estimators": 300, "max_samples": 2048, "max_features": 1.0},
    {"n_estimators": 300, "max_samples": 2048, "max_features": 0.8},
)
BASELINE_CONFIG = {
    "n_estimators": 200,
    "max_samples": 1024,
    "max_features": 1.0,
}


def make_feature_views(
    transform_name: str,
    x_train: np.ndarray,
    x_validation: np.ndarray,
    x_test: np.ndarray,
    seed: int,
):
    """Fit any learned transform on benign training rows only."""
    transformer = None
    if transform_name == "raw":
        return x_train, x_validation, x_test, transformer
    if transform_name == "signed_log1p":
        fn = lambda values: np.sign(values) * np.log1p(np.abs(values))
        return fn(x_train), fn(x_validation), fn(x_test), transformer
    if transform_name in {"quantile_uniform", "quantile_normal"}:
        distribution = "uniform" if transform_name.endswith("uniform") else "normal"
        transformer = QuantileTransformer(
            n_quantiles=min(1000, len(x_train)),
            output_distribution=distribution,
            subsample=max(100_000, len(x_train)),
            random_state=seed,
            copy=True,
        )
        train_view = transformer.fit_transform(x_train)
        validation_view = transformer.transform(x_validation)
        test_view = transformer.transform(x_test)
        return train_view, validation_view, test_view, transformer
    raise ValueError(f"Unsupported feature transform: {transform_name}")


def fit_if(
    x_train: np.ndarray,
    x_validation: np.ndarray,
    config: dict,
    seed: int,
):
    model = IsolationForest(
        n_estimators=int(config["n_estimators"]),
        max_samples=min(int(config["max_samples"]), len(x_train)),
        max_features=float(config["max_features"]),
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )
    started = time.perf_counter()
    model.fit(x_train)
    fit_seconds = time.perf_counter() - started
    validation_scores = -model.score_samples(x_validation)
    return model, validation_scores, fit_seconds


def choose_rows(days, hashes, y, fold_plan, args, fold_seed):
    train_period_mask = np.isin(days, fold_plan["training_days"])
    validation_period_mask = days == fold_plan["validation_day"]
    test_period_mask = days == fold_plan["test_day"]

    train_hashes = np.unique(hashes[train_period_mask])
    train_benign = np.flatnonzero(train_period_mask & (y == 0))
    train_benign = first_position_per_hash(train_benign, hashes)

    validation = np.flatnonzero(validation_period_mask)
    validation = validation[~np.isin(hashes[validation], train_hashes)]
    validation_hashes = np.unique(hashes[validation])

    test = np.flatnonzero(test_period_mask)
    forbidden = np.concatenate([train_hashes, validation_hashes])
    test = test[~np.isin(hashes[test], forbidden)]

    if len(train_benign) < 100:
        raise ValueError(f"Fold {fold_plan['fold']} has fewer than 100 unique benign training flows.")
    if not len(validation) or np.unique(y[validation]).size != 2:
        raise ValueError(f"Fold {fold_plan['fold']} validation partition must contain both classes.")
    if not len(test) or np.unique(y[test]).size != 2:
        raise ValueError(f"Fold {fold_plan['fold']} test partition must contain both classes.")

    rng = np.random.default_rng(fold_seed)
    train_n = min(args.train_rows, len(train_benign))
    train = np.sort(rng.choice(train_benign, size=train_n, replace=False))
    validation = sample_binary_stratified(validation, y, args.validation_rows, fold_seed + 1)
    test = sample_binary_stratified(test, y, args.test_rows, fold_seed + 2)
    return train, validation, test


def evaluate_fold(
    fold_plan, x, hashes, labels, y, days, feature_columns, args, output
):
    fold_id = int(fold_plan["fold"])
    fold_seed = args.seed + fold_id * 100
    train_pos, validation_pos, test_pos = choose_rows(
        days, hashes, y, fold_plan, args, fold_seed
    )
    y_validation = y[validation_pos]
    y_test = y[test_pos]
    test_labels = labels[test_pos]

    # Imputation statistics are learned only from the benign training sample.
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    x_train = imputer.fit_transform(x[train_pos])
    x_validation = imputer.transform(x[validation_pos])
    x_test = imputer.transform(x[test_pos])

    candidate_records = []
    candidate_objects = {}
    baseline_key = None
    best_key = None
    selected_key = None

    print(
        f"\nFOLD {fold_id}: train={fold_plan['training_days'][0]}.."
        f"{fold_plan['training_days'][-1]}, validation={fold_plan['validation_day']}, "
        f"test={fold_plan['test_day']}; rows={len(train_pos):,}/"
        f"{len(validation_pos):,}/{len(test_pos):,}",
        flush=True,
    )

    for transform_name in TRANSFORMS:
        train_view, validation_view, test_view, transformer = make_feature_views(
            transform_name, x_train, x_validation, x_test, fold_seed
        )
        for config_index, config in enumerate(CONFIGS):
            model, validation_scores, fit_seconds = fit_if(
                train_view, validation_view, config, fold_seed
            )
            threshold = threshold_at_fpr(
                validation_scores[y_validation == 0], args.target_fpr
            )
            metrics = binary_metrics(y_validation, validation_scores, threshold)
            candidate_id = f"{transform_name}__config_{config_index + 1}"
            record = {
                "fold": fold_id,
                "validation_day": fold_plan["validation_day"],
                "test_day": fold_plan["test_day"],
                "candidate": candidate_id,
                "transform": transform_name,
                **config,
                "threshold": threshold,
                "fit_seconds": fit_seconds,
                "target_fpr": args.target_fpr,
                **metrics,
            }
            candidate_records.append(record)
            candidate_objects[candidate_id] = {
                "model": model,
                "transformer": transformer,
                "transform": transform_name,
                "config": dict(config),
                "validation_scores": validation_scores,
                "validation_threshold": threshold,
                "validation_metrics": metrics,
                "test_view": test_view,
                "fit_seconds": fit_seconds,
            }

            if transform_name == "raw" and config == BASELINE_CONFIG:
                baseline_key = candidate_id

            # Validation-only selection; test data and test labels are not consulted.
            selection_key = (
                metrics["recall"],
                metrics["f1"],
                metrics["average_precision"],
                -fit_seconds,
            )
            if best_key is None or selection_key > best_key:
                best_key = selection_key
                selected_key = candidate_id

            print(
                f"  {candidate_id}: val_recall={metrics['recall']:.4f}, "
                f"val_fpr={metrics['fpr']:.4f}, val_f1={metrics['f1']:.4f}",
                flush=True,
            )

    if baseline_key is None or selected_key is None:
        raise RuntimeError("Ablation did not produce both a baseline and selected candidate.")

    selected = candidate_objects[selected_key]
    baseline = candidate_objects[baseline_key]
    chosen = [("IF_raw_default_baseline", baseline), ("IF_validation_selected", selected)]

    # If selected equals baseline, emit one record with both roles rather than
    # duplicate identical test predictions.
    if selected_key == baseline_key:
        chosen = [("IF_raw_default_baseline_and_selected", baseline)]

    test_records = []
    attack_records = []
    for model_name, item in chosen:
        test_scores = -item["model"].score_samples(item["test_view"])
        threshold = float(item["validation_threshold"])
        metrics = binary_metrics(y_test, test_scores, threshold)
        test_records.append({
            "fold": fold_id,
            "training_days": ",".join(fold_plan["training_days"]),
            "validation_day": fold_plan["validation_day"],
            "test_day": fold_plan["test_day"],
            "model": model_name,
            "candidate": baseline_key if "baseline" in model_name else selected_key,
            "transform": item["transform"],
            **item["config"],
            "validation_threshold": threshold,
            "validation_recall": item["validation_metrics"]["recall"],
            "validation_fpr": item["validation_metrics"]["fpr"],
            **metrics,
        })

        for attack_name in sorted(set(test_labels.tolist())):
            if attack_name.casefold() == "benign":
                continue
            mask = test_labels == attack_name
            support = int(mask.sum())
            detected = int(np.sum(test_scores[mask] >= threshold))
            attack_records.append({
                "fold": fold_id,
                "test_day": fold_plan["test_day"],
                "model": model_name,
                "candidate": baseline_key if "baseline" in model_name else selected_key,
                "attack_type": attack_name,
                "test_support": support,
                "detected": detected,
                "missed": support - detected,
                "recall": detected / support if support else float("nan"),
            })

    selected_artifact = {
        "artifact_version": 1,
        "model_name": "IsolationForest",
        "model": selected["model"],
        "imputer": imputer,
        "transform": selected["transform"],
        "transformer": selected["transformer"],
        "feature_columns": feature_columns,
        "primary_target_fpr": args.target_fpr,
        "primary_threshold": float(selected["validation_threshold"]),
        "threshold_source": "validation benign-only scores",
        "training_days": fold_plan["training_days"],
        "validation_day": fold_plan["validation_day"],
        "test_day": fold_plan["test_day"],
        "training_rows": int(len(train_pos)),
        "hyperparameters": selected["config"],
        "selection_candidate": selected_key,
        "selection_metric": "validation recall at target FPR; ties by F1, AP, then fit time",
        "fold": fold_id,
    }
    fold_dir = output / f"fold_{fold_id}"
    fold_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(selected_artifact, fold_dir / "isolation_forest_ablation_selected.joblib")

    return {
        "validation": pd.DataFrame(candidate_records),
        "test": pd.DataFrame(test_records),
        "per_attack": pd.DataFrame(attack_records),
        "summary": {
            "fold": fold_id,
            "training_days": fold_plan["training_days"],
            "validation_day": fold_plan["validation_day"],
            "test_day": fold_plan["test_day"],
            "training_rows": int(len(train_pos)),
            "validation_rows": int(len(validation_pos)),
            "test_rows": int(len(test_pos)),
            "test_attack_prevalence": float(y_test.mean()),
            "baseline_candidate": baseline_key,
            "selected_candidate": selected_key,
            "selected_transform": selected["transform"],
            "selected_hyperparameters": selected["config"],
            "baseline_validation_recall": baseline["validation_metrics"]["recall"],
            "selected_validation_recall": selected["validation_metrics"]["recall"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--outdir", default="experiments/results/isolation-forest-ablation-v1")
    parser.add_argument("--folds", type=int, default=3)
    parser.add_argument("--train-rows", type=int, default=25_000)
    parser.add_argument("--validation-rows", type=int, default=120_000)
    parser.add_argument("--test-rows", type=int, default=0)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.folds < 1 or args.train_rows < 100:
        raise ValueError("folds must be >=1 and train-rows must be >=100.")
    if args.validation_rows < 0 or args.test_rows < 0:
        raise ValueError("validation/test row limits cannot be negative.")
    if not 0.0 < args.target_fpr < 0.5:
        raise ValueError("target-fpr must be between 0 and 0.5.")

    started = time.perf_counter()
    output = Path(args.outdir)
    output.mkdir(parents=True, exist_ok=True)

    x, hashes, labels, y, days, feature_columns, dropped = load_temporal_csvs(
        Path(args.data_dir)
    )
    fold_plans = rolling_forward_splits(days, args.folds)
    results = [
        evaluate_fold(
            plan, x, hashes, labels, y, days, feature_columns, args, output
        )
        for plan in fold_plans
    ]

    validation = pd.concat([r["validation"] for r in results], ignore_index=True)
    test = pd.concat([r["test"] for r in results], ignore_index=True)
    per_attack = pd.concat([r["per_attack"] for r in results], ignore_index=True)

    validation.sort_values(
        ["fold", "recall", "f1", "average_precision"],
        ascending=[True, False, False, False],
    ).to_csv(output / "if_ablation_validation_grid.csv", index=False)
    test.to_csv(output / "if_ablation_test_metrics.csv", index=False)
    per_attack.to_csv(output / "if_ablation_per_attack_recall.csv", index=False)

    summary = {
        "dataset": str(Path(args.data_dir)),
        "rows_loaded": int(len(x)),
        "rows_dropped_fully_blank": int(dropped),
        "numeric_features": int(x.shape[1]),
        "fold_count": len(fold_plans),
        "target_fpr": args.target_fpr,
        "transforms": list(TRANSFORMS),
        "configurations_per_transform": [dict(c) for c in CONFIGS],
        "selection": (
            "Validation attack recall at target FPR, ties by validation F1, "
            "average precision, then fit time. Thresholds use validation-benign "
            "scores only. Test labels are used only for final reporting."
        ),
        "preprocessing": (
            "Median imputation is fit on benign training data. Quantile transforms "
            "are also fit on benign training data only. Signed-log is a fixed "
            "monotonic transform applied after imputation."
        ),
        "folds": [r["summary"] for r in results],
        "test_results": test.to_dict(orient="records"),
        "interpretation_warning": (
            "This is a model/feature-representation ablation on one CICIDS2017 "
            "capture. A validation-selected candidate is not guaranteed to improve "
            "on future traffic. Treat the untouched test metrics as the decision "
            "evidence; do not retune against them."
        ),
        "elapsed_seconds": time.perf_counter() - started,
    }
    (output / "if_ablation_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    print("\nISOLATION FOREST ABLATION — untouched test results", flush=True)
    print(test[[
        "fold", "test_day", "model", "transform", "precision", "recall",
        "f1", "fpr", "average_precision", "roc_auc",
    ]].to_string(index=False), flush=True)
    print(f"\nSummary: {(output / 'if_ablation_summary.json').resolve()}", flush=True)


if __name__ == "__main__":
    main()
