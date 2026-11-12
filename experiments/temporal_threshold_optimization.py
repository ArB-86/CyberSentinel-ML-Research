#!/usr/bin/env python3
"""Tune Isolation Forest on validation data and compare detectors on a later day.

The script uses CICIDS2017 metadata-rich CSVs. Earlier capture days are used
for benign-only fitting, the penultimate day for validation/threshold choice,
and the final day as an untouched temporal test. Exact numeric-feature
duplicates are assigned to their earliest chronological partition only.

Thresholds are calibrated using validation-benign scores only. The selected
Isolation Forest hyperparameters use validation labels at a fixed FPR budget.
Test labels are used once, for final reporting only.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attack_graph.event_builder import normalize_columns


NON_FEATURE_COLUMNS = {
    "label", "timestamp", "src_ip", "dst_ip", "source ip", "destination ip",
    "flow id", "flow_id", "event_id", "event id", "incident_id", "incident id",
    "_id", "predicted_anomaly", "predicted_attack_type", "anomaly_score",
    "attack_type",
}


def parse_cicids_timestamps(values: pd.Series) -> pd.Series:
    """Parse CICIDS2017's day-first timestamps (e.g. 03/07/2017 = 3 July)."""
    return pd.to_datetime(
        values.astype("string").str.strip(),
        format="mixed",
        dayfirst=True,
        errors="coerce",
    )


def threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """Choose a strict score cutoff with empirical calibration FPR <= target.

    Scores must increase with anomaly likelihood. Using the next representable
    float above the boundary also makes tied calibration scores conservative.
    """
    scores = np.asarray(benign_scores, dtype=np.float64).reshape(-1)
    scores = scores[np.isfinite(scores)]
    if scores.size == 0:
        raise ValueError("At least one finite benign validation score is required.")
    if not 0.0 < target_fpr < 0.5:
        raise ValueError("target_fpr must be between 0 and 0.5.")
    allowed_false_positives = int(np.floor(target_fpr * scores.size))
    boundary_index = scores.size - allowed_false_positives - 1
    boundary = np.partition(scores, boundary_index)[boundary_index]
    return float(np.nextafter(boundary, np.inf))


def chronological_days(days: np.ndarray) -> tuple[list[str], str, str]:
    """Use all but the last two dates for fitting; penultimate validates; last tests."""
    unique_days = sorted(set(map(str, np.asarray(days).tolist())))
    if len(unique_days) < 3:
        raise ValueError(
            "Temporal validation requires at least three distinct capture dates; "
            f"found {unique_days}."
        )
    return unique_days[:-2], unique_days[-2], unique_days[-1]




def rolling_forward_splits(days: np.ndarray, n_folds: int | None = None) -> list[dict]:
    """Build expanding-window train / next-day validation / following-day test folds.

    For five CICIDS2017 capture days this yields:
      1) Monday -> Tuesday -> Wednesday
      2) Monday-Tuesday -> Wednesday -> Thursday
      3) Monday-Wednesday -> Thursday -> Friday
    """
    unique_days = sorted(set(map(str, np.asarray(days).tolist())))
    available = len(unique_days) - 2
    if available < 1:
        raise ValueError(
            "Rolling temporal validation requires at least three distinct dates; "
            f"found {unique_days}."
        )
    if n_folds is None:
        n_folds = available
    if n_folds < 1:
        raise ValueError("n_folds must be at least 1.")
    if n_folds > available:
        raise ValueError(
            f"Requested {n_folds} folds but only {available} are possible "
            f"with {len(unique_days)} capture dates."
        )
    return [
        {
            "fold": fold_index + 1,
            "training_days": unique_days[: fold_index + 1],
            "validation_day": unique_days[fold_index + 1],
            "test_day": unique_days[fold_index + 2],
        }
        for fold_index in range(n_folds)
    ]


def first_position_per_hash(positions: np.ndarray, hashes: np.ndarray) -> np.ndarray:
    """Keep one earliest row for each exact feature hash, preserving row order."""
    positions = np.asarray(positions, dtype=np.int64)
    if positions.size == 0:
        return positions
    _, first = np.unique(hashes[positions], return_index=True)
    return positions[np.sort(first)]


def sample_binary_stratified(
    positions: np.ndarray,
    y: np.ndarray,
    limit: int,
    seed: int,
) -> np.ndarray:
    """Cap validation/test rows while retaining their benign/attack prevalence."""
    positions = np.asarray(positions, dtype=np.int64)
    if limit <= 0 or limit >= positions.size:
        return positions
    rng = np.random.default_rng(seed)
    benign = positions[y[positions] == 0]
    attack = positions[y[positions] == 1]
    if not benign.size or not attack.size or limit < 2:
        raise ValueError("Stratified sampling requires both classes and limit >= 2.")
    attack_n = int(round(limit * len(attack) / len(positions)))
    attack_n = min(max(1, attack_n), len(attack), limit - 1)
    benign_n = min(limit - attack_n, len(benign))
    attack_n = min(limit - benign_n, len(attack))
    chosen = np.concatenate([
        rng.choice(benign, size=benign_n, replace=False),
        rng.choice(attack, size=attack_n, replace=False),
    ])
    return np.sort(chosen)


def binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    """Evaluate a fixed anomaly-score threshold; higher scores mean more anomalous."""
    y_true = np.asarray(y_true, dtype=np.int8)
    scores = np.asarray(scores, dtype=np.float64)
    pred = (scores >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    if np.unique(y_true).size != 2:
        raise ValueError("Metrics require both benign and attack examples.")
    fpr = float(fp / (fp + tn)) if tn + fp else float("nan")
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": fpr,
        "false_alerts_per_million_benign": fpr * 1_000_000,
        "average_precision": float(average_precision_score(y_true, scores)),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "support_benign": int(tn + fp),
        "support_attack": int(tp + fn),
    }


def parse_csv_grid(value: str, cast, argument: str):
    try:
        result = [cast(part.strip()) for part in value.split(",") if part.strip()]
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"Invalid {argument}: {value}") from exc
    if not result:
        raise argparse.ArgumentTypeError(f"{argument} cannot be empty.")
    return result


def load_temporal_csvs(data_dir: Path):
    """Load feature arrays and metadata while enforcing a consistent feature schema."""
    paths = sorted(data_dir.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"No CICIDS2017 CSV files found in {data_dir}")

    feature_columns: list[str] | None = None
    feature_parts, hash_parts, label_parts, day_parts = [], [], [], []
    rows_read = 0
    rows_dropped_fully_blank = 0

    for path in paths:
        print(f"Reading {path.name}...", flush=True)
        raw = pd.read_csv(path, low_memory=False, encoding="latin1")
        work = normalize_columns(raw)

        # CICIDS2017 mirrors sometimes pad a file with delimiter-only records.
        # These rows have no values in any column: discard them, but never
        # silently discard partially populated rows with missing timestamps/labels.
        empty_rows = work.isna().all(axis=1)
        empty_count = int(empty_rows.sum())
        if empty_count:
            rows_dropped_fully_blank += empty_count
            print(f"  Skipping {empty_count:,} fully empty rows.", flush=True)
            work = work.loc[~empty_rows].copy()
        if work.empty:
            raise ValueError(f"{path.name} contains no non-empty data rows.")

        required = {"timestamp", "label"}
        missing = required.difference(work.columns)
        if missing:
            raise ValueError(f"{path.name} is missing required columns: {sorted(missing)}")

        timestamps = parse_cicids_timestamps(work["timestamp"])
        if timestamps.isna().any():
            examples = work.loc[timestamps.isna(), "timestamp"].astype(str).head(5).tolist()
            raise ValueError(
                f"{path.name}: {int(timestamps.isna().sum())} timestamps failed "
                f"day-first parsing. Examples: {examples}"
            )

        labels = work["label"].astype("string").str.strip()
        labels = labels.str.replace("\x96", "-", regex=False).str.replace("\ufffd", "-", regex=False)
        if labels.isna().any() or labels.str.casefold().isin({"", "nan", "none", "null"}).any():
            raise ValueError(f"{path.name} contains missing/blank ground-truth labels.")

        drop = [
            col for col in work.columns
            if str(col).strip().casefold() in NON_FEATURE_COLUMNS
        ]
        numeric = work.drop(columns=drop, errors="ignore").select_dtypes(include=np.number)
        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        if numeric.empty:
            raise ValueError(f"{path.name} has no numeric detector features.")

        current_columns = list(numeric.columns)
        if feature_columns is None:
            feature_columns = current_columns
        else:
            extra = sorted(set(current_columns).difference(feature_columns))
            if extra:
                raise ValueError(
                    f"{path.name} contains unexpected numeric features {extra}; "
                    "feature schema must be consistent across dates."
                )
            numeric = numeric.reindex(columns=feature_columns)

        hashes = pd.util.hash_pandas_object(numeric, index=False).to_numpy(dtype=np.uint64)
        feature_parts.append(numeric.to_numpy(dtype=np.float32, copy=True))
        hash_parts.append(hashes)
        label_parts.append(labels.to_numpy(dtype=str))
        day_parts.append(timestamps.dt.strftime("%Y-%m-%d").to_numpy(dtype=str))
        rows_read += len(work)
        del raw, work, numeric

    x = np.concatenate(feature_parts, axis=0)
    hashes = np.concatenate(hash_parts)
    labels = np.concatenate(label_parts)
    days = np.concatenate(day_parts)
    y = (np.char.lower(labels) != "benign").astype(np.int8)
    print(
        f"Loaded {rows_read:,} non-empty rows | "
        f"dropped {rows_dropped_fully_blank:,} fully empty rows | "
        f"{x.shape[1]} numeric features | {len(np.unique(days))} capture dates.",
        flush=True,
    )
    return x, hashes, labels, y, days, feature_columns, rows_dropped_fully_blank


def fit_score_if(
    x_train: np.ndarray,
    x_validation: np.ndarray,
    imputer: SimpleImputer,
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
    started = time.perf_counter()
    validation_scores = -model.score_samples(x_validation)
    score_seconds = time.perf_counter() - started
    return model, validation_scores, fit_seconds, score_seconds


def fit_baseline_models(
    x_train: np.ndarray,
    x_validation: np.ndarray,
    x_test: np.ndarray,
    lof_neighbors: int,
    svm_nu: float,
    svm_cache_mb: float,
):
    """Fit novelty LOF and RBF One-Class SVM on the identical benign sample."""
    baselines = {}
    for name in ("LOF_novelty", "RBF_OneClassSVM"):
        scaler = StandardScaler()
        z_train = scaler.fit_transform(x_train)
        z_validation = scaler.transform(x_validation)
        z_test = scaler.transform(x_test)

        if name == "LOF_novelty":
            model = LocalOutlierFactor(
                n_neighbors=min(lof_neighbors, len(z_train) - 1),
                novelty=True,
                contamination="auto",
                n_jobs=-1,
            )
        else:
            model = OneClassSVM(
                kernel="rbf", nu=svm_nu, gamma="scale",
                cache_size=svm_cache_mb,
            )

        started = time.perf_counter()
        model.fit(z_train)
        fit_seconds = time.perf_counter() - started
        started = time.perf_counter()
        if name == "LOF_novelty":
            val_scores = -model.score_samples(z_validation)
        else:
            val_scores = -model.decision_function(z_validation).reshape(-1)
        validation_score_seconds = time.perf_counter() - started

        baselines[name] = {
            "model": model,
            "scaler": scaler,
            "validation_scores": val_scores,
            "fit_seconds": fit_seconds,
            "validation_score_seconds": validation_score_seconds,
            "z_test": z_test,
        }
        print(
            f"Fitted {name}: {fit_seconds:.2f}s; "
            f"validation scoring {validation_score_seconds:.2f}s",
            flush=True,
        )
    return baselines


def evaluate_rolling_fold(
    fold_plan: dict,
    x: np.ndarray,
    hashes: np.ndarray,
    labels: np.ndarray,
    y: np.ndarray,
    days: np.ndarray,
    feature_columns: list[str],
    output: Path,
    args: argparse.Namespace,
    fpr_grid: list[float],
    configs: list[dict],
) -> dict:
    """Fit on prior benign traffic, calibrate on the next day, and test on the following day."""
    fold_id = int(fold_plan["fold"])
    train_days = fold_plan["training_days"]
    validation_day = fold_plan["validation_day"]
    test_day = fold_plan["test_day"]
    fold_output = output / f"fold_{fold_id}"
    fold_output.mkdir(parents=True, exist_ok=True)

    train_period_mask = np.isin(days, train_days)
    validation_period_mask = days == validation_day
    test_period_mask = days == test_day

    # A feature hash is assigned to its earliest temporal partition only.
    train_period_hashes = np.unique(hashes[train_period_mask])
    train_benign_positions = np.flatnonzero(train_period_mask & (y == 0))
    train_benign_positions = first_position_per_hash(train_benign_positions, hashes)

    validation_positions = np.flatnonzero(validation_period_mask)
    validation_positions = validation_positions[
        ~np.isin(hashes[validation_positions], train_period_hashes)
    ]
    validation_hashes = np.unique(hashes[validation_positions])

    test_positions = np.flatnonzero(test_period_mask)
    forbidden_test_hashes = np.concatenate([train_period_hashes, validation_hashes])
    test_positions = test_positions[
        ~np.isin(hashes[test_positions], forbidden_test_hashes)
    ]

    if len(train_benign_positions) < 100:
        raise ValueError(
            f"Fold {fold_id} has too few unique benign training flows: "
            f"{len(train_benign_positions)}."
        )
    if not len(validation_positions) or np.unique(y[validation_positions]).size != 2:
        raise ValueError(
            f"Fold {fold_id} validation day {validation_day} must contain both classes "
            "after duplicate filtering."
        )
    if not len(test_positions) or np.unique(y[test_positions]).size != 2:
        raise ValueError(
            f"Fold {fold_id} test day {test_day} must contain both classes "
            "after duplicate filtering."
        )

    fold_seed = int(args.seed) + fold_id * 100
    rng = np.random.default_rng(fold_seed)
    train_n = min(args.train_rows, len(train_benign_positions))
    train_positions = np.sort(
        rng.choice(train_benign_positions, size=train_n, replace=False)
    )
    validation_positions = sample_binary_stratified(
        validation_positions, y, args.validation_rows, fold_seed + 1
    )
    test_positions = sample_binary_stratified(
        test_positions, y, args.test_rows, fold_seed + 2
    )

    x_train_raw = x[train_positions]
    x_validation_raw = x[validation_positions]
    x_test_raw = x[test_positions]
    y_validation = y[validation_positions]
    y_test = y[test_positions]
    labels_test = labels[test_positions]

    # Fit all preprocessing on the benign training sample only.
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    x_train = imputer.fit_transform(x_train_raw)
    x_validation = imputer.transform(x_validation_raw)
    x_test = imputer.transform(x_test_raw)

    print(
        f"\nFOLD {fold_id}: train={train_days[0]}..{train_days[-1]} "
        f"({len(train_days)} day(s)); validation={validation_day}; test={test_day}",
        flush=True,
    )
    print(
        f"Rows: benign_train={len(train_positions):,}; "
        f"validation={len(validation_positions):,}; test={len(test_positions):,}",
        flush=True,
    )

    # Select IF configuration using validation labels at the predeclared FPR budget.
    validation_benign_scores: dict[str, np.ndarray] = {}
    grid_rows = []
    best_key = None
    best_if = None
    default_if = None
    default_config = {
        "n_estimators": 200,
        "max_samples": 1024,
        "max_features": 1.0,
    }

    for config in configs:
        model, val_scores, fit_s, val_score_s = fit_score_if(
            x_train, x_validation, imputer, config, fold_seed
        )
        threshold = threshold_at_fpr(val_scores[y_validation == 0], args.target_fpr)
        metrics = binary_metrics(y_validation, val_scores, threshold)
        grid_rows.append({
            "fold": fold_id,
            "validation_day": validation_day,
            "test_day": test_day,
            **config,
            "threshold": threshold,
            "validation_fit_seconds": fit_s,
            "validation_score_seconds": val_score_s,
            "target_fpr": args.target_fpr,
            **metrics,
        })
        key = (
            metrics["recall"],
            metrics["f1"],
            metrics["average_precision"],
            -fit_s,
        )
        if best_key is None or key > best_key:
            best_key = key
            best_if = model
            validation_benign_scores["IsolationForest_tuned"] = val_scores
            best_config = dict(config)
            best_if_fit_seconds = fit_s
        if config == default_config:
            default_if = model
            validation_benign_scores["IsolationForest_default"] = val_scores
            default_if_fit_seconds = fit_s
        print(
            f"  IF {config}: validation recall={metrics['recall']:.4f}, "
            f"FPR={metrics['fpr']:.4f}, F1={metrics['f1']:.4f}",
            flush=True,
        )

    if best_if is None:
        raise RuntimeError(f"Fold {fold_id}: IF grid produced no fitted model.")
    if default_if is None:
        default_if, default_scores, default_if_fit_seconds, _ = fit_score_if(
            x_train, x_validation, imputer, default_config, fold_seed
        )
        validation_benign_scores["IsolationForest_default"] = default_scores

    grid_frame = pd.DataFrame(grid_rows)

    baselines = fit_baseline_models(
        x_train, x_validation, x_test,
        args.lof_neighbors, args.svm_nu, args.svm_cache_mb,
    )
    validation_benign_scores["LOF_novelty"] = baselines["LOF_novelty"]["validation_scores"]
    validation_benign_scores["RBF_OneClassSVM"] = baselines["RBF_OneClassSVM"]["validation_scores"]

    # Score this fold's test date only after configurations and thresholds are frozen.
    test_scores: dict[str, np.ndarray] = {}
    scoring_seconds: dict[str, float] = {}

    for name, model in (
        ("IsolationForest_tuned", best_if),
        ("IsolationForest_default", default_if),
    ):
        score_start = time.perf_counter()
        test_scores[name] = -model.score_samples(x_test)
        scoring_seconds[name] = time.perf_counter() - score_start

    for name, info in baselines.items():
        score_start = time.perf_counter()
        if name == "LOF_novelty":
            test_scores[name] = -info["model"].score_samples(info["z_test"])
        else:
            test_scores[name] = -info["model"].decision_function(
                info["z_test"]
            ).reshape(-1)
        scoring_seconds[name] = time.perf_counter() - score_start

    validation_rows, test_rows, attack_rows = [], [], []
    primary_thresholds = {}
    for model_name, val_scores in validation_benign_scores.items():
        for fpr_budget in fpr_grid:
            threshold = threshold_at_fpr(val_scores[y_validation == 0], fpr_budget)
            val_metric = binary_metrics(y_validation, val_scores, threshold)
            validation_rows.append({
                "fold": fold_id,
                "validation_day": validation_day,
                "test_day": test_day,
                "model": model_name,
                "target_fpr": fpr_budget,
                "threshold": threshold,
                **val_metric,
            })

            test_metric = binary_metrics(y_test, test_scores[model_name], threshold)
            test_rows.append({
                "fold": fold_id,
                "training_start_day": train_days[0],
                "training_end_day": train_days[-1],
                "validation_day": validation_day,
                "test_day": test_day,
                "model": model_name,
                "target_fpr": fpr_budget,
                "validation_threshold": threshold,
                "validation_measured_fpr": val_metric["fpr"],
                "test_scoring_seconds": scoring_seconds[model_name],
                "training_rows": int(len(train_positions)),
                "validation_rows": int(len(validation_positions)),
                **test_metric,
            })

            if np.isclose(fpr_budget, args.target_fpr):
                primary_thresholds[model_name] = threshold
                for attack_name in sorted(set(labels_test.tolist())):
                    if attack_name.casefold() == "benign":
                        continue
                    mask = labels_test == attack_name
                    detected = int(np.sum(test_scores[model_name][mask] >= threshold))
                    support = int(mask.sum())
                    attack_rows.append({
                        "fold": fold_id,
                        "validation_day": validation_day,
                        "test_day": test_day,
                        "model": model_name,
                        "target_fpr": fpr_budget,
                        "attack_type": attack_name,
                        "test_support": support,
                        "detected": detected,
                        "missed": support - detected,
                        "recall": detected / support if support else float("nan"),
                    })

    thresholds = {
        str(fpr): threshold_at_fpr(
            validation_benign_scores["IsolationForest_tuned"][y_validation == 0], fpr
        )
        for fpr in fpr_grid
    }
    joblib.dump({
        "artifact_version": 2,
        "model_name": "IsolationForest",
        "model": best_if,
        "imputer": imputer,
        "feature_columns": feature_columns,
        "thresholds_by_validation_fpr": thresholds,
        "primary_target_fpr": args.target_fpr,
        "primary_threshold": primary_thresholds["IsolationForest_tuned"],
        "score_direction": "higher score is more anomalous",
        "training_days": train_days,
        "validation_day": validation_day,
        "test_day": test_day,
        "training_rows": int(len(train_positions)),
        "hyperparameters": best_config,
        "threshold_source": "validation benign-only scores",
        "fold": fold_id,
    }, fold_output / "isolation_forest_temporally_tuned.joblib")

    primary_rows = [
        row for row in test_rows if np.isclose(row["target_fpr"], args.target_fpr)
    ]
    fold_winner = max(primary_rows, key=lambda row: row["recall"])
    label_counts = {
        str(k): int(v) for k, v in pd.Series(labels_test).value_counts().items()
    }
    fit_times = {
        "LOF_novelty": baselines["LOF_novelty"]["fit_seconds"],
        "RBF_OneClassSVM": baselines["RBF_OneClassSVM"]["fit_seconds"],
        "IsolationForest_tuned": best_if_fit_seconds,
        "IsolationForest_default": default_if_fit_seconds,
    }
    fold_summary = {
        "fold": fold_id,
        "training_days": train_days,
        "validation_day": validation_day,
        "test_day": test_day,
        "unique_benign_training_candidates": int(len(train_benign_positions)),
        "training_rows_benign_unique": int(len(train_positions)),
        "validation_rows": int(len(validation_positions)),
        "test_rows": int(len(test_positions)),
        "test_attack_prevalence": float(y_test.mean()),
        "test_label_counts": label_counts,
        "selected_isolation_forest_config": best_config,
        "test_winner_by_recall_at_target_fpr": {
            "model": fold_winner["model"],
            "recall": fold_winner["recall"],
            "precision": fold_winner["precision"],
            "f1": fold_winner["f1"],
            "fpr": fold_winner["fpr"],
        },
        "fit_times_seconds": fit_times,
        "test_scoring_times_seconds": scoring_seconds,
    }

    print(
        pd.DataFrame(primary_rows)[[
            "model", "precision", "recall", "f1", "fpr",
            "average_precision", "roc_auc",
        ]].sort_values("recall", ascending=False).to_string(index=False),
        flush=True,
    )
    print(
        f"Fold {fold_id} IF config: {best_config}; "
        f"highest test recall: {fold_winner['model']}",
        flush=True,
    )

    return {
        "grid": grid_frame,
        "validation": pd.DataFrame(validation_rows),
        "test": pd.DataFrame(test_rows),
        "per_attack": pd.DataFrame(attack_rows),
        "summary": fold_summary,
    }


def summarize_rolling_metrics(test_frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return fold-macro metrics and pooled confusion-count metrics.

    AP and ROC-AUC are reported as fold-macro means only; they are not computed
    from concatenated scores because anomaly-score scales differ by fitted fold.
    """
    metric_columns = [
        "precision", "recall", "f1", "fpr",
        "average_precision", "roc_auc",
    ]
    macro_rows = []
    pooled_rows = []
    for (model, target_fpr), group in test_frame.groupby(["model", "target_fpr"]):
        macro_row = {
            "model": model,
            "target_fpr": float(target_fpr),
            "folds": int(group["fold"].nunique()),
        }
        for metric in metric_columns:
            values = group[metric].astype(float)
            macro_row[f"{metric}_mean"] = float(values.mean())
            macro_row[f"{metric}_std"] = float(values.std(ddof=1)) if len(values) > 1 else 0.0
        macro_rows.append(macro_row)

        tn = int(group["tn"].sum())
        fp = int(group["fp"].sum())
        fn = int(group["fn"].sum())
        tp = int(group["tp"].sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else float("nan")
        pooled_rows.append({
            "model": model,
            "target_fpr": float(target_fpr),
            "folds": int(group["fold"].nunique()),
            "precision_pooled": precision,
            "recall_pooled": recall,
            "f1_pooled": f1,
            "fpr_pooled": fpr,
            "false_alerts_per_million_benign_pooled": fpr * 1_000_000,
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "support_benign": tn + fp,
            "support_attack": tp + fn,
        })
    return pd.DataFrame(macro_rows), pd.DataFrame(pooled_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, help="Folder containing the metadata-rich CICIDS2017 CSVs.")
    parser.add_argument("--outdir", default="experiments/results/temporal-rolling-v1")
    parser.add_argument("--folds", type=int, default=3,
                        help="Number of expanding-window train/validation/test folds (default: 3).")
    parser.add_argument("--train-rows", type=int, default=25_000,
                        help="Maximum unique benign training flows shared by every model in each fold.")
    parser.add_argument("--validation-rows", type=int, default=120_000,
                        help="Binary-stratified validation cap; 0 uses the full validation day.")
    parser.add_argument("--test-rows", type=int, default=0,
                        help="Binary-stratified test cap; 0 uses the full test day.")
    parser.add_argument("--target-fpr", type=float, default=0.01,
                        help="Primary validation FPR budget used to select IF hyperparameters.")
    parser.add_argument("--fpr-grid", default="0.005,0.01,0.02,0.05",
                        help="Validation-only threshold sweep, e.g. 0.005,0.01,0.02,0.05.")
    parser.add_argument("--trees-grid", default="100,200")
    parser.add_argument("--max-samples-grid", default="256,512,1024")
    parser.add_argument("--max-features-grid", default="0.8,1.0")
    parser.add_argument("--lof-neighbors", type=int, default=35)
    parser.add_argument("--svm-nu", type=float, default=0.05)
    parser.add_argument("--svm-cache-mb", type=float, default=512)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.train_rows < 100 or args.validation_rows < 0 or args.test_rows < 0:
        raise ValueError("train-rows must be >=100; validation/test row limits cannot be negative.")
    if not 0.0 < args.target_fpr < 0.5:
        raise ValueError("target-fpr must be between 0 and 0.5.")
    if args.folds < 1:
        raise ValueError("folds must be at least 1.")

    trees_grid = parse_csv_grid(args.trees_grid, int, "trees-grid")
    samples_grid = parse_csv_grid(args.max_samples_grid, int, "max-samples-grid")
    features_grid = parse_csv_grid(args.max_features_grid, float, "max-features-grid")
    fpr_grid = sorted(set(
        parse_csv_grid(args.fpr_grid, float, "fpr-grid") + [args.target_fpr]
    ))
    if any(v <= 0.0 or v >= 0.5 for v in fpr_grid):
        raise ValueError("Every FPR grid value must be between 0 and 0.5.")
    if any(v <= 0 for v in trees_grid + samples_grid):
        raise ValueError("Trees and max-samples grid values must be positive.")
    if any(v <= 0.0 or v > 1.0 for v in features_grid):
        raise ValueError("max-features grid values must be in (0, 1].")

    configs = [
        {"n_estimators": int(t), "max_samples": int(s), "max_features": float(f)}
        for t, s, f in itertools.product(trees_grid, samples_grid, features_grid)
    ]
    started_total = time.perf_counter()
    output = Path(args.outdir)
    output.mkdir(parents=True, exist_ok=True)

    (
        x, hashes, labels, y, days, feature_columns, rows_dropped_fully_blank,
    ) = load_temporal_csvs(Path(args.data_dir))
    fold_plans = rolling_forward_splits(days, args.folds)
    print(f"Rolling forward-chaining folds: {len(fold_plans)}", flush=True)
    for plan in fold_plans:
        print(
            f"  Fold {plan['fold']}: train={plan['training_days'][0]}.."
            f"{plan['training_days'][-1]}, validation={plan['validation_day']}, "
            f"test={plan['test_day']}",
            flush=True,
        )

    results = []
    for plan in fold_plans:
        results.append(evaluate_rolling_fold(
            plan, x, hashes, labels, y, days, feature_columns,
            output, args, fpr_grid, configs,
        ))

    grid_frame = pd.concat([item["grid"] for item in results], ignore_index=True)
    validation_frame = pd.concat([item["validation"] for item in results], ignore_index=True)
    test_frame = pd.concat([item["test"] for item in results], ignore_index=True)
    attack_frame = pd.concat([item["per_attack"] for item in results], ignore_index=True)

    grid_frame.sort_values(
        ["fold", "recall", "f1", "average_precision"],
        ascending=[True, False, False, False],
    ).to_csv(output / "rolling_if_validation_grid.csv", index=False)
    validation_frame.to_csv(
        output / "rolling_validation_threshold_sweep.csv", index=False
    )
    test_frame.to_csv(output / "rolling_test_metrics.csv", index=False)
    attack_frame.to_csv(output / "rolling_per_attack_recall.csv", index=False)

    macro_frame, pooled_frame = summarize_rolling_metrics(test_frame)
    macro_frame.to_csv(output / "rolling_macro_metrics.csv", index=False)
    pooled_frame.to_csv(output / "rolling_pooled_confusion_metrics.csv", index=False)

    summary = {
        "dataset": str(Path(args.data_dir)),
        "rows_loaded": int(len(x)),
        "rows_dropped_fully_blank": int(rows_dropped_fully_blank),
        "numeric_features": int(x.shape[1]),
        "timestamp_parse": "pandas format=mixed, dayfirst=True",
        "duplicate_policy": (
            "exact numeric-feature hashes retained in their earliest chronological "
            "train/validation/test partition only"
        ),
        "fold_design": (
            "expanding-window forward chaining: prior days train, next day validation, "
            "following day untouched test"
        ),
        "fold_count": len(fold_plans),
        "target_fpr": args.target_fpr,
        "fpr_grid": fpr_grid,
        "if_grid_candidates_per_fold": len(configs),
        "same_training_rows_for_all_models_within_each_fold": True,
        "threshold_selection": (
            "validation-benign-only empirical upper tail within each fold; test labels "
            "never used for threshold selection"
        ),
        "hyperparameter_selection": (
            "per-fold maximum validation attack recall at target FPR; ties by F1, "
            "average precision, then fit time"
        ),
        "folds": [item["summary"] for item in results],
        "macro_metrics_by_model_and_fpr": macro_frame.to_dict(orient="records"),
        "pooled_confusion_metrics_by_model_and_fpr": pooled_frame.to_dict(orient="records"),
        "metric_aggregation_note": (
            "Precision/recall/F1/FPR pooled from summed confusion counts are also reported. "
            "AP and ROC-AUC are fold-macro means only because fitted-fold anomaly score "
            "scales are not assumed comparable."
        ),
        "total_elapsed_seconds": time.perf_counter() - started_total,
        "interpretation_warning": (
            "These are three forward-chaining holdouts from one CICIDS2017 capture. "
            "The folds expose temporal and attack-family shift but are not independent "
            "datasets or proof of generalization to another network. Thresholds are "
            "calibrated per validation date and can exceed their nominal FPR on a later "
            "test date. Precision/AP depend on each test window's attack prevalence."
        ),
    }
    summary_path = output / "rolling_temporal_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    primary = test_frame[np.isclose(test_frame["target_fpr"], args.target_fpr)].copy()
    print("\nROLLING TEMPORAL TEST — per fold at validation-calibrated FPR budget", flush=True)
    print(primary[[
        "fold", "validation_day", "test_day", "model", "precision", "recall",
        "f1", "fpr", "average_precision", "roc_auc",
    ]].sort_values(["fold", "recall"], ascending=[True, False]).to_string(index=False))
    print("\nFOLD-MACRO SUMMARY", flush=True)
    primary_macro = macro_frame[np.isclose(macro_frame["target_fpr"], args.target_fpr)]
    print(primary_macro[[
        "model", "precision_mean", "precision_std", "recall_mean", "recall_std",
        "f1_mean", "f1_std", "fpr_mean", "average_precision_mean", "roc_auc_mean",
    ]].sort_values("f1_mean", ascending=False).to_string(index=False))
    print("\nPOOLED CONFUSION-COUNT SUMMARY", flush=True)
    primary_pooled = pooled_frame[np.isclose(pooled_frame["target_fpr"], args.target_fpr)]
    print(primary_pooled[[
        "model", "precision_pooled", "recall_pooled", "f1_pooled", "fpr_pooled",
        "false_alerts_per_million_benign_pooled", "support_benign", "support_attack",
    ]].sort_values("f1_pooled", ascending=False).to_string(index=False))
    print(f"\nSummary: {summary_path.resolve()}", flush=True)
    print(f"Outputs: {output.resolve()}", flush=True)


if __name__ == "__main__":
    main()
