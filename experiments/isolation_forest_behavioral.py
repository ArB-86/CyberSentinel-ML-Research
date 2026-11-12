#!/usr/bin/env python3
"""Evaluate causal host-behaviour features for CICIDS2017 Isolation Forest.

All behavioural features are computed from flows with strictly earlier
timestamps. Rows sharing the same timestamp see the same prior history.
Ground-truth labels are never read by the feature builder. Each feature-set
variant uses the same temporal folds, benign training rows, IF parameters,
and independently validation-benign-calibrated threshold.
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


IF_CONFIG = {
    "n_estimators": 200,
    "max_samples": 1024,
    "max_features": 1.0,
    "contamination": "auto",
}
FEATURE_SETS = {
    "raw_baseline": [],
    "source_augmented": [
        "src_prior_flow_count",
        "src_seconds_since_previous_flow",
        "src_prior_unique_dst_ip_count",
        "src_prior_unique_dst_port_count",
        "src_protocol_prior_flow_count",
    ],
    "destination_augmented": [
        "dst_prior_flow_count",
        "dst_seconds_since_previous_flow",
        "dst_prior_unique_src_ip_count",
    ],
    "pair_augmented": [
        "src_dst_prior_flow_count",
        "src_dst_seconds_since_previous_flow",
    ],
    "combined_augmented": [
        "src_prior_flow_count",
        "src_seconds_since_previous_flow",
        "src_prior_unique_dst_ip_count",
        "src_prior_unique_dst_port_count",
        "src_protocol_prior_flow_count",
        "dst_prior_flow_count",
        "dst_seconds_since_previous_flow",
        "dst_prior_unique_src_ip_count",
        "src_dst_prior_flow_count",
        "src_dst_seconds_since_previous_flow",
    ],
}


def _history_table(
    ordered: pd.DataFrame,
    original: pd.DataFrame,
    entity_columns: list[str],
    peer_columns: list[str],
    prefix: str,
) -> tuple[pd.DataFrame, list[str]]:
    """Create per-entity history as of each timestamp, excluding that timestamp."""
    keys = entity_columns + ["timestamp"]
    events = (
        ordered.groupby(keys, sort=False, dropna=False)
        .size()
        .rename("flows_at_timestamp")
        .reset_index()
        .sort_values(keys, kind="mergesort")
        .reset_index(drop=True)
    )

    entity_group = events.groupby(entity_columns, sort=False, dropna=False)
    prior_flow_name = f"{prefix}_prior_flow_count"
    events[prior_flow_name] = (
        entity_group["flows_at_timestamp"].cumsum() - events["flows_at_timestamp"]
    )
    previous_timestamp = entity_group["timestamp"].shift(1)
    gap_name = f"{prefix}_seconds_since_previous_flow"
    events[gap_name] = (
        events["timestamp"] - previous_timestamp
    ).dt.total_seconds().fillna(0.0)

    feature_names = [prior_flow_name, gap_name]
    for peer_column in peer_columns:
        # The first occurrence of each peer is attributed to its earliest
        # timestamp. All peers first seen at the current timestamp are then
        # excluded from "prior" counts for every row at that timestamp.
        first_seen = ordered.dropna(subset=entity_columns + [peer_column])
        first_seen = first_seen.drop_duplicates(
            subset=entity_columns + [peer_column], keep="first"
        )
        new_peer_counts = (
            first_seen.groupby(keys, sort=False, dropna=False)
            .size()
            .rename("new_peer_count")
            .reset_index()
        )
        events = events.merge(
            new_peer_counts, on=keys, how="left", sort=False, validate="one_to_one"
        )
        events = events.sort_values(keys, kind="mergesort").reset_index(drop=True)
        new_peer_counts_at_time = events["new_peer_count"].fillna(0.0)
        peer_metric = f"{prefix}_prior_unique_{peer_column}_count"
        events[peer_metric] = (
            events.groupby(entity_columns, sort=False, dropna=False)[
                "new_peer_count"
            ].cumsum()
            - new_peer_counts_at_time
        )
        events = events.drop(columns=["new_peer_count"])
        feature_names.append(peer_metric)

    # Use a MultiIndex lookup rather than a many-to-many merge. The entity +
    # timestamp key is unique in events but intentionally repeated in rows.
    row_keys = pd.MultiIndex.from_frame(original[keys])
    mapped = events.set_index(keys)[feature_names].reindex(row_keys)
    mapped = mapped.fillna(0.0)
    return mapped.reset_index(drop=True), feature_names


def build_causal_behavior_features(
    metadata: pd.DataFrame,
) -> tuple[np.ndarray, list[str]]:
    """Build label-free, strictly past-only source/destination/pair features.

    Feature state is captured at timestamp granularity: simultaneous flows do
    not see one another. History is cumulative from the beginning of the
    capture, so a test-day flow may use earlier validation-day traffic exactly
    as an online detector would, without using its labels.
    """
    required = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol"}
    missing = required.difference(metadata.columns)
    if missing:
        raise ValueError(f"Missing flow metadata columns: {sorted(missing)}")
    if metadata["timestamp"].isna().any():
        raise ValueError("Behavioural features require valid timestamps.")

    original = metadata.reset_index(drop=True).copy()
    for column in ("src_ip", "dst_ip", "protocol"):
        original[column] = (
            original[column].astype("string").str.strip().fillna("__MISSING__")
        )
    original["dst_port"] = pd.to_numeric(original["dst_port"], errors="coerce")

    # Stable chronological ordering ensures first-peer attribution is correct.
    order = np.argsort(original["timestamp"].to_numpy(), kind="stable")
    ordered = original.iloc[order][
        ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol"]
    ].reset_index(drop=True)

    specs = [
        (["src_ip"], ["dst_ip", "dst_port"], "src"),
        (["dst_ip"], ["src_ip"], "dst"),
        (["src_ip", "dst_ip"], [], "src_dst"),
        (["src_ip", "protocol"], [], "src_protocol"),
    ]
    feature_parts = []
    feature_names: list[str] = []
    for entities, peers, prefix in specs:
        mapped, names = _history_table(
            ordered, original, entities, peers, prefix
        )
        feature_parts.append(mapped.to_numpy(dtype=np.float32, copy=True))
        feature_names.extend(names)

    features = np.concatenate(feature_parts, axis=1)
    if not np.isfinite(features).all():
        raise RuntimeError("Causal behavioural features contain non-finite values.")
    return features, feature_names


def choose_fold_rows(
    days: np.ndarray,
    hashes: np.ndarray,
    y: np.ndarray,
    fold_plan: dict,
    args: argparse.Namespace,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    train_period = np.isin(days, fold_plan["training_days"])
    validation_period = days == fold_plan["validation_day"]
    test_period = days == fold_plan["test_day"]

    train_hashes = np.unique(hashes[train_period])
    benign_train = np.flatnonzero(train_period & (y == 0))
    benign_train = first_position_per_hash(benign_train, hashes)

    validation = np.flatnonzero(validation_period)
    validation = validation[~np.isin(hashes[validation], train_hashes)]
    validation_hashes = np.unique(hashes[validation])

    test = np.flatnonzero(test_period)
    forbidden_hashes = np.concatenate([train_hashes, validation_hashes])
    test = test[~np.isin(hashes[test], forbidden_hashes)]

    for name, positions in (("training", benign_train), ("validation", validation), ("test", test)):
        if not len(positions):
            raise ValueError(f"Fold {fold_plan['fold']} has no rows in {name} partition.")
    if len(benign_train) < 100:
        raise ValueError(f"Fold {fold_plan['fold']} has fewer than 100 unique benign training flows.")
    if np.unique(y[validation]).size != 2 or np.unique(y[test]).size != 2:
        raise ValueError(f"Fold {fold_plan['fold']} validation/test need both classes.")

    fold_seed = args.seed + int(fold_plan["fold"]) * 100
    rng = np.random.default_rng(fold_seed)
    train = np.sort(rng.choice(
        benign_train, size=min(args.train_rows, len(benign_train)), replace=False
    ))
    validation = sample_binary_stratified(
        validation, y, args.validation_rows, fold_seed + 1
    )
    test = sample_binary_stratified(test, y, args.test_rows, fold_seed + 2)
    return train, validation, test


def fit_and_evaluate_variant(
    name: str,
    columns: list[str],
    base_x: np.ndarray,
    behavior_x: np.ndarray,
    behavior_names: list[str],
    train_pos: np.ndarray,
    validation_pos: np.ndarray,
    test_pos: np.ndarray,
    y_validation: np.ndarray,
    y_test: np.ndarray,
    labels_test: np.ndarray,
    feature_columns: list[str],
    target_fpr: float,
    seed: int,
    fold_output: Path,
) -> tuple[dict, list[dict]]:
    """Fit one fixed-configuration IF variant and freeze its validation threshold."""
    behavior_indices = [behavior_names.index(column) for column in columns]
    selected_behavior = (
        behavior_x[:, behavior_indices] if behavior_indices else None
    )

    x_train = base_x[train_pos]
    x_validation = base_x[validation_pos]
    x_test = base_x[test_pos]
    if selected_behavior is not None:
        x_train = np.concatenate([x_train, selected_behavior[train_pos]], axis=1)
        x_validation = np.concatenate(
            [x_validation, selected_behavior[validation_pos]], axis=1
        )
        x_test = np.concatenate([x_test, selected_behavior[test_pos]], axis=1)

    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    x_train = imputer.fit_transform(x_train)
    x_validation = imputer.transform(x_validation)
    x_test = imputer.transform(x_test)

    model = IsolationForest(
        **IF_CONFIG,
        random_state=seed,
        n_jobs=-1,
    )
    fit_started = time.perf_counter()
    model.fit(x_train)
    fit_seconds = time.perf_counter() - fit_started

    validation_scores = -model.score_samples(x_validation)
    threshold = threshold_at_fpr(
        validation_scores[y_validation == 0], target_fpr
    )
    validation_metrics = binary_metrics(
        y_validation, validation_scores, threshold
    )

    test_started = time.perf_counter()
    test_scores = -model.score_samples(x_test)
    scoring_seconds = time.perf_counter() - test_started
    test_metrics = binary_metrics(y_test, test_scores, threshold)

    record = {
        "model": name,
        "feature_count": int(x_train.shape[1]),
        "behavior_feature_count": len(columns),
        "behavior_features": ",".join(columns),
        "fit_seconds": fit_seconds,
        "test_scoring_seconds": scoring_seconds,
        "threshold": float(threshold),
        "validation_precision": validation_metrics["precision"],
        "validation_recall": validation_metrics["recall"],
        "validation_f1": validation_metrics["f1"],
        "validation_fpr": validation_metrics["fpr"],
        **test_metrics,
    }

    attack_rows = []
    for attack_name in sorted(set(labels_test.tolist())):
        if str(attack_name).casefold() == "benign":
            continue
        mask = labels_test == attack_name
        support = int(mask.sum())
        detected = int(np.sum(test_scores[mask] >= threshold))
        attack_rows.append({
            "model": name,
            "attack_type": str(attack_name),
            "test_support": support,
            "detected": detected,
            "missed": support - detected,
            "recall": detected / support if support else float("nan"),
        })

    feature_names = list(feature_columns) + list(columns)
    artifact = {
        "artifact_version": 1,
        "model_name": "IsolationForest",
        "model": model,
        "imputer": imputer,
        "feature_set": name,
        "feature_names": feature_names,
        "base_feature_columns": list(feature_columns),
        "behavior_feature_names": list(columns),
        "hyperparameters": dict(IF_CONFIG),
        "primary_target_fpr": target_fpr,
        "primary_threshold": float(threshold),
        "threshold_source": "validation benign-only scores",
        "score_direction": "higher score is more anomalous",
        "behavior_feature_policy": (
            "strictly earlier timestamps only; same-timestamp flows share "
            "the same prior state; no labels used"
        ),
    }
    joblib.dump(artifact, fold_output / f"{name}.joblib")
    return record, attack_rows


def evaluate_fold(
    fold_plan: dict,
    x: np.ndarray,
    behavior_x: np.ndarray,
    behavior_names: list[str],
    hashes: np.ndarray,
    labels: np.ndarray,
    y: np.ndarray,
    days: np.ndarray,
    feature_columns: list[str],
    args: argparse.Namespace,
    output: Path,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    fold_id = int(fold_plan["fold"])
    train_pos, validation_pos, test_pos = choose_fold_rows(
        days, hashes, y, fold_plan, args
    )
    y_validation = y[validation_pos]
    y_test = y[test_pos]
    labels_test = labels[test_pos]
    fold_output = output / f"fold_{fold_id}"
    fold_output.mkdir(parents=True, exist_ok=True)

    print(
        f"\nFOLD {fold_id}: train={fold_plan['training_days'][0]}.."
        f"{fold_plan['training_days'][-1]}, validation={fold_plan['validation_day']}, "
        f"test={fold_plan['test_day']}; rows={len(train_pos):,}/"
        f"{len(validation_pos):,}/{len(test_pos):,}",
        flush=True,
    )

    test_rows = []
    attack_rows = []
    for variant_index, (name, columns) in enumerate(FEATURE_SETS.items()):
        record, attacks = fit_and_evaluate_variant(
            name=name,
            columns=columns,
            base_x=x,
            behavior_x=behavior_x,
            behavior_names=behavior_names,
            train_pos=train_pos,
            validation_pos=validation_pos,
            test_pos=test_pos,
            y_validation=y_validation,
            y_test=y_test,
            labels_test=labels_test,
            feature_columns=feature_columns,
            target_fpr=args.target_fpr,
            seed=args.seed + fold_id * 100,
            fold_output=fold_output,
        )
        record.update({
            "fold": fold_id,
            "validation_day": fold_plan["validation_day"],
            "test_day": fold_plan["test_day"],
            "target_fpr": args.target_fpr,
            "training_rows": len(train_pos),
            "validation_rows": len(validation_pos),
            "test_rows": len(test_pos),
        })
        for attack in attacks:
            attack.update({
                "fold": fold_id,
                "test_day": fold_plan["test_day"],
                "target_fpr": args.target_fpr,
            })
        test_rows.append(record)
        attack_rows.extend(attacks)
        print(
            f"  {name}: validation recall={record['validation_recall']:.4f}, "
            f"test recall={record['recall']:.4f}, test FPR={record['fpr']:.4f}, "
            f"test F1={record['f1']:.4f}",
            flush=True,
        )

    summary = {
        "fold": fold_id,
        "training_days": list(fold_plan["training_days"]),
        "validation_day": fold_plan["validation_day"],
        "test_day": fold_plan["test_day"],
        "training_rows": len(train_pos),
        "validation_rows": len(validation_pos),
        "test_rows": len(test_pos),
        "test_attack_prevalence": float(y_test.mean()),
    }
    return pd.DataFrame(test_rows), pd.DataFrame(attack_rows), summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument(
        "--outdir", default="experiments/results/isolation-forest-behavior-v1"
    )
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

    (
        x, hashes, labels, y, days, feature_columns, dropped, metadata,
    ) = load_temporal_csvs(Path(args.data_dir), return_metadata=True)
    print("Building causal host-behaviour features (labels are not passed)...", flush=True)
    behavior_x, behavior_names = build_causal_behavior_features(metadata)
    print(
        f"Built {len(behavior_names)} causal behavioural features for {len(x):,} flows.",
        flush=True,
    )

    fold_plans = rolling_forward_splits(days, args.folds)
    results = [
        evaluate_fold(
            plan, x, behavior_x, behavior_names, hashes, labels, y, days,
            feature_columns, args, output,
        )
        for plan in fold_plans
    ]

    test_frame = pd.concat([item[0] for item in results], ignore_index=True)
    attack_frame = pd.concat([item[1] for item in results], ignore_index=True)
    test_frame.to_csv(output / "if_behavior_test_metrics.csv", index=False)
    attack_frame.to_csv(output / "if_behavior_per_attack_recall.csv", index=False)

    summary = {
        "dataset": str(Path(args.data_dir)),
        "rows_loaded": int(len(x)),
        "rows_dropped_fully_blank": int(dropped),
        "base_numeric_features": int(x.shape[1]),
        "behavioral_features": behavior_names,
        "feature_sets": FEATURE_SETS,
        "isolation_forest_config": IF_CONFIG,
        "fold_count": len(fold_plans),
        "target_fpr": args.target_fpr,
        "threshold_policy": (
            "Each feature set has its own threshold calibrated on validation-benign "
            "scores only. Thresholds are frozen before the later test date is scored."
        ),
        "behavioral_feature_policy": (
            "Cumulative source/destination/pair history from strictly earlier "
            "timestamps only. All records with identical timestamps share the same "
            "prior state. Features use IP/port/protocol metadata and timestamps, "
            "never ground-truth labels."
        ),
        "duplicate_policy": (
            "The same exact numeric-feature hash policy as the rolling temporal "
            "experiment: a row's base feature hash belongs to its earliest "
            "chronological partition only."
        ),
        "folds": [item[2] for item in results],
        "test_results": test_frame.to_dict(orient="records"),
        "interpretation_warning": (
            "One CICIDS2017 capture only. Behavioural history is causally available "
            "within this capture, but IP identities and traffic history may not "
            "transfer to another network. Compare all feature sets across untouched "
            "test dates and attack families; do not choose from test labels."
        ),
        "elapsed_seconds": time.perf_counter() - started,
    }
    summary_path = output / "if_behavior_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    print("\nISOLATION FOREST CAUSAL BEHAVIOUR — untouched test results", flush=True)
    print(test_frame[[
        "fold", "test_day", "model", "behavior_feature_count",
        "precision", "recall", "f1", "fpr", "average_precision", "roc_auc",
    ]].to_string(index=False), flush=True)
    print(f"\nSummary: {summary_path.resolve()}", flush=True)
    print(f"Outputs: {output.resolve()}", flush=True)


if __name__ == "__main__":
    main()
