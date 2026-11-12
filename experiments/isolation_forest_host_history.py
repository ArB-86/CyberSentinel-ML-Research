#!/usr/bin/env python3
"""Test causal host-behaviour features for Isolation Forest on CICIDS2017.

The feature builder aggregates completed one-minute buckets only. Each flow
therefore receives history from earlier buckets, never from its own bucket or
any future traffic. The same expanding temporal folds, duplicate policy,
benign-only model fitting and validation-benign FPR calibration as the rolling
baseline are retained.
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

from attack_graph.event_builder import normalize_columns
from experiments.temporal_threshold_optimization import (
    NON_FEATURE_COLUMNS,
    binary_metrics,
    first_position_per_hash,
    parse_cicids_timestamps,
    rolling_forward_splits,
    sample_binary_stratified,
    threshold_at_fpr,
)


MINUTE_NS = 60 * 1_000_000_000
IF_CONFIG = {"n_estimators": 200, "max_samples": 1024, "max_features": 1.0}

BEHAVIORAL_FEATURE_COLUMNS = [
    "src_flows_prev_1m",
    "src_destination_ip_contacts_prev_1m",
    "src_destination_port_contacts_prev_1m",
    "src_bytes_prev_1m",
    "src_packets_prev_1m",
    "src_flows_prev_5m",
    "src_destination_ip_contacts_per_minute_sum_prev_5m",
    "src_destination_port_contacts_per_minute_sum_prev_5m",
    "src_bytes_prev_5m",
    "src_packets_prev_5m",
    "dst_flows_prev_1m",
    "dst_source_ip_contacts_prev_1m",
    "dst_bytes_prev_1m",
    "dst_packets_prev_1m",
    "dst_flows_prev_5m",
    "dst_source_ip_contacts_per_minute_sum_prev_5m",
    "dst_bytes_prev_5m",
    "dst_packets_prev_5m",
]


def _header_token(value: str) -> str:
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())


def _matching_numeric_columns(columns, aliases: set[str]) -> list[str]:
    lookup = {_header_token(column): column for column in columns}
    return [lookup[token] for token in aliases if token in lookup]


def _sum_numeric_columns(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    if not columns:
        return np.zeros(len(frame), dtype=np.float32)
    values = frame[columns].apply(pd.to_numeric, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return values.clip(lower=0.0).sum(axis=1).to_numpy(dtype=np.float32)


def load_behavioral_dataset(data_dir: Path):
    """Load the same flow features/labels as the baseline plus host metadata."""
    paths = sorted(data_dir.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"No CICIDS2017 CSV files found in {data_dir}")

    feature_columns: list[str] | None = None
    feature_parts, hash_parts, label_parts, day_parts = [], [], [], []
    timestamp_parts, src_ip_parts, dst_ip_parts, dst_port_parts = [], [], [], []
    byte_parts, packet_parts = [], []
    rows_loaded = 0
    rows_dropped_empty = 0

    byte_aliases = {
        _header_token("Total Length of Fwd Packets"),
        _header_token("Total Length of Bwd Packets"),
    }
    packet_aliases = {
        _header_token("Total Fwd Packets"),
        _header_token("Total Backward Packets"),
    }

    for path in paths:
        print(f"Reading {path.name}...", flush=True)
        raw = pd.read_csv(path, low_memory=False, encoding="latin1")
        work = normalize_columns(raw)

        empty_rows = work.isna().all(axis=1)
        empty_count = int(empty_rows.sum())
        if empty_count:
            rows_dropped_empty += empty_count
            print(f"  Skipping {empty_count:,} fully empty rows.", flush=True)
            work = work.loc[~empty_rows].copy()
        if work.empty:
            raise ValueError(f"{path.name} contains no non-empty data rows.")

        required = {"timestamp", "label", "src_ip", "dst_ip", "dst_port"}
        missing = required.difference(work.columns)
        if missing:
            raise ValueError(
                f"{path.name} is missing required behavioural metadata: {sorted(missing)}"
            )

        timestamps = parse_cicids_timestamps(work["timestamp"])
        if timestamps.isna().any():
            raise ValueError(
                f"{path.name}: {int(timestamps.isna().sum())} timestamps failed day-first parsing."
            )

        labels = work["label"].astype("string").str.strip()
        labels = labels.str.replace("\x96", "-", regex=False).str.replace("\ufffd", "-", regex=False)
        if (
            labels.isna().any()
            or labels.str.casefold().isin({"", "nan", "none", "null"}).any()
        ):
            raise ValueError(f"{path.name} contains missing/blank ground-truth labels.")

        src_ip = work["src_ip"].astype("string").str.strip()
        dst_ip = work["dst_ip"].astype("string").str.strip()
        if src_ip.isna().any() or src_ip.eq("").any():
            raise ValueError(f"{path.name} contains missing/blank source IP values.")
        if dst_ip.isna().any() or dst_ip.eq("").any():
            raise ValueError(f"{path.name} contains missing/blank destination IP values.")

        dst_port = pd.to_numeric(work["dst_port"], errors="coerce")
        if dst_port.isna().any():
            raise ValueError(f"{path.name} contains missing/non-numeric destination ports.")

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
        timestamp_parts.append(timestamps.astype("int64").to_numpy(dtype=np.int64))
        src_ip_parts.append(src_ip.to_numpy(dtype=object))
        dst_ip_parts.append(dst_ip.to_numpy(dtype=object))
        dst_port_parts.append(dst_port.to_numpy(dtype=np.int32))
        byte_columns = _matching_numeric_columns(numeric.columns, byte_aliases)
        packet_columns = _matching_numeric_columns(numeric.columns, packet_aliases)
        if not byte_columns or not packet_columns:
            raise ValueError(
                f"{path.name} must contain numeric forward/backward packet-byte totals "
                "to build host traffic-volume history features."
            )
        byte_parts.append(_sum_numeric_columns(numeric, byte_columns))
        packet_parts.append(_sum_numeric_columns(numeric, packet_columns))
        rows_loaded += len(work)
        del raw, work, numeric

    x = np.concatenate(feature_parts, axis=0)
    hashes = np.concatenate(hash_parts)
    labels = np.concatenate(label_parts)
    days = np.concatenate(day_parts)
    timestamps_ns = np.concatenate(timestamp_parts)
    src_ips = pd.Series(np.concatenate(src_ip_parts), dtype="string")
    dst_ips = pd.Series(np.concatenate(dst_ip_parts), dtype="string")
    src_codes, _ = pd.factorize(src_ips, sort=False)
    dst_codes, _ = pd.factorize(dst_ips, sort=False)
    dst_ports = np.concatenate(dst_port_parts).astype(np.int32, copy=False)
    flow_bytes = np.concatenate(byte_parts).astype(np.float32, copy=False)
    flow_packets = np.concatenate(packet_parts).astype(np.float32, copy=False)
    del src_ips, dst_ips, feature_parts, hash_parts, label_parts, day_parts
    del timestamp_parts, src_ip_parts, dst_ip_parts, dst_port_parts, byte_parts, packet_parts

    y = (np.char.lower(labels) != "benign").astype(np.int8)
    metadata_arrays = {
        "timestamps_ns": timestamps_ns,
        "src_codes": src_codes.astype(np.int32, copy=False),
        "dst_codes": dst_codes.astype(np.int32, copy=False),
        "dst_ports": dst_ports,
        "flow_bytes": flow_bytes,
        "flow_packets": flow_packets,
    }
    print(
        f"Loaded {rows_loaded:,} non-empty rows | dropped {rows_dropped_empty:,} fully "
        f"empty rows | {x.shape[1]} numeric features | {len(np.unique(days))} capture dates.",
        flush=True,
    )
    return x, hashes, labels, y, days, feature_columns, metadata_arrays, rows_dropped_empty


def _rolling_host_features(
    bucket_table: pd.DataFrame,
    host_column: str,
    metric_columns: list[str],
    output_names: dict[str, dict[str, str]],
) -> pd.DataFrame:
    """Sum prior host-minute buckets over exact causal 1m and 5m windows.

    Uses per-host prefix sums and searchsorted rather than pandas' grouped
    time-based rolling implementation. This makes the left-closed window
    semantics explicit and consistent across supported pandas versions.
    """
    ordered = bucket_table.sort_values(
        [host_column, "bucket"], kind="mergesort"
    ).reset_index(drop=True)
    result = ordered[[host_column, "bucket"]].copy()
    if ordered.empty:
        for mapping in output_names.values():
            for output_column in mapping.values():
                result[output_column] = np.zeros(0, dtype=np.float32)
        return result

    timestamps = ordered["bucket"].astype("int64").to_numpy(dtype=np.int64)
    values = ordered[metric_columns].to_numpy(dtype=np.float64, copy=True)
    grouped_positions = ordered.groupby(
        host_column, sort=False, dropna=False
    ).indices.values()

    for window_label, window in (("1m", "1min"), ("5m", "5min")):
        window_ns = int(pd.Timedelta(window).value)
        window_values = np.zeros(
            (len(ordered), len(metric_columns)), dtype=np.float64
        )
        for positions in grouped_positions:
            positions = np.asarray(positions, dtype=np.int64)
            group_times = timestamps[positions]
            group_values = values[positions]

            # Prefix[k] contains the sum of rows strictly before local row k.
            prefix = np.vstack([
                np.zeros((1, len(metric_columns)), dtype=np.float64),
                np.cumsum(group_values, axis=0, dtype=np.float64),
            ])
            left = np.searchsorted(
                group_times, group_times - window_ns, side="left"
            )
            current = np.arange(len(positions), dtype=np.int64)
            window_values[positions] = prefix[current] - prefix[left]

        for metric_index, metric in enumerate(metric_columns):
            output_column = output_names[window_label][metric]
            result[output_column] = window_values[:, metric_index].astype(
                np.float32, copy=False
            )

    return result


def build_behavioral_history_features(
    timestamps_ns: np.ndarray,
    src_codes: np.ndarray,
    dst_codes: np.ndarray,
    dst_ports: np.ndarray,
    flow_bytes: np.ndarray,
    flow_packets: np.ndarray,
) -> pd.DataFrame:
    """Build past-only source and destination behaviour features.

    Features are attached to a flow using its minute bucket, but rolling
    windows are closed on the left. Thus a flow at minute T sees only buckets
    strictly earlier than T. Same-minute traffic is deliberately excluded.
    """
    arrays = [
        np.asarray(value).reshape(-1)
        for value in (
            timestamps_ns, src_codes, dst_codes, dst_ports, flow_bytes, flow_packets
        )
    ]
    lengths = {len(value) for value in arrays}
    if len(lengths) != 1 or not lengths or next(iter(lengths)) == 0:
        raise ValueError("All behavioural feature arrays must have the same non-zero length.")

    timestamps_ns, src_codes, dst_codes, dst_ports, flow_bytes, flow_packets = arrays
    if np.any(timestamps_ns < 0):
        raise ValueError("timestamps_ns must contain valid non-negative epoch timestamps.")
    if np.any(src_codes < 0) or np.any(dst_codes < 0):
        raise ValueError("Host codes must be non-negative.")
    if not np.isfinite(flow_bytes).all() or not np.isfinite(flow_packets).all():
        raise ValueError("Flow byte/packet aggregates must be finite.")

    bucket_minute = timestamps_ns.astype(np.int64) // MINUTE_NS
    bucket = pd.to_datetime(bucket_minute, unit="m")
    src = pd.DataFrame({
        "host_id": src_codes.astype(np.int32, copy=False),
        "bucket": bucket,
        "dst_id": dst_codes.astype(np.int32, copy=False),
        "dst_port": dst_ports.astype(np.int32, copy=False),
        "flow_bytes": flow_bytes.astype(np.float32, copy=False),
        "flow_packets": flow_packets.astype(np.float32, copy=False),
    })
    src_buckets = (
        src.groupby(["host_id", "bucket"], sort=False, observed=True)
        .agg(
            flow_count=("dst_id", "size"),
            destination_ip_contacts=("dst_id", "nunique"),
            destination_port_contacts=("dst_port", "nunique"),
            bytes_sum=("flow_bytes", "sum"),
            packets_sum=("flow_packets", "sum"),
        )
        .reset_index()
    )
    del src

    src_output_names = {
        "1m": {
            "flow_count": "src_flows_prev_1m",
            "destination_ip_contacts": "src_destination_ip_contacts_prev_1m",
            "destination_port_contacts": "src_destination_port_contacts_prev_1m",
            "bytes_sum": "src_bytes_prev_1m",
            "packets_sum": "src_packets_prev_1m",
        },
        "5m": {
            "flow_count": "src_flows_prev_5m",
            "destination_ip_contacts": "src_destination_ip_contacts_per_minute_sum_prev_5m",
            "destination_port_contacts": "src_destination_port_contacts_per_minute_sum_prev_5m",
            "bytes_sum": "src_bytes_prev_5m",
            "packets_sum": "src_packets_prev_5m",
        },
    }
    src_features = _rolling_host_features(
        src_buckets, "host_id",
        ["flow_count", "destination_ip_contacts", "destination_port_contacts", "bytes_sum", "packets_sum"],
        src_output_names,
    )
    src_lookup = src_features.set_index(["host_id", "bucket"])
    row_lookup = pd.MultiIndex.from_arrays(
        [src_codes.astype(np.int32, copy=False), bucket],
        names=["host_id", "bucket"],
    )
    src_values = src_lookup.reindex(row_lookup)[
        [name for mapping in src_output_names.values() for name in mapping.values()]
    ].to_numpy(dtype=np.float32, copy=True)
    del src_buckets, src_features, src_lookup, row_lookup

    dst = pd.DataFrame({
        "host_id": dst_codes.astype(np.int32, copy=False),
        "bucket": bucket,
        "src_id": src_codes.astype(np.int32, copy=False),
        "flow_bytes": flow_bytes.astype(np.float32, copy=False),
        "flow_packets": flow_packets.astype(np.float32, copy=False),
    })
    dst_buckets = (
        dst.groupby(["host_id", "bucket"], sort=False, observed=True)
        .agg(
            flow_count=("src_id", "size"),
            source_ip_contacts=("src_id", "nunique"),
            bytes_sum=("flow_bytes", "sum"),
            packets_sum=("flow_packets", "sum"),
        )
        .reset_index()
    )
    del dst

    dst_output_names = {
        "1m": {
            "flow_count": "dst_flows_prev_1m",
            "source_ip_contacts": "dst_source_ip_contacts_prev_1m",
            "bytes_sum": "dst_bytes_prev_1m",
            "packets_sum": "dst_packets_prev_1m",
        },
        "5m": {
            "flow_count": "dst_flows_prev_5m",
            "source_ip_contacts": "dst_source_ip_contacts_per_minute_sum_prev_5m",
            "bytes_sum": "dst_bytes_prev_5m",
            "packets_sum": "dst_packets_prev_5m",
        },
    }
    dst_features = _rolling_host_features(
        dst_buckets, "host_id",
        ["flow_count", "source_ip_contacts", "bytes_sum", "packets_sum"],
        dst_output_names,
    )
    dst_lookup = dst_features.set_index(["host_id", "bucket"])
    row_lookup = pd.MultiIndex.from_arrays(
        [dst_codes.astype(np.int32, copy=False), bucket],
        names=["host_id", "bucket"],
    )
    dst_values = dst_lookup.reindex(row_lookup)[
        [name for mapping in dst_output_names.values() for name in mapping.values()]
    ].to_numpy(dtype=np.float32, copy=True)
    del dst_buckets, dst_features, dst_lookup, row_lookup

    values = np.column_stack([src_values, dst_values]).astype(np.float32, copy=False)
    if values.shape[1] != len(BEHAVIORAL_FEATURE_COLUMNS):
        raise RuntimeError("Behavioural feature schema does not match its declared names.")
    values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
    return pd.DataFrame(values, columns=BEHAVIORAL_FEATURE_COLUMNS)


def _fold_positions(hashes, y, days, fold_plan, args, fold_seed):
    train_period = np.isin(days, fold_plan["training_days"])
    validation_period = days == fold_plan["validation_day"]
    test_period = days == fold_plan["test_day"]

    train_hashes = np.unique(hashes[train_period])
    train_benign = np.flatnonzero(train_period & (y == 0))
    train_benign = first_position_per_hash(train_benign, hashes)

    validation = np.flatnonzero(validation_period)
    validation = validation[~np.isin(hashes[validation], train_hashes)]
    validation_hashes = np.unique(hashes[validation])

    test = np.flatnonzero(test_period)
    forbidden_hashes = np.concatenate([train_hashes, validation_hashes])
    test = test[~np.isin(hashes[test], forbidden_hashes)]

    if len(train_benign) < 100:
        raise ValueError(f"Fold {fold_plan['fold']} has too few unique benign training flows.")
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


def _fit_detector(x_train, x_validation, x_test, y_validation, args, seed, model_name):
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    train = imputer.fit_transform(x_train)
    validation = imputer.transform(x_validation)
    test = imputer.transform(x_test)

    model = IsolationForest(
        n_estimators=IF_CONFIG["n_estimators"],
        max_samples=min(IF_CONFIG["max_samples"], len(train)),
        max_features=IF_CONFIG["max_features"],
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )
    started = time.perf_counter()
    model.fit(train)
    fit_seconds = time.perf_counter() - started

    validation_scores = -model.score_samples(validation)
    threshold = threshold_at_fpr(validation_scores[y_validation == 0], args.target_fpr)
    validation_metrics = binary_metrics(y_validation, validation_scores, threshold)
    test_scores = -model.score_samples(test)

    return {
        "model": model,
        "imputer": imputer,
        "validation_scores": validation_scores,
        "threshold": threshold,
        "validation_metrics": validation_metrics,
        "test_scores": test_scores,
        "fit_seconds": fit_seconds,
        "model_name": model_name,
    }


def evaluate_fold(
    fold_plan, x, hashes, labels, y, days, feature_columns,
    behavioral, args, output,
):
    fold_id = int(fold_plan["fold"])
    fold_seed = args.seed + fold_id * 100
    train_pos, validation_pos, test_pos = _fold_positions(
        hashes, y, days, fold_plan, args, fold_seed
    )
    y_validation = y[validation_pos]
    y_test = y[test_pos]
    test_labels = labels[test_pos]

    print(
        f"\nFOLD {fold_id}: train={fold_plan['training_days'][0]}.."
        f"{fold_plan['training_days'][-1]}, validation={fold_plan['validation_day']}, "
        f"test={fold_plan['test_day']}; rows={len(train_pos):,}/"
        f"{len(validation_pos):,}/{len(test_pos):,}",
        flush=True,
    )

    models = []
    raw_model = _fit_detector(
        x[train_pos], x[validation_pos], x[test_pos],
        y_validation, args, fold_seed, "IF_raw_baseline",
    )
    models.append(raw_model)

    x_train_engineered = np.concatenate(
        [x[train_pos], behavioral[train_pos]], axis=1
    )
    x_validation_engineered = np.concatenate(
        [x[validation_pos], behavioral[validation_pos]], axis=1
    )
    x_test_engineered = np.concatenate(
        [x[test_pos], behavioral[test_pos]], axis=1
    )
    engineered_model = _fit_detector(
        x_train_engineered, x_validation_engineered, x_test_engineered,
        y_validation, args, fold_seed, "IF_raw_plus_host_history",
    )
    models.append(engineered_model)

    validation_rows, test_rows, attack_rows = [], [], []
    for info in models:
        validation_rows.append({
            "fold": fold_id,
            "validation_day": fold_plan["validation_day"],
            "test_day": fold_plan["test_day"],
            "model": info["model_name"],
            "training_rows": int(len(train_pos)),
            "validation_rows": int(len(validation_pos)),
            "target_fpr": args.target_fpr,
            "threshold": float(info["threshold"]),
            **info["validation_metrics"],
        })
        test_metrics = binary_metrics(y_test, info["test_scores"], info["threshold"])
        test_rows.append({
            "fold": fold_id,
            "test_day": fold_plan["test_day"],
            "model": info["model_name"],
            "training_rows": int(len(train_pos)),
            "validation_rows": int(len(validation_pos)),
            "test_rows": int(len(test_pos)),
            "target_fpr": args.target_fpr,
            "validation_threshold": float(info["threshold"]),
            "validation_recall": info["validation_metrics"]["recall"],
            "validation_fpr": info["validation_metrics"]["fpr"],
            "fit_seconds": info["fit_seconds"],
            **test_metrics,
        })

        for attack_name in sorted(set(test_labels.tolist())):
            if attack_name.casefold() == "benign":
                continue
            mask = test_labels == attack_name
            support = int(mask.sum())
            detected = int(np.sum(info["test_scores"][mask] >= info["threshold"]))
            attack_rows.append({
                "fold": fold_id,
                "test_day": fold_plan["test_day"],
                "model": info["model_name"],
                "attack_type": attack_name,
                "test_support": support,
                "detected": detected,
                "missed": support - detected,
                "recall": detected / support if support else float("nan"),
            })

    fold_dir = output / f"fold_{fold_id}"
    fold_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "artifact_version": 1,
        "model_name": "IsolationForest",
        "model": engineered_model["model"],
        "imputer": engineered_model["imputer"],
        "feature_columns": feature_columns,
        "behavioral_feature_columns": BEHAVIORAL_FEATURE_COLUMNS,
        "behavioral_history_spec": {
            "bucket_size": "1 minute",
            "windows": ["previous completed 1 minute", "previous completed 5 minutes"],
            "window_boundary": "closed='left'; current minute excluded",
            "history_scope": "source host and destination host",
            "source_ip_encoding": "not learned by model; used only to group history",
            "destination_port_encoding": "not learned by model; used only to count contacts",
        },
        "primary_target_fpr": args.target_fpr,
        "primary_threshold": float(engineered_model["threshold"]),
        "threshold_source": "validation benign-only anomaly scores",
        "training_days": fold_plan["training_days"],
        "validation_day": fold_plan["validation_day"],
        "test_day": fold_plan["test_day"],
        "training_rows": int(len(train_pos)),
        "hyperparameters": IF_CONFIG,
        "fold": fold_id,
    }, fold_dir / "isolation_forest_host_history.joblib")

    print(
        pd.DataFrame(test_rows)[[
            "model", "precision", "recall", "f1", "fpr", "average_precision", "roc_auc"
        ]].to_string(index=False),
        flush=True,
    )
    return {
        "validation": pd.DataFrame(validation_rows),
        "test": pd.DataFrame(test_rows),
        "per_attack": pd.DataFrame(attack_rows),
        "summary": {
            "fold": fold_id,
            "training_days": fold_plan["training_days"],
            "validation_day": fold_plan["validation_day"],
            "test_day": fold_plan["test_day"],
            "training_rows": int(len(train_pos)),
            "validation_rows": int(len(validation_pos)),
            "test_rows": int(len(test_pos)),
            "test_attack_prevalence": float(y_test.mean()),
            "validation_recall": {
                info["model_name"]: info["validation_metrics"]["recall"] for info in models
            },
            "test_recall": {
                row["model"]: row["recall"] for row in test_rows
            },
            "test_fpr": {
                row["model"]: row["fpr"] for row in test_rows
            },
            "fit_seconds": {
                info["model_name"]: info["fit_seconds"] for info in models
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument(
        "--outdir",
        default="experiments/results/isolation-forest-host-history-v1",
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
        x, hashes, labels, y, days, feature_columns,
        metadata_arrays, dropped_empty,
    ) = load_behavioral_dataset(Path(args.data_dir))

    print("Building past-only host-history features...", flush=True)
    behavior_frame = build_behavioral_history_features(**metadata_arrays)
    behavioral = behavior_frame.to_numpy(dtype=np.float32, copy=True)
    del behavior_frame, metadata_arrays
    print(
        f"Added {behavioral.shape[1]} behavioural features; "
        f"matrix shape={behavioral.shape}.",
        flush=True,
    )

    fold_plans = rolling_forward_splits(days, args.folds)
    results = [
        evaluate_fold(
            plan, x, hashes, labels, y, days, feature_columns,
            behavioral, args, output,
        )
        for plan in fold_plans
    ]

    validation = pd.concat([result["validation"] for result in results], ignore_index=True)
    test = pd.concat([result["test"] for result in results], ignore_index=True)
    per_attack = pd.concat([result["per_attack"] for result in results], ignore_index=True)

    validation.to_csv(output / "if_host_history_validation.csv", index=False)
    test.to_csv(output / "if_host_history_test_metrics.csv", index=False)
    per_attack.to_csv(output / "if_host_history_per_attack_recall.csv", index=False)

    summary = {
        "dataset": str(Path(args.data_dir)),
        "rows_loaded": int(len(x)),
        "rows_dropped_fully_blank": int(dropped_empty),
        "base_numeric_features": int(x.shape[1]),
        "behavioral_features": list(BEHAVIORAL_FEATURE_COLUMNS),
        "behavioral_feature_count": int(behavioral.shape[1]),
        "history_design": (
            "Per-source-IP and per-destination-IP aggregates over completed one-minute "
            "buckets. Each row receives sums from the previous completed 1-minute and "
            "5-minute windows. The current minute is excluded (closed-left)."
        ),
        "behavioral_aggregates": (
            "Source: prior flow counts, per-minute destination-IP/port cardinalities, "
            "bytes and packets. Destination: prior inbound flow counts, per-minute "
            "source-IP cardinalities, bytes and packets. Five-minute contact features "
            "sum per-minute cardinalities and can count a host/port again in another minute."
        ),
        "temporal_validation": (
            "Same expanding-window forward folds, earliest-partition exact numeric-feature "
            "duplicate policy, benign-only model training, and validation-benign-only "
            "threshold calibration as temporal_threshold_optimization.py."
        ),
        "model_comparison": (
            "Same Isolation Forest hyperparameters and training/validation/test rows: "
            "80-or-baseline numeric features versus numeric plus host-history features."
        ),
        "target_fpr": args.target_fpr,
        "isolation_forest_config": IF_CONFIG,
        "folds": [result["summary"] for result in results],
        "test_results": test.to_dict(orient="records"),
        "interpretation_warning": (
            "History features are causal at one-minute bucket resolution but deliberately "
            "exclude earlier flows in the same minute. Host identifiers are grouping keys, "
            "not model inputs. Features use unlabeled past traffic, including traffic in "
            "earlier validation/test windows, as an online stateful detector would. "
            "This is one CICIDS2017 capture, not proof of cross-network generalization."
        ),
        "elapsed_seconds": time.perf_counter() - started,
    }
    (output / "if_host_history_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    print("\nISOLATION FOREST — RAW BASELINE VS CAUSAL HOST HISTORY", flush=True)
    print(test[[
        "fold", "test_day", "model", "precision", "recall", "f1", "fpr",
        "average_precision", "roc_auc",
    ]].to_string(index=False), flush=True)
    print(f"\nSummary: {(output / 'if_host_history_summary.json').resolve()}", flush=True)
    print(f"Outputs: {output.resolve()}", flush=True)


if __name__ == "__main__":
    main()
