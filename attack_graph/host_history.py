"""Causal host-history features shared by training and inference.

Each flow sees aggregates from completed one-minute buckets only. IP addresses
are grouping keys, never model inputs. The feature builder is batch-oriented:
the supplied frame must contain the complete traffic history available to the
detector for that scoring run.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


MINUTE_NS = 60 * 1_000_000_000

HOST_HISTORY_FEATURE_COLUMNS = [
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

_BYTE_ALIASES = {
    "totallengthoffwdpackets",
    "totallengthofbwdpackets",
}
_PACKET_ALIASES = {
    "totalfwdpackets",
    "totalbackwardpackets",
}


def _header_token(value: object) -> str:
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())


def _sum_feature_columns(features: pd.DataFrame, aliases: set[str], label: str) -> np.ndarray:
    columns = [
        column for column in features.columns
        if _header_token(column) in aliases
    ]
    if not columns:
        raise ValueError(
            f"Host-history model requires numeric {label} columns; "
            f"expected one or more of {sorted(aliases)}."
        )
    values = features[columns].apply(pd.to_numeric, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return values.clip(lower=0.0).sum(axis=1).to_numpy(dtype=np.float32)


def _rolling_host_features(
    bucket_table: pd.DataFrame,
    host_column: str,
    metric_columns: list[str],
    output_names: dict[str, dict[str, str]],
) -> pd.DataFrame:
    """Sum previous host-minute buckets over 1m and 5m windows."""
    ordered = bucket_table.sort_values(
        [host_column, "bucket_minute"], kind="mergesort"
    ).reset_index(drop=True)
    result = ordered[[host_column, "bucket_minute"]].copy()
    if ordered.empty:
        for mapping in output_names.values():
            for output_column in mapping.values():
                result[output_column] = np.zeros(0, dtype=np.float32)
        return result

    # Integer minute units avoid pandas datetime-resolution differences.
    bucket_minutes = ordered["bucket_minute"].to_numpy(dtype=np.int64, copy=False)
    values = ordered[metric_columns].to_numpy(dtype=np.float64, copy=True)
    grouped_positions = ordered.groupby(
        host_column, sort=False, dropna=False
    ).indices.values()

    for window_label, window_minutes in (("1m", 1), ("5m", 5)):
        window_values = np.zeros(
            (len(ordered), len(metric_columns)), dtype=np.float64
        )
        for positions in grouped_positions:
            positions = np.asarray(positions, dtype=np.int64)
            group_times = bucket_minutes[positions]
            group_values = values[positions]
            prefix = np.vstack([
                np.zeros((1, len(metric_columns)), dtype=np.float64),
                np.cumsum(group_values, axis=0, dtype=np.float64),
            ])
            left = np.searchsorted(
                group_times,
                group_times - window_minutes,
                side="left",
            )
            current = np.arange(len(positions), dtype=np.int64)
            # Prefix[current] excludes the current host-minute bucket.
            window_values[positions] = prefix[current] - prefix[left]

        for metric_index, metric in enumerate(metric_columns):
            output_column = output_names[window_label][metric]
            result[output_column] = window_values[:, metric_index].astype(
                np.float32, copy=False
            )

    return result


def build_causal_host_history_features(
    metadata: pd.DataFrame,
    numeric_features: pd.DataFrame,
) -> pd.DataFrame:
    """Build 18 past-only host features and preserve input row alignment.

    Required metadata columns are normalized names: timestamp, src_ip,
    dst_ip and dst_port. Numeric byte/packet totals are read from the same
    raw numeric feature frame used by the detector.
    """
    if len(metadata) == 0 or len(metadata) != len(numeric_features):
        raise ValueError("Metadata and numeric feature rows must be non-empty and aligned.")
    required = {"timestamp", "src_ip", "dst_ip", "dst_port"}
    missing = required.difference(metadata.columns)
    if missing:
        raise ValueError(
            f"Host-history features require metadata columns: {sorted(missing)}"
        )

    timestamps = pd.to_datetime(
        metadata["timestamp"],
        errors="coerce",
        dayfirst=True,
        utc=True,
        format="mixed",
    )
    if timestamps.isna().any():
        raise ValueError(
            f"Host-history feature generation found {int(timestamps.isna().sum())} "
            "invalid timestamps."
        )
    timestamps_ns = timestamps.to_numpy(dtype="datetime64[ns]").astype(
        np.int64, copy=False
    )
    if np.any(timestamps_ns < 0):
        raise ValueError("Host-history timestamps must be valid non-negative epoch times.")

    src_ips = metadata["src_ip"].astype("string").str.strip()
    dst_ips = metadata["dst_ip"].astype("string").str.strip()
    if src_ips.isna().any() or src_ips.eq("").any():
        raise ValueError("Host-history metadata contains missing source IP values.")
    if dst_ips.isna().any() or dst_ips.eq("").any():
        raise ValueError("Host-history metadata contains missing destination IP values.")

    dst_ports = pd.to_numeric(metadata["dst_port"], errors="coerce")
    if dst_ports.isna().any() or not np.isfinite(dst_ports.to_numpy(dtype=float)).all():
        raise ValueError("Host-history metadata contains invalid destination ports.")

    src_codes, _ = pd.factorize(src_ips, sort=False)
    dst_codes, _ = pd.factorize(dst_ips, sort=False)
    if np.any(src_codes < 0) or np.any(dst_codes < 0):
        raise ValueError("Host-history IP grouping produced missing host identifiers.")

    flow_bytes = _sum_feature_columns(
        numeric_features, _BYTE_ALIASES, "forward/backward packet-byte total"
    )
    flow_packets = _sum_feature_columns(
        numeric_features, _PACKET_ALIASES, "forward/backward packet-count total"
    )
    if not np.isfinite(flow_bytes).all() or not np.isfinite(flow_packets).all():
        raise ValueError("Host-history traffic-volume inputs must be finite.")

    bucket_minute = timestamps_ns // MINUTE_NS

    src = pd.DataFrame({
        "host_id": src_codes.astype(np.int32, copy=False),
        "bucket_minute": bucket_minute,
        "peer_id": dst_codes.astype(np.int32, copy=False),
        "dst_port": dst_ports.to_numpy(dtype=np.int32, copy=False),
        "flow_bytes": flow_bytes,
        "flow_packets": flow_packets,
    })
    src_buckets = (
        src.groupby(["host_id", "bucket_minute"], sort=False, observed=True)
        .agg(
            flow_count=("peer_id", "size"),
            destination_ip_contacts=("peer_id", "nunique"),
            destination_port_contacts=("dst_port", "nunique"),
            bytes_sum=("flow_bytes", "sum"),
            packets_sum=("flow_packets", "sum"),
        )
        .reset_index()
    )
    del src

    src_names = {
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
    src_history = _rolling_host_features(
        src_buckets,
        "host_id",
        [
            "flow_count",
            "destination_ip_contacts",
            "destination_port_contacts",
            "bytes_sum",
            "packets_sum",
        ],
        src_names,
    )
    src_lookup = src_history.set_index(["host_id", "bucket_minute"])
    row_lookup = pd.MultiIndex.from_arrays(
        [src_codes.astype(np.int32, copy=False), bucket_minute],
        names=["host_id", "bucket_minute"],
    )
    src_values = src_lookup.reindex(row_lookup)[
        [name for mapping in src_names.values() for name in mapping.values()]
    ].to_numpy(dtype=np.float32, copy=True)
    del src_buckets, src_history, src_lookup

    dst = pd.DataFrame({
        "host_id": dst_codes.astype(np.int32, copy=False),
        "bucket_minute": bucket_minute,
        "peer_id": src_codes.astype(np.int32, copy=False),
        "flow_bytes": flow_bytes,
        "flow_packets": flow_packets,
    })
    dst_buckets = (
        dst.groupby(["host_id", "bucket_minute"], sort=False, observed=True)
        .agg(
            flow_count=("peer_id", "size"),
            source_ip_contacts=("peer_id", "nunique"),
            bytes_sum=("flow_bytes", "sum"),
            packets_sum=("flow_packets", "sum"),
        )
        .reset_index()
    )
    del dst

    dst_names = {
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
    dst_history = _rolling_host_features(
        dst_buckets,
        "host_id",
        [
            "flow_count",
            "source_ip_contacts",
            "bytes_sum",
            "packets_sum",
        ],
        dst_names,
    )
    dst_lookup = dst_history.set_index(["host_id", "bucket_minute"])
    row_lookup = pd.MultiIndex.from_arrays(
        [dst_codes.astype(np.int32, copy=False), bucket_minute],
        names=["host_id", "bucket_minute"],
    )
    dst_values = dst_lookup.reindex(row_lookup)[
        [name for mapping in dst_names.values() for name in mapping.values()]
    ].to_numpy(dtype=np.float32, copy=True)
    del dst_buckets, dst_history, dst_lookup, row_lookup

    values = np.column_stack([src_values, dst_values]).astype(np.float32, copy=False)
    if values.shape[1] != len(HOST_HISTORY_FEATURE_COLUMNS):
        raise RuntimeError("Host-history feature matrix does not match its declared schema.")
    values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
    return pd.DataFrame(
        values,
        columns=HOST_HISTORY_FEATURE_COLUMNS,
        index=metadata.index,
    )
