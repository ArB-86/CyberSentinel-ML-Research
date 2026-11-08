from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import pandas as pd


REQUIRED_METADATA_COLUMNS = ("timestamp", "src_ip", "dst_ip", "protocol")


@dataclass(frozen=True)
class EventConfig:
    """Configurable, label-independent rules for grouping suspicious flows."""

    time_window_seconds: int = 60
    max_flows_per_event: int = 5000
    use_ports_in_key: bool = False

    def __post_init__(self) -> None:
        if self.time_window_seconds <= 0:
            raise ValueError("time_window_seconds must be positive.")
        if self.max_flows_per_event <= 0:
            raise ValueError("max_flows_per_event must be positive.")


def _first_existing(columns: Iterable[str], aliases: Iterable[str]) -> Optional[str]:
    available = set(columns)
    for alias in aliases:
        if alias in available:
            return alias
    return None


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize common CICIDS and flow-export column names."""
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]

    aliases = {
        "timestamp": ["timestamp", "Timestamp", "Flow Start", "Date time", "flow start"],
        "src_ip": ["src_ip", "Source IP", "SourceIP", "Src IP", "source address"],
        "dst_ip": ["dst_ip", "Destination IP", "DestinationIP", "Dst IP", "destination address"],
        "src_port": ["src_port", "Source Port", "SourcePort", "Src Port"],
        "dst_port": ["dst_port", "Destination Port", "DestinationPort", "Dst Port"],
        "protocol": ["protocol", "Protocol"],
        "label": ["label", "Label", "Attack", "Attack Type"],
        "predicted_attack_type": ["predicted_attack_type", "Predicted Attack Type"],
        "predicted_anomaly": ["predicted_anomaly", "Predicted Anomaly"],
        "anomaly_score": ["anomaly_score", "Anomaly Score"],
    }

    rename = {}
    for canonical, names in aliases.items():
        actual = _first_existing(out.columns, names)
        if actual and actual != canonical:
            rename[actual] = canonical
    out = out.rename(columns=rename)

    # Canonical lower-case names are also recognised without relying on aliases.
    out.columns = [str(c).strip() for c in out.columns]
    return out


def validate_event_input(df: pd.DataFrame, require_metadata: bool = True) -> dict:
    """Validate inference metadata without requiring ground-truth attack labels."""
    normalized = normalize_columns(df)
    missing = [c for c in REQUIRED_METADATA_COLUMNS if c not in normalized.columns]
    if not require_metadata:
        missing = [c for c in ("protocol",) if c not in normalized.columns]
    return {
        "valid_base": "protocol" in normalized.columns,
        "valid_metadata": not missing,
        "missing_base_columns": [c for c in ("protocol",) if c not in normalized.columns],
        "missing_metadata_columns": missing,
        "metadata_available": not missing,
        "usable_for_temporal_source_target_graph": not missing,
        "ground_truth_label_optional": True,
    }


def _truthy(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    values = series.astype(str).str.strip().str.casefold()
    return values.isin({"1", "true", "yes", "y", "attack", "anomaly"})


def _event_key_columns(work: pd.DataFrame, config: EventConfig) -> list[str]:
    keys = ["src_ip", "dst_ip", "protocol"]
    if config.use_ports_in_key:
        for name in ("src_port", "dst_port"):
            if name not in work.columns:
                raise ValueError(f"use_ports_in_key=True requires {name!r}.")
            keys.append(name)
    return keys


def _split_group(group: pd.DataFrame, config: EventConfig) -> list[pd.DataFrame]:
    """Split one connection key into time-contiguous event windows."""
    group = group.sort_values("timestamp", kind="mergesort")
    chunks: list[pd.DataFrame] = []
    start = 0
    times = group["timestamp"].tolist()
    for i in range(1, len(group)):
        gap = (times[i] - times[i - 1]).total_seconds()
        full = (i - start) >= config.max_flows_per_event
        if gap > config.time_window_seconds or full:
            chunks.append(group.iloc[start:i])
            start = i
    if start < len(group):
        chunks.append(group.iloc[start:])
    return chunks


def build_attack_events(
    df: pd.DataFrame,
    *,
    anomalous_only: bool = True,
    threshold: Optional[float] = None,
    config: EventConfig = EventConfig(),
) -> pd.DataFrame:
    """Group suspicious flows without using CICIDS ground-truth labels.

    Inference selection must come from the detector's predicted_anomaly flag
    or an explicitly supplied threshold applied to anomaly_score. Dataset
    labels are never used to select, split, or group events.
    """
    normalized = normalize_columns(df)
    report = validate_event_input(normalized)
    if not report["valid_metadata"]:
        raise ValueError(
            "Temporal event grouping requires metadata columns "
            f"{report['missing_metadata_columns']}; missing fields are not inferred."
        )
    if anomalous_only:
        if "predicted_anomaly" in normalized.columns:
            work = normalized.loc[_truthy(normalized["predicted_anomaly"])].copy()
        elif threshold is not None and "anomaly_score" in normalized.columns:
            score = pd.to_numeric(normalized["anomaly_score"], errors="coerce")
            work = normalized.loc[score.lt(float(threshold))].copy()
        else:
            raise ValueError(
                "anomalous_only=True requires predicted_anomaly or both "
                "anomaly_score and an explicit threshold. Ground-truth Label "
                "is evaluation data and is never a fallback detector."
            )
    else:
        work = normalized.copy()

    if work.empty:
        return pd.DataFrame(columns=[
            "event_id", "start_time", "end_time", "duration_seconds",
            "src_ip", "dst_ip", "protocol", "attack_type", "attack_type_source",
            "flow_count", "mean_anomaly_score", "min_anomaly_score",
            "max_anomaly_score", "ports_observed",
        ])

    work["timestamp"] = pd.to_datetime(
        work["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    if work["timestamp"].isna().any():
        bad = int(work["timestamp"].isna().sum())
        raise ValueError(f"{bad} suspicious flow(s) have invalid timestamps.")

    for col in ("src_ip", "dst_ip", "protocol"):
        if work[col].isna().any():
            raise ValueError(f"Suspicious flows contain missing {col} values.")
        work[col] = work[col].astype(str).str.strip()

    keys = _event_key_columns(work, config)
    events: list[dict] = []
    for key_values, group in work.groupby(keys, sort=True, dropna=False):
        # The grouping key contains only flow/connection metadata. Label is
        # deliberately excluded so that event formation works on unlabeled
        # production traffic and cannot leak CICIDS ground truth.
        for chunk in _split_group(group, config):
            scores = (
                pd.to_numeric(chunk["anomaly_score"], errors="coerce")
                if "anomaly_score" in chunk.columns else pd.Series(dtype=float)
            )
            predicted_type = "Unclassified"
            type_source = "not_predicted"
            if "predicted_attack_type" in chunk.columns:
                candidates = chunk["predicted_attack_type"].dropna().astype(str).str.strip()
                candidates = candidates[candidates.ne("")]
                if not candidates.empty:
                    predicted_type = str(candidates.mode().iloc[0])
                    type_source = "model_prediction"

            ports = []
            if {"src_port", "dst_port"}.issubset(chunk.columns):
                ports = sorted({
                    (str(src), str(dst))
                    for src, dst in zip(chunk["src_port"], chunk["dst_port"])
                    if pd.notna(src) and pd.notna(dst)
                })

            start_time = chunk["timestamp"].min()
            end_time = chunk["timestamp"].max()
            events.append({
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": float((end_time - start_time).total_seconds()),
                "src_ip": str(chunk["src_ip"].iloc[0]),
                "dst_ip": str(chunk["dst_ip"].iloc[0]),
                "protocol": str(chunk["protocol"].iloc[0]),
                "attack_type": predicted_type,
                "attack_type_source": type_source,
                "flow_count": int(len(chunk)),
                "mean_anomaly_score": float(scores.mean()) if scores.notna().any() else None,
                "min_anomaly_score": float(scores.min()) if scores.notna().any() else None,
                "max_anomaly_score": float(scores.max()) if scores.notna().any() else None,
                "ports_observed": ports,
            })

    events.sort(key=lambda e: (e["start_time"], e["src_ip"], e["dst_ip"], e["protocol"]))
    for idx, event in enumerate(events, start=1):
        event["event_id"] = f"EVT-{idx:05d}"

    columns = [
        "event_id", "start_time", "end_time", "duration_seconds",
        "src_ip", "dst_ip", "protocol", "attack_type", "attack_type_source",
        "flow_count", "mean_anomaly_score", "min_anomaly_score",
        "max_anomaly_score", "ports_observed",
    ]
    return pd.DataFrame(events, columns=columns)
