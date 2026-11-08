from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from itertools import product
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack_graph.event_builder import EventConfig, build_attack_events, normalize_columns
from attack_graph.graph_builder import add_sequence_edges, build_attack_graph
from attack_graph.incident_builder import build_potential_incidents


DEFAULT_TIME_WINDOWS = (30, 60, 120)
DEFAULT_SEQUENCE_GAPS = (60, 180, 300, 600)


def parse_positive_ints(value: str) -> tuple[int, ...]:
    try:
        parsed = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected comma-separated positive integers.") from exc
    if not parsed or any(number <= 0 for number in parsed):
        raise argparse.ArgumentTypeError("Expected one or more positive integers.")
    if len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("Duplicate parameter values are not allowed.")
    return parsed


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _distribution(values: pd.Series, prefix: str) -> dict[str, float | int | None]:
    numeric = pd.to_numeric(values, errors="coerce").dropna()
    if numeric.empty:
        return {
            f"{prefix}_mean": None,
            f"{prefix}_median": None,
            f"{prefix}_p95": None,
            f"{prefix}_max": None,
        }
    return {
        f"{prefix}_mean": float(numeric.mean()),
        f"{prefix}_median": float(numeric.median()),
        f"{prefix}_p95": float(numeric.quantile(0.95)),
        f"{prefix}_max": float(numeric.max()),
    }


def run_sensitivity(
    input_csv: str | Path,
    output_dir: str | Path,
    *,
    time_windows: tuple[int, ...] = DEFAULT_TIME_WINDOWS,
    sequence_gaps: tuple[int, ...] = DEFAULT_SEQUENCE_GAPS,
    min_events_per_incident: int = 2,
) -> pd.DataFrame:
    """Measure structural event/incident sensitivity without using ground truth.

    Input must be detector-flagged flow output containing predicted_anomaly and
    the metadata required by the event builder. The sweep reports fragmentation
    and grouping-count changes only. It does not measure whether candidate
    groups match true incidents or whether one parameter setting is more correct.
    """
    if min_events_per_incident < 2:
        raise ValueError("min_events_per_incident must be at least 2.")
    if not time_windows or not sequence_gaps:
        raise ValueError("At least one event window and one sequence gap are required.")
    if any(value <= 0 for value in (*time_windows, *sequence_gaps)):
        raise ValueError("All event windows and sequence gaps must be positive.")

    source = Path(input_csv)
    if not source.exists():
        raise FileNotFoundError(f"Suspicious-flow CSV not found: {source}")
    data = pd.read_csv(source, low_memory=False)
    normalized = normalize_columns(data)

    required = {"timestamp", "src_ip", "dst_ip", "protocol", "predicted_anomaly"}
    missing = required - set(normalized.columns)
    if missing:
        raise ValueError(
            "Sensitivity analysis requires detector-flagged flow metadata; "
            f"missing columns: {sorted(missing)}"
        )

    # Remove ground-truth annotations defensively. This experiment measures
    # event-formation structure only; it must not use labels to select/group rows.
    normalized = normalized.drop(
        columns=["label", "is_attack", "attack_type_ground_truth"],
        errors="ignore",
    )
    port_columns = {"src_port", "dst_port"}
    if bool(port_columns & set(normalized.columns)) and not port_columns.issubset(normalized.columns):
        raise ValueError("Source and destination port columns must either both exist or both be absent.")
    use_ports = port_columns.issubset(normalized.columns)

    from attack_graph.event_builder import _truthy

    flagged_mask = _truthy(normalized["predicted_anomaly"])
    suspicious = normalized.loc[flagged_mask].copy()
    if suspicious.empty:
        raise ValueError(
            "The supplied CSV contains no rows with predicted_anomaly=True. "
            "Provide detector-flagged suspicious-flow output."
        )

    rows = []
    for window, gap in product(time_windows, sequence_gaps):
        events = build_attack_events(
            suspicious,
            anomalous_only=True,
            config=EventConfig(
                time_window_seconds=window,
                use_ports_in_key=use_ports,
            ),
        )
        graph = build_attack_graph(events)
        graph = add_sequence_edges(graph, events, max_gap_seconds=gap)
        grouped_events, incidents = build_potential_incidents(
            events,
            graph,
            min_events=min_events_per_incident,
        )

        temporal_edges = [
            (source_node, target_node, attrs)
            for source_node, target_node, attrs in graph.edges(data=True)
            if attrs.get("relation") == "precedes"
            and attrs.get("temporal_correlation", False)
        ]
        event_sizes = (
            pd.to_numeric(grouped_events["flow_count"], errors="coerce")
            if not grouped_events.empty
            else pd.Series(dtype=float)
        )
        event_durations = (
            pd.to_numeric(grouped_events["duration_seconds"], errors="coerce")
            if not grouped_events.empty
            else pd.Series(dtype=float)
        )
        incident_sizes = (
            pd.to_numeric(incidents["event_count"], errors="coerce")
            if not incidents.empty
            else pd.Series(dtype=float)
        )
        events_in_candidates = (
            int(incident_sizes.sum()) if not incident_sizes.empty else 0
        )
        event_total = int(len(grouped_events))
        row = {
            "event_window_seconds": int(window),
            "max_sequence_gap_seconds": int(gap),
            "suspicious_flows": int(len(suspicious)),
            "event_count": event_total,
            "event_flow_coverage": (
                float(event_sizes.sum() / len(suspicious))
                if len(suspicious) else None
            ),
            "single_flow_event_count": int((event_sizes == 1).sum()),
            "events_in_candidate_incidents": events_in_candidates,
            "standalone_events": int(event_total - events_in_candidates),
            "candidate_incident_count": int(len(incidents)),
            "event_share_in_candidate_incidents": (
                float(events_in_candidates / event_total)
                if event_total else None
            ),
            "temporal_edge_count": int(len(temporal_edges)),
            "graph_node_count": int(graph.number_of_nodes()),
            "graph_edge_count": int(graph.number_of_edges()),
            "grouping_key": (
                "src_ip,dst_ip,protocol,src_port,dst_port"
                if use_ports else "src_ip,dst_ip,protocol"
            ),
            "incident_grouping": "shared_host_temporal_connected_components",
            "incident_status": "potential_correlation_requires_analyst_validation",
            "ground_truth_labels_used": False,
            "causal_claim": False,
        }
        row.update(_distribution(event_sizes, "flows_per_event"))
        row.update(_distribution(event_durations, "event_duration_seconds"))
        row.update(_distribution(incident_sizes, "events_per_candidate_incident"))
        rows.append(row)

    result = pd.DataFrame(rows).sort_values(
        ["event_window_seconds", "max_sequence_gap_seconds"]
    ).reset_index(drop=True)

    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    csv_path = target / "event_correlation_sensitivity.csv"
    json_path = target / "event_correlation_sensitivity_metadata.json"
    result.to_csv(csv_path, index=False)

    timestamps = pd.to_datetime(
        suspicious["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    metadata = {
        "experiment": "event_and_candidate_incident_parameter_sensitivity",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(source),
        "input_sha256": sha256_file(source),
        "input_rows": int(len(normalized)),
        "suspicious_flow_rows": int(len(suspicious)),
        "timestamp_min_utc": timestamps.min().isoformat() if timestamps.notna().any() else None,
        "timestamp_max_utc": timestamps.max().isoformat() if timestamps.notna().any() else None,
        "event_windows_seconds": list(time_windows),
        "sequence_gaps_seconds": list(sequence_gaps),
        "min_events_per_candidate_incident": int(min_events_per_incident),
        "port_aware_grouping": bool(use_ports),
        "ground_truth_labels_used": False,
        "output_rows": int(len(result)),
        "output_csv": str(csv_path),
        "interpretation": (
            "Structural sensitivity only: event counts, flow-per-event distributions, "
            "temporal-edge counts and candidate-incident counts. No incident ground truth "
            "is available in this input, so the sweep does not determine which parameter "
            "setting is correct or measure incident precision/recall."
        ),
    }
    json_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure event-window and temporal-gap sensitivity on detector-flagged flow records."
    )
    parser.add_argument(
        "--input",
        default="outputs/suspicious_flows_with_metadata.csv",
        help="Detector-flagged flow CSV from benchmark or unlabeled inference mode.",
    )
    parser.add_argument("--output-dir", default="experiments/results/event-sensitivity")
    parser.add_argument(
        "--time-windows",
        type=parse_positive_ints,
        default=DEFAULT_TIME_WINDOWS,
        help="Comma-separated flow-grouping windows in seconds (default: 30,60,120).",
    )
    parser.add_argument(
        "--sequence-gaps",
        type=parse_positive_ints,
        default=DEFAULT_SEQUENCE_GAPS,
        help="Comma-separated maximum temporal graph gaps in seconds (default: 60,180,300,600).",
    )
    parser.add_argument("--min-events-per-incident", type=int, default=2)
    args = parser.parse_args()
    result = run_sensitivity(
        args.input,
        args.output_dir,
        time_windows=args.time_windows,
        sequence_gaps=args.sequence_gaps,
        min_events_per_incident=args.min_events_per_incident,
    )
    print(result.to_string(index=False))


if __name__ == "__main__":
    main()
