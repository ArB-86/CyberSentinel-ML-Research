from __future__ import annotations

import argparse
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd


DEFAULT_WEIGHTS = {
    "anomaly_severity": 0.45,
    "event_volume": 0.20,
    "host_involvement": 0.20,
    "temporal_correlation": 0.15,
}


def _normalize_log(values: pd.Series, reference_q95: float | None = None) -> pd.Series:
    numeric = pd.to_numeric(values, errors="coerce").fillna(0).clip(lower=0)
    q95 = reference_q95 if reference_q95 is not None else float(numeric.quantile(0.95))
    if not np.isfinite(q95) or q95 <= 0:
        return pd.Series(0.0, index=values.index)
    denominator = np.log1p(q95)
    if denominator <= 0:
        return pd.Series(0.0, index=values.index)
    return (100.0 * np.log1p(numeric) / denominator).clip(0.0, 100.0)


def _anomaly_severity(scores: pd.Series) -> pd.Series:
    """Convert lower-is-more-anomalous scores to within-batch severity percentiles."""
    numeric = pd.to_numeric(scores, errors="coerce")
    if numeric.notna().sum() == 0:
        return pd.Series(np.nan, index=scores.index, dtype=float)
    # Lowest score receives the highest percentile severity.
    ranked = numeric.rank(method="average", ascending=False, pct=True) * 100.0
    return ranked.where(numeric.notna())


def _risk_level(score: float) -> str:
    # These are transparent triage bands, not calibrated probabilities.
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_incident_risks(
    events_csv_path: str | Path,
    graph_gexf_path: str | Path | None,
    output_csv_path: str | Path,
    weights: dict[str, float] | None = None,
) -> pd.DataFrame:
    """Calculate a transparent heuristic triage score; never a probability.

    No fixed Isolation Forest threshold or ground-truth attack category weight
    is used. Anomaly severity is ranked within the current event batch. Graph
    and volume factors are normalised from observed event data. Missing factors
    are omitted and the remaining configured weights are renormalised.
    """
    events_path = Path(events_csv_path)
    if not events_path.exists():
        raise FileNotFoundError(f"Events file not found: {events_path}")
    events = pd.read_csv(events_path)
    required = {"event_id", "flow_count"}
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Events file is missing required columns: {sorted(missing)}")
    if events.empty:
        output = Path(output_csv_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        empty = pd.DataFrame(columns=[
            "event_id", "attack_type", "risk_score", "risk_level",
            "anomaly_severity_factor", "frequency_factor",
            "host_involvement_factor", "temporal_correlation_factor",
            "in_degree", "out_degree", "flow_count",
            "risk_score_semantics", "risk_model_version",
        ])
        empty.to_csv(output, index=False)
        return empty

    weight_map = dict(DEFAULT_WEIGHTS if weights is None else weights)
    if set(weight_map) != set(DEFAULT_WEIGHTS):
        raise ValueError(f"Weights must contain exactly: {sorted(DEFAULT_WEIGHTS)}")
    if any((not np.isfinite(v) or v < 0) for v in weight_map.values()):
        raise ValueError("Risk weights must be finite and non-negative.")
    if sum(weight_map.values()) <= 0:
        raise ValueError("At least one risk weight must be positive.")

    graph = None
    if graph_gexf_path is not None:
        graph_path = Path(graph_gexf_path)
        if graph_path.exists():
            graph = nx.read_gexf(graph_path)

    flow_count = pd.to_numeric(events["flow_count"], errors="coerce").fillna(0).clip(lower=0)
    frequency = _normalize_log(flow_count)
    anomaly = (
        _anomaly_severity(events["mean_anomaly_score"])
        if "mean_anomaly_score" in events.columns
        else pd.Series(np.nan, index=events.index)
    )

    host_values = []
    temporal_values = []
    in_degrees = []
    out_degrees = []
    for _, row in events.iterrows():
        event_id = str(row["event_id"])
        event_node = f"event:{event_id}"
        if graph is None or event_node not in graph:
            host_degree = 0
            in_degree = 0
            out_degree = 0
            temporal_count = 0
        else:
            event_graph_degree = graph.degree(event_node)
            in_degree = graph.in_degree(event_node)
            out_degree = graph.out_degree(event_node)
            src_node = f"host:{row.get('src_ip')}"
            dst_node = f"host:{row.get('dst_ip')}"
            host_degree = max(
                graph.degree(src_node) if src_node in graph else 0,
                graph.degree(dst_node) if dst_node in graph else 0,
            )
            temporal_count = 0
            for neighbor in set(graph.predecessors(event_node)) | set(graph.successors(event_node)):
                edge = graph.get_edge_data(neighbor, event_node) or graph.get_edge_data(event_node, neighbor) or {}
                if edge.get("relation") == "precedes":
                    temporal_count += 1
            # An event not represented in a graph has no observed graph evidence.
            if event_graph_degree == 0:
                host_degree = 0
        host_values.append(host_degree)
        temporal_values.append(temporal_count)
        in_degrees.append(in_degree)
        out_degrees.append(out_degree)

    host_factor = _normalize_log(pd.Series(host_values, index=events.index))
    temporal_factor = _normalize_log(pd.Series(temporal_values, index=events.index), reference_q95=5.0)

    factor_values = {
        "anomaly_severity": anomaly,
        "event_volume": frequency,
        "host_involvement": host_factor,
        "temporal_correlation": temporal_factor,
    }
    factor_columns = {
        "anomaly_severity": "anomaly_severity_factor",
        "event_volume": "frequency_factor",
        "host_involvement": "host_involvement_factor",
        "temporal_correlation": "temporal_correlation_factor",
    }

    records = []
    for index, row in events.iterrows():
        available = {
            name: float(series.loc[index])
            for name, series in factor_values.items()
            if pd.notna(series.loc[index])
        }
        active_weight = sum(weight_map[name] for name in available)
        if active_weight <= 0:
            risk_score = 0.0
        else:
            risk_score = sum(
                weight_map[name] * value for name, value in available.items()
            ) / active_weight
        record = {
            "event_id": str(row["event_id"]),
            "attack_type": str(row.get("attack_type", "Unclassified")),
            "risk_score": round(float(risk_score), 2),
            "risk_level": _risk_level(float(risk_score)),
            "flow_count": int(flow_count.loc[index]),
            "in_degree": int(in_degrees[index]),
            "out_degree": int(out_degrees[index]),
            "risk_score_semantics": "heuristic_triage_score_not_probability",
            "risk_model_version": "transparent_4_factor_v2",
            "active_factors": ",".join(available.keys()),
        }
        for name, value in factor_values.items():
            record[factor_columns[name]] = (
                round(float(value.loc[index]), 2)
                if pd.notna(value.loc[index]) else np.nan
            )
        records.append(record)

    result = pd.DataFrame(records)
    output_path = Path(output_csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output_path, index=False)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate transparent event triage scores.")
    parser.add_argument("--events", default="outputs/attack_events.csv")
    parser.add_argument("--graph", default="outputs/attack_graph.gexf")
    parser.add_argument("--output", default="outputs/event_risk_scores.csv")
    args = parser.parse_args()
    calculate_incident_risks(args.events, args.graph, args.output)
