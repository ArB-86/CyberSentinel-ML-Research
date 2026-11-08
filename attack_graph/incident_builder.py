from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx
import pandas as pd


def build_potential_incidents(
    events: pd.DataFrame,
    graph: nx.DiGraph,
    *,
    min_events: int = 2,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Group graph-correlated events into potential incidents.

    Components are formed only from event-to-event edges explicitly marked as
    temporal correlations by the graph builder. A single isolated event is not
    promoted to an incident. Every generated group is labelled as a candidate
    correlation requiring analyst validation; the grouping is not causal proof.
    """
    if min_events < 2:
        raise ValueError("min_events must be at least 2.")
    required = {"event_id", "start_time", "end_time", "src_ip", "dst_ip", "flow_count"}
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Missing event columns: {sorted(missing)}")

    work = events.copy()
    work["event_id"] = work["event_id"].astype(str)
    work["start_time"] = pd.to_datetime(work["start_time"], errors="coerce", utc=True, format="mixed")
    work["end_time"] = pd.to_datetime(work["end_time"], errors="coerce", utc=True, format="mixed")
    if work[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Potential incident grouping requires valid event timestamps.")
    if work["event_id"].duplicated().any():
        raise ValueError("Event IDs must be unique before incident grouping.")

    event_nodes = {f"event:{event_id}" for event_id in work["event_id"]}
    correlation_graph = nx.Graph()
    correlation_graph.add_nodes_from(event_nodes)

    edge_details: dict[tuple[str, str], dict[str, Any]] = {}
    for source, target, attrs in graph.edges(data=True):
        if source not in event_nodes or target not in event_nodes:
            continue
        if attrs.get("relation") != "precedes" or not attrs.get("temporal_correlation", False):
            continue
        if attrs.get("causal_claim", False):
            # Causal claims are not valid grouping evidence for this stage.
            continue
        pair = tuple(sorted((str(source), str(target))))
        correlation_graph.add_edge(*pair)
        edge_details[pair] = attrs

    components = [
        sorted(component)
        for component in nx.connected_components(correlation_graph)
        if len(component) >= min_events
    ]
    event_lookup = work.set_index("event_id", drop=False)
    component_records: list[tuple[pd.Timestamp, list[str]]] = []
    for component in components:
        ids = sorted(node.removeprefix("event:") for node in component)
        start = event_lookup.loc[ids, "start_time"].min()
        component_records.append((start, ids))
    component_records.sort(key=lambda item: (item[0], item[1]))

    incident_for_event: dict[str, str] = {}
    incident_rows: list[dict[str, Any]] = []
    for sequence, (start, ids) in enumerate(component_records, start=1):
        incident_id = f"INC-{sequence:05d}"
        incident_for_event.update({event_id: incident_id for event_id in ids})
        group = event_lookup.loc[ids].copy().sort_values("start_time")
        hosts = sorted(set(group["src_ip"].dropna().astype(str)) | set(group["dst_ip"].dropna().astype(str)))
        event_node_set = {f"event:{event_id}" for event_id in ids}

        used_edges = []
        for source, target, attrs in graph.edges(data=True):
            if source in event_node_set and target in event_node_set:
                if attrs.get("relation") == "precedes" and attrs.get("temporal_correlation", False):
                    used_edges.append(attrs)

        gaps = [
            float(attrs["gap_seconds"])
            for attrs in used_edges
            if attrs.get("gap_seconds") is not None
        ]
        attack_types = sorted({
            str(value) for value in group.get("attack_type", pd.Series(dtype=str)).dropna()
            if str(value).strip() and str(value).casefold() != "unclassified"
        })
        incident_rows.append({
            "incident_id": incident_id,
            "start_time": group["start_time"].min(),
            "end_time": group["end_time"].max(),
            "duration_seconds": float(
                (group["end_time"].max() - group["start_time"].min()).total_seconds()
            ),
            "event_count": int(len(group)),
            "flow_count": int(pd.to_numeric(group["flow_count"], errors="coerce").fillna(0).sum()),
            "unique_host_count": int(len(hosts)),
            "hosts": hosts,
            "event_ids": ids,
            "predicted_attack_types": attack_types,
            "temporal_edge_count": int(len(used_edges)),
            "minimum_edge_gap_seconds": min(gaps) if gaps else None,
            "maximum_edge_gap_seconds": max(gaps) if gaps else None,
            "grouping_basis": "connected_component_of_shared_host_temporal_correlation_edges",
            "confirmation_status": "potential_correlation_requires_analyst_validation",
            "causal_claim": False,
        })

    work["incident_id"] = work["event_id"].map(incident_for_event)
    incidents = pd.DataFrame(incident_rows, columns=[
        "incident_id", "start_time", "end_time", "duration_seconds",
        "event_count", "flow_count", "unique_host_count", "hosts",
        "event_ids", "predicted_attack_types", "temporal_edge_count",
        "minimum_edge_gap_seconds", "maximum_edge_gap_seconds",
        "grouping_basis", "confirmation_status", "causal_claim",
    ])
    return work, incidents
