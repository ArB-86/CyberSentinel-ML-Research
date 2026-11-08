from __future__ import annotations

from collections import defaultdict

import networkx as nx
import pandas as pd


def _gexf_safe(value):
    """Convert pandas/numpy values to GEXF-compatible Python types."""
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, (pd.Series, pd.DataFrame)):
        return str(value)
    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _sanitize_graph_for_gexf(graph: nx.DiGraph) -> nx.DiGraph:
    """Convert supported attributes and omit missing values for GEXF export."""
    def clean_attributes(attrs: dict) -> dict:
        cleaned = {}
        for key, value in attrs.items():
            safe_value = _gexf_safe(value)
            if safe_value is not None:
                cleaned[str(key)] = safe_value
        return cleaned

    safe = nx.DiGraph()
    safe.graph.update(clean_attributes(graph.graph))
    for node, attrs in graph.nodes(data=True):
        safe.add_node(node, **clean_attributes(attrs))
    for source, target, attrs in graph.edges(data=True):
        safe.add_edge(source, target, **clean_attributes(attrs))
    return safe


def write_attack_graph_gexf(graph: nx.DiGraph, path: str) -> None:
    nx.write_gexf(_sanitize_graph_for_gexf(graph), path)


def build_attack_graph(events: pd.DataFrame) -> nx.DiGraph:
    """Build an entity/event graph using predicted classifications only."""
    required = {
        "event_id", "src_ip", "dst_ip", "protocol",
        "start_time", "end_time", "flow_count",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Missing event columns: {sorted(missing)}")

    graph = nx.DiGraph()
    for _, event in events.iterrows():
        src = f"host:{event['src_ip']}"
        dst = f"host:{event['dst_ip']}"
        event_node = f"event:{event['event_id']}"
        attack_type = str(event.get("attack_type", "Unclassified") or "Unclassified")
        type_source = str(event.get("attack_type_source", "not_predicted"))

        graph.add_node(src, node_type="host", label=str(event["src_ip"]))
        graph.add_node(dst, node_type="host", label=str(event["dst_ip"]))
        graph.add_node(
            event_node,
            node_type="event",
            label=str(event["event_id"]),
            protocol=str(event["protocol"]),
            start_time=_gexf_safe(event["start_time"]),
            end_time=_gexf_safe(event["end_time"]),
            flow_count=int(event["flow_count"]),
            mean_anomaly_score=_gexf_safe(event.get("mean_anomaly_score")),
            ports_observed=_gexf_safe(event.get("ports_observed", [])),
            attack_type=attack_type,
            attack_type_source=type_source,
        )
        graph.add_edge(src, event_node, relation="initiates")
        graph.add_edge(event_node, dst, relation="targets")

        # Only a model-produced class is allowed to create a classification
        # node. CICIDS ground-truth Label is not a production prediction.
        if type_source == "model_prediction" and attack_type != "Unclassified":
            attack_node = f"attack:{attack_type}"
            graph.add_node(
                attack_node,
                node_type="predicted_attack_type",
                label=attack_type,
            )
            graph.add_edge(event_node, attack_node, relation="predicted_as")

        if "incident_id" in event and pd.notna(event["incident_id"]):
            incident_node = f"incident:{event['incident_id']}"
            graph.add_node(incident_node, node_type="incident", label=str(event["incident_id"]))
            graph.add_edge(incident_node, event_node, relation="contains")
    return graph


def add_sequence_edges(
    graph: nx.DiGraph,
    events: pd.DataFrame,
    *,
    max_gap_seconds: int = 300,
) -> nx.DiGraph:
    """Link chronologically adjacent events that share a host.

    Each host has its own event timeline. This avoids the previous global
    adjacent-row bug, which missed related events whenever an unrelated event
    occurred between them in the global time ordering. Edges represent temporal
    correlation only; they do not assert causation.
    """
    if max_gap_seconds <= 0:
        raise ValueError("max_gap_seconds must be positive.")
    if events.empty:
        return graph

    required = {"event_id", "src_ip", "dst_ip", "start_time", "end_time"}
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Missing event columns: {sorted(missing)}")

    work = events.copy()
    work["start_time"] = pd.to_datetime(work["start_time"], errors="coerce", utc=True, format="mixed")
    work["end_time"] = pd.to_datetime(work["end_time"], errors="coerce", utc=True, format="mixed")
    if work[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Sequence edges require valid event timestamps.")

    host_events: dict[str, list[dict]] = defaultdict(list)
    for row in work.to_dict(orient="records"):
        event_id = str(row["event_id"])
        start = row["start_time"]
        end = row["end_time"]
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        host_events[src].append({"event_id": event_id, "start": start, "end": end, "role": "source"})
        if dst != src:
            host_events[dst].append({"event_id": event_id, "start": start, "end": end, "role": "target"})

    edge_candidates: dict[tuple[str, str], dict] = {}
    for host, items in host_events.items():
        items.sort(key=lambda item: (item["start"], item["event_id"]))
        for left, right in zip(items, items[1:]):
            if left["event_id"] == right["event_id"]:
                continue
            # A "precedes" edge requires the earlier event to finish before
            # the later event starts. Overlapping events are correlated by host
            # but are not asserted to be sequential.
            if right["start"] < left["end"]:
                continue
            gap = float((right["start"] - left["end"]).total_seconds())
            if gap > max_gap_seconds:
                continue

            pair = (left["event_id"], right["event_id"])
            basis = (
                "target_to_source"
                if left["role"] == "target" and right["role"] == "source"
                else "shared_source"
                if left["role"] == "source" and right["role"] == "source"
                else "shared_target"
                if left["role"] == "target" and right["role"] == "target"
                else "source_to_target"
            )
            record = edge_candidates.setdefault(pair, {
                "shared_hosts": set(), "link_basis": set(), "gap_seconds": gap
            })
            record["shared_hosts"].add(host)
            record["link_basis"].add(basis)
            record["gap_seconds"] = min(record["gap_seconds"], gap)

    for (left_id, right_id), attrs in edge_candidates.items():
        left_node = f"event:{left_id}"
        right_node = f"event:{right_id}"
        if left_node not in graph or right_node not in graph:
            continue
        if left_id == right_id:
            continue
        graph.add_edge(
            left_node,
            right_node,
            relation="precedes",
            temporal_correlation=True,
            causal_claim=False,
            gap_seconds=float(attrs["gap_seconds"]),
            shared_hosts=sorted(attrs["shared_hosts"]),
            link_basis=sorted(attrs["link_basis"]),
        )
    return graph
