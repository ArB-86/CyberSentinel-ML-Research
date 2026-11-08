import pandas as pd

from attack_graph.graph_builder import add_sequence_edges, build_attack_graph
from attack_graph.incident_builder import build_potential_incidents


def _events():
    return pd.DataFrame([
        {"event_id": "EVT-00001", "start_time": "2026-01-01T00:00:00Z",
         "end_time": "2026-01-01T00:00:05Z", "src_ip": "A", "dst_ip": "B",
         "protocol": "6", "flow_count": 2, "attack_type": "Unclassified"},
        {"event_id": "EVT-00002", "start_time": "2026-01-01T00:00:10Z",
         "end_time": "2026-01-01T00:00:15Z", "src_ip": "B", "dst_ip": "C",
         "protocol": "6", "flow_count": 3, "attack_type": "Unclassified"},
        {"event_id": "EVT-00003", "start_time": "2026-01-01T00:00:12Z",
         "end_time": "2026-01-01T00:00:14Z", "src_ip": "X", "dst_ip": "Y",
         "protocol": "6", "flow_count": 1, "attack_type": "Unclassified"},
    ])


def test_connected_temporal_events_form_a_potential_incident_only():
    events = _events()
    graph = add_sequence_edges(build_attack_graph(events), events, max_gap_seconds=60)
    grouped, incidents = build_potential_incidents(events, graph)

    linked = grouped[grouped["event_id"].isin(["EVT-00001", "EVT-00002"])]
    isolated = grouped[grouped["event_id"] == "EVT-00003"]

    assert linked["incident_id"].nunique() == 1
    assert linked["incident_id"].iloc[0] == "INC-00001"
    assert isolated["incident_id"].isna().all()
    assert len(incidents) == 1
    row = incidents.iloc[0]
    assert row["event_count"] == 2
    assert row["flow_count"] == 5
    assert row["confirmation_status"] == "potential_correlation_requires_analyst_validation"
    assert bool(row["causal_claim"]) is False


def test_no_temporal_edges_means_no_confirmed_incident():
    events = _events()
    graph = build_attack_graph(events)
    grouped, incidents = build_potential_incidents(events, graph)
    assert grouped["incident_id"].isna().all()
    assert incidents.empty

def test_overlapping_events_are_not_linked_as_precedence():
    events = _events().iloc[:2].copy()
    events.loc[0, "end_time"] = "2026-01-01T00:00:20Z"
    events.loc[1, "start_time"] = "2026-01-01T00:00:10Z"
    graph = add_sequence_edges(build_attack_graph(events), events, max_gap_seconds=60)
    assert not graph.has_edge("event:EVT-00001", "event:EVT-00002")
