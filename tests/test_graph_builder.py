import pandas as pd

from attack_graph.graph_builder import add_sequence_edges, build_attack_graph


def _events():
    return pd.DataFrame([
        {
            "event_id": "EVT-00001", "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:00:05Z", "src_ip": "A", "dst_ip": "B",
            "protocol": "6", "flow_count": 2, "attack_type": "Unclassified",
        },
        {
            "event_id": "EVT-00002", "start_time": "2026-01-01T00:00:01Z",
            "end_time": "2026-01-01T00:00:02Z", "src_ip": "C", "dst_ip": "D",
            "protocol": "6", "flow_count": 1, "attack_type": "Unclassified",
        },
        {
            "event_id": "EVT-00003", "start_time": "2026-01-01T00:00:10Z",
            "end_time": "2026-01-01T00:00:15Z", "src_ip": "B", "dst_ip": "E",
            "protocol": "6", "flow_count": 1, "attack_type": "Unclassified",
        },
    ])


def test_graph_links_target_to_source_even_with_unrelated_global_event_between():
    events = _events()
    graph = add_sequence_edges(build_attack_graph(events), events, max_gap_seconds=60)

    assert graph.has_edge("event:EVT-00001", "event:EVT-00003")
    edge = graph.edges["event:EVT-00001", "event:EVT-00003"]
    assert edge["relation"] == "precedes"
    assert edge["causal_claim"] is False
    assert edge["link_basis"] == ["target_to_source"]
    assert not graph.has_edge("event:EVT-00001", "event:EVT-00002")


def test_dataset_labels_are_not_added_as_predicted_attack_nodes():
    events = _events()
    events["Label"] = ["DoS", "Bot", "DDoS"]
    graph = build_attack_graph(events)
    assert not any(str(node).startswith("attack:") for node in graph.nodes)
