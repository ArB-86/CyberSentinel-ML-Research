import pandas as pd

from agent.tools import flow_evidence as flow_evidence_module


def test_flow_evidence_matches_port_pairs_and_exact_event_interval(monkeypatch):
    start = pd.Timestamp("2026-01-01T00:00:00Z")
    end = pd.Timestamp("2026-01-01T00:00:10Z")
    events = pd.DataFrame([{
        "event_id": "EVT-00001",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "ports_observed": "[('51000', '22')]",
        "_start_time_parsed": start,
        "_end_time_parsed": end,
    }])
    flows = pd.DataFrame([
        {
            "flow id": "MATCH",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 51000, "dst_port": 22,
            "timestamp": "2026-01-01T00:00:05Z",
            "_parsed_time": pd.Timestamp("2026-01-01T00:00:05Z"),
            "label": "BENIGN", "anomaly_score": -0.3,
        },
        {
            "flow id": "WRONG_PORT",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 51000, "dst_port": 443,
            "timestamp": "2026-01-01T00:00:05Z",
            "_parsed_time": pd.Timestamp("2026-01-01T00:00:05Z"),
            "label": "BENIGN", "anomaly_score": -0.2,
        },
        {
            "flow id": "OUTSIDE_INTERVAL",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 51000, "dst_port": 22,
            "timestamp": "2026-01-01T00:00:11Z",
            "_parsed_time": pd.Timestamp("2026-01-01T00:00:11Z"),
            "label": "BENIGN", "anomaly_score": -0.1,
        },
    ])
    monkeypatch.setattr(flow_evidence_module, "get_events", lambda: events)
    monkeypatch.setattr(flow_evidence_module, "get_flows", lambda: flows)

    result = flow_evidence_module.get_flow_evidence.invoke({
        "event_id": "EVT-00001",
        "max_flows": 5,
    })
    assert "Flow ID: MATCH" in result
    assert "Flow ID: WRONG_PORT" not in result
    assert "Flow ID: OUTSIDE_INTERVAL" not in result
    assert "Label:" not in result
    assert "Label counts:" not in result


def test_malformed_event_port_metadata_fails_closed(monkeypatch):
    events = pd.DataFrame([{
        "event_id": "EVT-00002",
        "src_ip": "A", "dst_ip": "B",
        "ports_observed": "__import__('os').system('echo unsafe')",
        "_start_time_parsed": pd.Timestamp("2026-01-01T00:00:00Z"),
        "_end_time_parsed": pd.Timestamp("2026-01-01T00:00:01Z"),
    }])
    monkeypatch.setattr(flow_evidence_module, "get_events", lambda: events)
    monkeypatch.setattr(flow_evidence_module, "get_flows", lambda: pd.DataFrame())

    result = flow_evidence_module.get_flow_evidence.invoke({
        "event_id": "EVT-00002",
    })
    assert "malformed" in result
