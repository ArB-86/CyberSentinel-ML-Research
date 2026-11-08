import pandas as pd
import pytest

from attack_graph.event_builder import EventConfig, build_attack_events


def _flows(with_label=True):
    rows = [
        # Same pair, interleaved with an unrelated pair in global time order.
        ("2026-01-01 00:00:00", "10.0.0.1", "10.0.0.2", 6, True, -0.30, "DoS"),
        ("2026-01-01 00:00:10", "10.0.0.3", "10.0.0.4", 6, True, -0.20, "Benign"),
        ("2026-01-01 00:00:20", "10.0.0.1", "10.0.0.2", 6, True, -0.40, "Benign"),
        ("2026-01-01 00:00:30", "10.0.0.3", "10.0.0.4", 6, True, -0.50, "DDoS"),
    ]
    frame = pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "dst_ip", "protocol",
        "predicted_anomaly", "anomaly_score", "Label",
    ])
    if not with_label:
        frame = frame.drop(columns=["Label"])
    return frame


def test_grouping_does_not_require_or_use_ground_truth_label():
    events = build_attack_events(
        _flows(with_label=False),
        config=EventConfig(time_window_seconds=60),
    )
    assert len(events) == 2
    assert sorted(events["flow_count"].tolist()) == [2, 2]
    assert set(events["attack_type"]) == {"Unclassified"}
    assert set(events["attack_type_source"]) == {"not_predicted"}


def test_ground_truth_label_is_not_a_detector_fallback():
    frame = _flows(with_label=True).drop(columns=["predicted_anomaly"])
    with pytest.raises(ValueError, match="Ground-truth Label"):
        build_attack_events(frame, anomalous_only=True)


def test_interleaved_flows_are_grouped_per_connection_key():
    events = build_attack_events(
        _flows(),
        config=EventConfig(time_window_seconds=60),
    )
    by_source = events.set_index("src_ip")["flow_count"].to_dict()
    assert by_source == {"10.0.0.1": 2, "10.0.0.3": 2}


def test_explicit_threshold_can_select_suspicious_flows():
    frame = _flows(with_label=False).drop(columns=["predicted_anomaly"])
    events = build_attack_events(
        frame,
        anomalous_only=True,
        threshold=-0.35,
        config=EventConfig(time_window_seconds=60),
    )
    assert len(events) == 2
    assert events["flow_count"].tolist() == [1, 1]


def test_missing_temporal_metadata_fails_closed():
    frame = _flows().drop(columns=["timestamp"])
    with pytest.raises(ValueError, match="metadata columns"):
        build_attack_events(frame)



def test_port_aware_grouping_keeps_distinct_services_separate():
    frame = pd.DataFrame([
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 51000, "dst_port": 22, "protocol": 6,
            "predicted_anomaly": True, "anomaly_score": -0.2,
        },
        {
            "timestamp": "2026-01-01T00:00:10Z",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 51000, "dst_port": 443, "protocol": 6,
            "predicted_anomaly": True, "anomaly_score": -0.3,
        },
    ])
    events = build_attack_events(
        frame,
        config=EventConfig(time_window_seconds=60, use_ports_in_key=True),
    )
    assert len(events) == 2
    assert sorted(events["flow_count"].tolist()) == [1, 1]



def test_numeric_float_prediction_flags_are_supported():
    frame = _flows(with_label=False)
    frame["predicted_anomaly"] = [1.0, 0.0, 1.0, 0.0]
    events = build_attack_events(
        frame,
        config=EventConfig(time_window_seconds=60),
    )
    assert events["flow_count"].sum() == 2
    assert set(events["src_ip"]) == {"10.0.0.1"}
