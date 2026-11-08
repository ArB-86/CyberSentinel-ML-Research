import json

import networkx as nx
import pandas as pd

from risk_analyzer import calculate_incident_risks


def test_risk_uses_benign_calibration_distribution_and_no_attack_label_weight(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    graph_path = tmp_path / "attack_graph.gexf"
    summary_path = tmp_path / "pipeline_summary.json"
    output_path = tmp_path / "event_risk_scores.csv"

    pd.DataFrame([
        {"event_id": "E1", "src_ip": "A", "dst_ip": "B", "flow_count": 5,
         "mean_anomaly_score": 0.02, "attack_type": "DoS"},
        {"event_id": "E2", "src_ip": "C", "dst_ip": "D", "flow_count": 50,
         "mean_anomaly_score": 0.20, "attack_type": "Benign"},
    ]).to_csv(events_path, index=False)

    summary_path.write_text(json.dumps({
        "calibration_score_quantiles": {
            "0.0": -0.1, "0.05": 0.0, "0.5": 0.2, "0.95": 0.8, "1.0": 1.0
        }
    }), encoding="utf-8")

    graph = nx.DiGraph()
    for node in ["host:A", "host:B", "event:E1", "host:C", "host:D", "event:E2"]:
        graph.add_node(node)
    graph.add_edge("host:A", "event:E1", relation="initiates")
    graph.add_edge("event:E1", "host:B", relation="targets")
    graph.add_edge("event:E1", "event:E2", relation="precedes")
    nx.write_gexf(graph, graph_path)

    result = calculate_incident_risks(events_path, graph_path, output_path)
    assert output_path.exists()
    assert "attack_category_factor" not in result.columns
    assert result["risk_score"].between(0, 100).all()
    assert result.loc[0, "anomaly_severity_factor"] > result.loc[1, "anomaly_severity_factor"]
    assert set(result["risk_score_semantics"]) == {"heuristic_triage_score_not_probability"}
    assert set(result["anomaly_reference_source"]) == {"benign_calibration_distribution"}


def test_missing_graph_is_not_treated_as_zero_graph_evidence(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    output_path = tmp_path / "event_risk_scores.csv"
    pd.DataFrame([
        {"event_id": "E1", "flow_count": 1, "mean_anomaly_score": 0.1}
    ]).to_csv(events_path, index=False)

    result = calculate_incident_risks(events_path, None, output_path)
    assert pd.isna(result.loc[0, "host_involvement_factor"])
    assert pd.isna(result.loc[0, "temporal_correlation_factor"])
    assert result.loc[0, "risk_score"] == 100.0
