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
         "mean_anomaly_score": 0.02, "attack_type": "Unclassified", "incident_id": "INC-00001"},
        {"event_id": "E2", "src_ip": "C", "dst_ip": "D", "flow_count": 50,
         "mean_anomaly_score": 0.20, "attack_type": "Unclassified", "incident_id": "INC-00001"},
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
    incident_output = pd.read_csv(tmp_path / "incident_risk_scores.csv")
    assert len(incident_output) == 1
    assert incident_output.loc[0, "incident_id"] == "INC-00001"
    assert incident_output.loc[0, "event_count"] == 2
    assert incident_output.loc[0, "confirmation_status"] == "potential_correlation_requires_analyst_validation"
    assert bool(incident_output.loc[0, "causal_claim"]) is False


def test_missing_graph_is_not_treated_as_zero_graph_evidence(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    output_path = tmp_path / "event_risk_scores.csv"
    pd.DataFrame([
        {"event_id": "E1", "flow_count": 1, "mean_anomaly_score": 0.1}
    ]).to_csv(events_path, index=False)

    result = calculate_incident_risks(events_path, None, output_path)
    assert pd.isna(result.loc[0, "host_involvement_factor"])
    assert pd.isna(result.loc[0, "temporal_correlation_factor"])
    assert pd.isna(result.loc[0, "in_degree"])
    assert pd.isna(result.loc[0, "out_degree"])
    assert pd.isna(result.loc[0, "risk_score"])
    assert result.loc[0, "risk_level"] == "UNASSESSED"
    assert result.loc[0, "risk_score_semantics"] == "heuristic_triage_score_not_probability"



def test_no_candidate_incidents_writes_readable_empty_incident_file(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    output_path = tmp_path / "event_risk_scores.csv"
    pd.DataFrame([
        {"event_id": "E1", "incident_id": None, "flow_count": 10,
         "mean_anomaly_score": -0.1, "attack_type": "Unclassified"}
    ]).to_csv(events_path, index=False)

    calculate_incident_risks(events_path, None, output_path)
    incident_path = tmp_path / "incident_risk_scores.csv"
    assert incident_path.exists()
    incident_scores = pd.read_csv(incident_path)
    assert incident_scores.empty
    assert "incident_id" in incident_scores.columns



def test_missing_flow_count_is_not_treated_as_zero_evidence(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    graph_path = tmp_path / "attack_graph.gexf"
    summary_path = tmp_path / "pipeline_summary.json"
    output_path = tmp_path / "event_risk_scores.csv"

    pd.DataFrame([
        {"event_id": "E1", "src_ip": "A", "dst_ip": "B",
         "flow_count": None, "mean_anomaly_score": -0.1},
        {"event_id": "E2", "src_ip": "C", "dst_ip": "D",
         "flow_count": None, "mean_anomaly_score": -0.2},
    ]).to_csv(events_path, index=False)
    summary_path.write_text(json.dumps({
        "calibration_score_quantiles": {
            "0.0": -0.5, "0.5": 0.0, "1.0": 0.5
        }
    }), encoding="utf-8")

    graph = nx.DiGraph()
    for event in ("E1", "E2"):
        graph.add_node(f"event:{event}")
        graph.add_node(f"host:{'A' if event == 'E1' else 'C'}")
        graph.add_node(f"host:{'B' if event == 'E1' else 'D'}")
    graph.add_edge("host:A", "event:E1", relation="initiates")
    graph.add_edge("event:E1", "host:B", relation="targets")
    graph.add_edge("host:C", "event:E2", relation="initiates")
    graph.add_edge("event:E2", "host:D", relation="targets")
    nx.write_gexf(graph, graph_path)

    result = calculate_incident_risks(events_path, graph_path, output_path)
    assert result["frequency_factor"].isna().all()
    assert result["risk_score"].notna().all()



def test_one_positive_risk_weight_cannot_create_a_score(tmp_path):
    events_path = tmp_path / "attack_events.csv"
    graph_path = tmp_path / "attack_graph.gexf"
    summary_path = tmp_path / "pipeline_summary.json"
    output_path = tmp_path / "event_risk_scores.csv"
    pd.DataFrame([
        {"event_id": "E1", "src_ip": "A", "dst_ip": "B",
         "flow_count": 5, "mean_anomaly_score": -0.2},
        {"event_id": "E2", "src_ip": "C", "dst_ip": "D",
         "flow_count": 8, "mean_anomaly_score": 0.1},
    ]).to_csv(events_path, index=False)
    summary_path.write_text(json.dumps({
        "calibration_score_quantiles": {
            "0.0": -0.5, "0.5": 0.0, "1.0": 0.5
        }
    }), encoding="utf-8")

    weights = {
        "anomaly_severity": 1.0,
        "event_volume": 0.0,
        "host_involvement": 0.0,
        "temporal_correlation": 0.0,
    }
    result = calculate_incident_risks(
        events_path, None, output_path, weights=weights
    )
    assert result["risk_score"].isna().all()
    assert set(result["risk_level"]) == {"UNASSESSED"}
