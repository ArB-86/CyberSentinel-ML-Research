import json

from agent.workflow import generate_report_from_json


def test_report_renderer_does_not_request_or_invent_external_metrics():
    payload = {
        "event_id": "EVT-00001",
        "executive_summary": "A suspicious flow group was detected.",
        "incident_overview": "Source A communicated with destination B.",
        "observed_network_evidence": ["Mean anomaly score: 0.01."],
        "anomaly_analysis": "Score is below the configured threshold.",
        "related_events_summary": "No related events were returned.",
        "risk_assessment": "Heuristic triage only.",
        "investigation_limitations": ["Authentication logs were unavailable."],
        "recommended_soc_actions": ["Review endpoint and firewall logs."],
        "final_assessment": "Analyst validation is required.",
    }
    report = generate_report_from_json(json.dumps(payload))
    assert "Authentication logs were unavailable." in report
    assert "cryptographic signature" in report
    assert "CPU" not in report
    assert "network throughput" not in report


def test_report_renderer_rejects_invalid_json():
    try:
        generate_report_from_json("{not-json")
    except ValueError:
        return
    raise AssertionError("Invalid JSON must fail closed.")
