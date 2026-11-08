import json

import pandas as pd

from experiments.event_correlation_sensitivity import run_sensitivity


def test_sensitivity_sweep_reports_structure_without_ground_truth(tmp_path):
    input_path = tmp_path / "suspicious_flows.csv"
    rows = [
        ("2026-01-01T00:00:00Z", "A", "B", 50000, 22, True, -0.3, "DoS"),
        ("2026-01-01T00:00:40Z", "A", "B", 50000, 22, True, -0.4, "Benign"),
        ("2026-01-01T00:01:30Z", "B", "C", 22, 443, True, -0.5, "DDoS"),
        ("2026-01-01T00:02:30Z", "C", "D", 443, 80, True, -0.6, "Bot"),
        ("2026-01-01T00:01:35Z", "X", "Y", 51000, 53, True, -0.2, "Benign"),
    ]
    flows = pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "predicted_anomaly", "anomaly_score", "Label",
    ])
    flows.to_csv(input_path, index=False)

    output_dir = tmp_path / "sensitivity"
    result = run_sensitivity(
        input_path,
        output_dir,
        time_windows=(30, 60),
        sequence_gaps=(30, 60),
    )

    assert len(result) == 4
    assert set(result["event_window_seconds"]) == {30, 60}
    assert set(result["max_sequence_gap_seconds"]) == {30, 60}
    assert result["ground_truth_labels_used"].eq(False).all()
    assert result["grouping_key"].eq(
        "src_ip,dst_ip,protocol,src_port,dst_port"
    ).all()
    assert (result["event_count"] > 0).all()
    assert (result["event_flow_coverage"] == 1.0).all()
    narrow = result[result["event_window_seconds"] == 30]["event_count"].iloc[0]
    wide = result[result["event_window_seconds"] == 60]["event_count"].iloc[0]
    assert narrow > wide

    metadata = json.loads(
        (output_dir / "event_correlation_sensitivity_metadata.json").read_text()
    )
    assert metadata["ground_truth_labels_used"] is False
    assert metadata["input_sha256"]
    assert "does not determine which parameter setting is correct" in metadata["interpretation"]
    saved = pd.read_csv(output_dir / "event_correlation_sensitivity.csv")
    assert "candidate_incident_count" in saved.columns
