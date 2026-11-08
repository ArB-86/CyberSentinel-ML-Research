import json

import pandas as pd

from attack_graph.if_attack_graph_pipeline import prepare_features, run, run_inference


def test_prepare_features_preserves_missing_values_for_train_only_imputation():
    frame = pd.DataFrame({
        "Timestamp": ["2026-01-01 00:00:00", "2026-01-01 00:00:01", "2026-01-01 00:00:02"],
        "Source IP": ["A", "B", "C"],
        "Destination IP": ["B", "C", "D"],
        "Source Port": [1000, 1001, 1002],
        "Destination Port": [80, 81, 82],
        "Protocol": [6, 17, 6],
        "Flow Duration": [10.0, None, 20.0],
        "Entirely Missing Feature": [None, None, None],
        "Label": ["BENIGN", "DoS", "DDoS"],
    })
    _, x, _ = prepare_features(frame)
    assert x["Flow Duration"].isna().sum() == 1
    assert "Label" not in x.columns
    assert "src_ip" not in x.columns
    assert "Entirely Missing Feature" in x.columns
    assert x["Entirely Missing Feature"].isna().all()


def test_metadata_pipeline_runs_with_train_only_imputation(tmp_path):
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "outputs"
    data_dir.mkdir()
    rows = []
    for i in range(80):
        label = "BENIGN" if i < 64 else "DoS Hulk"
        rows.append({
            "Flow ID": f"flow-{i}",
            "Timestamp": f"2026-01-01 00:{i // 60:02d}:{i % 60:02d}",
            "Source IP": f"10.0.0.{1 + (i % 4)}",
            "Destination IP": f"10.0.1.{1 + (i % 5)}",
            "Source Port": 1000 + (i % 20),
            "Destination Port": 80 + (i % 3),
            "Protocol": 6,
            "Flow Duration": float(i + 1) if i != 3 else None,
            "Total Fwd Packets": 2 + (i % 7),
            "Label": label,
        })
    pd.DataFrame(rows).to_csv(data_dir / "flows.csv", index=False)

    run(
        str(data_dir),
        str(output_dir),
        nrows=0,
        benign_sample_n=20,
        n_estimators=10,
        calibration_quantile=0.1,
        time_window_seconds=60,
        max_sequence_gap_seconds=300,
    )

    assert (output_dir / "pipeline_summary.json").exists()
    assert (output_dir / "suspicious_flows_with_metadata.csv").exists()
    assert (output_dir / "attack_events.csv").exists()
    assert (output_dir / "incident_groups.csv").exists()
    assert (output_dir / "attack_graph.gexf").exists()
    events = pd.read_csv(output_dir / "attack_events.csv")
    assert "incident_id" in events.columns
    model_artifact = output_dir / "isolation_forest_model.joblib"
    assert model_artifact.exists()

    # A separate production-style CSV without Label must be scoreable with the
    # persisted model, imputer, feature order and benign-calibrated threshold.
    inference_dir = tmp_path / "unlabeled"
    inference_dir.mkdir()
    unlabeled = pd.read_csv(data_dir / "flows.csv").drop(columns=["Label"])
    unlabeled.to_csv(inference_dir / "unlabeled_flows.csv", index=False)
    inference_output = tmp_path / "inference-output"
    run_inference(
        str(inference_dir),
        str(model_artifact),
        str(inference_output),
        nrows=0,
        time_window_seconds=60,
        max_sequence_gap_seconds=300,
    )
    inference_summary = json.loads(
        (inference_output / "pipeline_summary.json").read_text(encoding="utf-8")
    )
    assert inference_summary["mode"] == "unlabeled_inference"
    assert inference_summary["ground_truth_labels_required"] is False
    assert inference_summary["ground_truth_labels_used"] is False
    suspicious = pd.read_csv(inference_output / "suspicious_flows_with_metadata.csv")
    assert "Label" not in suspicious.columns
    assert "predicted_anomaly" in suspicious.columns
