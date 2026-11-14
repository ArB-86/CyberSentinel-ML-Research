import json

import joblib
import pandas as pd

from attack_graph.if_attack_graph_pipeline import (
    _chronological_benign_split,
    clean_labels,
    prepare_features,
    run,
    run_inference,
)


def test_prepare_features_preserves_missing_values_for_train_only_imputation():
    frame = pd.DataFrame({
        "Timestamp": ["2026-01-01 00:00:00", "2026-01-01 00:00:01", "2026-01-01 00:00:02"],
        "Source IP": ["A", "B", "C"],
        "Destination IP": ["B", "C", "D"],
        "Source Port": [1000, 1001, 1002],
        "Destination Port": [80, 81, 82],
        "Protocol": [6, 17, 6],
        "Flow Duration": [10.0, None, 20.0],
        "Entirely Missing Feature": [float("nan"), float("nan"), float("nan")],
        "Event ID": [1, 2, 3],
        "Incident ID": [11, 12, 13],
        "Label": ["BENIGN", "DoS", "DDoS"],
    })
    _, x, _ = prepare_features(frame)
    assert x["Flow Duration"].isna().sum() == 1
    assert "Label" not in x.columns
    assert "src_ip" not in x.columns
    assert "Event ID" not in x.columns
    assert "Incident ID" not in x.columns
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
            "Total Backward Packets": 1 + (i % 3),
            "Total Length of Fwd Packets": float(100 + i),
            "Total Length of Bwd Packets": float(50 + i),
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
    assert (output_dir / "event_risk_scores.csv").exists()
    assert (output_dir / "incident_risk_scores.csv").exists()
    benchmark_suspicious = pd.read_csv(output_dir / "suspicious_flows_with_metadata.csv")
    assert "label" not in {str(column).casefold() for column in benchmark_suspicious.columns}
    events = pd.read_csv(output_dir / "attack_events.csv")
    assert "incident_id" in events.columns
    benchmark_suspicious = pd.read_csv(
        output_dir / "suspicious_flows_with_metadata.csv"
    )
    assert "Label" not in benchmark_suspicious.columns
    assert "label" not in benchmark_suspicious.columns

    model_artifact = output_dir / "isolation_forest_model.joblib"
    assert model_artifact.exists()
    artifact = joblib.load(model_artifact)
    assert artifact["artifact_version"] == 2
    assert artifact["feature_mode"] == "raw_plus_causal_host_history_v1"
    assert len(artifact["behavioral_feature_columns"]) == 18
    assert len(artifact["feature_columns"]) == (
        len(artifact["base_feature_columns"]) + 18
    )

    # A separate production-style CSV without Label must be scoreable with the
    # persisted model, imputer, feature order and benign-calibrated threshold.
    inference_dir = tmp_path / "unlabeled"
    inference_dir.mkdir()
    unlabeled = pd.read_csv(data_dir / "flows.csv").drop(columns=["Label"])
    unlabeled.to_csv(inference_dir / "unlabeled_flows.csv", index=False)
    # Reuse the benchmark output directory to prove stale benchmark metrics are removed.
    inference_output = output_dir
    assert (inference_output / "detection_metrics.json").exists()
    assert (inference_output / "per_attack_detection_evaluation.csv").exists()
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
    assert inference_summary["model_feature_mode"] == (
        "raw_plus_causal_host_history_v1"
    )
    assert inference_summary["behavioral_feature_count"] == 18
    assert not (inference_output / "detection_metrics.json").exists()
    assert not (inference_output / "per_attack_detection_evaluation.csv").exists()
    assert (inference_output / "event_risk_scores.csv").exists()
    assert (inference_output / "incident_risk_scores.csv").exists()
    suspicious = pd.read_csv(inference_output / "suspicious_flows_with_metadata.csv")
    assert "Label" not in suspicious.columns
    assert "predicted_anomaly" in suspicious.columns



def test_missing_benchmark_labels_remain_missing_not_attack_labels():
    frame = pd.DataFrame({
        "Flow Duration": [1.0, 2.0, 3.0],
        "Label": ["BENIGN", None, "  "],
    })
    cleaned = clean_labels(frame)
    assert cleaned["label"].iloc[0] == "BENIGN"
    assert cleaned["label"].iloc[1:].isna().all()



def test_chronological_split_holds_out_later_days_and_duplicate_hashes():
    timestamps = pd.Series([
        "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z",
        "2026-01-02T00:00:00Z", "2026-01-02T01:00:00Z",
        "2026-01-03T00:00:00Z", "2026-01-03T01:00:00Z",
    ])
    positions = pd.Series(range(6)).to_numpy()
    hashes = pd.Series([10, 11, 10, 12, 13, 14]).to_numpy(dtype="uint64")

    result = _chronological_benign_split(positions, hashes, timestamps)
    assert result is not None
    train = result["train_positions"]
    calibration = result["calibration_positions"]
    evaluation = result["benign_test_positions"]

    assert result["strategy"] == "chronological_calendar_day_holdout"
    assert pd.to_datetime(timestamps.iloc[train], utc=True).max() < pd.to_datetime(
        timestamps.iloc[calibration], utc=True
    ).min()
    assert pd.to_datetime(timestamps.iloc[calibration], utc=True).max() < pd.to_datetime(
        timestamps.iloc[evaluation], utc=True
    ).min()
    assert not (set(hashes[train]) & set(hashes[calibration]))
    assert not (set(hashes[train]) & set(hashes[evaluation]))
    assert not (set(hashes[calibration]) & set(hashes[evaluation]))
    assert result["benign_calibration_rows_excluded_for_earlier_duplicate_hash"] == 1


def test_cicids_day_first_timestamps_keep_july_calendar_dates():
    timestamps = pd.Series([
        "03/07/2017 08:00:00", "03/07/2017 09:00:00",
        "04/07/2017 08:00:00", "04/07/2017 09:00:00",
        "05/07/2017 08:00:00", "05/07/2017 09:00:00",
    ])
    positions = pd.Series(range(6)).to_numpy()
    hashes = pd.Series(range(6)).to_numpy(dtype="uint64")

    result = _chronological_benign_split(positions, hashes, timestamps)

    assert result is not None
    assert result["train_day_start"].startswith("2017-07-03")
    assert result["train_day_end"].startswith("2017-07-03")
    assert result["calibration_day_start"].startswith("2017-07-04")
    assert result["evaluation_day_start"].startswith("2017-07-05")


def test_chronological_split_uses_explicit_fallback_for_single_day():
    timestamps = pd.Series([
        "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z",
        "2026-01-01T02:00:00Z",
    ])
    result = _chronological_benign_split(
        pd.Series([0, 1, 2]).to_numpy(),
        pd.Series([1, 2, 3]).to_numpy(dtype="uint64"),
        timestamps,
    )
    assert result is None
