import pandas as pd

from attack_graph.if_attack_graph_pipeline import prepare_features, run


def test_prepare_features_preserves_missing_values_for_train_only_imputation():
    frame = pd.DataFrame({
        "Timestamp": ["2026-01-01 00:00:00", "2026-01-01 00:00:01"],
        "Source IP": ["A", "B"],
        "Destination IP": ["B", "C"],
        "Source Port": [1000, 1001, 1002],
        "Destination Port": [80, 81, 82],
        "Protocol": [6, 17, 6],
        "Flow Duration": [10.0, None, 20.0],
        "Label": ["BENIGN", "DoS"],
    })
    _, x, _ = prepare_features(frame)
    assert x["Flow Duration"].isna().sum() == 1
    assert "Label" not in x.columns
    assert "src_ip" not in x.columns


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
    assert (output_dir / "attack_graph.gexf").exists()
