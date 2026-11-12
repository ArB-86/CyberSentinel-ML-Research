import numpy as np
import pandas as pd
import pytest

from experiments.temporal_threshold_optimization import (
    binary_metrics,
    chronological_days,
    parse_cicids_timestamps,
    sample_binary_stratified,
    threshold_at_fpr,
)


def test_cicids_timestamp_parser_uses_day_first_dates():
    raw = pd.Series(["03/07/2017 08:55:58", "7/7/2017 1:00"])
    parsed = parse_cicids_timestamps(raw)
    assert parsed.dt.strftime("%Y-%m-%d").tolist() == [
        "2017-07-03",
        "2017-07-07",
    ]


def test_threshold_respects_calibration_fpr_budget():
    benign_scores = np.arange(100, dtype=float)
    threshold = threshold_at_fpr(benign_scores, 0.05)
    measured_fpr = float(np.mean(benign_scores >= threshold))
    assert measured_fpr <= 0.05
    assert measured_fpr == pytest.approx(0.05)


def test_threshold_ties_are_handled_conservatively():
    benign_scores = np.array([0, 0, 1, 1, 1, 2, 2, 2], dtype=float)
    threshold = threshold_at_fpr(benign_scores, 0.25)
    assert float(np.mean(benign_scores >= threshold)) <= 0.25


def test_threshold_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        threshold_at_fpr(np.array([1.0, 2.0]), 0.5)
    with pytest.raises(ValueError):
        threshold_at_fpr(np.array([np.nan]), 0.01)


def test_chronological_split_reserves_latest_days():
    train_days, validation_day, test_day = chronological_days(
        np.array(["2017-07-03", "2017-07-04", "2017-07-05", "2017-07-06", "2017-07-07"])
    )
    assert train_days == ["2017-07-03", "2017-07-04", "2017-07-05"]
    assert validation_day == "2017-07-06"
    assert test_day == "2017-07-07"


def test_chronological_split_requires_three_days():
    with pytest.raises(ValueError):
        chronological_days(np.array(["2017-07-03", "2017-07-04"]))


def test_binary_stratified_sample_preserves_both_classes():
    positions = np.arange(1000)
    y = np.array([0] * 900 + [1] * 100, dtype=np.int8)
    sampled = sample_binary_stratified(positions, y, limit=200, seed=7)
    assert len(sampled) == 200
    assert int(y[sampled].sum()) == 20
    assert len(np.unique(sampled)) == 200


def test_metrics_use_the_supplied_fixed_threshold():
    y = np.array([0, 0, 1, 1], dtype=np.int8)
    scores = np.array([0.1, 0.4, 0.6, 0.9])
    metrics = binary_metrics(y, scores, threshold=0.5)
    assert metrics["recall"] == pytest.approx(1.0)
    assert metrics["precision"] == pytest.approx(1.0)
    assert metrics["fpr"] == pytest.approx(0.0)

def test_temporal_csv_loader_keeps_numeric_features_and_correct_dates(tmp_path):
    from experiments.temporal_threshold_optimization import load_temporal_csvs

    data_dir = tmp_path / "cicids"
    data_dir.mkdir()
    dates = [
        ("Monday.csv", "03/07/2017"),
        ("Thursday.csv", "06/07/2017"),
        ("Friday.csv", "07/07/2017"),
    ]
    for filename, date in dates:
        pd.DataFrame({
            "Timestamp": [f"{date} 08:00:00", f"{date} 08:01:00"],
            "Source IP": ["10.0.0.1", "10.0.0.2"],
            "Destination IP": ["10.0.0.3", "10.0.0.4"],
            "Protocol": [6, 17],
            "Source Port": [1000, 2000],
            "Destination Port": [80, 53],
            "Flow Duration": [100.0, 200.0],
            "Label": ["BENIGN", "DDoS"],
        }).to_csv(data_dir / filename, index=False)

    x, hashes, labels, y, days, features = load_temporal_csvs(data_dir)

    assert x.shape == (6, 4)
    assert len(hashes) == 6
    assert y.tolist() == [0, 1, 0, 1, 0, 1]
    assert days.tolist() == [
        "2017-07-03", "2017-07-03",
        "2017-07-06", "2017-07-06",
        "2017-07-07", "2017-07-07",
    ]
    assert "timestamp" not in features
    assert "label" not in features
    assert "Flow Duration" in features
    assert "Source Port" in features
