import numpy as np
import pandas as pd
import pytest

from experiments.temporal_threshold_optimization import (
    binary_metrics,
    chronological_days,
    parse_cicids_timestamps,
    sample_binary_stratified,
    threshold_at_fpr,
    rolling_forward_splits,
    summarize_rolling_metrics,
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
        ("01_Monday.csv", "03/07/2017"),
        ("02_Thursday.csv", "06/07/2017"),
        ("03_Friday.csv", "07/07/2017"),
    ]
    for filename, date in dates:
        frame = pd.DataFrame({
            "Timestamp": [f"{date} 08:00:00", f"{date} 08:01:00"],
            "Source IP": ["10.0.0.1", "10.0.0.2"],
            "Destination IP": ["10.0.0.3", "10.0.0.4"],
            "Protocol": [6, 17],
            "Source Port": [1000, 2000],
            "Destination Port": [80, 53],
            "Flow Duration": [100.0, 200.0],
            "Label": ["BENIGN", "DDoS"],
        })
        if filename == "02_Thursday.csv":
            # Mirrors can contain delimiter-only records with no data at all.
            frame.loc[len(frame)] = [np.nan] * len(frame.columns)
            frame.loc[len(frame)] = [np.nan] * len(frame.columns)
        frame.to_csv(data_dir / filename, index=False)

    x, hashes, labels, y, days, features, dropped_empty = load_temporal_csvs(data_dir)

    assert dropped_empty == 2
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
    assert "src_port" in features


def test_temporal_csv_loader_does_not_hide_partially_populated_bad_rows(tmp_path):
    from experiments.temporal_threshold_optimization import load_temporal_csvs

    data_dir = tmp_path / "cicids"
    data_dir.mkdir()
    for filename, date in (
        ("01_Monday.csv", "03/07/2017"),
        ("02_Thursday.csv", "06/07/2017"),
        ("03_Friday.csv", "07/07/2017"),
    ):
        frame = pd.DataFrame({
            "Timestamp": [f"{date} 08:00:00", f"{date} 08:01:00"],
            "Source IP": ["10.0.0.1", "10.0.0.2"],
            "Destination IP": ["10.0.0.3", "10.0.0.4"],
            "Protocol": [6, 17],
            "Source Port": [1000, 2000],
            "Destination Port": [80, 53],
            "Flow Duration": [100.0, 200.0],
            "Label": ["BENIGN", "DDoS"],
        })
        frame.to_csv(data_dir / filename, index=False)

    bad = pd.read_csv(data_dir / "02_Thursday.csv")
    bad.loc[0, "Timestamp"] = np.nan
    bad.to_csv(data_dir / "02_Thursday.csv", index=False)

    with pytest.raises(ValueError, match="timestamps failed"):
        load_temporal_csvs(data_dir)



def test_rolling_forward_splits_make_three_expanding_windows():
    days = np.array([
        "2017-07-03", "2017-07-04", "2017-07-05",
        "2017-07-06", "2017-07-07",
    ])
    folds = rolling_forward_splits(days, n_folds=3)

    assert folds == [
        {
            "fold": 1,
            "training_days": ["2017-07-03"],
            "validation_day": "2017-07-04",
            "test_day": "2017-07-05",
        },
        {
            "fold": 2,
            "training_days": ["2017-07-03", "2017-07-04"],
            "validation_day": "2017-07-05",
            "test_day": "2017-07-06",
        },
        {
            "fold": 3,
            "training_days": ["2017-07-03", "2017-07-04", "2017-07-05"],
            "validation_day": "2017-07-06",
            "test_day": "2017-07-07",
        },
    ]


def test_rolling_forward_splits_reject_invalid_fold_counts():
    days = np.array(["2017-07-03", "2017-07-04", "2017-07-05"])
    with pytest.raises(ValueError, match="at least 1"):
        rolling_forward_splits(days, n_folds=0)
    with pytest.raises(ValueError, match="only 1 are possible"):
        rolling_forward_splits(days, n_folds=2)


def test_rolling_metric_summary_uses_pooled_confusion_counts_and_fold_macro_auc():
    frame = pd.DataFrame([
        {
            "fold": 1, "model": "LOF_novelty", "target_fpr": 0.01,
            "precision": 0.5, "recall": 0.5, "f1": 0.5, "fpr": 0.1,
            "average_precision": 0.6, "roc_auc": 0.7,
            "tn": 90, "fp": 10, "fn": 50, "tp": 50,
        },
        {
            "fold": 2, "model": "LOF_novelty", "target_fpr": 0.01,
            "precision": 0.8, "recall": 0.4, "f1": 0.5333333333, "fpr": 0.05,
            "average_precision": 0.8, "roc_auc": 0.9,
            "tn": 190, "fp": 10, "fn": 60, "tp": 40,
        },
    ])

    macro, pooled = summarize_rolling_metrics(frame)
    macro_row = macro.iloc[0]
    pooled_row = pooled.iloc[0]

    assert macro_row["folds"] == 2
    assert macro_row["average_precision_mean"] == pytest.approx(0.7)
    assert macro_row["roc_auc_mean"] == pytest.approx(0.8)
    assert pooled_row["tn"] == 280
    assert pooled_row["fp"] == 20
    assert pooled_row["fn"] == 110
    assert pooled_row["tp"] == 90
    assert pooled_row["recall_pooled"] == pytest.approx(90 / 200)
    assert pooled_row["fpr_pooled"] == pytest.approx(20 / 300)
