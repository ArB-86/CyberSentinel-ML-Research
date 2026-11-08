import numpy as np
import pandas as pd

from experiments.compare_models import load_dataset as load_comparison_dataset
from experiments.compare_model_scales import load_dataset as load_scaling_dataset


def _write_parquet(path):
    frame = pd.DataFrame({
        "Label": ["BENIGN", "DoS Hulk", "BENIGN", "DDoS"],
        "Flow ID": ["f1", "f2", "f3", "f4"],
        "Event ID": [101, 102, 103, 104],
        "Incident ID": [1, 1, 2, 3],
        "Source IP": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "Timestamp": ["2026-01-01T00:00:00Z"] * 4,
        "Flow Duration": [10.0, 20.0, 30.0, 40.0],
        "Constant Numeric": [7, 7, 7, 7],
        "All Missing Numeric": [float("nan")] * 4,
        "Source Port": [1000, 1001, 1002, 1003],
    })
    frame.to_parquet(path, index=False)


def _assert_declared_feature_schema(features, labels, y):
    assert len(features) == 4
    assert list(labels) == ["BENIGN", "DoS Hulk", "BENIGN", "DDoS"]
    assert y.tolist() == [0, 1, 0, 1]
    assert "Flow Duration" in features.columns
    assert "Constant Numeric" in features.columns
    assert "All Missing Numeric" in features.columns
    assert "Source Port" in features.columns
    assert "Event ID" not in features.columns
    assert "Incident ID" not in features.columns
    assert "Flow ID" not in features.columns
    assert "Timestamp" not in features.columns
    assert "Label" not in features.columns


def test_model_comparison_load_keeps_full_numeric_schema(tmp_path):
    path = tmp_path / "comparison.parquet"
    _write_parquet(path)

    features, labels, y = load_comparison_dataset(path)
    _assert_declared_feature_schema(features, labels, y)


def test_scaling_study_load_keeps_full_numeric_schema(tmp_path):
    path = tmp_path / "scaling.parquet"
    _write_parquet(path)

    features, labels, y = load_scaling_dataset(path)
    _assert_declared_feature_schema(features, labels, y)
