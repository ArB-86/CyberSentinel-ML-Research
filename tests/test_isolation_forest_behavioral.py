import numpy as np
import pandas as pd
import pytest

from experiments.isolation_forest_behavioral import build_causal_behavior_features


def test_behavior_features_use_only_strictly_prior_timestamps():
    t0 = pd.Timestamp("2017-07-03 09:00:00")
    t1 = pd.Timestamp("2017-07-03 09:00:01")
    t2 = pd.Timestamp("2017-07-03 09:00:03")
    metadata = pd.DataFrame([
        # Deliberately not chronological: output must remain row-aligned.
        {"timestamp": t1, "src_ip": "A", "dst_ip": "B", "dst_port": 80, "protocol": 6},
        {"timestamp": t0, "src_ip": "A", "dst_ip": "C", "dst_port": 443, "protocol": 6},
        {"timestamp": t0, "src_ip": "A", "dst_ip": "B", "dst_port": 80, "protocol": 6},
        {"timestamp": t2, "src_ip": "A", "dst_ip": "D", "dst_port": 22, "protocol": 6},
        {"timestamp": t1, "src_ip": "X", "dst_ip": "B", "dst_port": 80, "protocol": 17},
    ])

    features, names = build_causal_behavior_features(metadata)
    frame = pd.DataFrame(features, columns=names)

    # All flows at t0 share an empty prior state; they cannot see each other.
    assert frame.loc[1, "src_prior_flow_count"] == 0
    assert frame.loc[2, "src_prior_flow_count"] == 0
    assert frame.loc[1, "src_prior_unique_dst_ip_count"] == 0
    assert frame.loc[2, "src_prior_unique_dst_port_count"] == 0

    # At t1, source A has two prior flows and two previously seen peers/ports.
    assert frame.loc[0, "src_prior_flow_count"] == 2
    assert frame.loc[0, "src_prior_unique_dst_ip_count"] == 2
    assert frame.loc[0, "src_prior_unique_dst_port_count"] == 2
    assert frame.loc[0, "src_seconds_since_previous_flow"] == 1
    assert frame.loc[0, "src_protocol_prior_flow_count"] == 2

    # At t2 the source has three strictly earlier flows; the new peer is not
    # counted until a later timestamp.
    assert frame.loc[3, "src_prior_flow_count"] == 3
    assert frame.loc[3, "src_prior_unique_dst_ip_count"] == 2
    assert frame.loc[3, "src_prior_unique_dst_port_count"] == 2
    assert frame.loc[3, "src_seconds_since_previous_flow"] == 2

    # Destination B had one prior flow from source A at t0.
    assert frame.loc[0, "dst_prior_flow_count"] == 1
    assert frame.loc[0, "dst_prior_unique_src_ip_count"] == 1
    assert frame.loc[0, "dst_seconds_since_previous_flow"] == 1

    # The source-destination pair A->B was seen once before t1.
    assert frame.loc[0, "src_dst_prior_flow_count"] == 1
    assert frame.loc[0, "src_dst_seconds_since_previous_flow"] == 1

    assert np.isfinite(features).all()
    assert features.shape == (len(metadata), len(names))


def test_behavior_feature_builder_rejects_missing_metadata():
    metadata = pd.DataFrame({
        "timestamp": [pd.Timestamp("2017-07-03 09:00:00")],
        "src_ip": ["A"],
        "dst_ip": ["B"],
        "protocol": [6],
    })
    with pytest.raises(ValueError, match="dst_port"):
        build_causal_behavior_features(metadata)


def test_temporal_loader_can_return_aligned_flow_metadata(tmp_path):
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

    result = load_temporal_csvs(data_dir, return_metadata=True)
    x, hashes, labels, y, days, features, dropped, metadata = result

    assert len(result) == 8
    assert len(metadata) == len(x) == len(labels) == len(days)
    assert metadata["src_ip"].tolist() == ["10.0.0.1", "10.0.0.2"] * 3
    assert metadata["dst_port"].tolist() == [80, 53] * 3
    assert metadata["timestamp"].dt.strftime("%Y-%m-%d").tolist() == [
        "2017-07-03", "2017-07-03",
        "2017-07-06", "2017-07-06",
        "2017-07-07", "2017-07-07",
    ]
