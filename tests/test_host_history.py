import numpy as np
import pandas as pd
import pytest

from attack_graph.host_history import (
    HOST_HISTORY_FEATURE_COLUMNS,
    build_causal_host_history_features,
)


def _toy_inputs():
    metadata = pd.DataFrame([
        # Deliberately unsorted to verify row alignment after chronological aggregation.
        {"timestamp": "2017-07-03 08:01:00", "src_ip": "A", "dst_ip": "D", "dst_port": 22},
        {"timestamp": "2017-07-03 08:00:00", "src_ip": "A", "dst_ip": "B", "dst_port": 80},
        {"timestamp": "2017-07-03 08:00:30", "src_ip": "A", "dst_ip": "C", "dst_port": 443},
        {"timestamp": "2017-07-03 08:02:00", "src_ip": "A", "dst_ip": "E", "dst_port": 53},
    ])
    numeric = pd.DataFrame({
        "Total Length of Fwd Packets": [30.0, 10.0, 20.0, 40.0],
        "Total Length of Bwd Packets": [3.0, 1.0, 2.0, 4.0],
        "Total Fwd Packets": [3.0, 1.0, 2.0, 4.0],
        "Total Backward Packets": [1.0, 1.0, 1.0, 1.0],
    })
    return metadata, numeric


def test_host_history_is_past_only_and_row_aligned():
    metadata, numeric = _toy_inputs()
    features = build_causal_host_history_features(metadata, numeric)

    assert features.columns.tolist() == HOST_HISTORY_FEATURE_COLUMNS
    assert np.isfinite(features.to_numpy()).all()

    # The two 08:00 flows share the same empty prior-minute state.
    assert features.loc[1, "src_flows_prev_1m"] == 0
    assert features.loc[2, "src_flows_prev_1m"] == 0

    # The 08:01 flow sees both completed 08:00 flows, despite unsorted input.
    assert features.loc[0, "src_flows_prev_1m"] == 2
    assert features.loc[0, "src_destination_ip_contacts_prev_1m"] == 2
    assert features.loc[0, "src_destination_port_contacts_prev_1m"] == 2
    assert features.loc[0, "src_bytes_prev_1m"] == 33
    assert features.loc[0, "src_packets_prev_1m"] == 5

    # At 08:02, the one-minute window sees 08:01, while five minutes sees 08:00 + 08:01.
    assert features.loc[3, "src_flows_prev_1m"] == 1
    assert features.loc[3, "src_flows_prev_5m"] == 3
    assert features.loc[3, "src_bytes_prev_5m"] == 66


def test_host_history_rejects_missing_metadata_and_incomplete_flow_totals():
    metadata, numeric = _toy_inputs()
    with pytest.raises(ValueError, match="metadata columns"):
        build_causal_host_history_features(metadata.drop(columns=["src_ip"]), numeric)
    with pytest.raises(ValueError, match="packet-byte total"):
        build_causal_host_history_features(
            metadata,
            numeric.drop(columns=["Total Length of Fwd Packets", "Total Length of Bwd Packets"]),
        )
