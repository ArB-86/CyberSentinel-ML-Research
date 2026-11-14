import numpy as np
import pandas as pd
import pytest

from experiments.isolation_forest_host_history import (
    BEHAVIORAL_FEATURE_COLUMNS,
    build_behavioral_history_features,
)


def _toy_history():
    timestamps = pd.to_datetime([
        "2017-07-03 08:00:05",
        "2017-07-03 08:00:20",
        "2017-07-03 08:01:00",
        "2017-07-03 08:01:30",
        "2017-07-03 08:02:00",
        "2017-07-03 08:06:00",
    ]).to_numpy(dtype="datetime64[ns]").astype(np.int64, copy=False)
    return {
        "timestamps_ns": timestamps,
        "src_codes": np.array([0, 0, 0, 0, 0, 0], dtype=np.int32),
        "dst_codes": np.array([9, 9, 9, 9, 9, 9], dtype=np.int32),
        "dst_ports": np.array([80, 22, 443, 443, 80, 80], dtype=np.int32),
        "flow_bytes": np.array([10, 20, 30, 40, 50, 60], dtype=np.float32),
        "flow_packets": np.array([1, 2, 3, 4, 5, 6], dtype=np.float32),
    }


def test_feature_builder_excludes_current_minute_and_is_causal():
    features = build_behavioral_history_features(**_toy_history())

    assert list(features.columns) == BEHAVIORAL_FEATURE_COLUMNS
    # Both rows in the first minute see no completed prior minute.
    assert features.loc[0, "src_flows_prev_1m"] == 0
    assert features.loc[1, "src_flows_prev_1m"] == 0
    assert features.loc[1, "dst_flows_prev_1m"] == 0

    # At 08:01, both 08:00 flows are available as history.
    assert features.loc[2, "src_flows_prev_1m"] == 2
    assert features.loc[2, "src_destination_ip_contacts_prev_1m"] == 1
    assert features.loc[2, "src_destination_port_contacts_prev_1m"] == 2
    assert features.loc[2, "src_bytes_prev_1m"] == 30
    assert features.loc[2, "src_packets_prev_1m"] == 3
    assert features.loc[2, "dst_flows_prev_1m"] == 2
    assert features.loc[2, "dst_source_ip_contacts_prev_1m"] == 1

    # A second row in the same minute gets exactly the same lagged features:
    # the earlier 08:01:00 flow is deliberately not visible at 08:01:30.
    np.testing.assert_array_equal(features.loc[2].to_numpy(), features.loc[3].to_numpy())

    # At 08:02, the previous minute is available; the 5-minute window also
    # includes the previous two completed minute buckets.
    assert features.loc[4, "src_flows_prev_1m"] == 2
    assert features.loc[4, "src_destination_port_contacts_prev_1m"] == 1
    assert features.loc[4, "src_bytes_prev_1m"] == 70
    assert features.loc[4, "src_flows_prev_5m"] == 4
    assert features.loc[4, "src_destination_ip_contacts_per_minute_sum_prev_5m"] == 2
    assert features.loc[4, "src_destination_port_contacts_per_minute_sum_prev_5m"] == 3
    assert features.loc[4, "src_bytes_prev_5m"] == 100

    # At 08:06, the 08:00 bucket has expired; 08:01 and 08:02 remain.
    assert features.loc[5, "src_flows_prev_1m"] == 0
    assert features.loc[5, "src_flows_prev_5m"] == 3
    assert features.loc[5, "dst_flows_prev_5m"] == 3


def test_behavioral_feature_builder_rejects_misaligned_arrays():
    values = _toy_history()
    values["dst_ports"] = values["dst_ports"][:-1]
    with pytest.raises(ValueError, match="same non-zero length"):
        build_behavioral_history_features(**values)


def test_behavioral_feature_matrix_is_finite_and_has_expected_width():
    features = build_behavioral_history_features(**_toy_history())
    assert features.shape == (6, 18)
    assert np.isfinite(features.to_numpy()).all()
