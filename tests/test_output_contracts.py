from attack_graph.output_contracts import benchmark_metrics_available


def test_benchmark_metrics_require_evaluation_payload_from_current_run():
    benchmark = {
        "mode": "benchmark",
        "evaluation_metrics": {"roc_auc": 0.9, "pr_auc_average_precision": 0.7},
    }
    inference = {
        "mode": "unlabeled_inference",
        "isolation_forest_threshold": -0.2,
    }
    legacy_summary_without_metrics = {"pipeline_version": "2.0"}

    assert benchmark_metrics_available(benchmark)
    assert not benchmark_metrics_available(inference)
    assert not benchmark_metrics_available(legacy_summary_without_metrics)
    assert not benchmark_metrics_available(None)


def test_event_id_formatter_preserves_canonical_ids():
    from attack_graph.output_contracts import format_event_id

    assert format_event_id("EVT-00001") == "EVT-00001"
    assert format_event_id("0001") == "EVT-00001"
    assert format_event_id(1) == "EVT-00001"
    assert format_event_id("event-7") == "EVT-event-7"
