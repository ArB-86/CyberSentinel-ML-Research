from __future__ import annotations


def benchmark_metrics_available(summary: dict | None) -> bool:
    """Return True only when the current run contains benchmark evaluation results.

    File existence alone is not sufficient: benchmark metric files can remain
    in an output directory after a later unlabeled inference run. The summary
    belonging to the current pipeline execution is the source of truth.
    """
    if not isinstance(summary, dict):
        return False
    if summary.get("mode", "benchmark") != "benchmark":
        return False
    metrics = summary.get("evaluation_metrics")
    return isinstance(metrics, dict) and bool(metrics)


def format_event_id(value: object) -> str:
    """Format raw numeric event IDs without double-prefixing canonical IDs."""
    raw = str(value).strip()
    if raw.upper().startswith("EVT-"):
        return raw
    return f"EVT-{raw.zfill(5)}"
