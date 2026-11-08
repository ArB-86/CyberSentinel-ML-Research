from __future__ import annotations

import hashlib
import re


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
    if raw.isdigit():
        return f"EVT-{raw.zfill(5)}"
    return raw



def safe_artifact_stem(value: object, max_length: int = 80) -> str:
    """Create a path-safe, collision-resistant filename stem from an event ID."""
    raw = str(value).strip()
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_-")
    if not safe:
        safe = "event"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    # Always append a digest so sanitisation cannot collapse distinct IDs.
    prefix = safe[:max(1, max_length - len(digest) - 1)]
    return f"{prefix}_{digest}"
