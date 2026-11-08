from __future__ import annotations

from pathlib import Path
from typing import Iterable


def file_cache_signature(path: str | Path | None) -> tuple[int, int, int, int] | None:
    """Return a cheap cache key that changes when a file is replaced or rewritten.

    Streamlit hashes ordinary function arguments, not the contents of a file
    referenced only through a captured/global Path. Pass this tuple into every
    cached file loader so rerunning the detection pipeline invalidates stale UI
    data without disabling caching entirely.
    """
    if path is None:
        return None
    try:
        stat = Path(path).stat()
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
        return None
    return (
        int(stat.st_mtime_ns),
        int(stat.st_ctime_ns),
        int(stat.st_size),
        int(getattr(stat, "st_ino", 0)),
    )


def file_set_cache_signature(
    paths: Iterable[str | Path | None],
) -> tuple[tuple[str, tuple[int, int, int, int] | None], ...]:
    """Signature for ordered candidate-path lists used by fallback loaders."""
    return tuple(
        (str(Path(path)) if path is not None else "<none>", file_cache_signature(path))
        for path in paths
    )
