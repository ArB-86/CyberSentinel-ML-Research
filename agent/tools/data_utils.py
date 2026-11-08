"""Shared, cached data loading for all investigation tools.

WHY THIS FILE CHANGED
---------------------
The old tools re-read the 154 MB flow CSV on *every* tool call and then ran a
Python-level `.apply()` over every matching row to parse timestamps. For big
attack groups (DoS Hulk, DDoS ...) that takes minutes, which looked like the
agent was "stuck". Now each CSV is loaded once per process (and reloaded only if
the file changes), with only the needed columns and vectorised timestamp parsing.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pandas as pd

EVENTS_PATH = Path("outputs/attack_events.csv")
FLOWS_PATH = Path("outputs/suspicious_flows_with_metadata.csv")
GRAPH_PATH = Path("outputs/attack_graph.gexf")

TIMESTAMP_CANDIDATES = [
    "start_time",
    "timestamp",
    "Timestamp",
    "event_start",
    "first_seen",
    "start_timestamp",
    "date",
]

# Only these flow columns are loaded (the file has ~85 columns).
FLOW_COLUMNS = {
    "flow id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "timestamp", "flow duration", "total fwd packets",
    "total backward packets", "fin flag count", "syn flag count",
    "rst flag count", "psh flag count", "ack flag count",
    "label", "is_attack", "anomaly_score", "predicted_anomaly",
}


# ---------------------------------------------------------------- generic ---

def load_csv(path: Path) -> pd.DataFrame:
    if not Path(path).exists():
        raise FileNotFoundError(f"File not found: {path}")
    return pd.read_csv(path)


def find_timestamp_column(df):
    for column in TIMESTAMP_CANDIDATES:
        if column in df.columns:
            return column
    return None


def parse_timestamp(value):
    if value is None or pd.isna(value):
        return pd.NaT
    return pd.to_datetime(value, errors="coerce", utc=True)


def parse_timestamp_series(series: pd.Series) -> pd.Series:
    """Vectorised UTC parsing. Month-first, same as the event builder used."""
    parsed = pd.to_datetime(
        series, format="%m/%d/%Y %H:%M", errors="coerce", utc=True
    )
    missing = parsed.isna() & series.notna()
    if missing.any():  # other formats (e.g. ISO strings)
        parsed.loc[missing] = pd.to_datetime(
            series[missing], errors="coerce", utc=True, format="mixed"
        )
    return parsed


def sort_by_timestamp(df, ascending=True):
    timestamp_col = find_timestamp_column(df)
    if timestamp_col is None:
        return df, None

    result = df.copy()
    result["_parsed_time"] = pd.to_datetime(
        result[timestamp_col], errors="coerce", utc=True
    )
    result = result.sort_values(
        "_parsed_time", ascending=ascending, na_position="last"
    )
    return result, timestamp_col


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return default


def safe_float(value, default=None):
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (ValueError, TypeError):
        return default


# ----------------------------------------------------------------- cached ---

def _mtime(path: Path) -> float:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return path.stat().st_mtime


@lru_cache(maxsize=2)
def _load_events(mtime: float) -> pd.DataFrame:
    df = pd.read_csv(EVENTS_PATH)
    df["event_id"] = df["event_id"].astype(str)
    for col in ("start_time", "end_time"):
        if col in df.columns:
            df[f"_{col}_parsed"] = pd.to_datetime(
                df[col], errors="coerce", utc=True
            )
    return df


def get_events() -> pd.DataFrame:
    """Cached events table (do not mutate the returned frame; copy first)."""
    return _load_events(_mtime(EVENTS_PATH))


@lru_cache(maxsize=2)
def _load_flows(mtime: float) -> pd.DataFrame:
    df = pd.read_csv(
        FLOWS_PATH,
        usecols=lambda c: str(c).strip().lower() in FLOW_COLUMNS,
        low_memory=False,
    )
    df.columns = [str(c).strip().lower() for c in df.columns]
    if "timestamp" in df.columns:
        df["_parsed_time"] = parse_timestamp_series(df["timestamp"])
    return df


def get_flows() -> pd.DataFrame:
    """Cached flows table (loaded once, only needed columns)."""
    return _load_flows(_mtime(FLOWS_PATH))