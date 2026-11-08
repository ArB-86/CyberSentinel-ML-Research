import pandas as pd
from langchain_core.tools import tool

from agent.tools.data_utils import get_events

WINDOW_SECONDS = 300


@tool
def get_related_events(event_id: str, max_results: int = 10) -> str:
    """Find other events that share either endpoint IP with the target event
    and occurred within 300 seconds of it. Returns a compact JSON list.
    """

    try:
        df = get_events()

        target_match = df[df["event_id"] == str(event_id)]
        if target_match.empty:
            return f"Event ID {event_id} not found."

        target = target_match.iloc[0]
        src_ip, dst_ip = target["src_ip"], target["dst_ip"]

        shared = df[
            (df["event_id"] != str(event_id))
            & (
                (df["src_ip"] == src_ip) | (df["dst_ip"] == src_ip)
                | (df["src_ip"] == dst_ip) | (df["dst_ip"] == dst_ip)
            )
        ].copy()

        if shared.empty:
            return "No related events found (no other event shares an endpoint IP)."

        total_shared = len(shared)
        note = f"{total_shared} other event(s) share an endpoint IP."

        t_start = target.get("_start_time_parsed", pd.NaT)
        t_end = target.get("_end_time_parsed", pd.NaT)

        if pd.notna(t_start):
            if pd.isna(t_end):
                t_end = t_start
            window = pd.Timedelta(seconds=WINDOW_SECONDS)

            starts = shared["_start_time_parsed"]
            ends = shared["_end_time_parsed"].fillna(starts)

            # overlap of [start-300s, end+300s] with the other event
            in_window = (
                starts.notna()
                & (starts <= t_end + window)
                & (ends >= t_start - window)
            )
            shared = shared[in_window].copy()

            if shared.empty:
                return (
                    f"No related events within {WINDOW_SECONDS}s of event "
                    f"{event_id}. {note}"
                )

            shared["_time_difference_s"] = (
                (shared["_start_time_parsed"] - t_start)
                .abs()
                .dt.total_seconds()
            )
            shared = shared.sort_values("_time_difference_s")
            note += f" {len(shared)} fall within {WINDOW_SECONDS}s."
        else:
            note += " Target timestamp unavailable; no time filtering applied."

        max_results = max(1, min(int(max_results), 10))

        columns = [
            "event_id", "src_ip", "dst_ip", "protocol", "attack_type",
            "start_time", "end_time", "flow_count", "mean_anomaly_score",
            "_time_difference_s",
        ]
        columns = [c for c in columns if c in shared.columns]

        out = shared[columns].head(max_results).rename(
            columns={"_time_difference_s": "seconds_from_target"}
        )

        return note + "\n" + out.to_json(orient="records", date_format="iso")

    except Exception as e:
        return f"Error retrieving related events: {str(e)}"