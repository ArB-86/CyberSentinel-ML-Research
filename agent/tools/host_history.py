from langchain_core.tools import tool

from agent.tools.data_utils import get_events, sort_by_timestamp


@tool
def get_host_history(ip_address: str, max_records: int = 10) -> str:
    """Retrieve a compact chronological history (most recent N, max 10) of
    suspicious events involving a host IP, either as source or destination."""

    try:
        df = get_events()

        history = df[
            (df["src_ip"] == ip_address) | (df["dst_ip"] == ip_address)
        ].copy()

        if history.empty:
            return f"No historical suspicious events found for {ip_address}."

        total_records = len(history)
        attack_mix = history["attack_type"].value_counts().to_dict() \
            if "attack_type" in history.columns else {}

        history, timestamp_col = sort_by_timestamp(history, ascending=True)

        max_records = max(1, min(int(max_records), 10))
        history = history.tail(max_records)

        columns = [
            "event_id", "src_ip", "dst_ip", "protocol", "attack_type",
            "start_time", "end_time", "flow_count", "mean_anomaly_score",
        ]
        history = history[[c for c in columns if c in history.columns]]

        return (
            f"Host IP: {ip_address}\n"
            f"Total matching events: {total_records}\n"
            f"Attack type counts (all events): {attack_mix}\n"
            f"Events returned (most recent {len(history)}, oldest first): "
            f"{len(history)}\n\n"
            + history.to_json(orient="records", date_format="iso")
        )

    except Exception as e:
        return f"Error retrieving host history: {str(e)}"