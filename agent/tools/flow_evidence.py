import pandas as pd
from langchain_core.tools import tool

from agent.tools.data_utils import get_events, get_flows, safe_int

WINDOW_SECONDS = 60


@tool
def get_flow_evidence(event_id: str, max_flows: int = 5) -> str:
    """
    Retrieve individual network flow evidence for a specific event.

    Returns a summary (flow count, label counts) plus up to `max_flows`
    flow records with IPs, ports, packet counts, TCP flags, label and
    anomaly score (lower score = more anomalous).

    Use this when the event metadata alone is insufficient to explain
    the suspicious network behaviour.
    """

    try:
        events_df = get_events()
        event_match = events_df[events_df["event_id"] == str(event_id)]

        if event_match.empty:
            return f"Event ID {event_id} was not found."

        event = event_match.iloc[0]
        flows_df = get_flows()

        if not {"src_ip", "dst_ip"}.issubset(flows_df.columns):
            return "Error: Required IP columns are missing from flow data."

        matched = flows_df[
            (flows_df["src_ip"] == event["src_ip"])
            & (flows_df["dst_ip"] == event["dst_ip"])
        ]
        ip_pair_total = len(matched)
        note = f"Matched {ip_pair_total} flow(s) by source/destination IP."

        t_start = event.get("_start_time_parsed", pd.NaT)
        t_end = event.get("_end_time_parsed", pd.NaT)

        if "_parsed_time" in matched.columns and pd.notna(t_start):
            if pd.isna(t_end):
                t_end = t_start
            window = pd.Timedelta(seconds=WINDOW_SECONDS)

            times = matched["_parsed_time"]
            in_window = (
                times.notna()
                & (times >= t_start - window)
                & (times <= t_end + window)
            )
            matched = matched[in_window]
            note += (
                f" Time-filtered to event window +/-{WINDOW_SECONDS}s "
                f"-> {len(matched)} flow(s)."
            )
        else:
            note += " Time filtering not applied (timestamp unavailable)."

        if matched.empty:
            return (
                f"No flow records found for event {event_id} in its time "
                f"window. {note} Do not retry this tool; report that flow "
                f"evidence is unavailable."
            )

        label_counts = (
            matched["label"].value_counts().head(5).to_dict()
            if "label" in matched.columns else {}
        )

        max_flows = max(1, min(int(max_flows), 20))

        if "anomaly_score" in matched.columns:
            shown = matched.sort_values("anomaly_score", ascending=True)
        else:
            shown = matched
        shown = shown.head(max_flows)

        lines = [
            f"Event ID: {event_id}",
            f"Matching flows: {len(matched)}",
            f"Label counts: {label_counts}",
            f"Displaying the {len(shown)} most anomalous flow(s).",
            note,
            "",
        ]

        for _, row in shown.iterrows():
            flags = [
                name
                for col, name in [
                    ("syn flag count", "SYN"),
                    ("ack flag count", "ACK"),
                    ("psh flag count", "PSH"),
                    ("rst flag count", "RST"),
                    ("fin flag count", "FIN"),
                ]
                if safe_int(row.get(col)) > 0
            ]
            lines.append(
                f"Flow ID: {row.get('flow id', 'N/A')}\n"
                f"Connection: {row.get('src_ip')}:{safe_int(row.get('src_port'))}"
                f" -> {row.get('dst_ip')}:{safe_int(row.get('dst_port'))}\n"
                f"Time: {row.get('timestamp', 'N/A')}\n"
                f"Label: {row.get('label', 'Unknown')}\n"
                f"Anomaly score: {row.get('anomaly_score', 'N/A')}\n"
                f"Duration: {row.get('flow duration', 'N/A')}\n"
                f"Forward packets: {row.get('total fwd packets', 'N/A')}\n"
                f"Backward packets: {row.get('total backward packets', 'N/A')}\n"
                f"TCP flags: {', '.join(flags) if flags else 'None'}\n"
            )

        return "\n".join(lines)

    except Exception as e:
        return f"Error retrieving flow evidence: {str(e)}"