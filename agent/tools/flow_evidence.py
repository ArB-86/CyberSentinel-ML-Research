import ast

import pandas as pd
from langchain_core.tools import tool

from agent.tools.data_utils import get_events, get_flows, safe_int


def _normalise_port(value):
    try:
        numeric = float(value)
        if numeric.is_integer() and 0 <= numeric <= 65535:
            return int(numeric)
    except (TypeError, ValueError, OverflowError):
        pass
    return str(value).strip()


def _observed_port_pairs(value):
    """Parse event_builder's list-of-port-pairs CSV representation safely."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return set()
    parsed = value
    if isinstance(value, str):
        if not value.strip():
            return set()
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            raise ValueError("Event port metadata is malformed; refusing a broad IP-only flow match.")
    if not isinstance(parsed, (list, tuple, set)):
        raise ValueError("Event port metadata must be a sequence of source/destination port pairs.")
    pairs = set()
    for item in parsed:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError("Event port metadata contains an invalid port pair.")
        pairs.add((_normalise_port(item[0]), _normalise_port(item[1])))
    return pairs


@tool
def get_flow_evidence(event_id: str, max_flows: int = 5) -> str:
    """
    Retrieve individual network flow evidence for a specific event.

    Returns a flow count plus up to `max_flows` flow records with IPs,
    ports, packet counts, TCP flags and anomaly score (lower score = more
    anomalous). Ground-truth labels are intentionally excluded from agent evidence.

    Use this when the event metadata alone is insufficient to explain
    the suspicious network behaviour.
    """

    try:
        events_df = get_events()
        event_match = events_df[events_df["event_id"] == str(event_id)]

        if event_match.empty:
            return f"Event ID {event_id} was not found."

        event = event_match.iloc[0]
        # Validate event metadata before loading or inspecting the flow source.
        # Malformed port metadata must never be hidden by an unrelated data error.
        observed_ports = _observed_port_pairs(event.get("ports_observed"))
        flows_df = get_flows()

        if not {"src_ip", "dst_ip"}.issubset(flows_df.columns):
            return "Error: Required IP columns are missing from flow data."

        matched = flows_df[
            (flows_df["src_ip"] == event["src_ip"])
            & (flows_df["dst_ip"] == event["dst_ip"])
        ].copy()
        ip_pair_total = len(matched)
        note = f"Matched {ip_pair_total} flow(s) by source/destination IP."

        if observed_ports:
            if not {"src_port", "dst_port"}.issubset(matched.columns):
                return (
                    "Event contains observed port pairs, but the flow source "
                    "does not contain source/destination port columns. "
                    "Refusing an IP-only match that could mix separate services."
                )
            source_ports = matched["src_port"].map(_normalise_port)
            destination_ports = matched["dst_port"].map(_normalise_port)
            keep_ports = pd.Series(
                [
                    (source_port, destination_port) in observed_ports
                    for source_port, destination_port
                    in zip(source_ports, destination_ports)
                ],
                index=matched.index,
            )
            matched = matched[keep_ports].copy()
            note += (
                f" Port-filtered to {len(observed_ports)} observed "
                f"source/destination tuple(s) -> {len(matched)} flow(s)."
            )
        else:
            note += " No observed port pairs were available for this event."

        t_start = event.get("_start_time_parsed", pd.NaT)
        t_end = event.get("_end_time_parsed", pd.NaT)

        if "_parsed_time" in matched.columns and pd.notna(t_start):
            if pd.isna(t_end):
                t_end = t_start
            times = matched["_parsed_time"]
            in_window = (
                times.notna()
                & (times >= t_start)
                & (times <= t_end)
            )
            matched = matched[in_window].copy()
            note += (
                f" Restricted to the exact observed event interval "
                f"-> {len(matched)} flow(s)."
            )
        else:
            note += " Time filtering not applied (event timestamp unavailable)."

        if matched.empty:
            return (
                f"No flow records found for event {event_id} in its time "
                f"window. {note} Do not retry this tool; report that flow "
                f"evidence is unavailable."
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
                f"Anomaly score: {row.get('anomaly_score', 'N/A')}\n"
                f"Duration: {row.get('flow duration', 'N/A')}\n"
                f"Forward packets: {row.get('total fwd packets', 'N/A')}\n"
                f"Backward packets: {row.get('total backward packets', 'N/A')}\n"
                f"TCP flags: {', '.join(flags) if flags else 'None'}\n"
            )

        return "\n".join(lines)

    except Exception as e:
        return f"Error retrieving flow evidence: {str(e)}"