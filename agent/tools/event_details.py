import pandas as pd
from langchain_core.tools import tool

from agent.tools.data_utils import get_events


@tool
def get_event_details(event_id: str) -> str:
    """
    Retrieve the metadata of one specific attack event.

    Use this first when an investigation starts with an event ID.
    Returns source/destination IPs, start/end times, attack category,
    protocol, flow count, mean anomaly score and observed ports.
    """

    try:
        df = get_events()

        match = df[df["event_id"] == str(event_id)]

        if match.empty:
            return f"Event ID {event_id} was not found."

        row = match.iloc[0]
        row = row[[c for c in row.index if not str(c).startswith("_")]]
        row = row.astype(object).where(pd.notna(row), None)

        return row.to_json(force_ascii=False, date_format="iso")

    except Exception as e:
        return f"Error retrieving event details: {str(e)}"