# maintain state across multi step tool interactions


from __future__ import annotations

from typing import Annotated, TypedDict, List, Dict, Any
from langchain_core.messages import BaseMessage
import operator


class InvestigationState(TypedDict):
    event_id: str
    target_ip: str | None

    # Append new messages instead of overwriting history
    messages: Annotated[List[BaseMessage], operator.add]

    # Tracks which tools were executed and with what arguments
    investigation_steps: Annotated[
        List[Dict[str, Any]],
        operator.add
    ]

    retrieved_evidence: Dict[str, Any]

    investigation_complete: bool
    final_report: Dict[str, Any] | None
