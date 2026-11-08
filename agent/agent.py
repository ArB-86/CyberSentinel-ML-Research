from __future__ import annotations
from langchain_core.messages import HumanMessage
from agent.workflow import create_investigation_graph


def run_investigation(event_id: str, target_ip: str | None = None):
    """
    Initialize and execute the LangGraph investigation workflow for a given security event.
    """
    initial_state = {
        "event_id": str(event_id),
        "target_ip": target_ip,
        "messages": [
            HumanMessage(
                content=(
                    f"Investigate security event {event_id}. "
                    "Identify suspicious behaviour and relevant "
                    "supporting evidence."
                )
            )
        ],
        "investigation_steps": [],
        "retrieved_evidence": {},
        "investigation_complete": False,
        "final_report": None
    }

    graph = create_investigation_graph()

    result = graph.invoke(
        initial_state,
        config={
            "recursion_limit": 25
        }
    )
    
    return result