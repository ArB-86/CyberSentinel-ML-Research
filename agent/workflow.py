from __future__ import annotations

import os
import json
import time

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from agent.state import InvestigationState
from agent.tools.event_details import get_event_details
from agent.tools.get_related_events import get_related_events
from agent.tools.host_history import get_host_history
from agent.tools.temporal_paths import find_temporal_paths
from agent.tools.flow_evidence import get_flow_evidence


# -----------------------------
# Configuration
# -----------------------------

MAX_TOOL_CALLS = 5

tools = [
    get_event_details,
    get_related_events,
    get_host_history,
    find_temporal_paths,
    get_flow_evidence
]

tool_node = ToolNode(tools)


# -----------------------------
# System prompt
# -----------------------------

SYSTEM_PROMPT = """
You are an evidence-grounded SOC incident investigation agent.
Your task is to investigate suspicious network events using the available tools efficiently and produce structured evidence.

CRITICAL INSTRUCTIONS TO AVOID LOOPS:
1. Call 'get_event_details' ONCE for the given event ID. Do not retry with variations.
2. Do not call the same tool with identical arguments more than once.
3. Use a mix of tools logically: get event details -> check related events or host history -> check flow evidence -> finalize.
4. Stop investigating as soon as you have sufficient data. Maximum 4 to 5 tool calls total.
5. Never invent tool results or IDs.
"""


def get_gemini_model():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")

    return ChatGoogleGenerativeAI(
        model="gemini-3.6-flash",
        google_api_key=api_key,
        timeout=120,
        max_retries=2
    ).bind_tools(tools)


# -----------------------------
# Tool-call signature
# -----------------------------

def get_tool_signature(tool_call):
    return (
        tool_call.get("name"),
        json.dumps(
            tool_call.get("args", {}),
            sort_keys=True,
            default=str
        )
    )


# -----------------------------
# Agent node
# -----------------------------

def call_model(state: InvestigationState):
    start_time = time.time()
    model = get_gemini_model()

    messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]

    print(f"\n[Agent] Calling model. Messages count: {len(state['messages'])}")
    response = model.invoke(messages)
    duration = time.time() - start_time

    print(f"[Agent] Response received in {duration:.2f}s")

    if response.tool_calls:
        print("[Agent] Requested tools:")
        for call in response.tool_calls:
            print(f"  -> {call['name']} Args: {call['args']}")
    else:
        print("[Agent] Final response generated.")

    return {"messages": [response]}


# -----------------------------
# Tool execution node
# -----------------------------

def run_tools(state: InvestigationState):
    last_message = state["messages"][-1]
    tool_calls = getattr(last_message, "tool_calls", [])

    print(f"\n[Tools] Executing {len(tool_calls)} tool call(s).")
    result = tool_node.invoke(state)

    new_steps = []
    for call in tool_calls:
        new_steps.append({
            "tool_name": call["name"],
            "arguments": call.get("args", {}),
            "signature": get_tool_signature(call),
            "executed_at": time.time()
        })

    return {
        "messages": result["messages"],
        "investigation_steps": new_steps
    }


# -----------------------------
# Conditional routing
# -----------------------------

def should_continue(state: InvestigationState):
    last_message = state["messages"][-1]
    tool_calls = getattr(last_message, "tool_calls", [])

    if not tool_calls:
        print("[Router] No more tool calls. Ending investigation.")
        return END

    previous_steps = state.get("investigation_steps", [])

    previous_signatures = {
        tuple(step["signature"])
        for step in previous_steps
        if "signature" in step
    }

    current_signatures = [
        get_tool_signature(call)
        for call in tool_calls
    ]

    duplicates = [sig for sig in current_signatures if sig in previous_signatures]
    if duplicates:
        print("[Router] Duplicate tool call detected! Forcing finalization.")
        return "finalize"

    if len(previous_steps) + len(tool_calls) > MAX_TOOL_CALLS:
        print("[Router] Tool call budget reached. Moving to finalization.")
        return "finalize"

    print("[Router] New tool calls approved. Routing to tools.")
    return "tools"


# -----------------------------
# Controlled finalization node
# -----------------------------

def finalize_investigation(state: InvestigationState):
    print("\n[Finalize] Finalizing investigation and generating structured JSON.")
    model = get_gemini_model()
    previous_messages = state["messages"][:-1]

    finalization_instruction = HumanMessage(
        content=(
            "The investigation must now be finalized. Do not request additional tools. "
            "Use only the evidence already retrieved. "
            "Output the final investigation summary strictly as a valid JSON object with keys: "
            "executive_summary, incident_overview, observed_network_evidence, anomaly_analysis, "
            "related_events_summary, risk_assessment, investigation_limitations, recommended_soc_actions, final_assessment."
        )
    )

    messages = [SystemMessage(content=SYSTEM_PROMPT)] + previous_messages + [finalization_instruction]
    response = model.invoke(messages)

    return {
        "messages": [response],
        "investigation_complete": True
    }


# -----------------------------
# Separate Utility: Convert JSON to Markdown Report using GROQ
# -----------------------------

def _as_markdown_items(value):
    if value is None:
        return ["- Not available in the retrieved evidence."]
    if isinstance(value, list):
        return [f"- {item}" for item in value] or ["- None recorded."]
    if isinstance(value, dict):
        return [f"- **{key}:** {item}" for key, item in value.items()] or ["- None recorded."]
    return [str(value)]


def generate_report_from_json(investigation_json_str: str) -> str:
    """Render investigation JSON deterministically without a second LLM.

    This prevents the report-formatting stage from inventing impact metrics,
    signatures, timestamps, or remediation actions absent from the evidence.
    """
    try:
        payload = json.loads(investigation_json_str)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Investigation output is not valid JSON; report was not generated.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Investigation output must be a JSON object.")

    sections = [
        ("Executive summary", "executive_summary"),
        ("Incident overview", "incident_overview"),
        ("Observed network evidence", "observed_network_evidence"),
        ("Anomaly analysis", "anomaly_analysis"),
        ("Related events", "related_events_summary"),
        ("Risk assessment", "risk_assessment"),
        ("Limitations and unknowns", "investigation_limitations"),
        ("Recommended SOC actions", "recommended_soc_actions"),
        ("Final assessment", "final_assessment"),
    ]

    lines = [
        f"# Security investigation: {payload.get('event_id', 'Unknown event')}",
        "",
        "**Report type:** Evidence-based investigation summary",
        "",
        "> This report is a rendering of the retrieved investigation output. "
        "It is not a cryptographic signature, a verified incident verdict, or "
        "proof of successful compromise. Unknown fields remain unknown.",
        "",
    ]
    for heading, key in sections:
        lines.extend([f"## {heading}", ""])
        lines.extend(_as_markdown_items(payload.get(key)))
        lines.append("")

    lines.extend([
        "## Review status",
        "",
        "- Analyst review is required before containment, eradication, or recovery actions.",
        "- Dataset labels and anomaly scores are indicators; they do not prove authentication outcome, compromise, data loss, or service impact.",
        "- Quantitative impact metrics are omitted unless present in the retrieved evidence.",
        "",
    ])
    return "\n".join(lines)


# -----------------------------
# Graph construction (Required for agent.py import)
# -----------------------------

def create_investigation_graph():
    workflow = StateGraph(InvestigationState)

    workflow.add_node("agent", call_model)
    workflow.add_node("tools", run_tools)
    workflow.add_node("finalize", finalize_investigation)

    workflow.set_entry_point("agent")

    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            "finalize": "finalize",
            END: END
        }
    )

    workflow.add_edge("tools", "agent")
    workflow.add_edge("finalize", END)

    return workflow.compile()