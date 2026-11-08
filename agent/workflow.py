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

def generate_report_from_json(investigation_json_str: str) -> str:
    """
    Takes the structured JSON from the investigation and uses Groq (Llama-3) 
    to format it into a professional Markdown SOC incident investigation report.
    """
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise ValueError("GROQ_API_KEY environment variable is not set.")

    model = ChatGroq(
        model="openai/gpt-oss-20b",
        temperature=0.2,
        groq_api_key=groq_api_key
    )
    
    prompt = f"""
    You are an elite, senior Tier-3 Security Operations Center (SOC) Incident Responder and Threat Hunter.
    Your task is to convert the following structured agent investigation JSON into a comprehensive, 
    highly detailed, professional Markdown incident investigation report suitable for CISO and forensic review.
    
    The report structure must strictly follow the gold-standard format of advanced threat intelligence reports (such as detailed volumetric impact metrics, campaign timelines, and technical breakdowns), ensuring maximum readability and professional rigor.

    Investigation JSON Payload:
    {investigation_json_str}

    CRITICAL FORMATTING INSTRUCTIONS:
    - In the header, set "Prepared by: CyberSentinel AI Investigator" (Do not use placeholders like [Your Name]).
    - Include proper cryptographic signature block at the end.
    - Use clear markdown tables, bold headers, and rich security terminology throughout the document.

    CRITICAL SECTIONS TO INCLUDE IN THE MARKDOWN REPORT:
    1. Executive Summary: High-level overview of the incident, impact, scope, and final disposition.
    2. Technical Findings & Traffic Analysis: Detailed evaluation of event logs, protocol metrics, flow volumes, anomaly scores, and behavioral indicators.
    3. Attack Chain & Campaign Flow: Precise timestamps, sequence of actions, temporal path analysis, and related historical events.
    4. Impact Assessment: Quantifiable impact on CPU, memory, network throughput, response time, and service availability.
    5. Recommended Remediation & Mitigation: Immediate containment steps, short-term actions, and strategic infrastructure hardening.
    6. Operational Insights & Improvement Roadmap (Post-Incident Retrospective): Key takeaways, detection engineering gaps, and preventive strategies to avoid recurrence.

    Output clean, professional Markdown matching the rigorous depth of a Senior SOC Incident Response report.
    """

    response = model.invoke([HumanMessage(content=prompt)])
    content = response.content

    if isinstance(content, list):
        markdown_text = "".join([
            str(item.get("text", item)) if isinstance(item, dict) else str(item) 
            for item in content
        ])
    else:
        markdown_text = str(content)

    return markdown_text


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