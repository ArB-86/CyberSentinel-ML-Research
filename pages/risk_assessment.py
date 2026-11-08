from pathlib import Path
import pandas as pd

from attack_graph.output_contracts import safe_artifact_stem
import json
import streamlit as st
from langchain_core.messages import HumanMessage
from agent.agent import run_investigation
from agent.workflow import generate_report_from_json

import os
from dotenv import load_dotenv

load_dotenv()

# Map GEMINI_API_KEY to GOOGLE_API_KEY if needed by LangChain
if os.getenv("GEMINI_API_KEY") and not os.getenv("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = os.getenv("GEMINI_API_KEY")

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberSentinel | Risk Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# GLOBAL STYLING (Matching Dashboard)
# ============================================================

st.markdown(
    """
    <style>

    .stApp {
        background: #070b11;
        color: #edf3fa;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    [data-testid="stSidebar"] {
        background: #0b121c;
        border-right: 1px solid #1d2b3c;
    }

    .smallcaps {
        color: #6f9fc8;
        font-size: .7rem;
        font-weight: 800;
        letter-spacing: .18em;
        text-transform: uppercase;
    }

    .subtitle {
        color: #8190a3;
        font-size: .92rem;
        margin-top: -.5rem;
    }

    .card {
        background: linear-gradient(145deg, #0f1823, #0b121b);
        border: 1px solid #26374b;
        border-radius: 14px;
        padding: 18px;
        min-height: 112px;
    }

    .label {
        color: #8190a3;
        font-size: .66rem;
        font-weight: 800;
        letter-spacing: .13em;
        text-transform: uppercase;
    }

    .value {
        font-size: 1.65rem;
        font-weight: 800;
        margin-top: 7px;
    }

    .desc {
        color: #718196;
        font-size: .75rem;
        margin-top: 5px;
    }

    .hero {
        background:
            radial-gradient(
                circle at 85% 0%,
                rgba(73,168,255,.13),
                transparent 38%
            ),
            #0b141f;
        border: 1px solid #263b51;
        border-radius: 16px;
        padding: 24px;
    }

    .badge {
        display: inline-block;
        border: 1px solid #28506d;
        background: #0b1a27;
        color: #8fd7ff;
        border-radius: 999px;
        padding: 7px 11px;
        font-size: .72rem;
        font-weight: 800;
    }

    .green {
        color: #32d296;
    }

    .amber {
        color: #f0b35a;
    }

    .muted {
        color: #718196;
    }

    .rule {
        height: 1px;
        background: #1c2938;
        margin: 30px 0;
    }

    .callout {
        border: 1px solid #234c6a;
        border-left: 3px solid #49a8ff;
        background: #0b1824;
        border-radius: 10px;
        padding: 13px 15px;
        color: #91abc1;
        font-size: .8rem;
    }

    .badge-critical { background: #7f1d1d; color: #fca5a5; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }
    .badge-high { background: #78350f; color: #fde68a; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }
    .badge-medium { background: #1e3a8a; color: #93c5fd; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }
    .badge-low { background: #064e3b; color: #6ee7b7; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }

    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# DATA LOADERS
# ============================================================

@st.cache_data
def load_risk_data():
    risk_csv = Path("outputs/event_risk_scores.csv")
    if not risk_csv.exists():
        risk_csv = Path("attack_graph_output/event_risk_scores.csv")
    if risk_csv.exists():
        return pd.read_csv(risk_csv)
    return pd.DataFrame()

@st.cache_data
def load_incident_risk_data():
    risk_csv = Path("outputs/incident_risk_scores.csv")
    if not risk_csv.exists():
        risk_csv = Path("attack_graph_output/incident_risk_scores.csv")
    if risk_csv.exists():
        return pd.read_csv(risk_csv)
    return pd.DataFrame()


@st.cache_data
def get_total_flows():
    flows_path = Path("outputs/suspicious_flows_with_metadata.csv")
    if not flows_path.exists():
        flows_path = Path("attack_graph_output/suspicious_flows_with_metadata.csv")
    if flows_path.exists():
        try:
            df = pd.read_csv(flows_path, usecols=[0])
            return len(df)
        except Exception:
            return None
    return None

df_risks = load_risk_data()
df_incident_risks = load_incident_risk_data()
total_flows = get_total_flows()

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel")

    st.divider()

    st.markdown('<div class="smallcaps">Overview</div>', unsafe_allow_html=True)
    st.page_link("app.py", label="Dashboard")

    st.markdown('<div class="smallcaps" style="margin-top:18px">Detection</div>', unsafe_allow_html=True)
    st.page_link("pages/attack_detection.py", label="Attack Detection")

    st.markdown('<div class="smallcaps" style="margin-top:18px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Event Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")

    st.markdown(
        '<div class="smallcaps" style="margin-top:18px">'
        'Agentic Investigation & Risk Assessment </div>',
        unsafe_allow_html=True,
    )
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")

    st.divider()

    st.html(
        f"""
        <div class="card" style="min-height:0;padding:13px">
            <div class="green" style="font-weight:800;font-size:.76rem">
                ● {"TRIAGE DATA AVAILABLE" if (not df_risks.empty or not df_incident_risks.empty) else "TRIAGE DATA NOT AVAILABLE"}
            </div>
            <div style="color:#718196;font-size:.7rem;margin-top:6px;">
                {"Suspicious flows · {:,}".format(total_flows) if total_flows is not None else "Flow data not generated"}
            </div>
        </div>
        """
    )

# ============================================================
# HEADER & EVENT SELECTOR
# ============================================================

st.markdown('<div class="smallcaps">SOC EVENT REVIEW WORKSPACE</div>', unsafe_allow_html=True)
st.title("Event Triage, Risk Analysis & AI Investigation")
st.markdown('<div class="subtitle">Review heuristic triage indicators, inspect event/graph evidence, and generate an analyst-reviewable investigation summary.</div>', unsafe_allow_html=True)

if not df_incident_risks.empty:
    st.markdown("### Potential Incident Priority")
    st.caption(
        "Candidate groups are based on shared-host temporal correlations. "
        "The maximum available event triage index is shown; it is not a calibrated "
        "incident probability or a confirmed incident verdict."
    )
    incident_columns = [
        column for column in [
            "incident_id", "event_count", "flow_count", "risk_score",
            "risk_level", "confirmation_status", "causal_claim"
        ]
        if column in df_incident_risks.columns
    ]
    if incident_columns:
        st.dataframe(
            df_incident_risks[incident_columns],
            use_container_width=True,
            hide_index=True,
        )
    st.divider()

if not df_risks.empty:
    col_sel1, col_sel2 = st.columns([3, 1])
    with col_sel1:
        event_options = [
            f"{row['event_id']} — {row['attack_type']} (Triage: {row['risk_score']} [{row['risk_level']}])"
            for _, row in df_risks.iterrows()
        ]
        selected_str = st.selectbox("Select Event for Triage & Investigation", event_options)
        selected_event_id = selected_str.split(" — ")[0]
        selected_row = df_risks[df_risks['event_id'].astype(str) == selected_event_id].iloc[0]
    
    with col_sel2:
        st.markdown("<br>", unsafe_allow_html=True)
        level_class = f"badge-{selected_row['risk_level'].lower()}"
        st.markdown(f"**Priority Band:** <span class='{level_class}'>{selected_row['risk_level']}</span>", unsafe_allow_html=True)
else:
    st.warning("No risk scores found. Make sure `event_risk_scores.csv` is generated in your outputs folder.")
    st.stop()

if not df_incident_risks.empty:
    st.markdown("### Potential incident triage")
    incident_display_columns = [
        column for column in [
            "incident_id", "event_count", "flow_count", "risk_score",
            "risk_level", "confirmation_status",
        ]
        if column in df_incident_risks.columns
    ]
    st.dataframe(
        df_incident_risks[incident_display_columns],
        use_container_width=True,
        hide_index=True,
    )
    st.caption(
        "Incident-level priority is the maximum available event heuristic score. "
        "These groups remain unconfirmed temporal correlations, not validated incidents."
    )
else:
    st.info(
        "No candidate incident triage records are available. This may mean no "
        "multi-event temporal groups were formed; it does not mean no attack activity occurred."
    )

st.divider()

# ============================================================
# EVENT TRIAGE METRICS
# ============================================================

score = selected_row['risk_score']
level = selected_row['risk_level']
attack_type = selected_row['attack_type']
flow_count_value = selected_row.get("flow_count", float("nan"))
flow_count = int(flow_count_value) if pd.notna(flow_count_value) else "N/A"
in_degree_value = selected_row.get("in_degree", float("nan"))
out_degree_value = selected_row.get("out_degree", float("nan"))
in_deg = int(in_degree_value) if pd.notna(in_degree_value) else "N/A"
out_deg = int(out_degree_value) if pd.notna(out_degree_value) else "N/A"

factor_a = selected_row.get('anomaly_severity_factor', float('nan'))
factor_b = selected_row.get('frequency_factor', float('nan'))
factor_h = selected_row.get('host_involvement_factor', float('nan'))
factor_t = selected_row.get('temporal_correlation_factor', float('nan'))

# Check if Markdown report file exists in outputs folder
safe_event_stem = safe_artifact_stem(selected_event_id)
report_file_path = Path("outputs/agentic_investigation_output") / f"report_{safe_event_stem}.md"
report_content = ""
if report_file_path.exists():
    try:
        report_content = report_file_path.read_text(encoding="utf-8")
    except Exception:
        pass

# ============================================================
# UNIFIED TABS
# ============================================================

tab1, tab2, tab3 = st.tabs([
    "AI Investigator",
    "Risk Analysis",
    "Analyst Verification Checklist"
])

with tab1:
    st.markdown(f"### Evidence Review for `{selected_event_id}` ({attack_type})")
    st.markdown("The investigation is based on retrieved event, flow and graph evidence. Dataset labels and anomaly scores are indicators, not proof of compromise or impact.")
    
    col_run, col_status = st.columns([1, 2])
    with col_run:
        if st.button(f"Generate Evidence Review for {selected_event_id}", type="primary"):
            with st.spinner(f"Investigator retrieving event and graph evidence for {selected_event_id}... Please wait."):
                try:
                    # 1. Run agent investigation workflow
                    result = run_investigation(event_id=selected_event_id)
                    
                    # 2. Extract raw JSON string from final message
                    final_messages = result.get("messages", [])
                    if final_messages:
                        raw_content = final_messages[-1].content
                        if isinstance(raw_content, list):
                            investigation_json_str = "".join([str(item) for item in raw_content])
                        else:
                            investigation_json_str = str(raw_content)
                    else:
                        investigation_json_str = "{}"

                    # 3. Render the evidence summary as Markdown without another LLM call
                    report_content = generate_report_from_json(investigation_json_str)

                    # 4. Save into outputs/agentic_investigation_output/
                    output_dir = Path("outputs/agentic_investigation_output")
                    output_dir.mkdir(parents=True, exist_ok=True)

                    json_file_path = output_dir / f"investigation_{safe_event_stem}.json"
                    json_file_path.write_text(investigation_json_str, encoding="utf-8")

                    md_file_path = output_dir / f"report_{safe_event_stem}.md"
                    md_file_path.write_text(report_content, encoding="utf-8")

                    st.success("Evidence review generated and saved.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error running investigation agent: {e}")
    
    with col_status:
        if report_file_path.exists():
            st.success("Status: Investigation report found in output directory.")
        else:
            st.warning("Click the button to run the AI agent & generate investigation report.")

    st.divider()

    if report_file_path.exists():
        report_content = report_file_path.read_text(encoding="utf-8")
        st.markdown(report_content)
        
        st.markdown("### Export Report")
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.download_button(
                label="Download Report as Markdown (.md)",
                data=report_content,
                file_name=f"report_{safe_event_stem}.md",
                mime="text/markdown"
            )
        with col_d2:
            json_file = Path("outputs/agentic_investigation_output") / f"investigation_{safe_event_stem}.json"
            json_data = json_file.read_text(encoding="utf-8") if json_file.exists() else "{}"
            st.download_button(
                label="Download Report as JSON (.json)",
                data=json_data,
                file_name=f"investigation_{safe_event_stem}.json",
                mime="application/json"
            )
    else:
        st.info("Click **'Generate Evidence Review'** above to inspect retrieved evidence and view the structured report.")

with tab2:
    st.markdown("### Four-Factor Evidence-Based Triage Index")
    st.markdown(
        "This is a transparent heuristic priority score (0–100), not a calibrated "
        "probability, verified incident severity, or an automatic response decision."
    )
    
    col_score, col_metrics = st.columns([1, 2])
    
    with col_score:
        st.markdown(
            f"""
            <div class="card" style="padding: 20px; min-height: unset; text-align: center;">
                <div style="font-size:0.75rem; color:#8190a3; font-weight:800; text-transform:uppercase; letter-spacing:.13em;">Triage Priority Index</div>
                <div style="font-size: 3.5rem; font-weight: 900; color: #49a8ff; margin: 10px 0;">{"Unassessed" if pd.isna(score) else f"{float(score):.1f}"}</div>
                <div style="font-size: 0.9rem; color: #cbd5e1;">{"Insufficient reference evidence" if pd.isna(score) else f"Heuristic triage band: {level}"}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown(f"<br><b>Attack Vector:</b> `{attack_type}`<br><b>Flow Volume:</b> `{flow_count}` records<br><b>Graph In/Out Degree:</b> `{in_deg}` / `{out_deg}` links", unsafe_allow_html=True)

    with col_metrics:
        st.markdown("**Configured base weights: $R = 0.45A + 0.20F + 0.20H + 0.15T$**")
        st.caption(
            "Unavailable evidence factors are omitted and remaining weights are renormalised. This is a configurable heuristic, not a calibrated probability."
        )

        for label, value in [
            ("Anomaly severity", factor_a),
            ("Event volume", factor_b),
            ("Host involvement", factor_h),
            ("Temporal correlation", factor_t),
        ]:
            if pd.isna(value):
                st.markdown(f"**{label}:** Not assessed (reference evidence unavailable)")
            else:
                st.markdown(f"**{label}:** {float(value):.1f} / 100")
                st.progress(min(1.0, max(0.0, float(value) / 100.0)))

        st.info("Ground-truth attack labels are not used as production risk weights.")

with tab3:
    st.markdown("### Analyst Response Checklist")
    st.warning(
        "These are manual recommendations only. CyberSentinel does not execute "
        "firewall, host-isolation, SSH, FTP, or containment actions from this page. "
        "Verify the evidence and obtain the required operational approval first."
    )
    
    steps = [
        ("Validate the flow evidence", "Review the underlying flow rows, timestamps, ports, protocol and detector scores for this event."),
        ("Corroborate with independent telemetry", "Check firewall, endpoint, DNS, authentication and server logs for the same host and time window."),
        ("Review related event context", "Inspect shared-host graph links and temporal relationships; treat them as correlation, not causation."),
        ("Preserve relevant evidence", "Export the required flow and host records with timestamps and hashes under the organisation evidence-handling process."),
        ("Obtain analyst approval", "Do not block, isolate, disable accounts or change production systems until evidence is independently reviewed and authorised."),
    ]

    for idx, (title, desc) in enumerate(steps, 1):
        col_chk, col_desc = st.columns([0.05, 0.95])
        with col_chk:
            done = st.checkbox("", key=f"playbook_{selected_event_id}_{idx}")
        with col_desc:
            status_style = "text-decoration: line-through; color: #64748b;" if done else ""
            st.markdown(f"<div style='{status_style}'><b>Step 0{idx}: {title}</b><br><span style='font-size:0.85rem; color:#94a3b8;'>{desc}</span></div>", unsafe_allow_html=True)
        st.markdown("<div style='margin: 8px 0;'></div>", unsafe_allow_html=True)