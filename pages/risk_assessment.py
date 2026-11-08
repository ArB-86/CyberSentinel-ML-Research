from pathlib import Path
import pandas as pd
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
def get_total_flows():
    flows_path = Path("outputs/suspicious_flows_with_metadata.csv")
    if not flows_path.exists():
        flows_path = Path("attack_graph_output/suspicious_flows_with_metadata.csv")
    if flows_path.exists():
        try:
            df = pd.read_csv(flows_path, usecols=[0])
            return len(df)
        except Exception:
            return 243222
    return 243222

df_risks = load_risk_data()
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
    st.page_link("pages/incident_investigation.py", label="Incident Investigation")
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
                ● SYSTEM ONLINE
            </div>
            <div style="color:#718196;font-size:.7rem;margin-top:6px;">
                CICIDS2017 · {total_flows:,} flows
            </div>
        </div>
        """
    )

# ============================================================
# HEADER & INCIDENT SELECTOR
# ============================================================

st.markdown('<div class="smallcaps">ENTERPRISE SOAR COMMAND CENTER</div>', unsafe_allow_html=True)
st.title("Incident Triage, Risk Analysis & AI Investigation")
st.markdown('<div class="subtitle">Inspect deterministic risk scores, trigger autonomous multi-step AI investigations, execute SOAR playbooks, and export SOC reports from a single console.</div>', unsafe_allow_html=True)

if not df_risks.empty:
    col_sel1, col_sel2 = st.columns([3, 1])
    with col_sel1:
        incident_options = [
            f"{row['event_id']} — {row['attack_type']} (Risk Score: {row['risk_score']} [{row['risk_level']}])"
            for _, row in df_risks.iterrows()
        ]
        selected_str = st.selectbox("Select Active Incident for Triage & Investigation", incident_options)
        selected_event_id = selected_str.split(" — ")[0]
        selected_row = df_risks[df_risks['event_id'].astype(str) == selected_event_id].iloc[0]
    
    with col_sel2:
        st.markdown("<br>", unsafe_allow_html=True)
        level_class = f"badge-{selected_row['risk_level'].lower()}"
        st.markdown(f"**Severity Band:** <span class='{level_class}'>{selected_row['risk_level']}</span>", unsafe_allow_html=True)
else:
    st.warning("No risk scores found. Make sure `event_risk_scores.csv` is generated in your outputs folder.")
    st.stop()

st.divider()

# ============================================================
# INCIDENT METRICS
# ============================================================

score = selected_row['risk_score']
level = selected_row['risk_level']
attack_type = selected_row['attack_type']
flow_count = selected_row.get('flow_count', 1)
in_deg = selected_row.get('in_degree', 0)
out_deg = selected_row.get('out_degree', 0)

factor_a = selected_row.get('anomaly_severity_factor', 50.0)
factor_b = selected_row.get('frequency_factor', 30.0)
factor_h = selected_row.get('host_involvement_factor', 40.0)
factor_t = selected_row.get('temporal_correlation_factor', 0.0)

# Check if Markdown report file exists in outputs folder
report_file_path = Path(f"outputs/agentic_investigation_output/report_{selected_event_id}.md")
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
    "Analyst Response Checklist"
])

with tab1:
    st.markdown(f"### Autonomous Investigation Report for `{selected_event_id}` ({attack_type})")
    st.markdown("Generated dynamically by the LangGraph multi-step agent using Gemini API and specialized SOC tools, formatted into a professional Tier-3 SOC report.")
    
    col_run, col_status = st.columns([1, 2])
    with col_run:
        if st.button(f"Trigger AI Investigation for {selected_event_id}", type="primary"):
            with st.spinner(f"Agent running multi-step tool calls and generating SOC report for {selected_event_id}... Please wait."):
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

                    # 3. Generate professional Markdown report using Groq / GPT-OSS
                    report_content = generate_report_from_json(investigation_json_str)

                    # 4. Save into outputs/agentic_investigation_output/
                    output_dir = Path("outputs/agentic_investigation_output")
                    output_dir.mkdir(parents=True, exist_ok=True)

                    json_file_path = output_dir / f"investigation_{selected_event_id}.json"
                    json_file_path.write_text(investigation_json_str, encoding="utf-8")

                    md_file_path = output_dir / f"report_{selected_event_id}.md"
                    md_file_path.write_text(report_content, encoding="utf-8")

                    st.success("Investigation complete and professional report generated successfully!")
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
                file_name=f"report_{selected_event_id}.md",
                mime="text/markdown"
            )
        with col_d2:
            json_file = Path(f"outputs/agentic_investigation_output/investigation_{selected_event_id}.json")
            json_data = json_file.read_text(encoding="utf-8") if json_file.exists() else "{}"
            st.download_button(
                label="Download Report as JSON (.json)",
                data=json_data,
                file_name=f"investigation_{selected_event_id}.json",
                mime="application/json"
            )
    else:
        st.info("Click **'Trigger AI Investigation'** above to execute the agentic workflow and view the report.")

with tab2:
    st.markdown("### Four-Factor Evidence-Based Triage Score")
    st.markdown(
        "This is a transparent heuristic priority score (0–100), not a calibrated "
        "probability, verified incident severity, or an automatic response decision."
    )
    
    col_score, col_metrics = st.columns([1, 2])
    
    with col_score:
        st.markdown(
            f"""
            <div class="card" style="padding: 20px; min-height: unset; text-align: center;">
                <div style="font-size:0.75rem; color:#8190a3; font-weight:800; text-transform:uppercase; letter-spacing:.13em;">Composite Risk Score</div>
                <div style="font-size: 3.5rem; font-weight: 900; color: #49a8ff; margin: 10px 0;">{score}</div>
                <div style="font-size: 0.9rem; color: #cbd5e1;">Scale: 0 to 100 ({level})</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown(f"<br><b>Attack Vector:</b> `{attack_type}`<br><b>Flow Volume:</b> `{flow_count}` records<br><b>Graph In/Out Degree:</b> `{in_deg}` / `{out_deg}` links", unsafe_allow_html=True)

    with col_metrics:
        st.markdown("**Configured base weights: $R = 0.45A + 0.20F + 0.20H + 0.15T$**")
        st.caption(
            "If a factor is unavailable, the risk engine renormalises the weights "
            "over the available factors. Dataset ground-truth attack labels are not "
            "used as a risk factor."
        )
        
        st.markdown(f"1. **Anomaly Severity ($A$ - Isolation Forest)**: `{factor_a:.1f} / 100`")
        st.progress(min(1.0, factor_a / 100.0))
        
        st.markdown(f"2. **Event Frequency ($F$ - Flow Volume)**: `{factor_b:.1f} / 100`")
        st.progress(min(1.0, factor_b / 100.0))
        
        st.markdown(f"3. **Host Topological Spread ($H$ - NetworkX Degrees)**: `{factor_h:.1f} / 100`")
        st.progress(min(1.0, factor_h / 100.0))
        
        st.markdown(f"4. **Temporal Correlation ($T$ - 300s Window Cluster)**: `{factor_t:.1f} / 100`")
        st.progress(min(1.0, factor_t / 100.0))
        
        st.info(
            "Attack-category weighting is intentionally excluded. The event pipeline "
            "does not use CICIDS ground-truth labels as production predictions."
        )

with tab3:
    st.markdown("### Analyst Response Checklist")
    st.warning(
        "These are manual recommendations only. CyberSentinel does not execute "
        "firewall, host-isolation, SSH, FTP, or containment actions from this page. "
        "Verify the evidence and obtain the required operational approval first."
    )
    
    if "ssh" in attack_type.lower():
        steps = [
            ("Block Source IP at Perimeter Firewall", "Add ingress drop rule for the malicious source IP in iptables / security groups."),
            ("Disable Password Authentication", "Enforce strict public-key cryptography on the destination SSH daemon (`/etc/ssh/sshd_config`)."),
            ("Deploy Fail2ban Defense", "Configure Fail2ban to temporarily ban IPs exceeding 3 failed login attempts on port 22."),
            ("Audit System Auth Logs", "Inspect `/var/log/auth.log` around incident timestamp for successful unauthorized sessions.")
        ]
    elif "ftp" in attack_type.lower():
        steps = [
            ("Enforce Rate Limiting on Port 21", "Restrict FTP concurrent connection thresholds in vsftpd service config."),
            ("Disable Anonymous FTP Access", "Verify anonymous login is completely disabled across FTP server instances."),
            ("Isolate Destination Segment", "Move destination host to an isolated VLAN pending forensic memory dump.")
        ]
    else:
        steps = [
            ("Isolate Affected Host", "Quarantine destination IP from the core internal broadcast domain."),
            ("Capture NetFlow Forensic Dump", "Export PCAP packets for the offending time window for offline analysis."),
            ("Review Privilege Escalation Logs", "Audit recent sudo and su commands executed on the target server.")
        ]

    for idx, (title, desc) in enumerate(steps, 1):
        col_chk, col_desc = st.columns([0.05, 0.95])
        with col_chk:
            done = st.checkbox("", key=f"playbook_{selected_event_id}_{idx}")
        with col_desc:
            status_style = "text-decoration: line-through; color: #64748b;" if done else ""
            st.markdown(f"<div style='{status_style}'><b>Step 0{idx}: {title}</b><br><span style='font-size:0.85rem; color:#94a3b8;'>{desc}</span></div>", unsafe_allow_html=True)
        st.markdown("<div style='margin: 8px 0;'></div>", unsafe_allow_html=True)