from __future__ import annotations

from html import escape

import streamlit as st


st.set_page_config(
    page_title="CyberSentinel | Future Scope",
    page_icon="🧭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Keep this page aligned with the dark SOC dashboard.
st.markdown(
    """
    <style>
    .stApp { background:#070b11; color:#edf3fa; }
    [data-testid="stSidebar"] { background:#0b121c; border-right:1px solid #1d2b3c; }
    .block-container { max-width:1500px; padding-top:1.7rem; padding-bottom:3rem; }

    .fs-kicker {
        color:#6f9fc8; font-size:.68rem; font-weight:800;
        letter-spacing:.17em; text-transform:uppercase;
    }
    .fs-subtitle { color:#8797aa; font-size:.9rem; margin-top:-.45rem; }

    .fs-hero {
        position:relative; overflow:hidden; padding:24px 26px;
        border:1px solid #263b51; border-radius:16px;
        background:radial-gradient(circle at 92% 0%,rgba(73,168,255,.15),transparent 34%),#0b141f;
    }
    .fs-hero-title {
        color:#f0f6ff; font-size:1.55rem; line-height:1.25;
        font-weight:850; max-width:850px;
    }
    .fs-hero-copy {
        color:#9aabbe; font-size:.86rem; line-height:1.55;
        margin-top:9px; max-width:850px;
    }
    .fs-chip {
        display:inline-block; margin:14px 7px 0 0; padding:5px 9px;
        color:#a9d4f5; background:#102337; border:1px solid #294966;
        border-radius:999px; font-size:.66rem; font-weight:800;
        letter-spacing:.04em;
    }

    .fs-flow {
        min-height:112px; padding:14px 15px; border-radius:12px;
        border:1px solid #26374b; background:linear-gradient(145deg,#0f1823,#0b121b);
    }
    .fs-flow-num { color:#6f9fc8; font-size:.66rem; font-weight:850; letter-spacing:.13em; }
    .fs-flow-title { color:#eaf2fb; font-size:.9rem; font-weight:800; margin-top:8px; }
    .fs-flow-copy { color:#8192a6; font-size:.74rem; line-height:1.45; margin-top:5px; }

    .fs-card {
        min-height:326px; height:100%; padding:18px 19px 16px;
        border:1px solid #26374b; border-radius:14px;
        background:linear-gradient(145deg,#0f1823,#0b121b);
        margin-bottom:14px;
    }
    .fs-card-head {
        display:flex; align-items:flex-start; justify-content:space-between;
        gap:12px; margin-bottom:8px;
    }
    .fs-card-index { color:#6f9fc8; font-size:.67rem; font-weight:850; letter-spacing:.13em; }
    .fs-card-status {
        flex-shrink:0; color:#a8c9e5; background:#102337;
        border:1px solid #294966; border-radius:999px;
        padding:4px 8px; font-size:.61rem; font-weight:800;
    }
    .fs-card-title {
        color:#f0f6ff; font-size:1.02rem; line-height:1.32;
        font-weight:850; margin:5px 0 9px;
    }
    .fs-card-summary {
        color:#98aabd; font-size:.78rem; line-height:1.5;
        min-height:38px; margin-bottom:14px;
    }
    .fs-card-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    .fs-card-panel {
        background:#0a131d; border:1px solid #1f3041;
        border-radius:10px; padding:11px 12px; min-height:118px;
    }
    .fs-label {
        color:#7795b2; font-size:.62rem; font-weight:850;
        letter-spacing:.12em; text-transform:uppercase; margin-bottom:7px;
    }
    .fs-card-text { color:#d0dbe7; font-size:.75rem; line-height:1.48; }
    .fs-output {
        color:#a6d8c0; font-size:.75rem; line-height:1.45;
        padding-top:12px; margin-top:12px; border-top:1px solid #203144;
    }
    .fs-output b { color:#70c99e; font-size:.62rem; letter-spacing:.1em; }

    .fs-priority {
        min-height:98px; padding:13px 14px; border-radius:11px;
        background:#0d1722; border:1px solid #26374b;
    }
    .fs-priority-num { color:#6f9fc8; font-size:.63rem; font-weight:850; letter-spacing:.12em; }
    .fs-priority-title { color:#eaf2fb; font-size:.84rem; font-weight:800; margin-top:7px; }
    .fs-priority-copy { color:#8192a6; font-size:.71rem; line-height:1.4; margin-top:4px; }

    .fs-boundary {
        padding:13px 15px; border:1px solid #293b4e; border-left:3px solid #d39b4d;
        border-radius:9px; background:#0c151f; color:#aab8c8;
        font-size:.78rem; line-height:1.5;
    }
    .fs-boundary b { color:#e8c18a; }

    @media (max-width: 850px) {
        .fs-card { min-height:0; }
        .fs-card-grid { grid-template-columns:1fr; }
        .fs-card-summary { min-height:0; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel")
    st.divider()
    st.markdown('<div class="fs-kicker">Overview</div>', unsafe_allow_html=True)
    st.page_link("app.py", label="Dashboard")
    st.markdown('<div class="fs-kicker" style="margin-top:16px">Detection</div>', unsafe_allow_html=True)
    st.page_link("pages/attack_detection.py", label="Attack Detection")
    st.page_link("pages/model_selection.py", label="Model Selection & Evidence")
    st.markdown('<div class="fs-kicker" style="margin-top:16px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Incident Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")
    st.markdown('<div class="fs-kicker" style="margin-top:16px">Project</div>', unsafe_allow_html=True)
    st.page_link("pages/future_scope.py", label="Future Scope")

# ---------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------
st.markdown('<div class="fs-kicker">PROJECT ROADMAP</div>', unsafe_allow_html=True)
st.title("Future Scope")
st.markdown(
    """
    <div class="fs-hero">
      <div class="fs-hero-title">Four practical steps beyond batch-based detection.</div>
      <div class="fs-hero-copy">
        The roadmap extends capabilities already present in CyberSentinel.
        Each card separates the current implementation from the work still required.
      </div>
      <span class="fs-chip">4 proposed improvements</span>
      <span class="fs-chip">Grounded in the current codebase</span>
      <span class="fs-chip">Not yet implemented</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------
# Current system — one compact view, without repeating this in every card.
# ---------------------------------------------------------------------
st.markdown("### Current pipeline")
st.caption("What the application does today.")
flow = [
    ("01", "Flow batches", "Network-flow CSV input"),
    ("02", "Anomaly scoring", "Isolation Forest scores flows"),
    ("03", "Event correlation", "Events and graph connections"),
    ("04", "Investigation", "Risk indicators and AI evidence"),
]
flow_cols = st.columns(4)
for col, (number, title, description) in zip(flow_cols, flow):
    with col:
        st.markdown(
            f'<div class="fs-flow"><div class="fs-flow-num">{number}</div>'
            f'<div class="fs-flow-title">{escape(title)}</div>'
            f'<div class="fs-flow-copy">{escape(description)}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown("### Roadmap")
st.caption("Each item shows the gap, the next engineering step, and the concrete output.")

roadmap = [
    {
        "number": "01",
        "area": "DETECTION RELIABILITY",
        "status": "EXPERIMENT EXISTS",
        "title": "Test detection across different days",
        "summary": "A threshold that works on one day may create too many alerts on another. That stability has to be measured.",
        "current": "Isolation Forest, chronological data handling and a temporal-threshold experiment script already exist.",
        "next": "Complete a repeatable multi-fold run. Compare 0.5%, 1%, 2% and 5% benign-calibration FPR targets; evaluate later-day false alerts and missed attacks without tuning on the final test fold.",
        "output": "Per-fold metrics and a threshold comparison for unseen days.",
    },
    {
        "number": "02",
        "area": "INCIDENT VALIDATION",
        "status": "VALIDATION WORK",
        "title": "Measure whether event groups are meaningful",
        "summary": "Shared-host and time-based links produce candidate incident groups—not verified incidents.",
        "current": "The pipeline already forms events, connects related events and groups graph components.",
        "next": "Run the event-window/gap sensitivity sweep. Have an analyst label a sample of event pairs as related or unrelated, then measure over-merging and over-splitting.",
        "output": "Reviewed grouping results, with evidence for why each pair was connected.",
    },
    {
        "number": "03",
        "area": "ATTACK IDENTIFICATION",
        "status": "NEW ML MODEL",
        "title": "Predict a likely attack family",
        "summary": "Anomaly detection answers “does this look unusual?” It does not identify the attack type.",
        "current": "Isolation Forest flags unusual flows; it does not classify DDoS, PortScan, brute force or XSS.",
        "next": "Train a separate supervised multiclass model on labelled data. Use time/group-aware evaluation, report per-class metrics, and return “Unclassified” when evidence is insufficient.",
        "output": "Separate UI fields for anomaly status and predicted attack family.",
    },
    {
        "number": "04",
        "area": "INCREMENTAL INGESTION",
        "status": "NEW ENGINEERING MODULE",
        "title": "Keep host history between batches",
        "summary": "The current inference path scores a supplied batch; it does not preserve rolling state across separate runs.",
        "current": "CSV inference and host-history features are implemented, but history is rebuilt from the input batch.",
        "next": "Add incremental batch ingestion and persist per-host timestamps/counters in SQLite. Handle duplicate and late records before scoring only newly arrived flows.",
        "output": "A local prototype that processes successive batches without losing host context.",
    },
]

def render_card(item: dict) -> str:
    return f"""
    <div class="fs-card">
      <div class="fs-card-head">
        <div class="fs-card-index">{escape(item['number'])} / {escape(item['area'])}</div>
        <div class="fs-card-status">{escape(item['status'])}</div>
      </div>
      <div class="fs-card-title">{escape(item['title'])}</div>
      <div class="fs-card-summary">{escape(item['summary'])}</div>
      <div class="fs-card-grid">
        <div class="fs-card-panel">
          <div class="fs-label">In the project now</div>
          <div class="fs-card-text">{escape(item['current'])}</div>
        </div>
        <div class="fs-card-panel">
          <div class="fs-label">Next engineering step</div>
          <div class="fs-card-text">{escape(item['next'])}</div>
        </div>
      </div>
      <div class="fs-output"><b>EXPECTED OUTPUT</b><br>{escape(item['output'])}</div>
    </div>
    """

for start in (0, 2):
    left, right = st.columns(2, gap="medium")
    with left:
        st.markdown(render_card(roadmap[start]), unsafe_allow_html=True)
    with right:
        st.markdown(render_card(roadmap[start + 1]), unsafe_allow_html=True)

# ---------------------------------------------------------------------
# Build order — validation first, new features after evidence.
# ---------------------------------------------------------------------
st.markdown("### Recommended build order")
st.caption("Validate the current pipeline before expanding its capabilities.")
priorities = [
    ("PRIORITY 1", "Temporal evaluation", "Complete the experiment that already has code."),
    ("PRIORITY 2", "Incident review", "Check event-group quality against analyst labels."),
    ("PRIORITY 3", "Attack-family model", "Add classification as a separate ML component."),
    ("PRIORITY 4", "Persistent batches", "Introduce stateful ingestion after batch behaviour is trusted."),
]
priority_cols = st.columns(4)
for col, (number, title, description) in zip(priority_cols, priorities):
    with col:
        st.markdown(
            f'<div class="fs-priority"><div class="fs-priority-num">{number}</div>'
            f'<div class="fs-priority-title">{escape(title)}</div>'
            f'<div class="fs-priority-copy">{escape(description)}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown(
    """
    <div class="fs-boundary">
      <b>Out of scope for this roadmap:</b> automatic blocking, guaranteed zero-day detection,
      autonomous response and production-grade live monitoring. None is supported by the current implementation.
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption("Proposed work only. The roadmap does not describe completed capabilities.")
