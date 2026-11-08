import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Investigation",
    layout="wide"
)


# ============================================================
# STYLING
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

.smallcaps {
    color: #6f9fc8;
    font-size: 0.70rem;
    font-weight: 800;
    letter-spacing: 0.18em;
    text-transform: uppercase;
}

.subtitle {
    color: #8190a3;
    font-size: 1rem;
}

.rule {
    height: 1px;
    background: #1c2938;
    margin: 30px 0;
}

.card {
    background: #0e1722;
    border: 1px solid #26374b;
    border-radius: 14px;
    padding: 20px;
    min-height: 150px;
}

.value {
    font-size: 1.5rem;
    font-weight: 800;
    margin: 8px 0;
}

.desc {
    color: #718196;
    font-size: 0.8rem;
}

.callout {
    border: 1px solid #234c6a;
    border-left: 3px solid #49a8ff;
    background: #0b1824;
    border-radius: 10px;
    padding: 16px;
    color: #91abc1;
}

.agent-card {
    background: #0e1722;
    border: 1px solid #26374b;
    border-radius: 14px;
    padding: 22px;
    min-height: 170px;
}

.agent-title {
    color: #edf3fa;
    font-size: 1rem;
    font-weight: 800;
    margin-top: 10px;
}

.agent-text {
    color: #718196;
    font-size: 0.82rem;
    line-height: 1.6;
    margin-top: 8px;
}

.finding {
    background: #0b121b;
    border: 1px solid #1d2b3a;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 12px;
}

.step-row {
    display: flex;
    gap: 18px;
    padding: 16px 0;
    border-bottom: 1px solid #182432;
}

.step-number {
    color: #49a8ff;
    font-size: 0.72rem;
    font-weight: 800;
    min-width: 30px;
}

.step-title {
    color: #edf3fa;
    font-weight: 800;
}

</style>
""",
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ CyberSentinel")
    st.caption("ML-Based Cyber Attack Detection")

    st.divider()

    st.page_link(
        "app.py",
        label="Dashboard",
    )

    st.page_link(
        "pages/attack_detection.py",
        label="Attack Detection",
    )

    st.markdown("**INVESTIGATION**")

    st.page_link(
        "pages/incident_investigation.py",
        label="Incident Investigation",
    )

    st.page_link(
        "pages/attack_graph.py",
        label="Attack Graph",
    )

    st.page_link(
        "pages/risk_assessment.py",
        label="Risk Assessment",
    )

    # st.page_link(
    #     "pages/ai_investigation.py",
    #     label="AI Investigation",
    # )


# ============================================================
# PAGE HEADER
# ============================================================

st.markdown(
    '<div class="smallcaps">CYBERSENTINEL INVESTIGATION</div>',
    unsafe_allow_html=True
)

st.title("AI Investigation")

st.markdown(
    '<div class="subtitle">Evidence-backed investigation workspace for the agentic AI layer.</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div style="margin:16px 0;color:#8fd7ff;font-weight:800;">● INVESTIGATION AGENT READY</div>',
    unsafe_allow_html=True
)


# ============================================================
# AGENT OVERVIEW
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="smallcaps">AGENTIC INVESTIGATION</div>',
    unsafe_allow_html=True
)

st.markdown("## Investigation Workspace")

cols = st.columns(3)

agent_cards = [
    (
        "Evidence Analysis",
        "Analyze correlated incident evidence including suspicious flows, events and attack graph relationships."
    ),
    (
        "Event Correlation",
        "Use reconstructed relationships and temporal context to understand how an incident developed."
    ),
    (
        "Evidence-backed Findings",
        "Produce traceable investigation findings based on the evidence available from earlier pipeline stages."
    ),
]

for col, (title, description) in zip(cols, agent_cards):

    card_html = (
        '<div class="agent-card">'
        f'<div class="agent-title">{title}</div>'
        f'<div class="agent-text">{description}</div>'
        '</div>'
    )

    with col:
        st.markdown(
            card_html,
            unsafe_allow_html=True
        )


# ============================================================
# SELECT INCIDENT
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="smallcaps">INVESTIGATION CASE</div>',
    unsafe_allow_html=True
)

st.markdown("## Select Incident")

incident = st.selectbox(
    "Incident",
    [
        "INC-001 — Multi-stage network activity",
        "INC-002 — Repeated anomalous connection pattern",
        "INC-003 — Suspicious service interaction",
        "INC-004 — Repeated attack traffic",
    ]
)


# ============================================================
# INVESTIGATION STATUS
# ============================================================

status_html = (
    '<div class="callout" style="margin-top:15px;">'
    '<div class="smallcaps">SELECTED CASE</div>'
    f'<div style="color:#edf3fa;font-weight:800;margin-top:8px;">{incident}</div>'
    '<div class="desc" style="margin-top:12px;">'
    'The agentic investigation workspace is prepared to receive '
    'the finalized incident, risk and attack graph outputs.'
    '</div>'
    '</div>'
)

st.markdown(
    status_html,
    unsafe_allow_html=True
)


# ============================================================
# EVIDENCE INVENTORY
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="smallcaps">EVIDENCE INVENTORY</div>',
    unsafe_allow_html=True
)

st.markdown("## Available Investigation Evidence")

evidence = [
    (
        "01",
        "Suspicious Network Flows",
        "Flows flagged as anomalous by the Isolation Forest detection stage."
    ),
    (
        "02",
        "Correlated Attack Events",
        "Related suspicious flows grouped into higher-level attack events."
    ),
    (
        "03",
        "Attack Graph",
        "Source hosts, target hosts, attack types and event relationships."
    ),
    (
        "04",
        "Temporal Relationships",
        "Ordering and timing relationships between correlated events."
    ),
    (
        "05",
        "Risk Assessment",
        "Incident-level risk information produced from available evidence."
    ),
]

for number, title, description in evidence:

    evidence_html = (
        '<div class="finding">'
        '<div style="display:flex;gap:15px;">'
        f'<div style="color:#49a8ff;font-size:0.72rem;font-weight:800;min-width:28px;">{number}</div>'
        '<div>'
        f'<div style="color:#edf3fa;font-weight:800;">{title}</div>'
        f'<div class="desc" style="margin-top:6px;">{description}</div>'
        '</div>'
        '</div>'
        '</div>'
    )

    st.markdown(
        evidence_html,
        unsafe_allow_html=True
    )


# ============================================================
# INVESTIGATION FINDINGS
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="smallcaps">AGENT OUTPUT</div>',
    unsafe_allow_html=True
)

st.markdown("## Investigation Findings")

st.markdown(
    """
    <div class="callout">

        <div class="smallcaps">
            AGENT STATUS
        </div>

        <div style="
            color:#edf3fa;
            font-weight:800;
            margin-top:8px;
        ">
            Awaiting finalized investigation backend
        </div>

        <div class="desc" style="margin-top:10px;">
            The interface is ready for evidence-backed findings
            generated from the reconstructed incident. Final
            findings will be connected once the agentic investigation
            layer is implemented.
        </div>

    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# INVESTIGATION PIPELINE
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="smallcaps">INVESTIGATION PIPELINE</div>',
    unsafe_allow_html=True
)

st.markdown("## How the Agent Investigates")

steps = [
    (
        "01",
        "Receive Incident",
        "The agent receives a correlated incident and its supporting evidence."
    ),
    (
        "02",
        "Inspect Evidence",
        "Suspicious flows, attack events, timestamps and graph relationships are examined."
    ),
    (
        "03",
        "Reconstruct Activity",
        "The available evidence is organized into a chronological incident narrative."
    ),
    (
        "04",
        "Generate Findings",
        "The agent produces evidence-backed observations about the reconstructed activity."
    ),
    (
        "05",
        "Trace Evidence",
        "Findings remain connected to the underlying evidence used during investigation."
    ),
]

for number, title, description in steps:

    step_html = (
        '<div class="step-row">'
        f'<div class="step-number">{number}</div>'
        '<div>'
        f'<div class="step-title">{title}</div>'
        f'<div class="desc" style="margin-top:5px;">{description}</div>'
        '</div>'
        '</div>'
    )

    st.markdown(
        step_html,
        unsafe_allow_html=True
    )


# ============================================================
# BACKEND STATUS
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="callout">'
    '<b>Backend connection:</b> '
    'The AI investigation interface is prepared for the finalized '
    'incident, risk and attack graph outputs. The findings shown here '
    'are interface placeholders and are not being presented as '
    'completed agentic analysis.'
    '</div>',
    unsafe_allow_html=True
)