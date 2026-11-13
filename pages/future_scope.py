from __future__ import annotations

from html import escape

import streamlit as st


st.set_page_config(
    page_title="CyberSentinel | Future Scope",
    page_icon="🧭",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background:#070b11; color:#edf3fa; }
    [data-testid="stSidebar"] { background:#0b121c; border-right:1px solid #1d2b3c; }
    .block-container { max-width:1450px; padding-top:1.7rem; padding-bottom:3rem; }

    .fs-kicker { color:#6f9fc8; font-size:.67rem; font-weight:850; letter-spacing:.16em; text-transform:uppercase; }
    .fs-hero {
        padding:23px 25px; border:1px solid #263b51; border-radius:15px;
        background:radial-gradient(circle at 90% 0%,rgba(73,168,255,.14),transparent 36%),#0b141f;
    }
    .fs-hero-title { color:#f0f6ff; font-size:1.45rem; line-height:1.25; font-weight:850; }
    .fs-hero-copy { color:#9aabbe; font-size:.86rem; line-height:1.5; margin-top:7px; max-width:850px; }

    .fs-flow {
        padding:13px 14px; border-radius:11px; border:1px solid #26374b;
        background:linear-gradient(145deg,#0f1823,#0b121b); min-height:83px;
    }
    .fs-flow-no { color:#6f9fc8; font-size:.64rem; font-weight:850; letter-spacing:.12em; }
    .fs-flow-name { color:#edf4fc; font-size:.86rem; font-weight:800; margin-top:7px; }
    .fs-flow-detail { color:#8495a9; font-size:.72rem; margin-top:3px; line-height:1.4; }

    div[data-testid="stTabs"] button {
        color:#aab9ca; font-weight:750; font-size:.8rem;
    }
    div[data-testid="stTabs"] button[aria-selected="true"] {
        color:#d9edff;
    }
    .fs-feature {
        border:1px solid #2a4055; border-radius:14px; padding:19px 20px;
        background:linear-gradient(145deg,#0f1a26,#0b131d);
    }
    .fs-feature-top { color:#75a6d2; font-size:.65rem; font-weight:850; letter-spacing:.14em; }
    .fs-feature-title { color:#f1f6fc; font-size:1.25rem; line-height:1.3; font-weight:850; margin-top:7px; }
    .fs-feature-sub { color:#98aabd; font-size:.82rem; line-height:1.5; margin-top:7px; }
    .fs-panels { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:17px; }
    .fs-panel { border:1px solid #26394d; background:#0a131d; border-radius:10px; padding:13px 14px; min-height:125px; }
    .fs-panel-label { color:#7898b7; font-size:.64rem; font-weight:850; letter-spacing:.12em; text-transform:uppercase; margin-bottom:8px; }
    .fs-panel-copy { color:#d4deea; font-size:.81rem; line-height:1.55; }
    .fs-example {
        margin-top:13px; padding:12px 14px; border-left:3px solid #4c9de0;
        border-radius:7px; background:#0b1723; color:#b6c5d5; font-size:.8rem; line-height:1.5;
    }
    .fs-example b { color:#91c8f2; }
    .fs-result { color:#a6d8c0; font-size:.8rem; line-height:1.45; margin-top:13px; }
    .fs-result b { color:#70c99e; font-size:.64rem; letter-spacing:.1em; }

    .fs-order {
        border:1px solid #26374b; border-radius:10px; padding:13px;
        background:#0d1722; min-height:82px;
    }
    .fs-order-no { color:#6f9fc8; font-size:.63rem; font-weight:850; letter-spacing:.12em; }
    .fs-order-name { color:#eaf2fb; font-size:.82rem; font-weight:800; margin-top:7px; }
    .fs-order-copy { color:#8192a6; font-size:.71rem; line-height:1.4; margin-top:4px; }

    .fs-foot { color:#899bad; font-size:.76rem; line-height:1.5; border-top:1px solid #223144; padding-top:12px; }
    @media(max-width:800px) {
        .fs-panels { grid-template-columns:1fr; }
        .fs-panel { min-height:0; }
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

# Header
st.markdown('<div class="fs-kicker">CYBERSENTINEL · WHAT&#39;S NEXT</div>', unsafe_allow_html=True)
st.title("Future Scope")
st.markdown(
    """
    <div class="fs-hero">
      <div class="fs-hero-title">What should we improve next?</div>
      <div class="fs-hero-copy">
        Today, CyberSentinel checks traffic from uploaded files and helps investigate
        suspicious activity. These are four sensible next steps—not features already built.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Present-day flow
st.markdown("### What works today")
flow = [
    ("01", "Upload traffic", "Choose a CSV file"),
    ("02", "Find unusual flows", "Isolation Forest"),
    ("03", "Group activity", "Events and graph"),
    ("04", "Review", "Risk and AI evidence"),
]
flow_cols = st.columns(4, gap="small")
for col, (number, title, detail) in zip(flow_cols, flow):
    with col:
        st.markdown(
            f'<div class="fs-flow"><div class="fs-flow-no">{number}</div>'
            f'<div class="fs-flow-name">{escape(title)}</div>'
            f'<div class="fs-flow-detail">{escape(detail)}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown("### Pick an improvement")
st.caption("Open a topic to see what we have, what needs to change, and a simple example.")

roadmap = [
    {
        "tab": "01 · Better alerts",
        "area": "DETECTION",
        "title": "Check if detection works on other days",
        "intro": "A setting that works today may create too many false alerts tomorrow.",
        "now": "Isolation Forest already marks unusual traffic. We also have a script to test it using dates.",
        "next": "Run the test on several days. Try different alert settings and count normal traffic flagged by mistake, along with attacks the model misses.",
        "example": "The same setting gives few false alerts on Monday but many on Tuesday. We need to know that before trusting it.",
        "result": "A simple comparison showing which alert setting stays more reliable on later days.",
    },
    {
        "tab": "02 · Better groups",
        "area": "INVESTIGATION",
        "title": "Check whether grouped events belong together",
        "intro": "The system connects events, but a connection does not prove they are one incident.",
        "now": "Suspicious flows are already grouped into events. Events can be linked when they share a host and happen close in time.",
        "next": "Ask a reviewer to check a sample and mark each pair as related or unrelated. Compare those answers with the groups made by the system.",
        "example": "Two events from the same computer, but hours apart, may have nothing to do with each other.",
        "result": "A way to show which groups make sense and which links need fixing.",
    },
    {
        "tab": "03 · Name the attack",
        "area": "DETECTION",
        "title": "Show what type of attack it might be",
        "intro": "Finding unusual traffic and naming an attack are two different jobs.",
        "now": "Isolation Forest can flag a flow as unusual. It cannot tell us whether it is DDoS, a port scan or brute force.",
        "next": "Train a second model using labelled attack examples. Test it on data it has never seen, and show 'Unknown' when its result is not reliable.",
        "example": "The first model says 'unusual'. The second may say 'DDoS'. If it cannot make a reliable choice, show 'Unknown'.",
        "result": "The screen can show both: 'Unusual traffic' and 'Possible attack type'.",
    },
    {
        "tab": "04 · Remember traffic",
        "area": "DATA INPUT",
        "title": "Let the next file remember the last one",
        "intro": "Right now, each uploaded batch is handled on its own.",
        "now": "The system can use host activity inside a CSV, but it does not keep that history for the next separate run.",
        "next": "Save recent host activity after each batch. When a new file arrives, use the saved history while checking only the new rows.",
        "example": "File 2 arrives after File 1. The system should still remember what each host was doing in File 1.",
        "result": "A small working demo that can process one new batch after another without losing host history.",
    },
]

tabs = st.tabs([item["tab"] for item in roadmap])
for tab, item in zip(tabs, roadmap):
    with tab:
        st.markdown(
            f"""
            <div class="fs-feature">
              <div class="fs-feature-top">{escape(item['area'])} · FUTURE WORK</div>
              <div class="fs-feature-title">{escape(item['title'])}</div>
              <div class="fs-feature-sub">{escape(item['intro'])}</div>
              <div class="fs-panels">
                <div class="fs-panel">
                  <div class="fs-panel-label">Already in the project</div>
                  <div class="fs-panel-copy">{escape(item['now'])}</div>
                </div>
                <div class="fs-panel">
                  <div class="fs-panel-label">What we will add</div>
                  <div class="fs-panel-copy">{escape(item['next'])}</div>
                </div>
              </div>
              <div class="fs-example"><b>Example</b><br>{escape(item['example'])}</div>
              <div class="fs-result"><b>YOU WILL GET</b><br>{escape(item['result'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Build order
st.markdown("### In what order?")
st.caption("First check the parts we already have. Then add new features.")
order = [
    ("FIRST", "Test detection", "Check it on different days."),
    ("SECOND", "Review event groups", "See whether related events are grouped correctly."),
    ("THIRD", "Add attack type", "Train and test a separate model."),
    ("FOURTH", "Remember past batches", "Keep host history between files."),
]
order_cols = st.columns(4, gap="small")
for col, (number, title, detail) in zip(order_cols, order):
    with col:
        st.markdown(
            f'<div class="fs-order"><div class="fs-order-no">{number}</div>'
            f'<div class="fs-order-name">{escape(title)}</div>'
            f'<div class="fs-order-copy">{escape(detail)}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown(
    """
    <div class="fs-foot">
      These are planned improvements. CyberSentinel does not currently block attacks,
      respond on its own, or monitor a live network continuously.
    </div>
    """,
    unsafe_allow_html=True,
)
