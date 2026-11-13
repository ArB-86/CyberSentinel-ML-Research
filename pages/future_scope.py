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
    .stApp {
        background: #070b11;
        color: #edf3fa;
    }
    .block-container {
        max-width: 1500px;
        padding-top: 1.8rem;
        padding-bottom: 3rem;
    }
    [data-testid="stSidebar"] {
        background: #0b121c;
        border-right: 1px solid #1d2b3c;
    }
    .fs-kicker {
        color: #6f9fc8;
        font-size: .68rem;
        font-weight: 800;
        letter-spacing: .16em;
        text-transform: uppercase;
    }
    .fs-hero {
        position: relative;
        overflow: hidden;
        padding: 25px 27px;
        border: 1px solid #263b51;
        border-radius: 16px;
        background:
            radial-gradient(circle at 88% 5%, rgba(73,168,255,.17), transparent 31%),
            linear-gradient(120deg, #0d1926, #0a121c 72%);
    }
    .fs-hero-title {
        color: #f1f6fc;
        font-size: 1.55rem;
        font-weight: 850;
        line-height: 1.2;
        max-width: 760px;
    }
    .fs-hero-copy {
        color: #9aabbe;
        font-size: .88rem;
        line-height: 1.55;
        max-width: 760px;
        margin-top: 9px;
    }
    .fs-hero-tag {
        display: inline-block;
        margin-top: 16px;
        padding: 6px 10px;
        border: 1px solid #28506d;
        border-radius: 7px;
        background: #0b1a27;
        color: #91cfff;
        font-size: .66rem;
        font-weight: 800;
        letter-spacing: .1em;
    }

    .fs-section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin: 27px 0 12px;
    }
    .fs-section-title {
        color: #eaf2fb;
        font-size: 1rem;
        font-weight: 800;
    }
    .fs-section-note {
        color: #71849a;
        font-size: .72rem;
    }

    .fs-pipeline {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 10px;
    }
    .fs-pipeline-step {
        position: relative;
        min-height: 91px;
        padding: 14px 15px;
        border: 1px solid #26374b;
        border-radius: 11px;
        background: linear-gradient(145deg, #101b28, #0b131d);
    }
    .fs-pipeline-step:not(:last-child):after {
        content: "›";
        position: absolute;
        z-index: 2;
        top: 29px;
        right: -11px;
        width: 13px;
        color: #5b91bd;
        font-size: 1.35rem;
        font-weight: 800;
        text-align: center;
    }
    .fs-pipeline-num {
        color: #609fd2;
        font-size: .63rem;
        font-weight: 850;
        letter-spacing: .12em;
    }
    .fs-pipeline-name {
        color: #edf4fc;
        font-size: .86rem;
        font-weight: 800;
        margin-top: 7px;
    }
    .fs-pipeline-sub {
        color: #8192a6;
        font-size: .72rem;
        line-height: 1.4;
        margin-top: 3px;
    }

    .fs-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 15px;
    }
    .fs-card {
        position: relative;
        overflow: hidden;
        min-width: 0;
        padding: 19px 20px 17px;
        border: 1px solid #293e53;
        border-radius: 14px;
        background: linear-gradient(145deg, #101b28 0%, #0b131d 78%);
        box-shadow: 0 8px 24px rgba(0,0,0,.13);
    }
    .fs-card:before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, #4b9de0, transparent 76%);
    }
    .fs-card-head {
        display: flex;
        align-items: center;
        gap: 11px;
    }
    .fs-card-num {
        display: flex;
        align-items: center;
        justify-content: center;
        flex: 0 0 37px;
        height: 37px;
        border: 1px solid #315675;
        border-radius: 10px;
        background: #0b1c2b;
        color: #8bc8f3;
        font-size: .78rem;
        font-weight: 850;
    }
    .fs-card-kind {
        color: #79a7ce;
        font-size: .62rem;
        font-weight: 850;
        letter-spacing: .13em;
    }
    .fs-card-state {
        margin-left: auto;
        padding: 5px 8px;
        border: 1px solid #34485b;
        border-radius: 6px;
        color: #a6b5c5;
        font-size: .58rem;
        font-weight: 800;
        letter-spacing: .08em;
        white-space: nowrap;
    }
    .fs-card-title {
        color: #f0f5fb;
        font-size: 1.08rem;
        line-height: 1.3;
        font-weight: 850;
        margin-top: 14px;
    }
    .fs-card-summary {
        min-height: 40px;
        color: #91a2b5;
        font-size: .79rem;
        line-height: 1.48;
        margin-top: 6px;
    }
    .fs-mini-flow {
        display: flex;
        align-items: center;
        gap: 6px;
        margin: 15px 0 14px;
    }
    .fs-mini-node {
        flex: 1 1 0;
        min-width: 0;
        padding: 9px 7px;
        border: 1px solid #263c51;
        border-radius: 8px;
        background: #0a141f;
        color: #c8d7e6;
        font-size: .68rem;
        font-weight: 750;
        line-height: 1.3;
        text-align: center;
    }
    .fs-mini-arrow {
        flex: 0 0 auto;
        color: #528dbb;
        font-size: .9rem;
        font-weight: 800;
    }
    .fs-card-details {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
    }
    .fs-detail {
        min-width: 0;
        padding: 11px 12px;
        border: 1px solid #25384a;
        border-radius: 9px;
        background: rgba(7, 15, 24, .58);
    }
    .fs-detail-label {
        color: #789bb9;
        font-size: .6rem;
        font-weight: 850;
        letter-spacing: .12em;
        margin-bottom: 6px;
    }
    .fs-detail-copy {
        color: #cbd7e3;
        font-size: .75rem;
        line-height: 1.5;
    }
    .fs-output {
        display: flex;
        gap: 9px;
        align-items: flex-start;
        margin-top: 12px;
        padding: 10px 12px;
        border: 1px solid #24483e;
        border-radius: 9px;
        background: #0b1918;
        color: #a9d9c2;
        font-size: .75rem;
        line-height: 1.45;
    }
    .fs-output-label {
        flex: 0 0 auto;
        color: #70c99e;
        font-size: .59rem;
        font-weight: 850;
        letter-spacing: .1em;
        padding-top: 2px;
    }

    .fs-build {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 10px;
    }
    .fs-build-step {
        display: flex;
        align-items: center;
        gap: 10px;
        min-height: 66px;
        padding: 11px 12px;
        border: 1px solid #26374b;
        border-radius: 10px;
        background: #0d1722;
    }
    .fs-build-num {
        display: flex;
        flex: 0 0 29px;
        align-items: center;
        justify-content: center;
        width: 29px;
        height: 29px;
        border-radius: 50%;
        background: #10263a;
        color: #8bc8f3;
        font-size: .7rem;
        font-weight: 850;
    }
    .fs-build-name {
        color: #e6eef7;
        font-size: .76rem;
        font-weight: 800;
        line-height: 1.3;
    }
    .fs-note {
        margin-top: 19px;
        padding-top: 12px;
        border-top: 1px solid #223144;
        color: #8192a6;
        font-size: .72rem;
        line-height: 1.5;
    }

    @media (max-width: 900px) {
        .fs-grid { grid-template-columns: 1fr; }
        .fs-card-summary { min-height: 0; }
    }
    @media (max-width: 650px) {
        .fs-pipeline, .fs-build { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .fs-pipeline-step:after { display: none; }
        .fs-card-details { grid-template-columns: 1fr; }
        .fs-card-state { font-size: .53rem; }
        .fs-hero { padding: 20px; }
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

st.markdown('<div class="fs-kicker">PROJECT ROADMAP</div>', unsafe_allow_html=True)
st.title("Future Scope")

st.markdown(
    """
    <div class="fs-hero">
      <div class="fs-hero-title">Make detection more reliable. Then make it smarter.</div>
      <div class="fs-hero-copy">
        Four changes: improve alerts, check event groups, identify attack types,
        and carry host history from one file to the next.
      </div>
      <div class="fs-hero-tag">4 PLANNED IMPROVEMENTS · NOT BUILT YET</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">CyberSentinel today</div>
      <div class="fs-section-note">Current app flow</div>
    </div>
    <div class="fs-pipeline">
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">01</div>
        <div class="fs-pipeline-name">Traffic file</div>
        <div class="fs-pipeline-sub">Upload network flows</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">02</div>
        <div class="fs-pipeline-name">Find unusual flows</div>
        <div class="fs-pipeline-sub">Isolation Forest</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">03</div>
        <div class="fs-pipeline-name">Connect events</div>
        <div class="fs-pipeline-sub">Time and shared hosts</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">04</div>
        <div class="fs-pipeline-name">Investigate</div>
        <div class="fs-pipeline-sub">Risk and AI evidence</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

roadmap = [
    {
        "num": "01",
        "kind": "DETECTION",
        "state": "EXISTING TEST",
        "title": "Alerts that work on different days",
        "summary": "An alert setting may work well one day and create too many false alerts the next.",
        "flow": ["Past days", "Test alert settings", "Count mistakes"],
        "today": "Isolation Forest and a date-based test script are already in the project.",
        "next": "Run the test across several time periods. Count normal traffic flagged by mistake and attacks missed.",
        "output": "See which alert setting stays reliable on later days.",
    },
    {
        "num": "02",
        "kind": "INVESTIGATION",
        "state": "REVIEW NEEDED",
        "title": "Event groups that make sense",
        "summary": "Events can be connected by host and time, but that does not prove they belong to one incident.",
        "flow": ["System groups events", "Reviewer checks", "Fix weak links"],
        "today": "The project already groups suspicious flows and connects related events.",
        "next": "Have a reviewer mark sample event pairs as related or unrelated. Check where the system joins the wrong events or misses a link.",
        "output": "Know how often the event groups match a human review.",
    },
    {
        "num": "03",
        "kind": "ATTACK DETECTION",
        "state": "NEW MODEL",
        "title": "Show the likely attack type",
        "summary": "The current model says a flow is unusual. It does not name the attack.",
        "flow": ["Unusual flow", "Second model", "DDoS / Scan / Unknown"],
        "today": "Isolation Forest flags unusual traffic; it does not classify DDoS, port scans or brute force.",
        "next": "Train a separate model on labelled examples. Test each attack type and show 'Unknown' when the result is weak.",
        "output": "Show 'Unusual' and 'Possible attack type' as two separate results.",
    },
    {
        "num": "04",
        "kind": "DATA INPUT",
        "state": "NEW MODULE",
        "title": "Remember activity from earlier files",
        "summary": "Host history is available inside one file, but it is not kept for the next run.",
        "flow": ["File 1", "Save host history", "File 2"],
        "today": "The current batch can build host history, but a separate run starts without that saved history.",
        "next": "Save recent host activity after each file and use it when scoring only the new rows. Avoid processing duplicate rows twice.",
        "output": "A working demo that keeps host context across files.",
    },
]

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">What to build next</div>
      <div class="fs-section-note">Current work → next change → result</div>
    </div>
    """,
    unsafe_allow_html=True,
)

cards_html = ['<div class="fs-grid">']
for item in roadmap:
    flow_html = (
        f'<div class="fs-mini-node">{escape(item["flow"][0])}</div>'
        f'<div class="fs-mini-arrow">›</div>'
        f'<div class="fs-mini-node">{escape(item["flow"][1])}</div>'
        f'<div class="fs-mini-arrow">›</div>'
        f'<div class="fs-mini-node">{escape(item["flow"][2])}</div>'
    )
    cards_html.append(
        f"""
        <section class="fs-card">
          <div class="fs-card-head">
            <div class="fs-card-num">{escape(item["num"])}</div>
            <div class="fs-card-kind">{escape(item["kind"])}</div>
            <div class="fs-card-state">{escape(item["state"])}</div>
          </div>
          <div class="fs-card-title">{escape(item["title"])}</div>
          <div class="fs-card-summary">{escape(item["summary"])}</div>
          <div class="fs-mini-flow">{flow_html}</div>
          <div class="fs-card-details">
            <div class="fs-detail">
              <div class="fs-detail-label">ALREADY HERE</div>
              <div class="fs-detail-copy">{escape(item["today"])}</div>
            </div>
            <div class="fs-detail">
              <div class="fs-detail-label">NEXT CHANGE</div>
              <div class="fs-detail-copy">{escape(item["next"])}</div>
            </div>
          </div>
          <div class="fs-output">
            <span class="fs-output-label">RESULT</span>
            <span>{escape(item["output"])}</span>
          </div>
        </section>
        """
    )
cards_html.append("</div>")
st.markdown("".join(cards_html), unsafe_allow_html=True)

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">Build order</div>
    </div>
    <div class="fs-build">
      <div class="fs-build-step">
        <div class="fs-build-num">1</div>
        <div class="fs-build-name">Test detection</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">2</div>
        <div class="fs-build-name">Review event groups</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">3</div>
        <div class="fs-build-name">Add attack type</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">4</div>
        <div class="fs-build-name">Keep host history</div>
      </div>
    </div>
    <div class="fs-note">
      These are planned changes. The current app does not block attacks or monitor a live network continuously.
    </div>
    """,
    unsafe_allow_html=True,
)
