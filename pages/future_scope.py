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

    .fs-limits {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
    }
    .fs-limit {
        display: flex;
        align-items: flex-start;
        gap: 11px;
        min-width: 0;
        padding: 12px 13px;
        border: 1px solid #26374b;
        border-radius: 10px;
        background: #0d1722;
    }
    .fs-limit-num {
        display: flex;
        flex: 0 0 27px;
        align-items: center;
        justify-content: center;
        width: 27px;
        height: 27px;
        border-radius: 8px;
        background: #172333;
        color: #91a9c1;
        font-size: .65rem;
        font-weight: 850;
    }
    .fs-limit-title {
        color: #e6eef7;
        font-size: .78rem;
        font-weight: 800;
        line-height: 1.3;
    }
    .fs-limit-copy {
        color: #91a2b5;
        font-size: .72rem;
        line-height: 1.45;
        margin-top: 4px;
    }

    .fs-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 15px;
    }
    .fs-card {
        box-sizing: border-box;
        position: relative;
        display: block;
        width: 100%;
        min-width: 0;
        height: 100%;
        padding: 19px 20px 17px;
        overflow: hidden;
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
        gap: 10px;
        min-width: 0;
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
        min-width: 0;
        color: #79a7ce;
        font-size: .62rem;
        font-weight: 850;
        letter-spacing: .11em;
        line-height: 1.3;
        overflow-wrap: anywhere;
    }
    .fs-card-state {
        flex: 0 0 auto;
        margin-left: auto;
        padding: 5px 8px;
        border: 1px solid #34485b;
        border-radius: 6px;
        color: #a6b5c5;
        font-size: .57rem;
        font-weight: 800;
        letter-spacing: .06em;
        line-height: 1.2;
        text-align: center;
        white-space: normal;
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
        align-items: stretch;
        gap: 6px;
        width: 100%;
        margin: 15px 0 14px;
    }
    .fs-mini-node {
        display: flex;
        flex: 1 1 0;
        align-items: center;
        justify-content: center;
        min-width: 0;
        min-height: 43px;
        padding: 8px 6px;
        border: 1px solid #263c51;
        border-radius: 8px;
        background: #0a141f;
        color: #c8d7e6;
        font-size: .66rem;
        font-weight: 750;
        line-height: 1.3;
        text-align: center;
        overflow-wrap: anywhere;
    }
    .fs-mini-arrow {
        flex: 0 0 auto;
        color: #528dbb;
        font-size: .9rem;
        font-weight: 800;
    }
    .fs-card-details {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        align-items: stretch;
        gap: 10px;
        width: 100%;
    }
    .fs-detail {
        box-sizing: border-box;
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
        font-size: .74rem;
        line-height: 1.5;
        overflow-wrap: anywhere;
    }
    .fs-output {
        display: flex;
        gap: 9px;
        align-items: flex-start;
        min-width: 0;
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
        grid-template-columns: repeat(5, minmax(0, 1fr));
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

    @media (max-width: 650px) {
        .fs-pipeline, .fs-build { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .fs-pipeline-step:after { display: none; }
        .fs-card { padding: 16px 14px; }
        .fs-card-details { grid-template-columns: 1fr; }
        .fs-limits { grid-template-columns: 1fr; }
        .fs-card-summary { min-height: 0; }
        .fs-card-state { font-size: .52rem; padding: 4px 6px; }
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
        First prove that detection and event grouping are reliable. Then add attack-type
        identification, saved history across batches, and continuous flow monitoring.
      </div>
      <div class="fs-hero-tag">5 PRACTICAL IMPROVEMENTS · FUTURE WORK</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">What the project does today</div>
      <div class="fs-section-note">Current system</div>
    </div>
    <div class="fs-pipeline">
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">01</div>
        <div class="fs-pipeline-name">Traffic file</div>
        <div class="fs-pipeline-sub">Upload flow CSV files</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">02</div>
        <div class="fs-pipeline-name">Find unusual flows</div>
        <div class="fs-pipeline-sub">Isolation Forest model</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">03</div>
        <div class="fs-pipeline-name">Group related activity</div>
        <div class="fs-pipeline-sub">Time and shared hosts</div>
      </div>
      <div class="fs-pipeline-step">
        <div class="fs-pipeline-num">04</div>
        <div class="fs-pipeline-name">Review the activity</div>
        <div class="fs-pipeline-sub">Graph, risk and AI evidence</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">Current limitations</div>
      <div class="fs-section-note">The five main gaps we plan to fix</div>
    </div>
    <div class="fs-limits">
      <div class="fs-limit">
        <div class="fs-limit-num">01</div>
        <div>
          <div class="fs-limit-title">Needs more testing on new traffic</div>
          <div class="fs-limit-copy">A test using later dates exists, but full testing and testing on a separate network are still needed.</div>
        </div>
      </div>
      <div class="fs-limit">
        <div class="fs-limit-num">02</div>
        <div>
          <div class="fs-limit-title">Event groups are not verified</div>
          <div class="fs-limit-copy">The system links activity by time and host, but we have not yet proved that each group matches a real incident.</div>
        </div>
      </div>
      <div class="fs-limit">
        <div class="fs-limit-num">03</div>
        <div>
          <div class="fs-limit-title">Cannot identify the attack type</div>
          <div class="fs-limit-copy">The detector marks unusual traffic but cannot name it as DDoS, a port scan or brute force.</div>
        </div>
      </div>
      <div class="fs-limit">
        <div class="fs-limit-num">04</div>
        <div>
          <div class="fs-limit-title">History is not saved between batches</div>
          <div class="fs-limit-copy">Each run rebuilds host history from the files it receives. It does not automatically remember the previous run.</div>
        </div>
      </div>
      <div class="fs-limit">
        <div class="fs-limit-num">05</div>
        <div>
          <div class="fs-limit-title">No live network feed</div>
          <div class="fs-limit-copy">The app reads CSV files. It does not process new network-flow records as they arrive.</div>
        </div>
      </div>
    </div>
    <div class="fs-note">
      Risk scores are rule-based guidance, not attack probabilities. AI-assisted findings need human review; the system does not automatically block traffic.
    </div>
    """,
    unsafe_allow_html=True,
)

roadmap = [
    {
        "num": "01",
        "kind": "DETECTION VALIDATION",
        "state": "MORE TESTING",
        "title": "Test detection on different days and networks",
        "summary": "A detector may work on one dataset but make mistakes on traffic from another network.",
        "flow": ["Different days", "New network", "Measure errors"],
        "today": "A test using later dates exists, but full testing and testing on a separate network are still needed.",
        "next": "Test the full flow dataset across different days, then test a separate network dataset. Where possible, keep test hosts or attack scenarios out of training. Measure false alarms, missed attacks and results for each attack type.",
        "output": "Evidence of how well detection holds up on traffic the model has not seen.",
    },
    {
        "num": "02",
        "kind": "INCIDENT VALIDATION",
        "state": "REVIEW NEEDED",
        "title": "Check whether event groups are correct",
        "summary": "Putting events together does not prove that they belong to the same real incident.",
        "flow": ["Grouped events", "Compare with review", "Measure mistakes"],
        "today": "The system links events by time and shared hosts. These are possible relationships, not confirmed incidents.",
        "next": "Run grouping tests on the full dataset. Compare groups with known attack scenarios and examples checked by an analyst. Count events wrongly joined and related events kept apart.",
        "output": "Measured evidence of when event grouping works and where it needs improvement.",
    },
    {
        "num": "03",
        "kind": "ATTACK CLASSIFICATION",
        "state": "NEW MODEL",
        "title": "Identify the likely attack type",
        "summary": "The current detector finds unusual traffic but does not tell the analyst which attack it may be.",
        "flow": ["Unusual flow", "Classify traffic", "Type or unknown"],
        "today": "Isolation Forest flags unusual flows. There is no separate trained model that predicts an attack family.",
        "next": "Train a separate model using labelled examples. Measure results for each attack type and show 'Unknown' when the model is not confident.",
        "output": "Show the possible attack family separately from the unusual-traffic alert.",
    },
    {
        "num": "04",
        "kind": "INCREMENTAL BATCHES",
        "state": "NEW FEATURE",
        "title": "Keep host history between CSV batches",
        "summary": "A new batch should not need every old file just to remember recent host activity.",
        "flow": ["New CSV batch", "Load saved history", "Score new flows"],
        "today": "Host-history features are rebuilt from the files in one run. Recent host state is not saved between separate runs.",
        "next": "Save recent host activity after each run. For the next CSV, process only new rows, skip duplicates and handle records that arrive late.",
        "output": "Process successive CSV batches without replaying all previous files.",
    },
    {
        "num": "05",
        "kind": "LIVE MONITORING",
        "state": "NEW PIPELINE",
        "title": "Monitor live network traffic",
        "summary": "Move from analysing uploaded files to analysing new network-flow records as they arrive.",
        "flow": ["Live flow feed", "Score new flows", "Update dashboard"],
        "today": "There is no connected live flow source or continuous processing loop.",
        "next": "Connect a live flow source such as NetFlow, IPFIX or Zeek logs. Process each new record, reuse saved host history and update the dashboard and alerts.",
        "output": "A working prototype that displays suspicious activity as new flow records arrive.",
    },
]

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">Practical future scope</div>
      <div class="fs-section-note">Only work that closes a current project gap</div>
    </div>
    """,
    unsafe_allow_html=True,
)

def render_roadmap_card(item):
    flow_html = (
        f'<div class="fs-mini-node">{escape(item["flow"][0])}</div>'
        f'<div class="fs-mini-arrow">›</div>'
        f'<div class="fs-mini-node">{escape(item["flow"][1])}</div>'
        f'<div class="fs-mini-arrow">›</div>'
        f'<div class="fs-mini-node">{escape(item["flow"][2])}</div>'
    )
    return f"""
    <div class="fs-card">
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
          <div class="fs-detail-label">CURRENT LIMITATION</div>
          <div class="fs-detail-copy">{escape(item["today"])}</div>
        </div>
        <div class="fs-detail">
          <div class="fs-detail-label">WHAT WE WILL DO</div>
          <div class="fs-detail-copy">{escape(item["next"])}</div>
        </div>
      </div>
      <div class="fs-output">
        <span class="fs-output-label">BENEFIT</span>
        <span>{escape(item["output"])}</span>
      </div>
    </div>
    """


# Keep the fifth card centered so the final row stays balanced.
for row_start in range(0, len(roadmap), 2):
    row_items = roadmap[row_start:row_start + 2]
    if len(row_items) == 1:
        left, center, right = st.columns([1, 2, 1], gap="medium")
        with center:
            st.html(render_roadmap_card(row_items[0]))
    else:
        left, right = st.columns(2, gap="medium")
        with left:
            st.html(render_roadmap_card(row_items[0]))
        with right:
            st.html(render_roadmap_card(row_items[1]))

st.markdown(
    """
    <div class="fs-section-head">
      <div class="fs-section-title">Recommended build order</div>
      <div class="fs-section-note">Validation first, live operation last</div>
    </div>
    <div class="fs-build">
      <div class="fs-build-step">
        <div class="fs-build-num">1</div>
        <div class="fs-build-name">Validate detection</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">2</div>
        <div class="fs-build-name">Validate event groups</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">3</div>
        <div class="fs-build-name">Add attack type</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">4</div>
        <div class="fs-build-name">Save batch history</div>
      </div>
      <div class="fs-build-step">
        <div class="fs-build-num">5</div>
        <div class="fs-build-name">Connect live flows</div>
      </div>
    </div>
    <div class="fs-note">
      These five items are future work, not current features. Incremental batch processing comes before live monitoring because live monitoring needs saved, continuously updated host history.
    </div>
    """,
    unsafe_allow_html=True,
)
