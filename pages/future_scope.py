from __future__ import annotations

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
    .stApp { background:#070c13; color:#edf3fa; }
    [data-testid="stSidebar"] { background:#0b1420; border-right:1px solid #1e3042; }
    .block-container { max-width:1480px; padding-top:1.5rem; padding-bottom:3rem; }
    .eyebrow { color:#78a9d8; font-size:.68rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
    .muted { color:#8b9bb0; }
    .hero { border:1px solid #29435c; border-radius:16px; padding:23px; background:linear-gradient(115deg,#102033,#0d1724 62%,#0b121c); }
    .hero-title { font-size:1.65rem; font-weight:850; color:#f0f6ff; line-height:1.2; }
    .hero-copy { color:#a2b2c5; font-size:.88rem; line-height:1.6; margin-top:9px; max-width:980px; }
    .pill { display:inline-block; padding:5px 9px; margin:5px 5px 0 0; border-radius:20px; font-size:.68rem; font-weight:750; border:1px solid #35516b; background:#112438; color:#c3e2ff; }
    .stepbox { background:#0d1722; border:1px solid #26384b; border-radius:12px; padding:13px; min-height:110px; }
    .stepnum { color:#78a9d8; font-weight:850; font-size:.68rem; letter-spacing:.12em; }
    .steptitle { color:#eff6ff; font-weight:800; margin-top:6px; font-size:.88rem; }
    .stepcopy { color:#91a2b6; font-size:.73rem; line-height:1.45; margin-top:5px; }
    .scope-card { border:1px solid #27394c; border-radius:14px; padding:16px; background:linear-gradient(145deg,#0e1925,#0b131d); margin-bottom:12px; }
    .scope-top { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .scope-title { color:#eff6ff; font-size:1.02rem; font-weight:850; }
    .scope-status { display:inline-block; border:1px solid #31506a; background:#102337; color:#a9d4f5; border-radius:20px; padding:4px 9px; font-size:.66rem; font-weight:800; }
    .scope-label { font-size:.65rem; font-weight:850; letter-spacing:.12em; text-transform:uppercase; color:#8da0b5; margin-bottom:7px; }
    .scope-text { color:#d5dfeb; font-size:.81rem; line-height:1.52; }
    .scope-result { color:#9dd9bd; font-size:.8rem; line-height:1.5; font-weight:650; }
    .example { color:#aebdd0; background:#101d2a; border-left:3px solid #65a7ff; border-radius:7px; padding:10px 12px; font-size:.77rem; line-height:1.5; margin-top:12px; }
    div[data-testid="stMetric"] { background:#0e1722; border:1px solid #26384b; padding:11px 13px; border-radius:12px; }
    div[data-testid="stMetricLabel"] { color:#92a3b7; }
    div[data-testid="stMetricValue"] { color:#eff6ff; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel")
    st.divider()
    st.markdown('<div class="eyebrow">Overview</div>', unsafe_allow_html=True)
    st.page_link("app.py", label="Dashboard")
    st.markdown('<div class="eyebrow" style="margin-top:16px">Detection</div>', unsafe_allow_html=True)
    st.page_link("pages/attack_detection.py", label="Attack Detection")
    st.page_link("pages/model_selection.py", label="Model Selection & Evidence")
    st.markdown('<div class="eyebrow" style="margin-top:16px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Incident Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")
    st.markdown('<div class="eyebrow" style="margin-top:16px">Project</div>', unsafe_allow_html=True)
    st.page_link("pages/future_scope.py", label="Future Scope")

st.markdown('<div class="eyebrow">PROJECT ROADMAP · PRACTICAL NEXT STEPS</div>', unsafe_allow_html=True)
st.title("Future Scope")
st.markdown(
    """
    <div class="hero">
      <div class="hero-title">What CyberSentinel can become next</div>
      <div class="hero-copy">
        These are not random add-on features. Each item starts from something the project
        already does, shows what is missing today, and explains the specific improvement
        we can build next. Planned items are clearly separated from completed work.
      </div>
      <span class="pill">4 achievable improvements</span>
      <span class="pill">Built around the current codebase</span>
      <span class="pill">No claims of features that do not exist yet</span>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("### First, see the difference")
st.caption("The current system works in batches. The future work strengthens detection, adds one new prediction capability, and makes investigation outputs easier to trust.")
a,b,c,d=st.columns(4)
for col,num,title,copy in [
    (a,"01","Traffic comes in","A CSV/batch of network-flow records is analysed."),
    (b,"02","Suspicious flows","Isolation Forest flags unusual records."),
    (c,"03","Events & graph","Related records are grouped and connected."),
    (d,"04","Analyst review","Risk indicators and AI evidence help investigation."),
]:
    with col:
        st.markdown(f'<div class="stepbox"><div class="stepnum">CURRENT SYSTEM · {num}</div><div class="steptitle">{title}</div><div class="stepcopy">{copy}</div></div>',unsafe_allow_html=True)

st.markdown("### The four improvements we can actually build")
st.caption("Read each row from left to right: what exists now → what we would add → what you will be able to see.")

def scope_card(number, title, status, feasibility, current, next_work, result, example, first_task):
    st.markdown(
        f"""
        <div class="scope-card">
          <div class="scope-top">
            <div><span class="eyebrow">{number} · FUTURE IMPROVEMENT</span><div class="scope-title">{title}</div></div>
            <span class="scope-status">{status} · {feasibility}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left,middle,right=st.columns([1,0.12,1.18])
    with left:
        st.markdown(f'<div class="scope-label">Already have</div><div class="scope-text">{current}</div>',unsafe_allow_html=True)
    with middle:
        st.markdown("<div style='text-align:center;color:#6fa9d8;font-size:1.5rem;padding-top:20px'>→</div>",unsafe_allow_html=True)
    with right:
        st.markdown(f'<div class="scope-label">Build next</div><div class="scope-text">{next_work}</div>',unsafe_allow_html=True)
    st.markdown(f'<div class="example"><b>Example:</b> {example}</div>',unsafe_allow_html=True)
    st.markdown(f'<div class="scope-result">What this adds: {result}</div>',unsafe_allow_html=True)
    with st.expander("What would we do first?"):
        st.write(first_task)

scope_card(
    "01",
    "Make attack detection more reliable across different days",
    "EXPERIMENT CODE EXISTS",
    "High",
    "Isolation Forest already scores flows. The project also has chronological train/calibration/test handling and a temporal experiment script.",
    "Finish a repeatable multi-fold evaluation. Compare thresholds such as 0.5%, 1%, 2% and 5% using benign validation traffic, then measure the false alerts and attacks missed on later days.",
    "A dashboard comparison showing which threshold gives a more useful balance between missed attacks and false alerts on unseen days.",
    "A threshold that gives 1% false positives on one day may produce more false positives on another day. We measure that change instead of assuming the threshold always holds.",
    "Run the existing temporal-threshold experiment on the complete CICIDS2017 CSV archive; save per-fold metrics and compare raw Isolation Forest with the host-history version. Do not tune using the final test-day labels.",
)

scope_card(
    "02",
    "Process new network traffic without restarting the whole batch",
    "NEW ENGINEERING MODULE",
    "Medium",
    "Inference can already score an unlabeled CSV batch and build host-history features. But its rolling history is rebuilt from the supplied batch and is not kept between separate runs.",
    "Add a small incremental input loop and persist the last-known host state. Each new batch updates 1-minute/5-minute history and only the incoming records are scored.",
    "A prototype dashboard that refreshes as new batches arrive and keeps host behaviour across batches. This can start with a local folder/API and SQLite; Kafka is not required.",
    "Batch 1 contains traffic from 10:00–10:01. Batch 2 arrives at 10:01–10:02. The system remembers Batch 1's host activity when scoring Batch 2.",
    "Build a local incremental prototype first: read one new CSV batch at a time, persist per-host rolling counters/timestamps in SQLite, handle duplicate and late records, and compare its scores with the existing batch pipeline.",
)

scope_card(
    "03",
    "Tell the analyst what kind of attack a suspicious flow may represent",
    "NEW ML COMPONENT",
    "Medium",
    "The current Isolation Forest answers a binary question: does this flow look unusual? It does not independently predict DDoS, PortScan, brute force, or XSS.",
    "Add a separate multiclass classifier trained on labelled training data. Run it only after anomaly detection, and return a class only when the model has enough support/confidence; otherwise keep the event Unclassified.",
    "The detection screen can show two separate results: 'Anomalous' and 'Predicted family: DDoS'. That keeps anomaly detection distinct from attack identification.",
    "An unusual flow is first flagged by Isolation Forest. A second model may label it DDoS. If the evidence is weak or the class is unsupported, it stays Unclassified.",
    "Start with well-represented CICIDS2017 attack families. Use a time/group-aware split, report per-class precision/recall/F1 and confusion matrix, and keep rare classes out of confident claims until enough examples exist.",
)

scope_card(
    "04",
    "Check whether grouped events are actually useful incidents",
    "VALIDATION WORK",
    "Medium",
    "The system already groups suspicious flows into events, connects events through shared-host temporal relationships, and forms potential incident groups. These are candidate correlations, not confirmed incidents.",
    "Run the existing event-window/gap sensitivity sweep, then create a small analyst-reviewed sample marking whether event pairs/groups are genuinely related. Use those judgements to assess over-merging and over-splitting; only then evaluate risk prioritisation.",
    "A reviewer can see why events were grouped, which links joined them, and how often the grouping agrees with reviewed examples. Risk scores can be assessed against reviewed priority labels rather than treated as probabilities.",
    "If two unrelated events happen on the same host hours apart, they should not automatically become one incident. Review labels help us test whether the grouping rules are too broad.",
    "Run experiments/event_correlation_sensitivity.py on the full metadata-rich output. Export candidate groups for manual review, record related/not-related decisions, and calculate agreement/precision only on the reviewed sample.",
)

st.markdown("---")
st.markdown("### Build order")
st.caption("This order avoids starting a new feature before the current pipeline has been evaluated properly.")
build_cols=st.columns(4)
for col,num,title,detail in [
    (build_cols[0],"1","Temporal validation","Finish the experiment that already has code."),
    (build_cols[1],"2","Incident review","Measure the quality of existing event groups."),
    (build_cols[2],"3","Attack classifier","Add attack-family prediction as a separate model."),
    (build_cols[3],"4","Incremental prototype","Move from batch input to persistent batches."),
]:
    with col:
        st.markdown(f'<div class="stepbox"><div class="stepnum">PRIORITY {num}</div><div class="steptitle">{title}</div><div class="stepcopy">{detail}</div></div>',unsafe_allow_html=True)

st.markdown("---")
st.info("What we are deliberately not promising yet: automatic firewall blocking, guaranteed zero-day detection, fully autonomous response, or production-grade live monitoring. Those require evidence and safeguards that the current project does not yet have.")

st.caption("Roadmap derived from the current CyberSentinel implementation. 'Future improvement' items are proposed work, not completed features.")
