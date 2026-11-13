from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st


st.set_page_config(
    page_title="CyberSentinel | Model Selection",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root {
        --page: #080e17;
        --panel: #101b29;
        --panel-soft: #0d1723;
        --line: #2a4056;
        --text: #f1f6fc;
        --muted: #afbed0;
        --blue: #7cc3f4;
        --green: #48d19a;
    }
    .stApp { background:var(--page); color:var(--text); }
    [data-testid="stAppViewContainer"] .main .block-container {
        max-width:1520px;
        padding:2.1rem clamp(1.1rem,3vw,3.2rem) 4.5rem;
    }
    [data-testid="stSidebar"] {
        background:#0b1420;
        border-right:1px solid #203348;
    }
    [data-testid="stMarkdownContainer"] p,
    [data-testid="stMarkdownContainer"] li {
        font-size:17px !important;
        line-height:1.65 !important;
    }
    [data-testid="stMarkdownContainer"] h1 {
        color:var(--text);
        font-size:clamp(2.45rem,4vw,3.45rem) !important;
        line-height:1.12 !important;
        font-weight:850 !important;
        letter-spacing:-.035em;
        margin:.25rem 0 .7rem !important;
    }
    [data-testid="stMarkdownContainer"] h2 {
        color:var(--text);
        font-size:clamp(1.55rem,2.4vw,2rem) !important;
        line-height:1.2 !important;
        font-weight:820 !important;
        margin:0 0 .55rem !important;
    }
    [data-testid="stMarkdownContainer"] h3 {
        color:var(--text);
        font-size:1.22rem !important;
        line-height:1.3 !important;
        font-weight:780 !important;
    }
    [data-testid="stCaptionContainer"] {
        color:#a9b9ca !important;
        font-size:15px !important;
        line-height:1.6 !important;
    }
    [data-testid="stMetricValue"] {
        font-size:2.25rem !important;
        line-height:1.15 !important;
        font-weight:850 !important;
    }
    [data-testid="stMetricLabel"] {
        font-size:15px !important;
        line-height:1.35 !important;
    }
    [data-testid="stPlotlyChart"] { width:100%; }
    .eyebrow {
        color:#8dc9f3;
        font-size:13px;
        font-weight:850;
        letter-spacing:.15em;
        text-transform:uppercase;
        line-height:1.45;
    }
    .page-subtitle {
        color:#bdcad8;
        font-size:19px;
        line-height:1.65;
        max-width:1050px;
        margin:0 0 22px;
    }
    .hero {
        border:1px solid #355673;
        border-radius:19px;
        padding:27px 29px;
        background:
          radial-gradient(circle at 91% 2%,rgba(65,155,218,.20),transparent 32%),
          linear-gradient(115deg,#12263a,#0d1928 66%,#0c1521);
        margin:18px 0 22px;
    }
    .hero-kicker {
        color:#9bcff3;
        font-size:13px;
        font-weight:850;
        letter-spacing:.14em;
        text-transform:uppercase;
        line-height:1.5;
    }
    .hero-title {
        color:#f4f8fd;
        font-size:clamp(1.85rem,3.1vw,2.65rem);
        font-weight:900;
        line-height:1.16;
        letter-spacing:-.025em;
        margin:8px 0 10px;
    }
    .hero-copy {
        color:#c0cede;
        font-size:18px;
        line-height:1.65;
        max-width:1030px;
    }
    .hero-stats {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:12px;
        margin-top:22px;
    }
    .hero-stat {
        min-width:0;
        padding:15px 17px;
        background:rgba(5,13,23,.52);
        border:1px solid #35516a;
        border-radius:12px;
    }
    .hero-stat strong {
        display:block;
        color:#f4f8fd;
        font-size:clamp(1.75rem,2.8vw,2.35rem);
        line-height:1.1;
        font-weight:900;
        font-variant-numeric:tabular-nums;
    }
    .hero-stat span {
        display:block;
        color:#b7c7d8;
        font-size:14px;
        line-height:1.45;
        margin-top:7px;
    }
    .section-head {
        display:flex;
        flex-wrap:wrap;
        align-items:flex-end;
        justify-content:space-between;
        gap:8px 18px;
        margin:36px 0 15px;
    }
    .section-title {
        color:#f0f5fb;
        font-size:clamp(1.55rem,2.4vw,1.95rem);
        line-height:1.2;
        font-weight:850;
    }
    .section-hint {
        color:#a7b6c7;
        font-size:14px;
        line-height:1.5;
    }
    .proof-grid {
        display:grid;
        grid-template-columns:repeat(5,minmax(0,1fr));
        gap:11px;
        margin:17px 0 8px;
    }
    .proof-item {
        min-width:0;
        padding:16px 15px;
        border:1px solid #2b435b;
        border-radius:12px;
        background:#0d1825;
    }
    .proof-item strong {
        display:block;
        color:#f1f7fd;
        font-size:clamp(1.45rem,2.3vw,1.9rem);
        line-height:1.1;
        font-weight:900;
        font-variant-numeric:tabular-nums;
        overflow-wrap:anywhere;
    }
    .proof-item span {
        display:block;
        color:#b3c2d1;
        font-size:14px;
        line-height:1.45;
        margin-top:7px;
    }
    .pipeline {
        display:grid;
        grid-template-columns:repeat(5,minmax(0,1fr));
        gap:10px;
        margin:14px 0 8px;
    }
    .pipeline-step {
        min-width:0;
        padding:17px 16px 18px;
        border:1px solid #2b435a;
        border-radius:12px;
        background:linear-gradient(150deg,#112033,#0d1723);
    }
    .step-no {
        color:#83c8f4;
        font-size:13px;
        font-weight:900;
        letter-spacing:.1em;
    }
    .step-title {
        color:#f0f6fc;
        font-size:17px;
        line-height:1.3;
        font-weight:850;
        margin:8px 0 6px;
    }
    .step-copy {
        color:#b0bfce;
        font-size:14px;
        line-height:1.5;
    }
    .model-grid {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:15px;
        margin-top:14px;
    }
    .model-card {
        min-width:0;
        padding:21px;
        border:1px solid #304960;
        border-radius:15px;
        background:linear-gradient(150deg,#111f2e,#0c1622);
    }
    .model-card.selected {
        border:1.5px solid #3b9c78;
        box-shadow:inset 0 0 0 1px rgba(72,209,154,.08);
    }
    .model-head {
        display:flex;
        flex-wrap:wrap;
        justify-content:space-between;
        align-items:center;
        gap:8px;
    }
    .model-name {
        color:#f3f7fc;
        font-size:21px;
        line-height:1.25;
        font-weight:900;
    }
    .model-status {
        color:#9fe7c6;
        border:1px solid #34785d;
        background:#10291f;
        border-radius:7px;
        padding:5px 9px;
        font-size:12px;
        font-weight:850;
        letter-spacing:.07em;
        white-space:nowrap;
    }
    .model-tag {
        color:#9bcdf0;
        font-size:13px;
        font-weight:850;
        letter-spacing:.11em;
        line-height:1.5;
        margin-top:7px;
    }
    .model-description {
        color:#c0ccda;
        font-size:16px;
        line-height:1.6;
        margin:12px 0 15px;
        min-height:0;
    }
    .model-flow {
        display:grid;
        grid-template-columns:minmax(0,1fr) 18px minmax(0,1fr) 18px minmax(0,1fr);
        align-items:stretch;
        gap:5px;
        margin:14px 0;
    }
    .flow-node {
        display:flex;
        align-items:center;
        justify-content:center;
        min-width:0;
        min-height:68px;
        padding:9px 7px;
        border:1px solid #35516a;
        border-radius:9px;
        background:#091522;
        color:#d6e3ef;
        text-align:center;
        font-size:13px;
        line-height:1.35;
        font-weight:750;
        overflow-wrap:anywhere;
    }
    .flow-arrow {
        align-self:center;
        color:#77b8e8;
        font-size:20px;
        line-height:1;
        font-weight:900;
        text-align:center;
    }
    .model-config {
        border-top:1px solid #263c51;
        padding-top:12px;
        color:#b4c4d4;
        font-size:14px;
        line-height:1.7;
    }
    .model-config b { color:#eef5fc; }
    .decision-grid {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:13px;
        margin:14px 0;
    }
    .decision-card {
        min-width:0;
        padding:18px;
        border:1px solid #30465c;
        border-radius:13px;
        background:#0e1926;
    }
    .decision-label {
        color:#91c8ee;
        font-size:13px;
        font-weight:900;
        letter-spacing:.1em;
        line-height:1.5;
    }
    .decision-value {
        color:#f3f7fc;
        font-size:24px;
        line-height:1.2;
        font-weight:900;
        margin:8px 0 6px;
        font-variant-numeric:tabular-nums;
    }
    .decision-copy {
        color:#b8c6d4;
        font-size:15px;
        line-height:1.55;
    }
    .selection-box {
        border:1px solid #34785d;
        border-left:5px solid #48d19a;
        border-radius:14px;
        background:linear-gradient(110deg,#0e241d,#0c1b1a);
        padding:20px 22px;
        margin:18px 0;
    }
    .selection-title {
        color:#c4f2dc;
        font-size:22px;
        line-height:1.25;
        font-weight:900;
    }
    .selection-copy {
        color:#c0d4cb;
        font-size:16px;
        line-height:1.65;
        margin-top:8px;
    }
    .table-scroll {
        width:100%;
        overflow-x:auto;
        border:1px solid #2a4056;
        border-radius:12px;
        margin:14px 0 8px;
    }
    .evidence-table {
        width:100%;
        min-width:900px;
        border-collapse:collapse;
        background:#0d1723;
        font-size:15px;
    }
    .evidence-table th {
        background:#152438;
        color:#d9e8f5;
        text-align:left;
        padding:14px 13px;
        font-size:14px;
        line-height:1.35;
        font-weight:850;
        white-space:nowrap;
        border-bottom:1px solid #314a62;
    }
    .evidence-table td {
        color:#d8e2ec;
        padding:14px 13px;
        line-height:1.45;
        border-bottom:1px solid #26394c;
        font-variant-numeric:tabular-nums;
        white-space:nowrap;
    }
    .evidence-table tr:last-child td { border-bottom:0; }
    .evidence-table .if-row td { background:rgba(53,145,105,.11); }
    .evidence-table td:first-child { color:#f1f6fc; font-weight:850; }
    .paper-grid {
        display:grid;
        grid-template-columns:repeat(2,minmax(0,1fr));
        gap:13px;
        margin:14px 0;
    }
    .paper-card {
        min-width:0;
        padding:18px 19px;
        border:1px solid #2c4359;
        border-radius:12px;
        background:#0e1926;
    }
    .paper-type {
        color:#91c9f0;
        font-size:12px;
        font-weight:900;
        letter-spacing:.12em;
        line-height:1.5;
    }
    .paper-title {
        color:#eff5fb;
        font-size:17px;
        font-weight:850;
        line-height:1.4;
        margin:7px 0;
    }
    .paper-meta {
        color:#aebed0;
        font-size:14px;
        line-height:1.5;
    }
    .paper-link {
        display:inline-block;
        color:#93ccf4 !important;
        font-size:14px;
        font-weight:800;
        text-decoration:none;
        margin-top:11px;
    }
    .paper-link:hover { text-decoration:underline; color:#c1e5ff !important; }
    .proof-links {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:12px;
        margin:14px 0;
    }
    .proof-link-card {
        min-width:0;
        padding:17px 18px;
        border:1px solid #34516a;
        border-radius:12px;
        background:#101f2e;
    }
    .proof-link-card a {
        color:#a5d8ff !important;
        font-size:16px;
        font-weight:850;
        line-height:1.45;
        text-decoration:none;
    }
    .proof-link-card a:hover { text-decoration:underline; }
    .proof-link-card p {
        color:#b2c1cf;
        font-size:14px;
        line-height:1.5;
        margin:8px 0 0;
    }
    .small-note {
        color:#9eafc1;
        font-size:14px;
        line-height:1.6;
        margin:10px 0;
    }
    @media (max-width:1100px) {
        .proof-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
        .pipeline { grid-template-columns:repeat(3,minmax(0,1fr)); }
        .model-grid { grid-template-columns:1fr; }
        .model-description { max-width:none; }
    }
    @media (max-width:760px) {
        [data-testid="stAppViewContainer"] .main .block-container {
            padding:1.15rem 1rem 3rem;
        }
        .hero { padding:20px 18px; }
        .hero-stats { grid-template-columns:1fr; }
        .proof-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
        .pipeline { grid-template-columns:1fr; }
        .decision-grid { grid-template-columns:1fr; }
        .paper-grid { grid-template-columns:1fr; }
        .proof-links { grid-template-columns:1fr; }
        .model-flow {
            grid-template-columns:1fr;
            gap:5px;
        }
        .flow-node { min-height:48px; }
        .flow-arrow { transform:rotate(90deg); }
        .model-card { padding:18px; }
        .section-head { margin-top:29px; }
    }
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


MODELS = ["Isolation Forest", "LOF", "RBF One-Class SVM"]
COLORS = {
    "Isolation Forest": "#43ca91",
    "LOF": "#e7ad57",
    "RBF One-Class SVM": "#69aef0",
}
SIZES = ["5k", "25k", "50k"]
RESULTS = {
    "Isolation Forest": {
        "roc": [0.8874, 0.8866, 0.8848], "roc_sd": [0.0023, 0.0027, 0.0039],
        "ap": [0.6793, 0.6725, 0.6736], "ap_sd": [0.0114, 0.0070, 0.0185],
        "precision": [0.7046, 0.6978, 0.7048], "precision_sd": [0.0151, 0.0088, 0.0103],
        "recall": [0.6786, 0.6642, 0.6855], "recall_sd": [0.0391, 0.0395, 0.0429],
        "f1": [0.6912, 0.6803, 0.6948], "f1_sd": [0.0275, 0.0246, 0.0269],
        "fpr": [5.05, 5.10, 5.09], "fpr_sd": [0.08, 0.11, 0.07],
        "fit": [0.274, 0.338, 0.411], "fit_sd": [0.008, 0.005, 0.002],
        "score": [0.104, 0.103, 0.104], "score_sd": [0.003, 0.001, 0.001],
    },
    "LOF": {
        "roc": [0.8899, 0.9084, 0.9087], "roc_sd": [0.0136, 0.0034, 0.0052],
        "ap": [0.5624, 0.5576, 0.5687], "ap_sd": [0.0290, 0.0161, 0.0120],
        "precision": [0.6170, 0.6380, 0.6553], "precision_sd": [0.0657, 0.0091, 0.0297],
        "recall": [0.4314, 0.4588, 0.5129], "recall_sd": [0.1245, 0.0304, 0.0863],
        "f1": [0.5053, 0.5335, 0.5740], "f1_sd": [0.1072, 0.0237, 0.0646],
        "fpr": [4.60, 4.62, 4.74], "fpr_sd": [0.09, 0.16, 0.18],
        "fit": [0.106, 1.966, 7.576], "fit_sd": [0.011, 0.003, 0.031],
        "score": [0.290, 1.253, 2.313], "score_sd": [0.003, 0.101, 0.019],
    },
    "RBF One-Class SVM": {
        "roc": [0.8514, 0.8439, 0.8430], "roc_sd": [0.0051, 0.0084, 0.0104],
        "ap": [0.7486, 0.7620, 0.7665], "ap_sd": [0.0023, 0.0013, 0.0029],
        "precision": [0.7293, 0.7222, 0.7225], "precision_sd": [0.0004, 0.0061, 0.0036],
        "recall": [0.7436, 0.7430, 0.7446], "recall_sd": [0.0009, 0.0005, 0.0023],
        "f1": [0.7363, 0.7324, 0.7334], "f1_sd": [0.0005, 0.0032, 0.0014],
        "fpr": [4.90, 5.08, 5.08], "fpr_sd": [0.01, 0.15, 0.10],
        "fit": [0.096, 2.383, 19.484], "fit_sd": [0.003, 0.012, 2.168],
        "score": [0.230, 1.024, 2.106], "score_sd": [0.007, 0.003, 0.065],
    },
}


def style_chart(fig: go.Figure, height: int = 430) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=55, r=30, t=72, b=58),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Arial, sans-serif", color="#dce8f4", size=16),
        title=dict(font=dict(size=21, color="#f1f6fc"), x=0.02, xanchor="left"),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            x=0,
            font=dict(size=15),
            title_text="",
        ),
        hoverlabel=dict(bgcolor="#101b28", font_color="#f0f6ff", font_size=15),
        bargap=0.25,
        bargroupgap=0.10,
    )
    fig.update_xaxes(
        showgrid=False,
        zeroline=False,
        color="#bdcada",
        tickfont=dict(size=15),
        automargin=True,
    )
    fig.update_yaxes(
        gridcolor="rgba(140,160,185,.18)",
        zeroline=False,
        color="#bdcada",
        tickfont=dict(size=15),
        automargin=True,
    )
    return fig


def section(title: str, hint: str = "") -> None:
    hint_html = f'<div class="section-hint">{hint}</div>' if hint else ""
    st.markdown(
        f'<div class="section-head"><div class="section-title">{title}</div>{hint_html}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Page heading and selected-model summary
# ---------------------------------------------------------------------------

st.markdown('<div class="eyebrow">CYBERSENTINEL · MODEL SELECTION STUDY</div>', unsafe_allow_html=True)
st.title("Model Selection & Evidence")
st.markdown(
    '<p class="page-subtitle">Three unsupervised detectors were trained and compared on the same '
    'CICIDS2017 evaluation setup. This page shows the training protocol, measured results, '
    'runtime comparison and research sources behind the methods.</p>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="hero-kicker">MODEL USED IN THE CURRENT APPLICATION</div>
      <div class="hero-title">Isolation Forest</div>
      <div class="hero-copy">
        The measured reason for selecting it is its low training and scoring cost while
        maintaining useful detection performance. On 50,000 benign training flows, it
        trained in <b>0.411 seconds</b>; it scored the shared 15,000-flow test sample in
        <b>0.104 seconds</b>.
      </div>
      <div class="hero-stats">
        <div class="hero-stat">
          <strong>0.411 s</strong>
          <span>Training time · 50,000 benign flows</span>
        </div>
        <div class="hero-stat">
          <strong>0.104 s</strong>
          <span>Scoring time · 15,000 test flows</span>
        </div>
        <div class="hero-stat">
          <strong>0.6948</strong>
          <span>F1 score · 50,000-flow benchmark</span>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Evidence that the comparison was actually executed
# ---------------------------------------------------------------------------

section("Experiment at a glance", "One shared evaluation protocol for all three detectors")
st.markdown(
    """
    <div class="proof-grid">
      <div class="proof-item"><strong>3</strong><span>Different unsupervised models</span></div>
      <div class="proof-item"><strong>27</strong><span>Model fits recorded: 3 models × 3 data sizes × 3 seeds</span></div>
      <div class="proof-item"><strong>15,000</strong><span>Same held-out test flows for every run</span></div>
      <div class="proof-item"><strong>5,000</strong><span>Benign-only calibration flows</span></div>
      <div class="proof-item"><strong>3 seeds</strong><span>42 · 43 · 44</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

section("How the benchmark was run", "The same split, calibration sample and test rows were shared")
pipeline = [
    ("01", "CICIDS2017 data", "2,228,970 rows · 69 numeric modelling features"),
    ("02", "Grouped split", "7-fold StratifiedGroupKFold; exact duplicate feature groups kept together"),
    ("03", "Benign-only fitting", "5k, 25k and 50k normal flows per model"),
    ("04", "Threshold calibration", "Same 5,000 benign rows; target false-positive rate 5%"),
    ("05", "Held-out evaluation", "Same 15,000 test rows; repeated with seeds 42, 43 and 44"),
]
pipeline_html = "".join(
    f'<div class="pipeline-step"><div class="step-no">{n}</div>'
    f'<div class="step-title">{title}</div><div class="step-copy">{copy}</div></div>'
    for n, title, copy in pipeline
)
st.markdown(f'<div class="pipeline">{pipeline_html}</div>', unsafe_allow_html=True)
st.caption(
    "Training used benign rows only. Attack labels were held back for measuring test performance; "
    "they were not used to fit the three unsupervised detectors or to choose the alert threshold."
)

# ---------------------------------------------------------------------------
# Three detector cards with fitted model configurations
# ---------------------------------------------------------------------------

section("The three models that were trained", "Each model uses a different way to describe unusual traffic")
model_cards = [
    {
        "name": "Isolation Forest",
        "tag": "RANDOM-PARTITION DETECTOR",
        "desc": "Builds random feature splits. Flows isolated in fewer splits receive higher anomaly scores.",
        "steps": ["Benign flow data", "Random feature splits", "Short path = unusual"],
        "config": "<b>Fit settings:</b> 200 trees · max_samples 1,024 · contamination auto",
        "selected": True,
    },
    {
        "name": "Local Outlier Factor",
        "tag": "LOCAL-DENSITY DETECTOR",
        "desc": "Compares each new flow with nearby flows. A flow in a much sparser local region receives a higher anomaly score.",
        "steps": ["Benign flow data", "Check 35 neighbours", "Low local density"],
        "config": "<b>Fit settings:</b> 35 neighbours · novelty mode · StandardScaler",
        "selected": False,
    },
    {
        "name": "RBF One-Class SVM",
        "tag": "NORMAL-BOUNDARY DETECTOR",
        "desc": "Learns a boundary around benign traffic using an RBF kernel. Flows outside the learned region receive higher anomaly scores.",
        "steps": ["Benign flow data", "Learn RBF boundary", "Outside = unusual"],
        "config": "<b>Fit settings:</b> RBF kernel · nu 0.05 · gamma scale · StandardScaler",
        "selected": False,
    },
]
model_html = []
for item in model_cards:
    steps_html = (
        f'<div class="flow-node">{item["steps"][0]}</div>'
        f'<div class="flow-arrow">›</div>'
        f'<div class="flow-node">{item["steps"][1]}</div>'
        f'<div class="flow-arrow">›</div>'
        f'<div class="flow-node">{item["steps"][2]}</div>'
    )
    selected_html = '<span class="model-status">IN CURRENT APP</span>' if item["selected"] else ""
    selected_class = " selected" if item["selected"] else ""
    model_html.append(
        f'<div class="model-card{selected_class}">'
        f'<div class="model-head"><div class="model-name">{item["name"]}</div>{selected_html}</div>'
        f'<div class="model-tag">{item["tag"]}</div>'
        f'<div class="model-description">{item["desc"]}</div>'
        f'<div class="model-flow">{steps_html}</div>'
        f'<div class="model-config">{item["config"]}</div>'
        f'</div>'
    )
st.markdown(f'<div class="model-grid">{"".join(model_html)}</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 50k comparison: chart and exact benchmark table
# ---------------------------------------------------------------------------

section("Measured detection quality", "50,000 benign training flows · mean ± standard deviation over 3 runs")

quality = go.Figure()
for model in MODELS:
    d = RESULTS[model]
    quality.add_trace(
        go.Bar(
            name=model,
            x=["Average Precision", "F1 score", "ROC-AUC"],
            y=[d["ap"][2], d["f1"][2], d["roc"][2]],
            marker_color=COLORS[model],
            error_y=dict(
                type="data",
                array=[d["ap_sd"][2], d["f1_sd"][2], d["roc_sd"][2]],
                visible=True,
                thickness=1.4,
                width=4,
            ),
            text=[f"{v:.3f}" for v in [d["ap"][2], d["f1"][2], d["roc"][2]]],
            textposition="outside",
            cliponaxis=False,
            hovertemplate="%{x}<br>Mean score: %{y:.4f}<extra>%{fullData.name}</extra>",
        )
    )
quality.update_layout(
    barmode="group",
    title="Detection scores by model",
    yaxis=dict(range=[0, 1.13], title="Score"),
    xaxis_title=None,
)
st.plotly_chart(
    style_chart(quality, 480),
    use_container_width=True,
    config={"displayModeBar": False, "responsive": True},
)

rows = []
for model in MODELS:
    d = RESULTS[model]
    css_class = "if-row" if model == "Isolation Forest" else ""
    rows.append(
        f'<tr class="{css_class}"><td>{model}</td>'
        f'<td>{d["ap"][2]:.4f} ± {d["ap_sd"][2]:.4f}</td>'
        f'<td>{d["f1"][2]:.4f} ± {d["f1_sd"][2]:.4f}</td>'
        f'<td>{d["roc"][2]:.4f} ± {d["roc_sd"][2]:.4f}</td>'
        f'<td>{d["fpr"][2]:.2f}% ± {d["fpr_sd"][2]:.2f}</td>'
        f'<td>{d["fit"][2]:.3f} ± {d["fit_sd"][2]:.3f}</td>'
        f'<td>{d["score"][2]:.3f} ± {d["score_sd"][2]:.3f}</td></tr>'
    )
st.markdown(
    f"""
    <div class="table-scroll">
      <table class="evidence-table">
        <thead>
          <tr>
            <th>Model</th><th>Average Precision</th><th>F1</th><th>ROC-AUC</th>
            <th>Test FPR</th><th>Fit time (s)</th><th>Score 15k (s)</th>
          </tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption(
    "Values are mean ± sample SD across seeds 42, 43 and 44. Error bars in the chart show the same run-to-run spread."
)

# ---------------------------------------------------------------------------
# Runtime evidence and the selection decision
# ---------------------------------------------------------------------------

section("Runtime comparison", "Lower time means less compute for the same benchmark workload")
fit_col, score_col = st.columns(2, gap="large")

fit_fig = go.Figure(
    go.Bar(
        x=MODELS,
        y=[RESULTS[m]["fit"][2] for m in MODELS],
        marker_color=[COLORS[m] for m in MODELS],
        error_y=dict(type="data", array=[RESULTS[m]["fit_sd"][2] for m in MODELS], visible=True),
        text=[f'{RESULTS[m]["fit"][2]:.3f} s' for m in MODELS],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{x}<br>Fit: %{y:.3f} seconds<extra></extra>",
    )
)
fit_fig.update_layout(
    title="Training 50,000 benign flows",
    showlegend=False,
    yaxis=dict(title="Seconds", rangemode="tozero"),
)
with fit_col:
    st.plotly_chart(
        style_chart(fit_fig, 390),
        use_container_width=True,
        config={"displayModeBar": False, "responsive": True},
    )

score_fig = go.Figure(
    go.Bar(
        x=MODELS,
        y=[RESULTS[m]["score"][2] for m in MODELS],
        marker_color=[COLORS[m] for m in MODELS],
        error_y=dict(type="data", array=[RESULTS[m]["score_sd"][2] for m in MODELS], visible=True),
        text=[f'{RESULTS[m]["score"][2]:.3f} s' for m in MODELS],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{x}<br>Score 15k rows: %{y:.3f} seconds<extra></extra>",
    )
)
score_fig.update_layout(
    title="Scoring the same 15,000 test flows",
    showlegend=False,
    yaxis=dict(title="Seconds", rangemode="tozero"),
)
with score_col:
    st.plotly_chart(
        style_chart(score_fig, 390),
        use_container_width=True,
        config={"displayModeBar": False, "responsive": True},
    )

fit_vs_svm = RESULTS["RBF One-Class SVM"]["fit"][2] / RESULTS["Isolation Forest"]["fit"][2]
score_vs_svm = RESULTS["RBF One-Class SVM"]["score"][2] / RESULTS["Isolation Forest"]["score"][2]
fit_vs_lof = RESULTS["LOF"]["fit"][2] / RESULTS["Isolation Forest"]["fit"][2]
score_vs_lof = RESULTS["LOF"]["score"][2] / RESULTS["Isolation Forest"]["score"][2]

section("Why Isolation Forest is the selected application model", "The selection is based on measured quality and measured runtime")
decision_cards = [
    (
        "TRAINING COST",
        f"{fit_vs_svm:.0f}× faster than SVM",
        f"0.411 s for Isolation Forest, compared with 19.484 s for One-Class SVM and 7.576 s for LOF."
    ),
    (
        "SCORING COST",
        f"{score_vs_svm:.0f}× faster than SVM",
        f"0.104 s to score 15k flows, compared with 2.106 s for One-Class SVM and 2.313 s for LOF."
    ),
    (
        "DETECTION QUALITY",
        "F1 = 0.6948",
        "Higher AP and F1 than LOF at the same threshold. ROC-AUC is 0.8848, above One-Class SVM at 0.8430."
    ),
]
decision_html = "".join(
    f'<div class="decision-card"><div class="decision-label">{label}</div>'
    f'<div class="decision-value">{value}</div><div class="decision-copy">{copy}</div></div>'
    for label, value, copy in decision_cards
)
st.markdown(f'<div class="decision-grid">{decision_html}</div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="selection-box">
      <div class="selection-title">Selection: Isolation Forest for the current application</div>
      <div class="selection-copy">
        Its measured advantage is speed: the lowest fit time and the lowest scoring time in this
        50k comparison, with F1 of 0.6948. It also scores higher than LOF on Average Precision and F1.
        One-Class SVM records the highest Average Precision (0.7665) and F1 (0.7334), while LOF
        records the highest ROC-AUC (0.9087). The model choice shown here is therefore a
        runtime–detection trade-off, not a claim that Isolation Forest has the highest score on every metric.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Training-size evidence
# ---------------------------------------------------------------------------

section("Results at three training sizes", "All models received the same benign training budgets")
trend = go.Figure()
for model in MODELS:
    d = RESULTS[model]
    trend.add_trace(
        go.Scatter(
            x=SIZES,
            y=d["f1"],
            name=model,
            mode="lines+markers",
            line=dict(color=COLORS[model], width=3),
            marker=dict(size=11),
            error_y=dict(type="data", array=d["f1_sd"], visible=True, thickness=1.3, width=4),
            hovertemplate="%{x} benign training flows<br>F1: %{y:.4f}<extra>%{fullData.name}</extra>",
        )
    )
trend.update_layout(
    title="F1 score as the benign training set grows",
    yaxis=dict(range=[0, 0.85], title="F1 score"),
    xaxis_title="Benign training rows",
)
st.plotly_chart(
    style_chart(trend, 420),
    use_container_width=True,
    config={"displayModeBar": False, "responsive": True},
)

# ---------------------------------------------------------------------------
# Research references
# ---------------------------------------------------------------------------

section("Research papers behind the model choices", "Foundational papers and intrusion-detection studies")
papers = [
    (
        "ISOLATION FOREST · ORIGINAL METHOD",
        "Liu, Ting & Zhou (2008) — Isolation Forest",
        "Introduces anomaly isolation using random partitions and sub-sampling; the foundation for the Isolation Forest detector tested here.",
        "https://doi.org/10.1109/ICDM.2008.17",
        "Open paper reference ↗",
    ),
    (
        "LOCAL OUTLIER FACTOR · ORIGINAL METHOD",
        "Breunig et al. (2000) — LOF: Identifying Density-Based Local Outliers",
        "Defines local-density outlier scoring; the method used for the LOF comparison.",
        "https://doi.org/10.1145/342009.335388",
        "Open paper reference ↗",
    ),
    (
        "ONE-CLASS SVM · ORIGINAL METHOD",
        "Schölkopf et al. (2001) — Estimating the Support of a High-Dimensional Distribution",
        "Establishes one-class support estimation, the basis for the RBF One-Class SVM comparator.",
        "https://doi.org/10.1162/089976601750264965",
        "Open paper reference ↗",
    ),
    (
        "INTRUSION DETECTION · CROSS-DATASET STUDY",
        "Verkerken et al. (2022) — Towards Model Generalization for Intrusion Detection",
        "Evaluates unsupervised intrusion-detection methods, including Isolation Forest and One-Class SVM, across CICIDS datasets.",
        "https://doi.org/10.1007/s10922-021-09615-7",
        "Read full text ↗",
    ),
    (
        "CICIDS2017 · DIRECT COMPARISON",
        "Xu & Liu (2025) — Robust Anomaly Detection in Network Traffic",
        "Compares LOF and One-Class SVM on CICIDS2017, including a scenario with previously unseen attack types.",
        "https://doi.org/10.1109/ICETIS66286.2025.11144025",
        "Open IEEE paper ↗",
    ),
    (
        "IMBALANCED METRICS · EVALUATION",
        "Saito & Rehmsmeier (2015) — The Precision-Recall Plot Is More Informative than the ROC Plot",
        "Explains why precision–recall analysis is important when the positive class is less common; supports reporting Average Precision alongside ROC-AUC.",
        "https://doi.org/10.1371/journal.pone.0118432",
        "Read PLOS paper ↗",
    ),
]
paper_html = "".join(
    f'<div class="paper-card"><div class="paper-type">{kind}</div>'
    f'<div class="paper-title">{title}</div><div class="paper-meta">{summary}</div>'
    f'<a class="paper-link" href="{url}" target="_blank" rel="noopener noreferrer">{link}</a></div>'
    for kind, title, summary, url, link in papers
)
st.markdown(f'<div class="paper-grid">{paper_html}</div>', unsafe_allow_html=True)
st.caption(
    "These papers support the choice of algorithms and evaluation measures. "
    "The scores and timings above are from the CyberSentinel benchmark, not copied from the papers."
)

# ---------------------------------------------------------------------------
# Direct, reproducible evidence
# ---------------------------------------------------------------------------

section("Benchmark files and execution proof", "Open the report, code and successful GitHub Actions run")
st.markdown(
    """
    <div class="proof-links">
      <div class="proof-link-card">
        <a href="https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/hardened-model-selection-results/research/HARDENED_SCALING_VALIDATION_2026-11-12.md" target="_blank" rel="noopener noreferrer">
          Full benchmark report ↗
        </a>
        <p>Dataset identity, split protocol, full metrics, per-attack recall, runtime and limitations.</p>
      </div>
      <div class="proof-link-card">
        <a href="https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/hardened-model-selection-results/experiments/compare_model_scales.py" target="_blank" rel="noopener noreferrer">
          Experiment source code ↗
        </a>
        <p>Python code that constructs and fits all three detectors, calibrates thresholds and records scores.</p>
      </div>
      <div class="proof-link-card">
        <a href="https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860" target="_blank" rel="noopener noreferrer">
          Successful benchmark run ↗
        </a>
        <p>GitHub Actions completed successfully on 12 November 2026. CSV metrics and run metadata are attached as an artifact.</p>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="small-note"><b>Run artifact SHA-256:</b> '
    '<span style="font-family:monospace;color:#c9d8e6">d4ac9de9011ad364620dfbd2a2e0e742b05d8b2e948dd1597c0559e006fc5513</span>'
    '<br><b>Dataset:</b> cleaned CICIDS2017 Parquet · SHA-256 verified before execution'
    '<br><b>Execution:</b> GitHub Actions run 43156530860 · completed successfully'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="small-note" style="margin-top:26px;padding-top:16px;border-top:1px solid #263a4e">'
    'Benchmark scope: one CICIDS2017 processed dataset, one shared held-out test sample, fixed model configurations '
    'and a nominal 5% benign-calibration threshold. The report records the limits of this split and the need for '
    'temporal, cross-dataset and deployment-hardware validation.'
    '</div>',
    unsafe_allow_html=True,
)
