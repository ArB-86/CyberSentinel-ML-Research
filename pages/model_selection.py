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
    .stApp { background:#070c13; color:#edf3fa; }
    [data-testid="stSidebar"] { background:#0b1420; border-right:1px solid #1e3042; }
    .block-container { max-width:1450px; padding-top:1.5rem; padding-bottom:3rem; }
    .eyebrow { color:#78a9d8; font-size:.67rem; font-weight:800; letter-spacing:.15em; text-transform:uppercase; }
    .muted { color:#91a2b6; }
    .hero {
        border:1px solid #31506c; border-radius:16px; padding:23px 25px;
        background:radial-gradient(circle at 92% 0%,rgba(62,151,218,.16),transparent 34%),
        linear-gradient(115deg,#102033,#0d1724 65%,#0b121c);
    }
    .hero-title { color:#f1f6fc; font-size:1.55rem; font-weight:850; line-height:1.25; }
    .hero-copy { color:#a8b8c9; font-size:.88rem; line-height:1.6; max-width:900px; margin-top:8px; }
    .hero-tag { display:inline-block; margin:14px 7px 0 0; padding:5px 9px; border:1px solid #35516b;
        border-radius:7px; background:#112438; color:#c3e2ff; font-size:.66rem; font-weight:750; }
    .section-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; margin:27px 0 12px; }
    .section-title { color:#eaf2fb; font-size:1rem; font-weight:850; }
    .section-hint { color:#8193a8; font-size:.72rem; }
    .model-card {
        height:100%; min-height:185px; padding:17px; border:1px solid #293e53;
        border-radius:13px; background:linear-gradient(145deg,#101b28,#0b131d);
    }
    .model-name { color:#eff5fc; font-size:.98rem; font-weight:850; }
    .model-type { color:#80b4df; font-size:.63rem; font-weight:850; letter-spacing:.1em; margin-top:4px; }
    .model-copy { color:#9aabbe; font-size:.77rem; line-height:1.48; min-height:48px; margin-top:10px; }
    .flow { display:flex; align-items:center; gap:5px; margin-top:14px; }
    .flow-box { flex:1; min-width:0; padding:8px 5px; border:1px solid #2b4258; border-radius:7px;
        background:#0a141f; color:#cbd9e7; font-size:.64rem; font-weight:750; text-align:center; line-height:1.3; }
    .flow-arrow { color:#68a8d8; font-weight:850; font-size:.85rem; }
    .choice-card {
        min-height:135px; padding:15px 16px; border:1px solid #2b4055; border-radius:12px;
        background:#0d1722;
    }
    .choice-label { color:#82a9c9; font-size:.62rem; font-weight:850; letter-spacing:.12em; }
    .choice-title { color:#edf4fb; font-size:.9rem; font-weight:850; margin-top:8px; }
    .choice-copy { color:#9aabbe; font-size:.75rem; line-height:1.5; margin-top:6px; }
    .callout { padding:13px 15px; border:1px solid #34495d; border-left:3px solid #6da9db;
        border-radius:10px; background:#0c1722; color:#b6c5d4; font-size:.79rem; line-height:1.55; }
    .decision { padding:17px 18px; border:1px solid #285643; border-radius:12px; background:#0c1a18; }
    .decision-title { color:#a9e1c6; font-size:.95rem; font-weight:850; }
    .decision-copy { color:#b6c9c0; font-size:.78rem; line-height:1.55; margin-top:7px; }
    @media(max-width:700px) {
        .hero { padding:18px; }
        .hero-title { font-size:1.25rem; }
        .model-card { min-height:0; }
        .model-copy { min-height:0; }
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
    "Isolation Forest": "#36c58b",
    "LOF": "#e5aa52",
    "RBF One-Class SVM": "#69aafa",
}
SIZES = ["5k", "25k", "50k"]
RESULTS = {
    "Isolation Forest": {
        "roc": [0.8874, 0.8866, 0.8848], "roc_sd": [0.0023, 0.0027, 0.0039],
        "ap": [0.6793, 0.6725, 0.6736], "ap_sd": [0.0114, 0.0070, 0.0185],
        "f1": [0.6912, 0.6803, 0.6948], "f1_sd": [0.0275, 0.0246, 0.0269],
        "fit": [0.274, 0.338, 0.411], "score": [0.104, 0.103, 0.104],
    },
    "LOF": {
        "roc": [0.8899, 0.9084, 0.9087], "roc_sd": [0.0136, 0.0034, 0.0052],
        "ap": [0.5624, 0.5576, 0.5687], "ap_sd": [0.0290, 0.0161, 0.0120],
        "f1": [0.5053, 0.5335, 0.5740], "f1_sd": [0.1072, 0.0237, 0.0646],
        "fit": [0.106, 1.966, 7.576], "score": [0.290, 1.253, 2.313],
    },
    "RBF One-Class SVM": {
        "roc": [0.8514, 0.8439, 0.8430], "roc_sd": [0.0051, 0.0084, 0.0104],
        "ap": [0.7486, 0.7620, 0.7665], "ap_sd": [0.0023, 0.0013, 0.0029],
        "f1": [0.7363, 0.7324, 0.7334], "f1_sd": [0.0005, 0.0032, 0.0014],
        "fit": [0.096, 2.383, 19.484], "score": [0.230, 1.024, 2.106],
    },
}


def style_chart(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=18, r=18, t=48, b=18),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#dce7f2", size=11),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
        hoverlabel=dict(bgcolor="#101b28", font_color="#f0f6ff"),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, color="#95a6bb")
    fig.update_yaxes(gridcolor="rgba(140,160,185,.14)", zeroline=False, color="#95a6bb")
    return fig


st.markdown('<div class="eyebrow">MODEL SELECTION · CICIDS2017 TEST RESULTS</div>', unsafe_allow_html=True)
st.title("Model Selection & Evidence")
st.caption("Three ways to find unusual traffic. The charts show what worked best and why the current app keeps Isolation Forest.")

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">CURRENT PROJECT DECISION</div>
      <div class="hero-title">Keep Isolation Forest in the app for now.</div>
      <div class="hero-copy">
        It is <b>not the most accurate model</b> in this test. One-Class SVM scored higher on
        Average Precision and F1, while LOF scored higher on ROC-AUC. Isolation Forest stays
        because it is already connected to the app and is much faster to train and score.
      </div>
      <span class="hero-tag">50,000 normal training flows</span>
      <span class="hero-tag">Same 15,000 test flows</span>
      <span class="hero-tag">Results averaged over 3 repeat runs</span>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-head"><div class="section-title">The three models we tested</div>'
    '<div class="section-hint">Same task: find traffic that looks unusual</div></div>',
    unsafe_allow_html=True,
)

c1, c2, c3 = st.columns(3, gap="medium")
cards = [
    (
        "Isolation Forest", "RANDOM SPLITS",
        "Finds flows that can be separated from normal traffic in only a few steps.",
        ["Network flow", "Random splits", "Short path = unusual"],
    ),
    (
        "LOF", "NEARBY FLOWS",
        "Finds a flow that looks less like its nearby flows.",
        ["Network flow", "Check neighbours", "Low local density"],
    ),
    (
        "RBF One-Class SVM", "NORMAL-TRAFFIC BORDER",
        "Learns a border around normal traffic and flags flows outside it.",
        ["Normal flows", "Learn a border", "Outside = unusual"],
    ),
]
for col, (name, kind, copy, steps) in zip((c1, c2, c3), cards):
    flow = (
        f'<div class="flow-box">{steps[0]}</div><div class="flow-arrow">›</div>'
        f'<div class="flow-box">{steps[1]}</div><div class="flow-arrow">›</div>'
        f'<div class="flow-box">{steps[2]}</div>'
    )
    with col:
        st.markdown(
            f'<div class="model-card"><div class="model-name">{name}</div>'
            f'<div class="model-type">{kind}</div><div class="model-copy">{copy}</div>'
            f'<div class="flow">{flow}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown(
    '<div class="section-head"><div class="section-title">Detection results at 50k training flows</div>'
    '<div class="section-hint">Higher score is better · average across 3 runs</div></div>',
    unsafe_allow_html=True,
)

qfig = go.Figure()
for model in MODELS:
    d = RESULTS[model]
    values = [d["ap"][2], d["f1"][2], d["roc"][2]]
    errors = [d["ap_sd"][2], d["f1_sd"][2], d["roc_sd"][2]]
    qfig.add_trace(go.Bar(
        name=model,
        x=["Average Precision", "F1", "ROC-AUC"],
        y=values,
        marker_color=COLORS[model],
        text=[f"{v:.3f}" for v in values],
        textposition="outside",
        cliponaxis=False,
        error_y=dict(type="data", array=errors, visible=True),
        hovertemplate="%{x}<br>Score: %{y:.4f}<extra>%{fullData.name}</extra>",
    ))
qfig.update_layout(
    barmode="group",
    title="Which model scored highest?",
    yaxis=dict(range=[0, 1.12], title="Score"),
    xaxis_title=None,
)
st.plotly_chart(style_chart(qfig, 390), use_container_width=True, config={"displayModeBar": False})

w1, w2, w3 = st.columns(3)
w1.metric("Best Average Precision", "0.7665", "One-Class SVM")
w2.metric("Best F1", "0.7334", "One-Class SVM")
w3.metric("Best ROC-AUC", "0.9087", "LOF")

st.markdown(
    '<div class="callout"><b>What this means:</b> One-Class SVM is strongest on AP and F1. '
    'LOF is strongest on ROC-AUC. Isolation Forest is not the accuracy winner; its advantage is speed.</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-head"><div class="section-title">Training and scoring time at 50k</div>'
    '<div class="section-hint">Lower time is better · measured on the same test runner</div></div>',
    unsafe_allow_html=True,
)
fit_col, score_col = st.columns(2, gap="large")
for col, key, title in [
    (fit_col, "fit", "Time to train the model"),
    (score_col, "score", "Time to score 15,000 test flows"),
]:
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=MODELS,
        y=[RESULTS[m][key][2] for m in MODELS],
        marker_color=[COLORS[m] for m in MODELS],
        text=[f"{RESULTS[m][key][2]:.3f} s" for m in MODELS],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{x}<br>%{y:.3f} seconds<extra></extra>",
    ))
    fig.update_layout(title=title, showlegend=False, yaxis_title="Seconds")
    with col:
        st.plotly_chart(style_chart(fig, 330), use_container_width=True, config={"displayModeBar": False})

f1_if = RESULTS["Isolation Forest"]["fit"][2]
f1_svm = RESULTS["RBF One-Class SVM"]["fit"][2]
f1_lof = RESULTS["LOF"]["fit"][2]
score_if = RESULTS["Isolation Forest"]["score"][2]
score_svm = RESULTS["RBF One-Class SVM"]["score"][2]
score_lof = RESULTS["LOF"]["score"][2]
s1, s2, s3 = st.columns(3)
s1.metric("Isolation Forest training", f"{f1_if:.3f} s", f"{f1_svm / f1_if:.0f}× faster than SVM")
s2.metric("Isolation Forest scoring", f"{score_if:.3f} s", f"{score_svm / score_if:.0f}× faster than SVM")
s3.metric("At 50k rows", f"{f1_if:.3f} s fit", f"LOF: {f1_lof:.3f} s · SVM: {f1_svm:.3f} s")

st.markdown(
    '<div class="section-head"><div class="section-title">What happens as training data grows?</div>'
    '<div class="section-hint">F1 score at 5k, 25k and 50k normal flows</div></div>',
    unsafe_allow_html=True,
)
trend = go.Figure()
for model in MODELS:
    d = RESULTS[model]
    trend.add_trace(go.Scatter(
        x=SIZES,
        y=d["f1"],
        name=model,
        mode="lines+markers",
        line=dict(color=COLORS[model], width=3),
        marker=dict(size=9),
        error_y=dict(type="data", array=d["f1_sd"], visible=True),
        hovertemplate="%{x} training flows<br>F1: %{y:.4f}<extra>%{fullData.name}</extra>",
    ))
trend.update_layout(
    title="F1 across training sizes",
    yaxis=dict(range=[0, 0.85], title="F1 score"),
    xaxis_title="Normal training flows",
)
st.plotly_chart(style_chart(trend, 365), use_container_width=True, config={"displayModeBar": False})
st.caption("Isolation Forest stays around 0.68–0.69 F1 as the training set grows. One-Class SVM stays higher at about 0.73. Error bars show the spread across the 3 repeat runs.")

st.markdown(
    '<div class="section-head"><div class="section-title">Why we keep Isolation Forest in the current app</div>'
    '<div class="section-hint">The actual reasons from this project</div></div>',
    unsafe_allow_html=True,
)
r1, r2, r3 = st.columns(3, gap="medium")
reasons = [
    ("01 · ALREADY CONNECTED", "Works with the current pipeline",
     "The app already uses Isolation Forest to score flows before event grouping, graph building and investigation."),
    ("02 · LOWEST RUNTIME", "Much faster at 50k rows",
     "It trains in 0.411 seconds and scores the 15k test sample in 0.104 seconds on the benchmark runner."),
    ("03 · KNOWN BASELINE", "A measured starting point",
     "Its results stay in a similar range as training data grows. We can compare future changes against this fixed baseline."),
]
for col, (label, title, copy) in zip((r1, r2, r3), reasons):
    with col:
        st.markdown(
            f'<div class="choice-card"><div class="choice-label">{label}</div>'
            f'<div class="choice-title">{title}</div><div class="choice-copy">{copy}</div></div>',
            unsafe_allow_html=True,
        )

st.markdown(
    """
    <div class="decision">
      <div class="decision-title">Decision: keep Isolation Forest; test One-Class SVM beside it.</div>
      <div class="decision-copy">
        The results do not prove that Isolation Forest is the most accurate. They show that it is
        much cheaper to run and is already part of the app. One-Class SVM is the strongest accuracy
        candidate in this test, so it should be tested in parallel before any replacement.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-head"><div class="section-title">About the bias–variance claim</div></div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="callout"><b>We have not measured bias and variance separately.</b> '
    'The current experiment measures test scores across training sizes and repeat runs. '
    'That is useful evidence of performance and stability, but it is not a formal bias–variance proof. '
    'So the honest reason for keeping Isolation Forest is its measured speed and current integration—not a bias–variance claim.</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-head"><div class="section-title">One important comparison detail</div></div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="callout"><b>Random Forest is a separate supervised test.</b> '
    'It learns from labelled attack examples. Isolation Forest, LOF and One-Class SVM in the main chart '
    'learn from normal traffic only. Mixing Random Forest into this chart would not be a fair like-for-like comparison.</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div style="margin-top:18px;color:#8192a6;font-size:.72rem;line-height:1.5">'
    'Evidence: hardened CICIDS2017 benchmark, run on 12 November 2026. '
    'The full metrics, split details and limitations are in the '
    '<a href="https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/hardened-model-selection-results/research/HARDENED_SCALING_VALIDATION_2026-11-12.md" target="_blank" style="color:#83bfff">research results file</a>. '
    'Runtime values are specific to the benchmark runner.</div>',
    unsafe_allow_html=True,
)
