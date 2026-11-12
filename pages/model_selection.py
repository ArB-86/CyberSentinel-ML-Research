from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# ---------------------------------------------------------------------
# Page shell
# ---------------------------------------------------------------------
st.set_page_config(
    page_title="CyberSentinel | Model Lab",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background: #080d14; color: #e8eef7; }
      [data-testid="stSidebar"] { background: #0b1420; border-right: 1px solid #1d2b3a; }
      .block-container { max-width: 1480px; padding-top: 1.4rem; padding-bottom: 2.5rem; }
      .eyebrow { color: #78a9d8; font-size: .68rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
      .muted { color: #8292a7; }
      .hero { border: 1px solid #29435c; border-radius: 16px; padding: 20px 22px; background: linear-gradient(115deg, #102033 0%, #0d1724 60%, #0b121c 100%); }
      .hero-model { font-size: 1.5rem; font-weight: 850; color: #f0f6ff; line-height: 1.2; }
      .hero-copy { color: #9bacc0; font-size: .82rem; margin-top: 7px; }
      .pill { display: inline-block; padding: 5px 9px; margin: 3px 5px 0 0; border-radius: 20px; font-size: .69rem; font-weight: 750; border: 1px solid #35516b; background: #112438; color: #b9dcfa; }
      .section-note { color: #8190a3; font-size: .75rem; }
      div[data-testid="stMetric"] { background: #0e1722; border: 1px solid #26384b; padding: 12px 14px; border-radius: 12px; }
      div[data-testid="stMetricLabel"] { color: #92a3b7; }
      div[data-testid="stMetricValue"] { color: #eff6ff; }
      div[data-testid="stTabs"] button { font-weight: 650; }
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
    st.page_link("pages/model_selection.py", label="Model Selection")
    st.markdown('<div class="eyebrow" style="margin-top:16px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Event Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")


# ---------------------------------------------------------------------
# Hardened paired benchmark: mean across seeds 42, 43, 44.
# ---------------------------------------------------------------------
TRAIN_SIZES = ["5k", "25k", "50k"]
MODELS = ["Isolation Forest", "LOF", "RBF One-Class SVM"]
COLORS = {
    "Isolation Forest": "#35c58b",
    "LOF": "#e6ad54",
    "RBF One-Class SVM": "#65a7ff",
}

DATA = {
    "Isolation Forest": {
        "roc": [0.8874, 0.8866, 0.8848], "roc_sd": [0.0023, 0.0027, 0.0039],
        "ap": [0.6793, 0.6725, 0.6736], "ap_sd": [0.0114, 0.0070, 0.0185],
        "precision": [0.7046, 0.6978, 0.7048], "recall": [0.6786, 0.6642, 0.6855],
        "f1": [0.6912, 0.6803, 0.6948], "f1_sd": [0.0275, 0.0246, 0.0269],
        "fpr": [5.05, 5.10, 5.09],
        "fit": [0.274, 0.338, 0.411], "score": [0.104, 0.103, 0.104],
    },
    "LOF": {
        "roc": [0.8899, 0.9084, 0.9087], "roc_sd": [0.0136, 0.0034, 0.0052],
        "ap": [0.5624, 0.5576, 0.5687], "ap_sd": [0.0290, 0.0161, 0.0120],
        "precision": [0.6170, 0.6380, 0.6553], "recall": [0.4314, 0.4588, 0.5129],
        "f1": [0.5053, 0.5335, 0.5740], "f1_sd": [0.1072, 0.0237, 0.0646],
        "fpr": [4.60, 4.62, 4.74],
        "fit": [0.106, 1.966, 7.576], "score": [0.290, 1.253, 2.313],
    },
    "RBF One-Class SVM": {
        "roc": [0.8514, 0.8439, 0.8430], "roc_sd": [0.0051, 0.0084, 0.0104],
        "ap": [0.7486, 0.7620, 0.7665], "ap_sd": [0.0023, 0.0013, 0.0029],
        "precision": [0.7293, 0.7222, 0.7225], "recall": [0.7436, 0.7430, 0.7446],
        "f1": [0.7363, 0.7324, 0.7334], "f1_sd": [0.0005, 0.0032, 0.0014],
        "fpr": [4.90, 5.08, 5.08],
        "fit": [0.096, 2.383, 19.484], "score": [0.230, 1.024, 2.106],
    },
}

ATTACKS = [
    ("Bot", 11, [0.0, 0.0, 0.0]),
    ("DDoS", 849, [55.9, 58.5, 63.6]),
    ("DoS GoldenEye", 61, [49.2, 31.7, 78.7]),
    ("DoS Hulk", 1164, [85.5, 51.1, 89.2]),
    ("DoS Slowhttptest", 38, [76.3, 26.3, 81.6]),
    ("DoS slowloris", 43, [48.1, 20.2, 55.8]),
    ("FTP-Patator", 42, [0.0, 23.8, 0.0]),
    ("PortScan", 17, [11.8, 7.8, 23.5]),
    ("SSH-Patator", 22, [0.0, 86.4, 0.0]),
    ("Web Brute Force", 10, [0.0, 0.0, 0.0]),
    ("SQL Injection", 1, [0.0, 0.0, 0.0]),
    ("XSS", 5, [0.0, 6.7, 0.0]),
]


def base_layout(fig: go.Figure, *, height: int = 300) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=12, r=12, t=48, b=16),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#dce7f2", size=11),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
        hoverlabel=dict(bgcolor="#101b28", font_color="#f0f6ff"),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, color="#95a6bb")
    fig.update_yaxes(gridcolor="rgba(140,160,185,.13)", zeroline=False, color="#95a6bb")
    return fig


def metric_bar(metric: str, title: str, height: int = 285) -> go.Figure:
    fig = go.Figure()
    for model in MODELS:
        d = DATA[model]
        fig.add_trace(go.Bar(
            name=model,
            x=[model],
            y=[d[metric][-1]],
            marker_color=COLORS[model],
            text=[f"{d[metric][-1]:.3f}"],
            textposition="outside",
            cliponaxis=False,
            hovertemplate="%{x}<br>" + title + ": %{y:.4f}<extra></extra>",
        ))
    fig.update_layout(title=dict(text=title, font=dict(size=14)), showlegend=False,
                      yaxis=dict(range=[0, 1.08], title=None, tickformat=".0%"))
    return base_layout(fig, height=height)


# ---------------------------------------------------------------------
# Header and primary decision
# ---------------------------------------------------------------------
st.markdown('<div class="eyebrow">MODEL LAB · CICIDS2017</div>', unsafe_allow_html=True)
st.title("Model Selection")
st.caption("Compare detection quality and runtime. The active application detector is shown separately from the benchmark leaders.")

with st.container(border=True):
    left, right = st.columns([1.35, 1])
    with left:
        st.markdown('<div class="eyebrow">CURRENT APPLICATION DETECTOR</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-model">Isolation Forest</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="hero-copy">Kept in the live application pipeline for its low measured runtime and existing integration.</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<span class="pill">ACTIVE MODEL</span><span class="pill">FASTEST SCORING</span><span class="pill">INTEGRATED PIPELINE</span>',
            unsafe_allow_html=True,
        )
    with right:
        r1, r2 = st.columns(2)
        r1.metric("Fit · 50k rows", "0.411 s")
        r2.metric("Score · 15k rows", "0.104 s")
        st.caption("SVM leads AP/F1. LOF leads ROC-AUC. Isolation Forest is the operational choice—not the quality winner.")

# A visible, compact distinction between the different winners.
k1, k2, k3, k4 = st.columns(4)
k1.metric("AP leader", "0.7665", "One-Class SVM")
k2.metric("F1 leader", "0.7334", "One-Class SVM")
k3.metric("ROC-AUC leader", "0.9087", "LOF")
k4.metric("Fastest scoring", "0.104 s", "Isolation Forest")

st.markdown("#### Evaluation flow")
flow = st.columns([1, 0.22, 1, 0.22, 1, 0.22, 1])
flow_items = [
    ("01", "Benign flows", "Training pool"),
    ("02", "Fit detectors", "5k · 25k · 50k"),
    ("03", "Calibrate", "5k benign rows"),
    ("04", "Evaluate", "Shared 15k holdout"),
]
for idx, item in enumerate(flow_items):
    with flow[idx * 2]:
        with st.container(border=True):
            st.markdown(f'<div class="eyebrow">{item[0]}</div><b>{item[1]}</b><br><span class="section-note">{item[2]}</span>', unsafe_allow_html=True)
    if idx < 3:
        with flow[idx * 2 + 1]:
            st.markdown("<div style='text-align:center;padding-top:18px;color:#6484a5;font-size:1.1rem'>→</div>", unsafe_allow_html=True)

quality_tab, runtime_tab, scale_tab, coverage_tab = st.tabs(
    ["Detection quality", "Runtime", "Training scale", "Attack coverage"]
)

with quality_tab:
    st.markdown("#### 50k benign training rows")
    st.caption("Mean across three seeds · higher is better")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.plotly_chart(metric_bar("ap", "Average Precision (AP)"), use_container_width=True, config={"displayModeBar": False})
    with c2:
        st.plotly_chart(metric_bar("f1", "F1 score"), use_container_width=True, config={"displayModeBar": False})
    with c3:
        st.plotly_chart(metric_bar("roc", "ROC-AUC"), use_container_width=True, config={"displayModeBar": False})

    st.markdown("#### 50k scorecard")
    score_rows = []
    for model in MODELS:
        d = DATA[model]
        score_rows.append({
            "Model": model,
            "AP": f"{d['ap'][-1]:.4f}",
            "F1": f"{d['f1'][-1]:.4f}",
            "ROC-AUC": f"{d['roc'][-1]:.4f}",
            "Fit (s)": f"{d['fit'][-1]:.3f}",
            "Score 15k (s)": f"{d['score'][-1]:.3f}",
        })
    st.dataframe(pd.DataFrame(score_rows), use_container_width=True, hide_index=True)
    st.caption("Benchmark only. Values are not production-network performance estimates.")

with runtime_tab:
    st.markdown("#### Runtime at 50k training rows")
    st.caption("Same experiment runner · scoring batch contains 15,000 held-out flows")
    fit_col, score_col = st.columns(2)
    with fit_col:
        fig = go.Figure()
        for model in MODELS:
            fig.add_trace(go.Bar(
                x=[DATA[model]["fit"][-1]], y=[model], orientation="h",
                name=model, marker_color=COLORS[model],
                text=[f"{DATA[model]['fit'][-1]:.3f} s"], textposition="outside",
                hovertemplate="%{y}<br>Fit: %{x:.3f} s<extra></extra>",
            ))
        fig.update_layout(title="Model fit time", showlegend=False, xaxis_title="Seconds", yaxis_title=None)
        st.plotly_chart(base_layout(fig, height=245), use_container_width=True, config={"displayModeBar": False})
    with score_col:
        fig = go.Figure()
        for model in MODELS:
            fig.add_trace(go.Bar(
                x=[DATA[model]["score"][-1]], y=[model], orientation="h",
                name=model, marker_color=COLORS[model],
                text=[f"{DATA[model]['score'][-1]:.3f} s"], textposition="outside",
                hovertemplate="%{y}<br>Scoring: %{x:.3f} s<extra></extra>",
            ))
        fig.update_layout(title="Score 15k flows", showlegend=False, xaxis_title="Seconds", yaxis_title=None)
        st.plotly_chart(base_layout(fig, height=245), use_container_width=True, config={"displayModeBar": False})

    fit_speedup = DATA["RBF One-Class SVM"]["fit"][-1] / DATA["Isolation Forest"]["fit"][-1]
    score_speedup = DATA["RBF One-Class SVM"]["score"][-1] / DATA["Isolation Forest"]["score"][-1]
    a, b = st.columns(2)
    a.metric("IF fit advantage vs SVM", f"{fit_speedup:.1f}×")
    b.metric("IF scoring advantage vs SVM", f"{score_speedup:.1f}×")
    st.caption("Wall-clock measurements from one GitHub Actions runner; target-machine benchmarking remains outstanding.")

with scale_tab:
    st.markdown("#### How scores change with training size")
    st.caption("Training sets are nested; values are means across seeds 42, 43 and 44.")
    ap_col, f1_col = st.columns(2)
    for col, metric, label in [(ap_col, "ap", "Average Precision"), (f1_col, "f1", "F1 score")]:
        fig = go.Figure()
        for model in MODELS:
            d = DATA[model]
            sd_key = "ap_sd" if metric == "ap" else "f1_sd"
            fig.add_trace(go.Scatter(
                x=TRAIN_SIZES, y=d[metric], mode="lines+markers", name=model,
                line=dict(color=COLORS[model], width=3),
                marker=dict(size=8),
                error_y=dict(type="data", array=d[sd_key], visible=True),
                hovertemplate="%{x}<br>" + label + ": %{y:.4f}<extra>%{fullData.name}</extra>",
            ))
        fig.update_layout(title=label, xaxis_title="Benign training rows", yaxis=dict(range=[0, 1], title=None))
        with col:
            st.plotly_chart(base_layout(fig, height=330), use_container_width=True, config={"displayModeBar": False})

with coverage_tab:
    st.markdown("#### Per-attack recall · 50k training rows")
    st.caption("Hover a cell for exact recall and unique test support. Very small classes are descriptive only.")
    attack_names = [row[0] for row in ATTACKS]
    support = [row[1] for row in ATTACKS]
    z = [[row[2][j] for j in range(3)] for row in ATTACKS]
    hover = [
        [f"{attack_names[i]}<br>{MODELS[j]}<br>Recall: {z[i][j]:.1f}%<br>Unique test support: {support[i]}" for j in range(3)]
        for i in range(len(ATTACKS))
    ]
    fig = go.Figure(go.Heatmap(
        z=z,
        x=["Isolation Forest", "LOF", "One-Class SVM"],
        y=attack_names,
        zmin=0, zmax=100,
        colorscale=[[0, "#182536"], [0.35, "#287b80"], [0.7, "#43b58c"], [1, "#d6e96d"]],
        text=[[f"{v:.1f}%" for v in row] for row in z],
        texttemplate="%{text}",
        textfont=dict(size=10),
        customdata=hover,
        hovertemplate="%{customdata}<extra></extra>",
        colorbar=dict(title="Recall", ticksuffix="%"),
    ))
    fig.update_layout(
        height=510,
        margin=dict(l=8, r=8, t=22, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#dce7f2", size=11),
        yaxis=dict(autorange="reversed", title=None),
        xaxis=dict(side="top", title=None),
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.caption("Heartbleed is absent from this shared test sample. No recall estimate is available for it.")

# Keep methodology out of the main visual path.
with st.expander("Experiment details & limitations"):
    st.markdown(
        """
        **Protocol**
        - Three unsupervised detectors trained on benign-only data.
        - 5k / 25k / 50k nested training sizes; three seeds (42, 43, 44).
        - Shared 5k benign calibration sample and shared 15k held-out test sample.
        - Threshold selected from the upper 5% anomaly-score tail of benign calibration data.
        - Exact duplicate feature groups separated across partitions; this cleaned Parquet has no timestamps or five-tuple metadata.

        **Interpretation**
        - RBF One-Class SVM leads AP and F1; LOF leads ROC-AUC at 25k and 50k.
        - Isolation Forest is retained as the integrated application detector due to much lower measured runtime and existing downstream integration.
        - One fixed test sample is reused across seeds, so standard deviations capture training/model variation, not independent test-set uncertainty.
        - This is a CICIDS2017 flow-level comparison, not external-network or production validation. A 5% false-positive target is not a suitable production alert threshold without further low-FPR calibration.
        """
    )
    st.markdown(
        "[Full benchmark report](https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/hardened-model-selection-results/research/HARDENED_SCALING_VALIDATION_2026-11-12.md) · "
        "[Completed benchmark workflow](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860)"
    )

st.caption("CICIDS2017 hardened paired benchmark · 12 Nov 2026 · not a production performance guarantee.")
