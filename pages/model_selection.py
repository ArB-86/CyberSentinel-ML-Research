from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="CyberSentinel | Model Selection",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------
# Visual system
# ---------------------------------------------------------------------
st.markdown(
    """
    <style>
    .stApp { background:#070c13; color:#edf3fa; }
    [data-testid="stSidebar"] { background:#0b1420; border-right:1px solid #1e3042; }
    .block-container { max-width:1500px; padding-top:1.5rem; padding-bottom:3rem; }
    .eyebrow { color:#78a9d8; font-size:.68rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
    .muted { color:#8798ad; }
    .hero { border:1px solid #29435c; border-radius:16px; padding:22px; background:linear-gradient(115deg,#102033,#0d1724 60%,#0b121c); }
    .hero-title { font-size:1.55rem; font-weight:850; color:#f0f6ff; }
    .hero-copy { color:#a1b1c4; font-size:.86rem; line-height:1.6; margin-top:8px; }
    .pill { display:inline-block; padding:5px 9px; margin:4px 5px 0 0; border-radius:20px; font-size:.68rem; font-weight:750; border:1px solid #35516b; background:#112438; color:#c3e2ff; }
    div[data-testid="stMetric"] { background:#0e1722; border:1px solid #26384b; padding:12px 14px; border-radius:12px; }
    div[data-testid="stMetricLabel"] { color:#92a3b7; }
    div[data-testid="stMetricValue"] { color:#eff6ff; }
    .note { border:1px solid #2a4055; border-left:3px solid #65a7ff; border-radius:10px; padding:12px 15px; background:#0b1723; color:#a7b8ca; font-size:.82rem; line-height:1.55; }
    .paper { background:#0d1722; border:1px solid #26384b; border-radius:12px; padding:15px; min-height:150px; }
    .paper-title { color:#e8f1fb; font-weight:800; font-size:.9rem; }
    .paper-copy { color:#91a2b6; font-size:.76rem; line-height:1.5; margin-top:7px; }
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

# ---------------------------------------------------------------------
# Hardened paired CICIDS2017 benchmark: means +/- sample SD, 3 seeds.
# Source: research/HARDENED_SCALING_VALIDATION_2026-11-12.md
# ---------------------------------------------------------------------
SIZES = ["5k", "25k", "50k"]
MODELS = ["Isolation Forest", "LOF (novelty)", "RBF One-Class SVM"]
COLORS = {
    "Isolation Forest": "#35c58b",
    "LOF (novelty)": "#e6ad54",
    "RBF One-Class SVM": "#65a7ff",
}
D = {
    "Isolation Forest": {
        "roc":[.8874,.8866,.8848], "roc_sd":[.0023,.0027,.0039],
        "ap":[.6793,.6725,.6736], "ap_sd":[.0114,.0070,.0185],
        "precision":[.7046,.6978,.7048], "recall":[.6786,.6642,.6855],
        "f1":[.6912,.6803,.6948], "f1_sd":[.0275,.0246,.0269],
        "fpr":[5.05,5.10,5.09], "fpr_sd":[.08,.11,.07],
        "fit":[.274,.338,.411], "fit_sd":[.008,.005,.002],
        "score":[.104,.103,.104], "score_sd":[.003,.001,.001],
    },
    "LOF (novelty)": {
        "roc":[.8899,.9084,.9087], "roc_sd":[.0136,.0034,.0052],
        "ap":[.5624,.5576,.5687], "ap_sd":[.0290,.0161,.0120],
        "precision":[.6170,.6380,.6553], "recall":[.4314,.4588,.5129],
        "f1":[.5053,.5335,.5740], "f1_sd":[.1072,.0237,.0646],
        "fpr":[4.60,4.62,4.74], "fpr_sd":[.09,.16,.18],
        "fit":[.106,1.966,7.576], "fit_sd":[.011,.003,.031],
        "score":[.290,1.253,2.313], "score_sd":[.003,.101,.019],
    },
    "RBF One-Class SVM": {
        "roc":[.8514,.8439,.8430], "roc_sd":[.0051,.0084,.0104],
        "ap":[.7486,.7620,.7665], "ap_sd":[.0023,.0013,.0029],
        "precision":[.7293,.7222,.7225], "recall":[.7436,.7430,.7446],
        "f1":[.7363,.7324,.7334], "f1_sd":[.0005,.0032,.0014],
        "fpr":[4.90,5.08,5.08], "fpr_sd":[.01,.15,.10],
        "fit":[.096,2.383,19.484], "fit_sd":[.003,.012,2.168],
        "score":[.230,1.024,2.106], "score_sd":[.007,.003,.065],
    },
}
ATTACKS = [
    ("Bot",11,0.0,0.0,0.0),
    ("DDoS",849,55.9,58.5,63.6),
    ("DoS GoldenEye",61,49.2,31.7,78.7),
    ("DoS Hulk",1164,85.5,51.1,89.2),
    ("DoS Slowhttptest",38,76.3,26.3,81.6),
    ("DoS slowloris",43,48.1,20.2,55.8),
    ("FTP-Patator",42,0.0,23.8,0.0),
    ("PortScan",17,11.8,7.8,23.5),
    ("SSH-Patator",22,0.0,86.4,0.0),
    ("Web Brute Force",10,0.0,0.0,0.0),
    ("SQL Injection",1,0.0,0.0,0.0),
    ("XSS",5,0.0,6.7,0.0),
]

def style_fig(fig, height=330):
    fig.update_layout(
        height=height, margin=dict(l=12,r=12,t=48,b=18),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#dce7f2",size=11),
        legend=dict(orientation="h",yanchor="bottom",y=1.02,x=0),
        hoverlabel=dict(bgcolor="#101b28",font_color="#f0f6ff"),
    )
    fig.update_xaxes(showgrid=False,zeroline=False,color="#95a6bb")
    fig.update_yaxes(gridcolor="rgba(140,160,185,.13)",zeroline=False,color="#95a6bb")
    return fig

def grouped_metric(metric, title, size_index=2):
    fig=go.Figure()
    for model in MODELS:
        val=D[model][metric][size_index]
        fig.add_trace(go.Bar(
            x=[model],y=[val],name=model,marker_color=COLORS[model],
            text=[f"{val:.4f}"],textposition="outside",cliponaxis=False,
            hovertemplate="%{x}<br>"+title+": %{y:.4f}<extra></extra>",
        ))
    fig.update_layout(title=title,showlegend=False,yaxis=dict(range=[0,1.08],title=None))
    return style_fig(fig,300)

# ---------------------------------------------------------------------
# Header / key result
# ---------------------------------------------------------------------
st.markdown('<div class="eyebrow">MODEL LAB · CICIDS2017 · RESEARCH EVIDENCE</div>',unsafe_allow_html=True)
st.title("Model Selection & Evidence")
st.caption("A transparent comparison of three benign-only anomaly detectors, their measured results and the research behind their selection.")

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">THE RESULT — NOT A FORCED WINNER</div>
      <div class="hero-title">Each detector wins on a different dimension.</div>
      <div class="hero-copy">
        <b>RBF One-Class SVM</b> leads Average Precision and F1.
        <b>LOF</b> leads ROC-AUC at 25k and 50k.
        <b>Isolation Forest</b> has the lowest measured fit and scoring time.
        The UI reports the measured winner for each metric instead of labelling one model universally best.
      </div>
      <span class="pill">3 independent seeds · 42 / 43 / 44</span>
      <span class="pill">5k / 25k / 50k benign-only training</span>
      <span class="pill">Shared 15k held-out test sample</span>
      <span class="pill">Shared 5k benign calibration sample</span>
    </div>
    """,
    unsafe_allow_html=True,
)

m1,m2,m3,m4=st.columns(4)
m1.metric("AP leader · 50k","0.7665","RBF One-Class SVM")
m2.metric("F1 leader · 50k","0.7334","RBF One-Class SVM")
m3.metric("ROC-AUC leader · 50k","0.9087","LOF novelty")
m4.metric("Fastest score · 15k","0.104 s","Isolation Forest")

st.markdown(
    '<div class="note"><b>Fair-comparison protocol:</b> all three unsupervised models were fitted on benign-only observations, used the same nested training sizes, shared benign calibration sample and shared held-out test observations. Thresholds target the upper 5% tail of each model’s benign calibration scores. Results are means ± sample standard deviations across three seeds.</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------
quality_tab, scale_tab, attacks_tab, why_tab, literature_tab, protocol_tab = st.tabs([
    "Detection quality", "Training-size trends", "Attack-family coverage",
    "Why these 3 models", "Research evidence", "Protocol & limitations"
])

with quality_tab:
    st.subheader("Measured detection quality · 50,000 benign training rows")
    st.caption("Higher is better for ROC-AUC, AP and F1. FPR is shown separately because lower is better.")
    a,b,c=st.columns(3)
    with a: st.plotly_chart(grouped_metric("ap","Average Precision (AP)"),use_container_width=True,config={"displayModeBar":False})
    with b: st.plotly_chart(grouped_metric("f1","Attack F1"),use_container_width=True,config={"displayModeBar":False})
    with c: st.plotly_chart(grouped_metric("roc","ROC-AUC"),use_container_width=True,config={"displayModeBar":False})
    rows=[]
    for model in MODELS:
        d=D[model]
        rows.append({
            "Model":model,
            "ROC-AUC":f"{d['roc'][2]:.4f} ± {d['roc_sd'][2]:.4f}",
            "AP":f"{d['ap'][2]:.4f} ± {d['ap_sd'][2]:.4f}",
            "Precision":f"{d['precision'][2]:.4f}",
            "Recall":f"{d['recall'][2]:.4f}",
            "F1":f"{d['f1'][2]:.4f} ± {d['f1_sd'][2]:.4f}",
            "Test FPR":f"{d['fpr'][2]:.2f}% ± {d['fpr_sd'][2]:.2f}%",
        })
    st.dataframe(pd.DataFrame(rows),use_container_width=True,hide_index=True)
    st.markdown("#### What the results actually establish")
    st.markdown("""
    - **SVM leads AP and F1 at all three training sizes** in this benchmark.
    - **LOF leads ROC-AUC at 25k and 50k**, but its AP and thresholded F1 are lower.
    - **Isolation Forest is not the detection-quality winner** on AP/F1 or ROC-AUC at 50k. It is the runtime winner.
    - Test FPR is close to the shared nominal 5% calibration target for all three methods.
    """)
    st.warning("Do not describe Isolation Forest as the most accurate model on this CICIDS2017 experiment. The measured AP/F1 leader is RBF One-Class SVM.")

with scale_tab:
    st.subheader("Does the ranking change as benign training data increases?")
    st.caption("Nested benign-only training subsets · means across seeds 42, 43 and 44 · error bars show sample standard deviation.")
    left,right=st.columns(2)
    for col,metric,label,sdkey in [
        (left,"ap","Average Precision (AP)","ap_sd"),
        (right,"f1","Attack F1","f1_sd"),
    ]:
        fig=go.Figure()
        for model in MODELS:
            d=D[model]
            fig.add_trace(go.Scatter(
                x=SIZES,y=d[metric],mode="lines+markers",name=model,
                line=dict(color=COLORS[model],width=3),marker=dict(size=8),
                error_y=dict(type="data",array=d[sdkey],visible=True),
                hovertemplate="%{x}<br>"+label+": %{y:.4f}<extra>%{fullData.name}</extra>",
            ))
        fig.update_layout(title=label,yaxis=dict(range=[0,1],title=None),xaxis_title="Benign training rows")
        with col: st.plotly_chart(style_fig(fig,350),use_container_width=True,config={"displayModeBar":False})
    st.subheader("Runtime versus training size")
    st.caption("Observed wall-clock time on the benchmark GitHub Actions runner; not a universal hardware guarantee.")
    l,r=st.columns(2)
    for col,metric,label in [(l,"fit","Fit time"),(r,"score","Score 15,000 held-out flows")]:
        fig=go.Figure()
        for model in MODELS:
            d=D[model]
            fig.add_trace(go.Scatter(
                x=SIZES,y=d[metric],mode="lines+markers",name=model,
                line=dict(color=COLORS[model],width=3),marker=dict(size=8),
                error_y=dict(type="data",array=d[metric+"_sd"],visible=True),
                hovertemplate="%{x}<br>"+label+": %{y:.3f} s<extra>%{fullData.name}</extra>",
            ))
        fig.update_layout(title=label,yaxis_title="Seconds")
        with col: st.plotly_chart(style_fig(fig,350),use_container_width=True,config={"displayModeBar":False})
    d_if=D["Isolation Forest"]; d_svm=D["RBF One-Class SVM"]
    x,y=st.columns(2)
    x.metric("IF fit-time advantage at 50k",f"{d_svm['fit'][2]/d_if['fit'][2]:.1f}×","vs RBF One-Class SVM")
    y.metric("IF scoring advantage at 50k",f"{d_svm['score'][2]/d_if['score'][2]:.1f}×","vs RBF One-Class SVM")

with attacks_tab:
    st.subheader("Per-attack recall · 50k benign training rows")
    st.caption("Pooled recall across three seeds. Unique support is shown to expose low-sample categories.")
    names=[r[0] for r in ATTACKS]
    supports=[r[1] for r in ATTACKS]
    z=[[r[2],r[3],r[4]] for r in ATTACKS]
    custom=[[f"{names[i]}<br>Unique test support: {supports[i]}<br>{MODELS[j]} recall: {z[i][j]:.1f}%" for j in range(3)] for i in range(len(ATTACKS))]
    fig=go.Figure(go.Heatmap(
        z=z,x=MODELS,y=names,zmin=0,zmax=100,
        colorscale=[[0,"#182536"],[.35,"#287b80"],[.7,"#43b58c"],[1,"#d6e96d"]],
        text=[[f"{v:.1f}%" for v in row] for row in z],texttemplate="%{text}",
        customdata=custom,hovertemplate="%{customdata}<extra></extra>",
        colorbar=dict(title="Recall",ticksuffix="%"),
    ))
    fig.update_layout(height=520,margin=dict(l=8,r=8,t=20,b=10),paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(color="#dce7f2",size=11),yaxis=dict(autorange="reversed"),xaxis=dict(side="top"))
    st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
    st.warning("Small supports make several class-level percentages unstable. In this sample, SVM misses the sampled FTP-Patator and SSH-Patator rows; LOF detects some of them. Aggregate AP/F1 does not imply uniform attack-family coverage.")

with why_tab:
    st.subheader("Why these three algorithms were selected")
    st.caption("Three distinct anomaly-detection hypotheses, evaluated under one shared protocol.")
    c1,c2,c3=st.columns(3)
    with c1:
        st.markdown("### Isolation Forest")
        st.markdown("**Isolation-based**")
        st.markdown("Tests whether rare, distinctive observations can be separated by short random-partition paths.")
        st.markdown("- Benign-only fitting")
        st.markdown("- Random isolation-tree ensemble")
        st.markdown("- Included as the project’s original detector and a strong research baseline")
        st.markdown("**Observed here:** stable AP around 0.67; fastest fit and scoring at all tested sizes.")
    with c2:
        st.markdown("### LOF (novelty)")
        st.markdown("**Local-density-based**")
        st.markdown("Tests whether a flow is locally sparse relative to its nearest benign neighbours.")
        st.markdown("- Benign-only reference neighbourhood")
        st.markdown("- Local reachability-density comparison")
        st.markdown("- Tests local deviations that global isolation may rank differently")
        st.markdown("**Observed here:** highest ROC-AUC at 25k/50k; lower AP and F1 at the selected operating point.")
    with c3:
        st.markdown("### RBF One-Class SVM")
        st.markdown("**Boundary-based**")
        st.markdown("Tests whether a nonlinear support boundary around benign traffic separates anomalous flows.")
        st.markdown("- Benign-only fitting")
        st.markdown("- RBF kernel; StandardScaler")
        st.markdown("- Tests nonlinear normal-region estimation")
        st.markdown("**Observed here:** highest AP and F1 at 5k, 25k and 50k.")
    st.markdown("---")
    st.markdown("#### Why compare rather than assume one method?")
    st.markdown("The three detectors operationalise different definitions of unusual traffic: isolation, local density and a learned normal-region boundary. A shared evaluation shows which assumption is most useful for this dataset and metric, rather than assuming the algorithm with the strongest reputation will win.")
    st.info("Selection rationale is not the same as a claim of superiority. The benchmark's metric-wise winners are shown in the Detection Quality tab.")

with literature_tab:
    st.subheader("Primary research references")
    st.caption("Original papers support the algorithmic foundations. The CICIDS2017 benchmark in this project supplies the project-specific performance evidence.")
    papers=[
        ("Isolation Forest — original method","Liu, Ting & Zhou (2008), “Isolation Forest”, IEEE ICDM. Introduces isolation-based anomaly detection and its subsampling design.","https://doi.org/10.1109/ICDM.2008.17","Algorithm foundation"),
        ("Isolation-based Anomaly Detection","Liu, Ting & Zhou (2012), ACM TKDD. Extended empirical study of isolation-based detection and comparisons with established anomaly detectors.","https://doi.org/10.1145/2133360.2133363","Comparative empirical literature"),
        ("Local Outlier Factor","Breunig et al. (2000), ACM SIGMOD. Introduces local-density-based outlier scoring using reachability density.","https://www.dbs.ifi.lmu.de/Publikationen/Papers/LOF.pdf","Algorithm foundation"),
        ("One-Class SVM","Schölkopf et al. (2001), Neural Computation. Develops support estimation for high-dimensional distributions.","https://doi.org/10.1162/089976601750264965","Algorithm foundation"),
        ("Unsupervised IDS generalisation","Verkerken et al. (2022), study of unsupervised intrusion-detection methods and cross-dataset generalisation using CICIDS2017 and CSE-CIC-IDS2018.","https://pmc.ncbi.nlm.nih.gov/articles/PMC8520582/","Cybersecurity-specific evidence"),
    ]
    for title,desc,url,tag in papers:
        st.markdown(
            f'<div class="paper"><div class="eyebrow">{tag}</div><div class="paper-title">{title}</div><div class="paper-copy">{desc}</div><div style="margin-top:9px"><a href="{url}" target="_blank" style="color:#78baff;font-weight:750">Open paper ↗</a></div></div>',
            unsafe_allow_html=True,
        )
    st.markdown("---")
    st.markdown("#### How to read the evidence")
    st.markdown("""
    - Original papers justify **why each method is a legitimate algorithmic candidate**.
    - Published comparative studies show that relative performance depends on the dataset and evaluation protocol.
    - Our own paired CICIDS2017 experiment decides which method performed best **in this project**.
    - A paper reporting Isolation Forest wins on another dataset does not override our measured SVM AP/F1 lead.
    """)

with protocol_tab:
    st.subheader("Benchmark design")
    p1,p2,p3,p4=st.columns(4)
    p1.metric("Dataset rows","2,228,970")
    p2.metric("Numeric features","69")
    p3.metric("Seeds","3","42 · 43 · 44")
    p4.metric("Test sample","15,000","shared across models")
    st.markdown("""
    **Data and split**
    - CICIDS2017 processed Parquet v1.0.1; SHA-256 verified before the benchmark.
    - StratifiedGroupKFold, 7 folds, seed 42; grouping by exact numeric-feature hashes.
    - Exact duplicate feature groups had zero overlap across train, validation and test.
    - The cleaned Parquet has no flow IDs, IP addresses, ports or timestamps; this run cannot establish connection-level or temporal independence.

    **Training and thresholding**
    - Unsupervised models fit benign-only observations at nested sizes of 5,000, 25,000 and 50,000.
    - One shared 5,000-row benign calibration sample and one shared binary-stratified 15,000-row test sample.
    - Threshold set from the upper 5% tail of each model's benign calibration scores.
    - Isolation Forest: 200 trees, max_samples=1,024.
    - LOF: novelty=True, 35 neighbours, StandardScaler.
    - One-Class SVM: RBF kernel, nu=0.05, gamma=scale, StandardScaler, 512 MB cache.
    """)
    st.warning("Limitations: one processed CICIDS2017 release; one shared test sample reused across seeds; no temporal or connection-level split; low support for several rare attack families. The benchmark is flow-level evidence, not proof of generalisation to live networks.")
    st.markdown("[Open full reproducibility results and raw artifacts](https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/hardened-model-selection-results/research/HARDENED_SCALING_VALIDATION_2026-11-12.md)")

st.caption("Source: hardened paired CICIDS2017 benchmark, executed 12 Nov 2026. Means ± sample SD over seeds 42, 43 and 44. Runtime measurements are specific to the benchmark runner.")
