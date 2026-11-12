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

st.markdown(
    """
    <style>
    .stApp { background: #070b11; color: #edf3fa; }
    [data-testid="stSidebar"] { background: #0b121c; border-right: 1px solid #1d2b3c; }
    .block-container { max-width: 1500px; padding-top: 2rem; padding-bottom: 4rem; }
    .smallcaps { color: #6f9fc8; font-size: .7rem; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; }
    .subtitle { color: #8190a3; font-size: .92rem; margin-top: -.45rem; }
    .card { background: linear-gradient(145deg, #0f1823, #0b121b); border: 1px solid #26374b; border-radius: 14px; padding: 18px; min-height: 112px; }
    .label { color: #8190a3; font-size: .66rem; font-weight: 800; letter-spacing: .13em; text-transform: uppercase; }
    .value { font-size: 1.55rem; font-weight: 800; margin-top: 7px; color: #edf3fa; }
    .desc { color: #718196; font-size: .75rem; margin-top: 5px; line-height: 1.45; }
    .hero { background: radial-gradient(circle at 85% 0%, rgba(73,168,255,.13), transparent 38%), #0b141f; border: 1px solid #263b51; border-radius: 16px; padding: 24px; }
    .callout { border: 1px solid #234c6a; border-left: 3px solid #49a8ff; background: #0b1824; border-radius: 10px; padding: 13px 15px; color: #91abc1; font-size: .82rem; line-height: 1.55; }
    .warning { border: 1px solid #66511d; border-left: 3px solid #e9c46a; background: #19160c; border-radius: 10px; padding: 13px 15px; color: #b8aa83; font-size: .82rem; line-height: 1.55; }
    .rule { height: 1px; background: #1c2938; margin: 28px 0; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel")
    st.divider()
    st.markdown('<div class="smallcaps">Overview</div>', unsafe_allow_html=True)
    st.page_link("app.py", label="Dashboard")
    st.markdown('<div class="smallcaps" style="margin-top:18px">Detection</div>', unsafe_allow_html=True)
    st.page_link("pages/attack_detection.py", label="Attack Detection")
    st.page_link("pages/model_selection.py", label="Model Selection & Evidence")
    st.markdown('<div class="smallcaps" style="margin-top:18px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Event Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")
    st.markdown('<div class="smallcaps" style="margin-top:18px">Agentic Investigation & Risk Assessment</div>', unsafe_allow_html=True)
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")

st.markdown('<div class="smallcaps">Research & Model Governance</div>', unsafe_allow_html=True)
st.title("Comparative Model Analysis")
st.markdown(
    '<div class="subtitle">Why Isolation Forest is the application detector, what the controlled benchmark measured, and where the alternatives performed better.</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="smallcaps">APPLICATION MODEL</div>
      <div style="font-size:1.35rem;font-weight:800;margin-top:7px">Isolation Forest remains the active detector</div>
      <div style="color:#8190a3;font-size:.84rem;line-height:1.55;margin-top:7px">
        The completed hardened paired study records higher Average Precision and F1 for RBF One-Class SVM,
        higher ROC-AUC for LOF at 25k and 50k training rows, and substantially lower fit/scoring time for
        Isolation Forest. Isolation Forest remains the integrated application detector for its measured
        runtime and existing downstream integration; this is an operational choice, not a claim that it
        leads detection quality.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("")
st.markdown(
    """
    <div class="callout">
      <b>Validation status: HARDENED RERUN COMPLETE · 12 NOVEMBER 2026.</b>
      The current comparison loaders were rerun on the checksum-verified CICIDS2017 Parquet
      (2,228,970 rows; 69 numeric features; SHA-256
      <code>9401495356b1b6f360d6aebf0ad7ddc18a39cbf02c02f7461338dea02a747146</code>).
      Results below use the hardened feature schema, training-subset-only median imputation,
      three seeds (42, 43, 44), 5k/25k/50k nested benign training samples, a shared 5k benign
      calibration sample, and a shared 15k held-out test sample. These are CICIDS2017 benchmark
      results, not a production performance guarantee. The older single-model Isolation Forest
      metrics on the Attack Detection page use another evaluation protocol and are not directly comparable.
      <a href="https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860" target="_blank">Open completed workflow and outputs</a>.
    </div>
    """,
    unsafe_allow_html=True,
)

# Hardened paired validation: mean and sample standard deviation across seeds 42, 43 and 44.
TRAIN_SIZES = [5000, 25000, 50000]
MODEL_DATA = {
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

MODEL_ORDER = ["Isolation Forest", "LOF", "RBF One-Class SVM"]

rows = []
for model_name in MODEL_ORDER:
    d = MODEL_DATA[model_name]
    for i, n in enumerate(TRAIN_SIZES):
        rows.append({
            "Model": model_name,
            "Benign train rows": f"{n:,}",
            "ROC-AUC (mean ± SD)": f"{d['roc'][i]:.4f} ± {d['roc_sd'][i]:.4f}",
            "Average Precision (mean ± SD)": f"{d['ap'][i]:.4f} ± {d['ap_sd'][i]:.4f}",
            "Precision (mean ± SD)": f"{d['precision'][i]:.4f} ± {d['precision_sd'][i]:.4f}",
            "Recall (mean ± SD)": f"{d['recall'][i]:.4f} ± {d['recall_sd'][i]:.4f}",
            "F1 (mean ± SD)": f"{d['f1'][i]:.4f} ± {d['f1_sd'][i]:.4f}",
            "Test FPR (mean ± SD)": f"{d['fpr'][i]:.2f}% ± {d['fpr_sd'][i]:.2f}%",
        })

quality_tab, runtime_tab, method_tab, references_tab = st.tabs(
    ["Detection quality", "Runtime & scale", "Model-selection rationale", "Research references"]
)

with quality_tab:
    st.markdown("### Hardened result at 50,000 benign training rows")
    kpi_cols = st.columns(4)
    kpis = [
        ("Highest AP", "0.7665", "RBF One-Class SVM"),
        ("Highest F1", "0.7334", "RBF One-Class SVM"),
        ("Highest ROC-AUC", "0.9087", "LOF"),
        ("Lowest test scoring time", "0.104 s", "Isolation Forest · 15k test rows"),
    ]
    for col, (label, value, note) in zip(kpi_cols, kpis):
        with col:
            st.markdown(
                f'<div class="card"><div class="label">{label}</div>'
                f'<div class="value">{value}</div><div class="desc">{note}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("#### Paired comparison results")
    st.caption("Hardened run completed 12 Nov 2026: mean ± sample SD across seeds 42, 43 and 44. Average Precision (AP) is the PR-AUC summary reported by the experiment.")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    chart_left, chart_right = st.columns(2)
    with chart_left:
        fig_ap = go.Figure()
        for model_name in MODEL_ORDER:
            d = MODEL_DATA[model_name]
            fig_ap.add_trace(go.Scatter(
                x=["5k", "25k", "50k"],
                y=d["ap"],
                mode="lines+markers",
                name=model_name,
                error_y={"type": "data", "array": d["ap_sd"], "visible": True},
            ))
        fig_ap.update_layout(
            title="Average Precision vs benign training size",
            xaxis_title="Benign training rows",
            yaxis_title="Average Precision",
            yaxis_range=[0, 1],
            height=360,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0d151f",
            font={"color": "#dce7f2"},
            legend={"orientation": "h", "y": -0.25},
            margin={"l": 10, "r": 10, "t": 55, "b": 70},
        )
        st.plotly_chart(fig_ap, use_container_width=True, config={"displayModeBar": False})

    with chart_right:
        fig_f1 = go.Figure()
        for model_name in MODEL_ORDER:
            d = MODEL_DATA[model_name]
            fig_f1.add_trace(go.Scatter(
                x=["5k", "25k", "50k"],
                y=d["f1"],
                mode="lines+markers",
                name=model_name,
                error_y={"type": "data", "array": d["f1_sd"], "visible": True},
            ))
        fig_f1.update_layout(
            title="F1 vs benign training size",
            xaxis_title="Benign training rows",
            yaxis_title="F1",
            yaxis_range=[0, 1],
            height=360,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0d151f",
            font={"color": "#dce7f2"},
            legend={"orientation": "h", "y": -0.25},
            margin={"l": 10, "r": 10, "t": 55, "b": 70},
        )
        st.plotly_chart(fig_f1, use_container_width=True, config={"displayModeBar": False})

    st.markdown(
        '<div class="callout"><b>Interpretation:</b> RBF One-Class SVM led Average Precision and F1 at every tested training size. '
        'LOF led ROC-AUC at 25k and 50k. Isolation Forest did not win the quality leaderboard; it remained comparatively stable '
        'as the benign training set grew.</div>',
        unsafe_allow_html=True,
    )

    st.markdown("#### Per-attack recall at 50k benign training rows")
    attack_rows = [
        {"Attack family": "Bot", "Unique test support": 11, "Isolation Forest": "0.0%", "LOF": "0.0%", "RBF One-Class SVM": "0.0%"},
        {"Attack family": "DDoS", "Unique test support": 849, "Isolation Forest": "55.9%", "LOF": "58.5%", "RBF One-Class SVM": "63.6%"},
        {"Attack family": "DoS GoldenEye", "Unique test support": 61, "Isolation Forest": "49.2%", "LOF": "31.7%", "RBF One-Class SVM": "78.7%"},
        {"Attack family": "DoS Hulk", "Unique test support": 1164, "Isolation Forest": "85.5%", "LOF": "51.1%", "RBF One-Class SVM": "89.2%"},
        {"Attack family": "DoS Slowhttptest", "Unique test support": 38, "Isolation Forest": "76.3%", "LOF": "26.3%", "RBF One-Class SVM": "81.6%"},
        {"Attack family": "DoS slowloris", "Unique test support": 43, "Isolation Forest": "48.1%", "LOF": "20.2%", "RBF One-Class SVM": "55.8%"},
        {"Attack family": "FTP-Patator", "Unique test support": 42, "Isolation Forest": "0.0%", "LOF": "23.8%", "RBF One-Class SVM": "0.0%"},
        {"Attack family": "PortScan", "Unique test support": 17, "Isolation Forest": "11.8%", "LOF": "7.8%", "RBF One-Class SVM": "23.5%"},
        {"Attack family": "SSH-Patator", "Unique test support": 22, "Isolation Forest": "0.0%", "LOF": "86.4%", "RBF One-Class SVM": "0.0%"},
        {"Attack family": "Web Attack - Brute Force", "Unique test support": 10, "Isolation Forest": "0.0%", "LOF": "0.0%", "RBF One-Class SVM": "0.0%"},
        {"Attack family": "Web Attack - SQL Injection", "Unique test support": 1, "Isolation Forest": "0.0%", "LOF": "0.0%", "RBF One-Class SVM": "0.0%"},
        {"Attack family": "Web Attack - XSS", "Unique test support": 5, "Isolation Forest": "0.0%", "LOF": "6.7%", "RBF One-Class SVM": "0.0%"},
    ]
    st.dataframe(pd.DataFrame(attack_rows), use_container_width=True, hide_index=True)
    st.caption("Recall is pooled over three seeds on the same fixed 15k test rows. Unique test support is shown once (not tripled across seeds). Small-support rows are descriptive only; do not infer stable class-level generalisation.")


with runtime_tab:
    st.markdown("### Measured runtime on the experiment runner · hardened rerun")
    runtime_rows = []
    for model_name in MODEL_ORDER:
        d = MODEL_DATA[model_name]
        for i, n in enumerate(TRAIN_SIZES):
            runtime_rows.append({
                "Model": model_name,
                "Benign train rows": f"{n:,}",
                "Fit time (s)": d["fit"][i],
                "Fit time SD (s)": d["fit_sd"][i],
                "Test scoring time (s)": d["score"][i],
                "Scoring time SD (s)": d["score_sd"][i],
                "Test scoring rows": 15000,
            })
    runtime_df = pd.DataFrame(runtime_rows)
    st.dataframe(
        runtime_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Fit time (s)": st.column_config.NumberColumn(format="%.3f"),
            "Fit time SD (s)": st.column_config.NumberColumn(format="%.3f"),
            "Test scoring time (s)": st.column_config.NumberColumn(format="%.3f"),
            "Scoring time SD (s)": st.column_config.NumberColumn(format="%.3f"),
        },
    )

    st.markdown("#### 50k training-row comparison")
    if_fit = MODEL_DATA["Isolation Forest"]["fit"][-1]
    svm_fit = MODEL_DATA["RBF One-Class SVM"]["fit"][-1]
    if_score = MODEL_DATA["Isolation Forest"]["score"][-1]
    svm_score = MODEL_DATA["RBF One-Class SVM"]["score"][-1]
    speed_cols = st.columns(2)
    speed_cols[0].metric("Isolation Forest fit time", f"{if_fit:.3f} s", help="Mean wall-clock time on the GitHub Actions runner.")
    speed_cols[1].metric("RBF One-Class SVM fit time", f"{svm_fit:.3f} s", f"{svm_fit / if_fit:.1f}× IF time", delta_color="inverse")
    speed_cols[0].metric("Isolation Forest scoring time", f"{if_score:.3f} s", help="Scoring the same 15,000 held-out rows.")
    speed_cols[1].metric("RBF One-Class SVM scoring time", f"{svm_score:.3f} s", f"{svm_score / if_score:.1f}× IF time", delta_color="inverse")

    st.markdown(
        '<div class="warning"><b>Runtime qualification:</b> timings are from one GitHub Actions runner and a 15,000-row test-scoring batch. '
        'They are not target-hardware benchmarks or production throughput guarantees. A full memory/throughput assessment on deployment hardware remains open.</div>',
        unsafe_allow_html=True,
    )

with method_tab:
    st.markdown("### Why these three detectors?")
    method_rows = [
        {
            "Detector": "Isolation Forest",
            "Different assumption": "Global isolation by random partitions; unusual records are separated in fewer splits.",
            "Purpose in study": "Existing application detector and scalable isolation-based baseline.",
            "Key setup": "200 trees; max_samples=1,024; max_features=1.0.",
        },
        {
            "Detector": "LOF",
            "Different assumption": "Local reachability density; anomalies are sparse relative to nearby observations.",
            "Purpose in study": "Tests a local-density approach unlike global isolation.",
            "Key setup": "novelty=True; 35 neighbours; StandardScaler.",
        },
        {
            "Detector": "RBF One-Class SVM",
            "Different assumption": "Learns a nonlinear support boundary around benign observations.",
            "Purpose in study": "Tests kernel-based normal-region estimation.",
            "Key setup": "RBF kernel; nu=0.05; gamma=scale; StandardScaler.",
        },
    ]
    st.dataframe(pd.DataFrame(method_rows), use_container_width=True, hide_index=True)

    st.markdown("### Why retain Isolation Forest in the application?")
    st.markdown(
        """
        - **Measured 50k cost:** Isolation Forest fit in 0.411 s and scored the shared 15k test batch in 0.104 s. RBF One-Class SVM took 19.484 s to fit and 2.106 s to score; LOF took 7.576 s to fit and 2.313 s to score. These are means on one GitHub Actions runner, not deployment-hardware guarantees.
        - **Measured quality:** RBF One-Class SVM led Average Precision (0.7665) and F1 (0.7334); Isolation Forest recorded AP 0.6736 and F1 0.6948. LOF led ROC-AUC (0.9087) but had lower AP/F1 (0.5687 / 0.5740).
        - **Per-attack caveat:** at 50k, SVM had 0% recall on 42 unique FTP-Patator and 22 unique SSH-Patator test rows; LOF achieved 23.8% and 86.4% recall respectively. All three models had 0% recall on the 11 Bot and 10 Web Attack - Brute Force rows. Aggregate F1 does not imply coverage of every attack family.
        - **Existing integration:** the detection, event, graph and risk pipeline already consumes an Isolation Forest artifact. Replacing it requires end-to-end validation on metadata-rich traffic and target hardware.
        - **Decision status:** retain Isolation Forest as the current integrated detector for its measured throughput advantage, existing integration and lower operational cost—not because it wins AP/F1. Treat RBF One-Class SVM as the leading aggregate AP/F1 shadow candidate and LOF as a complementary ROC-AUC / SSH-Patator candidate—not as proven production replacements.
        """
    )


    st.markdown("### Deployment decision: separate quality from operational fit")
    decision_rows = [
        {
            "Decision dimension": "Average Precision / F1 on this CICIDS2017 test",
            "Measured leader": "RBF One-Class SVM",
            "Evidence at 50k": "AP 0.7665 · F1 0.7334",
            "Interpretation": "Best aggregate flow-quality candidate in this experiment; not an automatic deployment winner.",
        },
        {
            "Decision dimension": "ROC-AUC at 25k / 50k",
            "Measured leader": "LOF",
            "Evidence at 50k": "ROC-AUC 0.9087",
            "Interpretation": "Better overall ranking by ROC-AUC, but lower AP/F1 at the selected operating point.",
        },
        {
            "Decision dimension": "Fit and test-scoring cost at 50k",
            "Measured leader": "Isolation Forest",
            "Evidence at 50k": "0.411 s fit · 0.104 s / 15k rows",
            "Interpretation": "About 47.4× faster fit and 20.3× faster scoring than exact RBF One-Class SVM on this runner.",
        },
        {
            "Decision dimension": "Existing application integration",
            "Measured leader": "Isolation Forest",
            "Evidence at 50k": "Current detector artifact feeds detection → events → graph → risk",
            "Interpretation": "Changing the detector also requires end-to-end revalidation of downstream outputs.",
        },
        {
            "Decision dimension": "Production / external-network validation",
            "Measured leader": "None",
            "Evidence at 50k": "No temporal holdout, target-hardware test or independent network dataset",
            "Interpretation": "No algorithm is production-validated by this experiment.",
        },
    ]
    st.dataframe(pd.DataFrame(decision_rows), use_container_width=True, hide_index=True)

    st.markdown("### Why the SVM leaderboard is not the deployment decision")
    st.markdown(
        """
        The SVM's AP/F1 advantage is real **for this benchmark protocol**; it must remain visible.
        The limitation is interpreting that result as a deployment guarantee:

        - CICIDS2017 has about **15.09% attack flows**, and the 15k test sample preserves approximately that prevalence. Average Precision and precision depend on class prevalence; they cannot be copied unchanged into a network where malicious flows are much rarer.
        - Every detector was thresholded for a **5% benign calibration FPR**. That operating point can still create a large alert burden at network scale.
        - A single aggregate AP/F1 number does not describe attack-family blind spots. At 50k, SVM detected 0/42 unique FTP-Patator and 0/22 SSH-Patator test flows; LOF detected some of both. IF also missed both groups in this test.
        - This experiment reuses one test sample across seeds and has no temporal/five-tuple separation. It is a controlled CICIDS2017 sensitivity study, not an external-network trial.
        """
    )

    prevalence_rows = [
        {
            "Assumed attack prevalence": "15.09% · benchmark",
            "IF projected precision": "70.5%",
            "SVM projected precision": "72.3%",
            "IF false alerts / 1M flows": "43,243",
            "SVM false alerts / 1M flows": "43,154",
        },
        {
            "Assumed attack prevalence": "1.0% · hypothetical",
            "IF projected precision": "12.0%",
            "SVM projected precision": "12.9%",
            "IF false alerts / 1M flows": "50,419",
            "SVM false alerts / 1M flows": "50,315",
        },
        {
            "Assumed attack prevalence": "0.1% · hypothetical",
            "IF projected precision": "1.33%",
            "SVM projected precision": "1.45%",
            "IF false alerts / 1M flows": "50,877",
            "SVM false alerts / 1M flows": "50,772",
        },
    ]
    st.markdown("#### Illustrative alert-quality sensitivity to attack prevalence")
    st.dataframe(pd.DataFrame(prevalence_rows), use_container_width=True, hide_index=True)
    st.caption(
        "Illustration only—not observed deployment results. Projected precision uses the measured 50k mean TPR/FPR "
        "for each model and Bayes' rule, assuming those class-conditional rates remain unchanged as prevalence shifts. "
        "False alerts per million are FPR × benign flows. A real deployment can have different TPR/FPR due to domain shift."
    )
    st.markdown(
        """
        **Selection:** retain Isolation Forest as the current integrated detector because it is much cheaper to fit and
        score and is already wired into the downstream application. Run SVM as a shadow candidate for aggregate
        flow-quality improvement, and retain LOF as a complementary comparison. Do not promote any candidate until
        it is tested at much lower FPR targets with a substantially larger benign calibration set, realistic event
        prevalence, temporal/connection-aware holdouts, target-hardware throughput and downstream incident outcomes.
        """
    )

    st.markdown("### Why not compare every algorithm?")
    st.markdown(
        """
        This was a focused three-paradigm comparison, not an exhaustive algorithm leaderboard:
        - **Isolation Forest:** isolation-based detector (existing system baseline).
        - **LOF:** local-density detector, testing a different anomaly assumption.
        - **RBF One-Class SVM:** nonlinear support-estimation detector.
        
        The literature includes direct or dataset-relevant evaluations of these families. Autoencoders and PCA are valid future comparators, but require their own controlled architecture/threshold or reconstruction setup. Random Forest is a supervised reference trained with attack labels, so it is not a like-for-like unsupervised competitor.
        """
    )

    st.markdown(
        '<div class="warning"><b>Limits:</b> the processed Parquet permits exact-feature-duplicate grouping, but does not retain timestamps, IP addresses or ports. '
        'This is not a temporal or five-tuple holdout. The same 15k test sample is reused across seeds, so SD measures training-sample/model randomness—not independent test-set uncertainty. '
        'Rare attack families have small support (SQL Injection has only 3 test rows); Heartbleed is absent from this sampled test set. '
        'The experiment covers flow-level detection only, not downstream incident/graph/agent outcomes or external-network generalisation.</div>',
        unsafe_allow_html=True,
    )

with references_tab:
    st.markdown("### Primary model papers")
    references = [
        ("Isolation Forest", "Liu, Ting & Zhou (2008), Isolation Forest, IEEE ICDM.", "https://doi.org/10.1109/ICDM.2008.17"),
        ("Isolation-based anomaly detection", "Liu, Ting & Zhou (2012), Isolation-Based Anomaly Detection, ACM TKDD.", "https://doi.org/10.1145/2133360.2133363"),
        ("Local Outlier Factor", "Breunig et al. (2000), LOF: Identifying Density-Based Local Outliers, ACM SIGMOD.", "https://doi.org/10.1145/342009.335388"),
        ("One-Class SVM", "Schölkopf et al. (2001), Estimating the Support of a High-Dimensional Distribution, Neural Computation.", "https://doi.org/10.1162/089976601750264965"),
    ]
    for label, description, url in references:
        st.markdown(f"- **{label}:** {description} [Paper]({url})")

    st.markdown("### CICIDS / intrusion-detection comparative evidence")
    st.markdown(
        """
        - Verkerken et al. (2022), *Towards Model Generalization for Intrusion Detection: Unsupervised Machine Learning Techniques*. [DOI](https://doi.org/10.1007/s10922-021-09615-7) — evaluates Isolation Forest and One-Class SVM on CICIDS2017/CSE-CIC-IDS-2018 and discusses cross-dataset generalisation.
        - Xu & Liu (2025), *Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017*. [DOI](https://doi.org/10.1109/ICETIS66286.2025.11144025) · [arXiv](https://arxiv.org/abs/2506.19877) — compares LOF and One-Class SVM among other methods on CICIDS2017 in known/unseen attack settings.
        - Saito & Rehmsmeier (2015), *The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets*. [DOI](https://doi.org/10.1371/journal.pone.0118432) — supports reporting precision-recall behaviour alongside ROC-AUC for imbalanced data.
        """
    )

    st.markdown("### Reproducible project evidence")
    st.markdown(
        """
        - [Scaling validation report](https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/extended-validation/research/SCALING_VALIDATION_RESULTS.md)
        - [Research rationale and full evidence map](https://github.com/ArB-86/CyberSentinel-ML-Research/blob/research/extended-validation/research/RESEARCH_EVIDENCE_AND_MODEL_SELECTION.md)
        - [Raw per-seed metrics and plots](https://github.com/ArB-86/CyberSentinel-ML-Research/tree/research/extended-validation/experiments/results/scaling-validation-v1)
        - [Training workflow run](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/42521225029)
        """
    )

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.caption(
    "Source: hardened CICIDS2017 scaling validation completed 12 Nov 2026, 2,228,970 records / 69 numeric features. "
    "Dataset checksum verified before the run. Three seeds (42, 43, 44), duplicate-feature-grouped split, "
    "shared 5,000-benign calibration sample, shared 15,000-row test sample, and benign-only training budgets "
    "of 5k / 25k / 50k. Means ± sample standard deviations; one benchmark dataset and one runner. "
    "Run details and raw outputs: https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860."
)
