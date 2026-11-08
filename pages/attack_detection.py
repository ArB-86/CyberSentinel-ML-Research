import streamlit as st
from pathlib import Path

import pandas as pd
import numpy as np
import plotly.graph_objects as go


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberSentinel | Attack Detection",
    layout="wide",
)


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent.parent

# Outputs folder path
OUTPUT_DIR = ROOT / "outputs"

SUSPICIOUS_PATH = OUTPUT_DIR / "suspicious_flows_with_metadata.csv"
SUMMARY_PATH = OUTPUT_DIR / "pipeline_summary.json"


# ============================================================
# GLOBAL STYLING
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

    [data-testid="stSidebar"] {
        background: #0b121c;
        border-right: 1px solid #1d2b3c;
    }

    .smallcaps {
        color: #6f9fc8;
        font-size: .7rem;
        font-weight: 800;
        letter-spacing: .18em;
        text-transform: uppercase;
    }

    .subtitle {
        color: #8190a3;
        font-size: .92rem;
        margin-top: -.5rem;
    }

    .card {
        background: linear-gradient(145deg, #0f1823, #0b121b);
        border: 1px solid #26374b;
        border-radius: 14px;
        padding: 18px;
        min-height: 110px;
    }

    .label {
        color: #8190a3;
        font-size: .66rem;
        font-weight: 800;
        letter-spacing: .13em;
        text-transform: uppercase;
    }

    .value {
        font-size: 1.5rem;
        font-weight: 800;
        margin-top: 7px;
    }

    .desc {
        color: #718196;
        font-size: .75rem;
        margin-top: 5px;
        line-height: 1.4;
    }

    .hero {
        background:
            radial-gradient(
                circle at 85% 0%,
                rgba(73,168,255,.13),
                transparent 38%
            ),
            #0b141f;
        border: 1px solid #263b51;
        border-radius: 16px;
        padding: 24px;
    }

    .badge {
        display: inline-block;
        border: 1px solid #28506d;
        background: #0b1a27;
        color: #8fd7ff;
        border-radius: 999px;
        padding: 7px 11px;
        font-size: .72rem;
        font-weight: 800;
    }

    .green {
        color: #32d296;
    }

    .amber {
        color: #f0b35a;
    }

    .blue {
        color: #49a8ff;
    }

    .rule {
        height: 1px;
        background: #1c2938;
        margin: 30px 0;
    }

    .callout {
        border: 1px solid #234c6a;
        border-left: 3px solid #49a8ff;
        background: #0b1824;
        border-radius: 10px;
        padding: 13px 15px;
        color: #91abc1;
        font-size: .8rem;
        line-height: 1.5;
    }

    .method-box {
        background: #0c151f;
        border: 1px solid #213246;
        border-radius: 12px;
        padding: 15px;
        height: 100%;
    }

    .method-title {
        font-size: .85rem;
        font-weight: 800;
        margin-top: 6px;
    }

    .method-text {
        color: #718196;
        font-size: .7rem;
        line-height: 1.45;
        margin-top: 5px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# LOAD PIPELINE SUMMARY
# ============================================================

@st.cache_data
def load_pipeline_summary():

    if not SUMMARY_PATH.exists():
        return {}

    try:
        import json

        with open(
            SUMMARY_PATH,
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)

    except Exception:
        return {}


# ============================================================
# LOAD SUSPICIOUS FLOWS
# ============================================================

@st.cache_data
def load_suspicious_flows():

    paths = [
        # Correct path pointing to your outputs/ folder
        OUTPUT_DIR / "suspicious_flows_with_metadata.csv",
        
        # Keep backups in case it's run from different working directories
        ROOT / "attack_graph_output" / "suspicious_flows_with_metadata.csv",
        ROOT / "suspicious_flows_with_metadata.csv",
    ]

    for path in paths:

        if path.exists():

            try:
                # Load a manageable preview instead of
                # loading the complete large CSV.
                df = pd.read_csv(
                    path,
                    nrows=100_000
                )

                return df, path

            except Exception:
                pass

    return None, None


@st.cache_data
def count_csv_rows(path):

    if path is None or not path.exists():
        return None

    try:

        with open(path, "rb") as f:
            return max(
                0,
                sum(1 for _ in f) - 1
            )

    except Exception:
        return None

@st.cache_data
def load_detection_metrics():
    path = OUTPUT_DIR / "detection_metrics.json"
    if not path.exists():
        return {}
    try:
        import json
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}


@st.cache_data
def load_per_attack_evaluation():
    path = OUTPUT_DIR / "per_attack_detection_evaluation.csv"
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


pipeline_summary = load_pipeline_summary()
detection_metrics = load_detection_metrics()
per_attack_evaluation = load_per_attack_evaluation()

suspicious_df, suspicious_file = (
    load_suspicious_flows()
)

suspicious_count = pipeline_summary.get(
    "suspicious_flows"
)

if suspicious_count is None:
    suspicious_count = count_csv_rows(
        suspicious_file
    )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ CyberSentinel")

    st.divider()

    st.markdown(
        '<div class="smallcaps">Overview</div>',
        unsafe_allow_html=True,
    )

    st.page_link(
        "app.py",
        label="Dashboard",
    )

    st.markdown(
        '<div class="smallcaps" '
        'style="margin-top:18px">Detection</div>',
        unsafe_allow_html=True,
    )

    st.page_link(
        "pages/attack_detection.py",
        label="Attack Detection",
    )

    st.markdown(
        '<div class="smallcaps" '
        'style="margin-top:18px">Investigation</div>',
        unsafe_allow_html=True,
    )

    st.page_link(
        "pages/incident_investigation.py",
        label="Incident Investigation",
    )

    st.page_link(
        "pages/attack_graph.py",
        label="Attack Graph",
    )

    st.markdown(
        '<div class="smallcaps" style="margin-top:18px">'
        'Agentic Investigation & Risk Assessment </div>',
        unsafe_allow_html=True,
    )

    st.page_link(
        "pages/risk_assessment.py",
        label="Risk Assessment",
    )

    # st.page_link(
    #     "pages/ai_investigation.py",
    #     label="AI Investigation",
    # )

    st.divider()

    st.html(
        """
        <div class="card"
             style="min-height:0;padding:13px">

            <div class="green"
                 style="
                    font-weight:800;
                    font-size:.76rem;
                 ">
                ● DETECTION ENGINE READY
            </div>

            <div style="
                color:#718196;
                font-size:.7rem;
                margin-top:6px;
            ">
                Isolation Forest · 69 features
            </div>

        </div>
        """
    )


# ============================================================
# PAGE HEADER
# ============================================================

st.markdown(
    '<div class="smallcaps">'
    'Threat Detection Engine'
    '</div>',
    unsafe_allow_html=True,
)

st.title("Attack Detection")

st.markdown(
    '<div class="subtitle">'
    'ML-based anomaly detection using Isolation Forest '
    'on CICIDS2017 network traffic.'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div style="margin:16px 0">'
    '<span class="badge">'
    '<span class="green">●</span> '
    'ISOLATION FOREST ACTIVE'
    '</span>'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# HERO / PROCESS
# ============================================================

st.html(
    """
    <div class="hero">

        <div class="smallcaps">
            ANOMALY DETECTION WORKFLOW
        </div>

        <div style="
            font-size:1.18rem;
            font-weight:800;
            margin-top:8px;
        ">
            Network flows are evaluated for anomalous behaviour
        </div>

        <div style="
            color:#8190a3;
            font-size:.8rem;
            line-height:1.5;
            margin-top:6px;
        ">
            The Isolation Forest model learns patterns from
            benign traffic and assigns an anomaly score to
            network flows. Lower scores indicate more anomalous
            observations.
        </div>

        <div style="
            display:flex;
            gap:10px;
            flex-wrap:wrap;
            margin-top:16px;
        ">

            <span class="badge">
                CICIDS2017
            </span>

            <span class="badge">
                69 FEATURES
            </span>

            <span class="badge">
                UNSUPERVISED
            </span>

            <span class="badge">
                ANOMALY SCORE
            </span>

        </div>

    </div>
    """
)


# ============================================================
# MODEL OVERVIEW
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">Model Overview</div>',
    unsafe_allow_html=True,
)

st.header("Isolation Forest Detection")


overview_cols = st.columns(4)

overview_data = [
    (
        "Detection Model",
        "Isolation Forest",
        "Unsupervised anomaly detector",
    ),
    (
        "Feature Space",
        "69 features",
        "Numerical network-flow features",
    ),
    (
        "Training Strategy",
        "Benign traffic",
        "Model learns normal traffic patterns",
    ),
    (
        "Detection Signal",
        "Anomaly score",
        "Lower score = more anomalous",
    ),
]


for col, (label, value, desc) in zip(
    overview_cols,
    overview_data
):

    with col:

        st.html(
            f"""
            <div class="card">

                <div class="label">
                    {label}
                </div>

                <div class="value"
                     style="font-size:1.12rem">
                    {value}
                </div>

                <div class="desc">
                    {desc}
                </div>

            </div>
            """
        )


# ============================================================
# MODEL CONFIGURATION
# ============================================================

st.markdown(
    '<div style="height:12px"></div>',
    unsafe_allow_html=True,
)

config_cols = st.columns(4)

config_data = [
    (
        "Estimators",
        "200",
        "Trees in evaluation model",
    ),
    (
        "Max Samples",
        "1,024",
        "Samples per tree",
    ),
    (
        "Max Features",
        "1.0",
        "Full feature space",
    ),
    (
        "Random State",
        "42",
        "Reproducible experiment",
    ),
]


for col, (label, value, desc) in zip(
    config_cols,
    config_data
):

    with col:

        st.html(
            f"""
            <div class="method-box">

                <div class="label">
                    {label}
                </div>

                <div style="
                    font-size:1.1rem;
                    font-weight:800;
                    margin-top:6px;
                ">
                    {value}
                </div>

                <div class="method-text">
                    {desc}
                </div>

            </div>
            """
        )


# ============================================================
# MODEL EVALUATION
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">Model Evaluation</div>',
    unsafe_allow_html=True,
)

st.header("Detection Performance")

st.caption(
    "Held-out evaluation results from the project "
    "Isolation Forest experiment."
)


metrics = [
    (
        "Accuracy",
        "89.66%",
        "Overall test accuracy",
    ),
    (
        "Precision",
        "63.86%",
        "Predicted attacks that were actual attacks",
    ),
    (
        "Recall",
        "72.50%",
        "Actual attacks detected",
    ),
    (
        "F1 Score",
        "67.91%",
        "Balance of precision and recall",
    ),
    (
        "ROC-AUC",
        "0.8862",
        "Ranking performance",
    ),
    (
        "PR-AUC",
        "0.6801",
        "Precision-recall area",
    ),
    (
        "False Positive Rate",
        "7.29%",
        "Benign flows flagged as anomalous",
    ),
    (
        "False Negative Rate",
        "27.50%",
        "Attacks missed by the detector",
    ),
]


for start in [0, 4]:

    row = st.columns(4)

    for col, (
        label,
        value,
        desc
    ) in zip(
        row,
        metrics[start:start + 4]
    ):

        with col:

            st.html(
                f"""
                <div class="card"
                     style="margin-bottom:12px">

                    <div class="label">
                        {label}
                    </div>

                    <div class="value">
                        {value}
                    </div>

                    <div class="desc">
                        {desc}
                    </div>

                </div>
                """
            )


# ============================================================
# CONFUSION MATRIX
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">'
    'Classification Outcomes'
    '</div>',
    unsafe_allow_html=True,
)

st.header("Confusion Matrix")

st.caption(
    "Held-out evaluation of normal versus attack predictions."
)


cm = np.array(
    [
        [263207, 20694],
        [13871, 36574],
    ]
)


fig = go.Figure(
    go.Heatmap(
        z=cm,
        x=[
            "Predicted Normal",
            "Predicted Attack"
        ],
        y=[
            "Actual Normal",
            "Actual Attack"
        ],
        text=cm,
        texttemplate="%{text:,}",
        colorscale=[
            [0, "#0f1c2a"],
            [.45, "#24527a"],
            [1, "#49a8ff"],
        ],
        showscale=False,
        hovertemplate=(
            "Actual: %{y}"
            "<br>Predicted: %{x}"
            "<br>Flows: %{z:,}"
            "<extra></extra>"
        ),
    )
)


fig.update_layout(
    height=360,
    margin=dict(
        l=10,
        r=10,
        t=10,
        b=10,
    ),
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(
        color="#dce7f2"
    ),
)


st.plotly_chart(
    fig,
    use_container_width=True,
    config={
        "displayModeBar": False
    },
)


cm_cols = st.columns(4)

cm_values = [
    ("True Positives", "36,574"),
    ("False Negatives", "13,871"),
    ("False Positives", "20,694"),
    ("True Negatives", "263,207"),
]


for col, (label, value) in zip(
    cm_cols,
    cm_values
):

    with col:
        st.metric(
            label,
            value
        )


st.html(
    """
    <div class="callout">

        <b>How to read this:</b>
        True positives are attack flows correctly detected
        as anomalous. False positives are benign flows that
        the anomaly detector flagged. False negatives are
        attack flows that the detector did not flag.

    </div>
    """
)


# ============================================================
# ATTACK-LEVEL ANALYSIS
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">'
    'Attack-Level Analysis'
    '</div>',
    unsafe_allow_html=True,
)

st.header("Detection by Attack Category")

st.caption(
    "Detection results for attack categories in the "
    "held-out evaluation set."
)


rows = [
    ("Infiltration", 7, 7),
    ("DoS Hulk", 26010, 23099),
    ("DoS Slowhttptest", 813, 696),
    ("DoS slowloris", 776, 475),
    ("DDoS", 19113, 11347),
    ("DoS GoldenEye", 1550, 892),
    ("PortScan", 301, 40),
    ("Web Attack - Brute Force", 212, 12),
    ("Web Attack - XSS", 92, 2),
    ("Bot", 210, 4),
    ("FTP-Patator", 860, 0),
    ("SSH-Patator", 497, 0),
    ("Web Attack - SQL Injection", 4, 0),
]


adf = pd.DataFrame(
    rows,
    columns=[
        "Attack Type",
        "Total Samples",
        "Detected",
    ],
)

adf["Detection Rate"] = (
    adf["Detected"]
    / adf["Total Samples"]
    * 100
)


left, right = st.columns(
    [1.2, 1]
)


with left:

    fig = go.Figure(
        go.Bar(
            x=adf["Detection Rate"],
            y=adf["Attack Type"],
            orientation="h",
            marker_color="#49a8ff",
            text=adf["Detection Rate"].map(
                lambda x: f"{x:.1f}%"
            ),
            textposition="outside",
            cliponaxis=False,
        )
    )

    fig.update_layout(
        height=500,
        margin=dict(
            l=0,
            r=55,
            t=10,
            b=20,
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#0d151f",
        font=dict(
            color="#dce7f2"
        ),
        xaxis=dict(
            range=[0, 110],
            gridcolor="#1f2d3d",
            title="Detection Rate (%)",
        ),
        yaxis=dict(
            gridcolor="rgba(0,0,0,0)"
        ),
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
        config={
            "displayModeBar": False
        },
    )


with right:

    display_df = adf.copy()

    display_df["Detection Rate"] = (
        display_df["Detection Rate"]
        .map(lambda x: f"{x:.2f}%")
    )

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=500,
    )


# ============================================================
# DETECTION OUTPUT
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">'
    'Detection Output'
    '</div>',
    unsafe_allow_html=True,
)

st.header("Suspicious Network Flows")

st.caption(
    "Flows flagged by the Isolation Forest on held-out evaluation data "
    "or by the calibrated inference model. Ground-truth labels are deliberately "
    "excluded from this artefact and remain in separate benchmark evaluation files."
)


if suspicious_df is None:

    st.html(
        """
        <div class="callout">

            <b>Pipeline output not found.</b>

            The page is configured to load
            <code>
            suspicious_flows_with_metadata.csv
            </code>
            from the attack-graph pipeline output.

        </div>
        """
    )

else:

    if suspicious_count is not None:

        st.markdown(
            f"""
            <div style="
                color:#8190a3;
                font-size:.76rem;
                margin-bottom:10px;
            ">
                <b style="color:#edf3fa">
                    {suspicious_count:,}
                </b>
                suspicious flows generated by the pipeline.
                Showing a preview of the output.
            </div>
            """,
            unsafe_allow_html=True,
        )


    view = suspicious_df.copy()


    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    filter_cols = st.columns(3)


    available_filters = [
        ("src_ip", "Source IP"),
        ("dst_ip", "Destination IP"),
        ("predicted_attack_type", "Model-Predicted Attack Type"),
    ]


    for col, (
        field,
        display_name
    ) in zip(
        filter_cols,
        available_filters
    ):

        if field in view.columns:

            with col:

                options = ["All"]

                unique_values = (
                    view[field]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                )

                options.extend(
                    sorted(unique_values)[:200]
                )

                selected = st.selectbox(
                    display_name,
                    options,
                    key=f"attack_filter_{field}",
                )

                if selected != "All":

                    view = view[
                        view[field]
                        .astype(str)
                        == selected
                    ]


    # --------------------------------------------------------
    # TABLE COLUMNS
    # --------------------------------------------------------

    preferred_columns = [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "predicted_attack_type",
        "anomaly_score",
        "predicted_anomaly",
    ]


    preferred = [
        column
        for column in preferred_columns
        if column in view.columns
    ]


    if preferred:

        st.dataframe(
            view[preferred],
            use_container_width=True,
            height=420,
            hide_index=True,
        )

    else:

        st.dataframe(
            view,
            use_container_width=True,
            height=420,
            hide_index=True,
        )


# ============================================================
# ML VS GROUND TRUTH EXPLANATION
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">'
    'Interpretation'
    '</div>',
    unsafe_allow_html=True,
)

st.header("Held-Out Benchmark Evaluation")

if detection_metrics:
    metric_specs = [
        ("ROC-AUC", detection_metrics.get("roc_auc")),
        ("PR-AUC / AP", detection_metrics.get("pr_auc_average_precision")),
        ("Precision", detection_metrics.get("precision")),
        ("Recall", detection_metrics.get("recall")),
        ("F1", detection_metrics.get("f1")),
        ("False Positive Rate", detection_metrics.get("false_positive_rate")),
    ]
    metric_cols = st.columns(3)
    for index, (label, value) in enumerate(metric_specs):
        with metric_cols[index % 3]:
            display_value = (
                f"{float(value):.4f}" if value is not None and pd.notna(value)
                else "Not available"
            )
            st.metric(label, display_value)

    st.caption(
        "These metrics are computed from the held-out benchmark evaluation set. "
        "They are not calculated from the suspicious-flow preview. In inference mode, "
        "ground-truth evaluation metrics are available only for benchmark runs; unlabeled inference does not produce these metrics."
    )
else:
    st.info(
        "No held-out detection_metrics.json is available. This is expected for "
        "unlabeled inference runs; model predictions are shown above without "
        "inventing ground-truth metrics."
    )

if not per_attack_evaluation.empty:
    st.markdown("#### Per-Attack Evaluation (Held-Out Benchmark)")
    st.dataframe(
        per_attack_evaluation,
        use_container_width=True,
        hide_index=True,
    )
elif detection_metrics:
    st.info("Per-attack evaluation file is not available for this run.")


st.header("What the Detection Result Means")


explanation_cols = st.columns(2)


with explanation_cols[0]:

    st.html(
        """
        <div class="method-box">

            <div class="blue"
                 style="
                    font-size:.68rem;
                    font-weight:800;
                    letter-spacing:.12em;
                 ">
                ML OUTPUT
            </div>

            <div class="method-title">
                Anomaly Prediction
            </div>

            <div class="method-text">

                The Isolation Forest assigns an anomaly
                score to each flow. Flows below the calibrated
                prototype threshold are marked as
                <b>predicted_anomaly = True</b> and passed
                forward as suspicious flows.

            </div>

        </div>
        """
    )


with explanation_cols[1]:

    st.html(
        """
        <div class="method-box">

            <div class="amber"
                 style="
                    font-size:.68rem;
                    font-weight:800;
                    letter-spacing:.12em;
                 ">
                DATASET REFERENCE
            </div>

            <div class="method-title">
                Ground-Truth Label
            </div>

            <div class="method-text">

                CICIDS2017 ground-truth labels are used only
                in the separate held-out benchmark evaluation
                artefacts. They are deliberately not passed to
                the suspicious-flow, event, graph or agent
                investigation pipeline.

            </div>

        </div>
        """
    )


# ============================================================
# HANDOFF
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.html(
    """
    <div class="callout">

        <b>Investigation handoff:</b>

        Flows flagged as anomalous are passed to the next
        stage for attack-event formation and relationship
        reconstruction. The current Mid-Viva pipeline therefore
        progresses from

        <b>
        anomaly detection → suspicious flows → attack events
        → attack graph
        </b>.

    </div>
    """
)