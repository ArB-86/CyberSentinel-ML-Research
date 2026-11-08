from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberSentinel | Attack Event Investigation",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "outputs"
EVENTS_PATH = OUTPUT_DIR / "attack_events.csv"
INCIDENTS_PATH = OUTPUT_DIR / "incident_groups.csv"


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

    [data-testid="stSidebar"] {
        background: #0b121c;
        border-right: 1px solid #1d2b3c;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 2.2rem;
        padding-bottom: 4rem;
    }

    /* TEXT */

    .smallcaps {
        color: #6f9fc8;
        font-size: 0.68rem;
        font-weight: 800;
        letter-spacing: 0.18em;
        text-transform: uppercase;
    }

    .subtitle {
        color: #8190a3;
        font-size: 0.95rem;
        margin-top: -0.35rem;
    }

    /* HERO */

    .hero {
        background:
            radial-gradient(
                circle at 85% 0%,
                rgba(73,168,255,0.13),
                transparent 38%
            ),
            #0b141f;

        border: 1px solid #263b51;
        border-radius: 16px;
        padding: 24px 26px;
        margin-top: 10px;
    }

    .status {
        display: inline-block;
        margin-top: 15px;
        padding: 7px 12px;
        border-radius: 999px;
        border: 1px solid #28506d;
        background: #0b1a27;
        color: #8fd7ff;
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.04em;
    }

    .status-dot {
        color: #32d296;
    }

    /* METRIC CARDS */

    .metric-card {
        background: linear-gradient(
            145deg,
            #0f1823,
            #0b121b
        );

        border: 1px solid #26374b;
        border-radius: 14px;
        padding: 20px;
        min-height: 135px;
    }

    .metric-label {
        color: #6f8094;
        font-size: 0.66rem;
        font-weight: 800;
        letter-spacing: 0.15em;
        text-transform: uppercase;
    }

    .metric-value {
        color: #edf3fa;
        font-size: 1.65rem;
        font-weight: 800;
        margin-top: 9px;
    }

    .metric-desc {
        color: #718196;
        font-size: 0.76rem;
        margin-top: 6px;
    }

    /* EVENT CARDS */

    .event-card {
        background: #0b121b;
        border: 1px solid #202f40;
        border-radius: 12px;
        padding: 17px 20px;
        margin-bottom: 10px;
    }

    .event-id {
        color: #8fd7ff;
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.1em;
    }

    .event-title {
        color: #edf3fa;
        font-size: 0.94rem;
        font-weight: 700;
        margin-top: 5px;
    }

    .event-meta {
        color: #718196;
        font-size: 0.72rem;
        margin-top: 7px;
        line-height: 1.7;
    }

    .severity-high {
        color: #ff8f8f;
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.08em;
    }

    .severity-medium {
        color: #e9c46a;
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.08em;
    }

    .severity-low {
        color: #72d7a2;
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.08em;
    }

    /* CALLOUT */

    .callout {
        border: 1px solid #234c6a;
        border-left: 3px solid #49a8ff;
        background: #0b1824;
        border-radius: 10px;
        padding: 14px 16px;
        color: #91abc1;
        font-size: 0.79rem;
        line-height: 1.6;
    }

    .warning-callout {
        border: 1px solid #66511d;
        border-left: 3px solid #e9c46a;
        background: #19160c;
        border-radius: 10px;
        padding: 14px 16px;
        color: #b8aa83;
        font-size: 0.79rem;
        line-height: 1.6;
    }

    /* DIVIDER */

    .rule {
        height: 1px;
        background: #1c2938;
        margin: 30px 0;
    }

    /* BUTTON */

    div.stButton > button {
        background: #0d1c2b;
        border: 1px solid #28506d;
        color: #8fd7ff;
        border-radius: 8px;
        font-weight: 700;
    }

    div.stButton > button:hover {
        border-color: #49a8ff;
        color: #ffffff;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# LOAD REAL ATTACK EVENTS
# ============================================================

@st.cache_data
def load_events(path):
    return pd.read_csv(
        path,
        low_memory=False,
    )

@st.cache_data
def load_potential_incidents(path):
    if not Path(path).exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, low_memory=False)
    except Exception:
        return pd.DataFrame()


if not EVENTS_PATH.exists():

    st.error(
        "The real attack event output was not found."
    )

    st.code(
        str(EVENTS_PATH),
        language="text",
    )

    st.info(
        "Make sure attack_events.csv is inside "
        "attack_graph_output/."
    )

    st.stop()


try:
    events = load_events(EVENTS_PATH)
    potential_incidents = load_potential_incidents(INCIDENTS_PATH)

except Exception as e:

    st.error(
        f"Could not load attack_events.csv: {e}"
    )

    st.stop()


# ============================================================
# NORMALIZE COLUMN NAMES
# ============================================================

events.columns = [
    str(column).strip()
    for column in events.columns
]


# The teammate's actual file uses "_id".
if "_id" in events.columns:
    event_id_column = "_id"

elif "event_id" in events.columns:
    event_id_column = "event_id"

else:
    event_id_column = None


with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel")

    st.divider()

    st.markdown('<div class="smallcaps">Overview</div>', unsafe_allow_html=True)
    st.page_link("app.py", label="Dashboard")

    st.markdown('<div class="smallcaps" style="margin-top:18px">Detection</div>', unsafe_allow_html=True)
    st.page_link("pages/attack_detection.py", label="Attack Detection")

    st.markdown('<div class="smallcaps" style="margin-top:18px">Investigation</div>', unsafe_allow_html=True)
    st.page_link("pages/incident_investigation.py", label="Event Investigation")
    st.page_link("pages/attack_graph.py", label="Attack Graph")

    st.markdown('<div class="smallcaps" style="margin-top:18px">Future Modules</div>', unsafe_allow_html=True)
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")

    st.divider()

    st.html(
        f"""
        <div class="card"
             style="min-height:0;padding:13px">

            <div class="green"
                 style="font-weight:800;font-size:.76rem">
                ● EVENT DATA READY
            </div>

            <div style="
                color:#718196;
                font-size:.7rem;
                margin-top:6px;
            ">
                {len(events):,} grouped events
            </div>

        </div>
        """
    )

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_value(row, column, default="—"):

    if column not in row.index:
        return default

    value = row[column]

    if pd.isna(value):
        return default

    return str(value)


def classification_status(row):
    source = get_value(row, "attack_type_source", "not_predicted")
    return "MODEL CLASSIFIED" if source == "model_prediction" else "UNCLASSIFIED"




# ============================================================
# BASIC DATA SUMMARY
# ============================================================

total_events = len(events)
classified_events = (
    int((events["attack_type_source"].astype(str) == "model_prediction").sum())
    if "attack_type_source" in events.columns else 0
)
standalone_events = (
    int(events["incident_id"].isna().sum())
    if "incident_id" in events.columns else int(len(events))
)


# ============================================================
# PAGE HEADER
# ============================================================

# st.markdown(
#     '<div class="smallcaps">CYBERSENTINEL EVENT REVIEW</div>',
#     unsafe_allow_html=True,
# )

st.title("Attack Event & Potential Incident Investigation")

st.markdown(
    '<div class="subtitle">'
    'Investigate correlated attack events generated from suspicious '
    'network activity.'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# HERO
# ============================================================

st.markdown(
    '<div class="hero">'
    '<div class="smallcaps">CORRELATION ENGINE</div>'
    '<div style="color:#edf3fa;font-size:1.25rem;font-weight:800;margin-top:7px;">'
    'Grouped suspicious events loaded'
    '</div>'
    '<div style="color:#8190a3;font-size:0.82rem;margin-top:5px;">'
    'The workspace displays grouped events and candidate multi-event '
    'correlations. Potential incident groups require analyst validation.'
    '</div>'
    '<div class="status">'
    '<span class="status-dot">●</span> '
    'EVENT AND CORRELATION OUTPUTS'
    '</div>'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# INCIDENT / EVENT SUMMARY
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">INVESTIGATION OVERVIEW</div>',
    unsafe_allow_html=True,
)

st.header("Event and Potential Incident Summary")


metric_cols = st.columns(4)
metrics = [
    ("Grouped Events", f"{total_events:,}", "Time/connection-based event records"),
    ("Potential Incidents", f"{len(potential_incidents):,}", "Multi-event correlations; analyst confirmation required"),
    ("Model-Classified Events", f"{classified_events:,}", "Only when a separate attack-type prediction is available"),
    ("Standalone Events", f"{standalone_events:,}", "Events not linked to a multi-event candidate group"),
]


for col, (label, value, description) in zip(
    metric_cols,
    metrics,
):

    with col:

        st.markdown(
            '<div class="metric-card">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div>'
            f'<div class="metric-desc">{description}</div>'
            '</div>',
            unsafe_allow_html=True,
        )


if not potential_incidents.empty:
    st.markdown("#### Candidate incident groups")
    display_cols = [
        column for column in [
            "incident_id", "start_time", "end_time", "event_count",
            "flow_count", "unique_host_count", "confirmation_status"
        ]
        if column in potential_incidents.columns
    ]
    st.dataframe(
        potential_incidents[display_cols],
        use_container_width=True,
        hide_index=True,
    )
    st.caption(
        "These are candidate groups based on shared-host temporal correlation. "
        "They are not confirmed incidents and do not establish causation."
    )
else:
    st.info(
        "No multi-event candidate groups were generated. Individual grouped events "
        "remain available for review; this does not mean no attack activity occurred."
    )


# ============================================================
# CORRELATION STATUS
# ============================================================

# st.markdown(
#     '<div style="height:18px;"></div>',
#     unsafe_allow_html=True,
# )

# st.markdown(
#     '<div class="warning-callout">'
#     '<b>Correlation status:</b> '
#     'The backend currently provides grouped attack events. '
#     'A separate higher-level incident ID / incident formation '
#     'output is not present in the supplied attack_events.csv, '
#     'so this interface does not present individual events as '
#     'confirmed incidents.'
#     '</div>',
#     unsafe_allow_html=True,
# )


# ============================================================
# FILTERS
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">EVENT EXPLORER</div>',
    unsafe_allow_html=True,
)

st.header("Attack Event Explorer")


filter_cols = st.columns(
    [1.3, 1.3, 1.0]
)


# ------------------------------------------------------------
# ATTACK TYPE FILTER
# ------------------------------------------------------------

with filter_cols[0]:

    if "attack_type" in events.columns:

        available_attack_types = sorted(
            events["attack_type"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_attack_type = st.selectbox(
            "Attack type",
            ["All"] + available_attack_types,
        )

    else:

        selected_attack_type = "All"


# ------------------------------------------------------------
# SOURCE FILTER
# ------------------------------------------------------------

with filter_cols[1]:

    if "src_ip" in events.columns:

        source_values = sorted(
            events["src_ip"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_source = st.selectbox(
            "Source host",
            ["All"] + source_values,
        )

    else:

        selected_source = "All"


# ------------------------------------------------------------
# DISPLAY LIMIT
# ------------------------------------------------------------

with filter_cols[2]:

    display_limit = st.selectbox(
        "Events to display",
        [10, 25, 50, 100],
        index=1,
    )


# ============================================================
# APPLY FILTERS
# ============================================================

filtered_events = events.copy()


if (
    selected_attack_type != "All"
    and "attack_type" in filtered_events.columns
):

    filtered_events = filtered_events[
        filtered_events["attack_type"]
        .astype(str)
        == selected_attack_type
    ]


if (
    selected_source != "All"
    and "src_ip" in filtered_events.columns
):

    filtered_events = filtered_events[
        filtered_events["src_ip"]
        .astype(str)
        == selected_source
    ]


# ============================================================
# EVENT COUNT
# ============================================================

st.caption(
    f"Showing {min(len(filtered_events), display_limit):,} "
    f"of {len(filtered_events):,} matching attack events."
)


# ============================================================
# EVENT LIST
# ============================================================

displayed_events = filtered_events.head(
    display_limit
)


if displayed_events.empty:

    st.info(
        "No attack events match the selected filters."
    )

else:

    for index, (_, row) in enumerate(
        displayed_events.iterrows()
    ):

        # ------------------------------------------------    
        # EVENT ID
        # ------------------------------------------------    

        if event_id_column:

            raw_id = get_value(
                row,
                event_id_column,
                str(index + 1),
            )

            # Your file currently stores IDs like 0001.
            event_id = f"EVT-{raw_id.zfill(5)}"

        else:

            event_id = f"EVT-{index + 1:05d}"


        # ------------------------------------------------    
        # DATA
        # ------------------------------------------------    

        start_time = get_value(
            row,
            "start_time",
        )

        end_time = get_value(
            row,
            "end_time",
        )

        source = get_value(
            row,
            "src_ip",
        )

        target = get_value(
            row,
            "dst_ip",
        )

        protocol = get_value(
            row,
            "protocol",
        )

        attack_type = get_value(
            row,
            "attack_type",
            "Unknown",
        )

        flow_count = get_value(
            row,
            "flow_count",
            "—",
        )

        duration = get_value(
            row,
            "duration_seconds",
            "—",
        )


        classification = classification_status(row)
        incident_id = get_value(row, "incident_id", "Standalone event")

        # ------------------------------------------------    
        # CARD
        # ------------------------------------------------    

        st.markdown(
            '<div class="event-card">'
            '<div style="display:flex;justify-content:space-between;'
            'align-items:flex-start;gap:20px;">'

            '<div style="flex:1;">'

            f'<div class="event-id">{event_id}</div>'

            f'<div class="event-title">'
            f'{attack_type}'
            f'</div>'

            f'<div class="event-meta">'
            f'<b>Source:</b> {source}'
            ' &nbsp;→&nbsp; '
            f'<b>Target:</b> {target}'
            '<br>'
            f'<b>Protocol:</b> {protocol}'
            ' &nbsp;·&nbsp; '
            f'<b>Flows:</b> {flow_count}'
            ' &nbsp;·&nbsp; '
            f'<b>Duration:</b> {duration}s'
            '<br>'
            f'<b>Start:</b> {start_time}'
            ' &nbsp;·&nbsp; '
            f'<b>End:</b> {end_time}'
            '<br>'
            f'<b>Potential incident:</b> {incident_id}'
            '</div>'

            '</div>'

            f'<div class="severity-medium">'
            f'{classification}'
            '</div>'

            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )


# ============================================================
# SELECTED EVENT
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

left, right = st.columns(
    [1.1, 1]
)


# ============================================================
# LEFT — EVENT DETAILS
# ============================================================

with left:

    st.markdown(
        '<div class="smallcaps">EVENT DETAILS</div>',
        unsafe_allow_html=True,
    )

    st.header("Inspect an Event")


    if event_id_column:

        event_ids = (
            filtered_events[
                event_id_column
            ]
            .dropna()
            .astype(str)
            .tolist()
        )

        if event_ids:

            selected_raw_id = st.selectbox(
                "Select event",
                event_ids,
            )

            selected_rows = filtered_events[
                filtered_events[
                    event_id_column
                ].astype(str)
                == selected_raw_id
            ]

            if not selected_rows.empty:

                selected = selected_rows.iloc[0]


                detail_cols = st.columns(2)


                with detail_cols[0]:

                    st.metric(
                        "Event ID",
                        f"EVT-{selected_raw_id.zfill(5)}",
                    )

                    st.metric(
                        "Source",
                        get_value(
                            selected,
                            "src_ip",
                        ),
                    )

                    st.metric(
                        "Protocol",
                        get_value(
                            selected,
                            "protocol",
                        ),
                    )


                with detail_cols[1]:

                    st.metric(
                        "Attack Type",
                        get_value(
                            selected,
                            "attack_type",
                        ),
                    )

                    st.metric(
                        "Target",
                        get_value(
                            selected,
                            "dst_ip",
                        ),
                    )

                    st.metric(
                        "Flow Count",
                        get_value(
                            selected,
                            "flow_count",
                        ),
                    )


                st.markdown(
                    '<div style="height:12px;"></div>',
                    unsafe_allow_html=True,
                )


                # st.markdown(
                #     '<div class="callout">'
                #     '<b>Temporal window</b><br>'
                #     f'{get_value(selected, "start_time")}'
                #     ' → '
                #     f'{get_value(selected, "end_time")}'
                #     '<br><br>'
                #     '<b>Duration:</b> '
                #     f'{get_value(selected, "duration_seconds")} seconds'
                #     '</div>',
                #     unsafe_allow_html=True,
                # )


# ============================================================
# RIGHT — ANOMALY INFORMATION
# ============================================================

with right:

    st.markdown(
        '<div class="smallcaps">ANOMALY EVIDENCE</div>',
        unsafe_allow_html=True,
    )

    st.header("Detection Evidence")


    if (
        "mean_anomaly_score"
        in events.columns
    ):

        score_values = pd.to_numeric(
            filtered_events[
                "mean_anomaly_score"
            ],
            errors="coerce",
        ).dropna()


        if not score_values.empty:

            st.metric(
                "Mean anomaly score",
                f"{score_values.mean():.4f}",
            )

            st.metric(
                "Lowest event score",
                f"{score_values.min():.4f}",
            )

            st.markdown(
                '<div class="callout">'
                '<b>Interpretation:</b><br>'
                'The anomaly score is inherited from the '
                'Isolation Forest detection stage. Lower '
                'scores represent more anomalous activity '
                'under the project pipeline convention.'
                '</div>',
                unsafe_allow_html=True,
            )

    else:

        st.info(
            "No anomaly score column is available "
            "in attack_events.csv."
        )


# ============================================================
# CORRELATION LOGIC
# ============================================================

st.markdown(
    '<div class="rule"></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="smallcaps">CORRELATION LOGIC</div>',
    unsafe_allow_html=True,
)

st.header("How Events and Potential Incidents Are Formed")


correlation_steps = [
    (
        "01",
        "Suspicious Flows",
        "Anomalous network flows enter the correlation stage.",
    ),
    (
        "02",
        "Event Grouping",
        "Suspicious flows are grouped by source, destination, protocol "
        "and time proximity. Ground-truth labels are not used for grouping.",
    ),
    (
        "03",
        "Attack Event",
        "Grouped flows become an event record. Attack type remains Unclassified "
        "unless a separate trained classifier supplies a prediction.",
    ),
    (
        "04",
        "Attack Graph",
        "Events are represented in the NetworkX attack graph "
        "alongside source hosts, target hosts and attack types.",
    ),
    (
        "05",
        "Potential Incident Grouping",
        "Connected components of shared-host temporal edges receive candidate incident IDs. "
        "They require analyst validation and do not prove causality.",
    ),
    (
        "06",
        "Risk Triage",
        "A transparent heuristic index is calculated from available anomaly, volume and graph evidence. "
        "It is not a calibrated probability.",
    ),
]


for number, title, description in correlation_steps:

    st.markdown(
        '<div style="display:flex;gap:15px;padding:12px 0;'
        'border-bottom:1px solid #1b2735;">'

        f'<div style="color:#49a8ff;font-weight:800;'
        f'font-size:0.7rem;min-width:25px;">'
        f'{number}'
        '</div>'

        '<div>'

        f'<div style="color:#edf3fa;font-weight:700;'
        f'font-size:0.82rem;">'
        f'{title}'
        '</div>'

        f'<div style="color:#718196;font-size:0.72rem;'
        f'margin-top:4px;line-height:1.5;">'
        f'{description}'
        '</div>'

        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# HANDOFF
# ============================================================

# st.markdown(
#     '<div class="rule"></div>',
#     unsafe_allow_html=True,
# )

# st.markdown(
#     '<div class="smallcaps">INVESTIGATION HANDOFF</div>',
#     unsafe_allow_html=True,
# )

# st.header("Next Investigation Layers")


# handoff_cols = st.columns(3)

# handoffs = [
#     (
#         "🕸️",
#         "Attack Graph",
#         "Trace relationships between hosts, attack events and attack types.",
#     ),
#     (
#         "⚠️",
#         "Risk Assessment",
#         "Evaluate severity once the risk-scoring backend is available.",
#     ),
#     (
#         "🤖",
#         "AI Investigation",
#         "Use reconstructed evidence for agentic investigation once the agent is connected.",
#     ),
# ]


# for col, (icon, title, description) in zip(
#     handoff_cols,
#     handoffs,
# ):

#     with col:

#         st.markdown(
#             '<div class="metric-card">'
#             f'<div style="font-size:1.35rem;">{icon}</div>'
#             f'<div style="color:#edf3fa;font-size:0.95rem;'
#             f'font-weight:800;margin-top:9px;">'
#             f'{title}'
#             '</div>'
#             f'<div class="metric-desc">{description}</div>'
#             '</div>',
#             unsafe_allow_html=True,
#         )


# ============================================================
# FOOTER NOTE
# ============================================================

# st.markdown(
#     '<div class="rule"></div>',
#     unsafe_allow_html=True,
# )

# st.markdown(
#     '<div class="callout">'
#     '<b>Backend integration status:</b> '
#     'This page is now driven by the actual attack_events.csv '
#     'output. The interface does not invent incident IDs or '
#     'claim that attack events are confirmed incidents. '
#     'Higher-level incident correlation can be connected when '
#     'that backend stage is implemented.'
#     '</div>',
#     unsafe_allow_html=True,
# )