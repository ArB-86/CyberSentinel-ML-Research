from pathlib import Path

import networkx as nx
from html import escape as escape_html
import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "outputs"

GEXF_PATH = OUTPUT_DIR / "attack_graph.gexf"
EVENTS_PATH = OUTPUT_DIR / "attack_events.csv"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Attack Graph | CyberSentinel",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded"
)


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
        padding-top: 2rem;
        padding-bottom: 4rem;
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

    .legend {
        display: flex;
        gap: 24px;
        flex-wrap: wrap;
        padding: 14px 0 18px 0;
        color: #9ca3af;
        font-size: .8rem;
    }

    .legend-item {
        display: flex;
        align-items: center;
        gap: 7px;
    }

    .legend-dot {
        width: 11px;
        height: 11px;
        border-radius: 50%;
        display: inline-block;
        border: 1px solid rgba(255,255,255,.45);
    }

    .blue-dot {
        background: #49a8ff;
    }

    .green-dot {
        background: #32d296;
    }

    .purple-dot {
        background: #a78bfa;
    }

    .orange-dot {
        background: #f0a35a;
    }

    .gray-dot {
        background: #94a3b8;
    }

    .rule {
        height: 1px;
        background: #1c2938;
        margin: 30px 0;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_resource
def load_graph(path):
    return nx.read_gexf(path)


@st.cache_data
def load_events(path):
    return pd.read_csv(path, low_memory=False)


# ============================================================
# FILE CHECK & INITIAL DATA SETUP (Moved Up)
# ============================================================

if not GEXF_PATH.exists():
    st.error(f"Attack graph file was not found at:\n\n`{GEXF_PATH}`")
    st.info("Make sure `attack_graph.gexf` is inside the `outputs` folder.")
    st.stop()

if not EVENTS_PATH.exists():
    events = pd.DataFrame()
else:
    try:
        events = load_events(EVENTS_PATH)
    except Exception:
        events = pd.DataFrame()

# Safe flow count variable for the sidebar badge
flow_count_str = f"{len(events):,} flows" if not events.empty else "0 flows"


# ============================================================
# HEADER
# ============================================================

st.html(
    """
    <div class="smallcaps">
        SECURITY OPERATIONS CENTER
    </div>
    """
)

st.title("Attack Graph")

st.markdown(
    '<div class="subtitle">'
    'Interactive reconstruction of suspicious network activity and '
    'relationships between hosts, attack events and attack types.'
    '</div>',
    unsafe_allow_html=True,
)

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

    st.markdown('<div class="smallcaps" style="margin-top:18px">Agentic Investigation & Risk Assessment</div>', unsafe_allow_html=True)
    st.page_link("pages/risk_assessment.py", label="Risk Assessment")

    st.divider()

    st.html(
        f"""
        <div class="card"
             style="min-height:0;padding:13px">

            <div class="green"
                 style="font-weight:800;font-size:.76rem">
                ● GRAPH DATA AVAILABLE
            </div>

            <div style="
                color:#718196;
                font-size:.7rem;
                margin-top:6px;
            ">
                CICIDS2017 · {flow_count_str}
            </div>

        </div>
        """
    )


# ============================================================
# LOAD GRAPH
# ============================================================

try:
    G = load_graph(GEXF_PATH)
except Exception as e:
    st.error(f"Could not load the attack graph: {e}")
    st.stop()


# ============================================================
# GRAPH STATISTICS
# ============================================================

total_nodes = G.number_of_nodes()
total_edges = G.number_of_edges()

node_types = {}

for _, data in G.nodes(data=True):
    node_type = str(
        data.get(
            "node_type",
            "unknown"
        )
    )
    node_types[node_type] = (
        node_types.get(node_type, 0) + 1
    )

event_nodes = node_types.get("event", 0)
host_nodes = node_types.get("host", 0)
incident_nodes = node_types.get("incident", 0)
predicted_attack_type_nodes = node_types.get("predicted_attack_type", 0)


# ============================================================
# TOP METRICS
# ============================================================

m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("Graph Nodes", f"{total_nodes:,}")
with m2:
    st.metric("Graph Edges", f"{total_edges:,}")
with m3:
    st.metric("Grouped Events", f"{event_nodes:,}")
with m4:
    st.metric("Host Nodes", f"{host_nodes:,}")
with m5:
    st.metric("Potential Incidents", f"{incident_nodes:,}")

st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)


# ============================================================
# GRAPH TYPE HELPERS
# ============================================================

def get_node_type(node_data):
    return str(
        node_data.get(
            "node_type",
            "unknown"
        )
    )


def node_label(node_id, data):
    return str(
        data.get(
            "label",
            data.get(
                "event_id",
                node_id
            )
        )
    )


# ============================================================
# EVENT FILTER OPTIONS
# ============================================================

selected_attack_type = "All"
selected_event_id = "All"

if not events.empty:
    attack_column = None
    for candidate in ["attack_type"]:
        if candidate in events.columns:
            attack_column = candidate
            break

    if attack_column:
        attack_types = (
            events[attack_column]
            .dropna()
            .astype(str)
            .sort_values()
            .unique()
            .tolist()
        )
        selected_attack_type = st.selectbox(
            "Filter by attack type",
            ["All"] + attack_types,
        )

    if "event_id" in events.columns:
        event_options = (
            events["event_id"]
            .dropna()
            .astype(str)
            .tolist()
        )
        selected_event_id = st.selectbox(
            "Focus on attack event",
            ["All"] + event_options,
        )


# ============================================================
# GRAPH CONTROLS
# ============================================================

graph_scope = "Event Focus"
max_nodes = 300
layout_choice = "Spring"


# ============================================================
# SELECT GRAPH SUBSET
# ============================================================

def choose_subgraph(
    graph,
    events_df,
    scope,
    attack_type,
    event_id,
    limit,
):
    if event_id != "All":
        possible_ids = [
            f"event:{event_id}",
            str(event_id),
        ]
        chosen = None
        for candidate in possible_ids:
            if candidate in graph:
                chosen = candidate
                break

        if chosen is not None:
            selected = {chosen}
            selected.update(graph.predecessors(chosen))
            selected.update(graph.successors(chosen))

            for neighbor in list(selected):
                if len(selected) >= limit:
                    break
                selected.update(graph.predecessors(neighbor))
                selected.update(graph.successors(neighbor))

            selected = list(selected)[:limit]
            return graph.subgraph(selected).copy()

    if attack_type != "All":
        matching_events = []
        if not events_df.empty:
            attack_column = None
            for candidate in ["attack_type"]:
                if candidate in events_df.columns:
                    attack_column = candidate
                    break

            if attack_column and "event_id" in events_df.columns:
                matching_events = (
                    events_df[
                        events_df[attack_column].astype(str)
                        == str(attack_type)
                    ]["event_id"]
                    .astype(str)
                    .tolist()
                )

        selected = set()
        for event in matching_events:
            candidate = f"event:{event}"
            if candidate in graph:
                selected.add(candidate)
            if len(selected) >= limit:
                break

        expanded = set(selected)
        for node in list(selected):
            expanded.update(graph.predecessors(node))
            expanded.update(graph.successors(node))
            if len(expanded) >= limit:
                break

        return graph.subgraph(list(expanded)[:limit]).copy()

    events_in_graph = [
        node
        for node, data in graph.nodes(data=True)
        if get_node_type(data) == "event"
    ]

    if events_in_graph:
        selected = set(
            events_in_graph[:min(40, len(events_in_graph))]
        )
        for node in list(selected):
            selected.update(graph.predecessors(node))
            selected.update(graph.successors(node))
            if len(selected) >= limit:
                break

        return graph.subgraph(list(selected)[:limit]).copy()

    if graph.number_of_nodes() <= limit:
        return graph.copy()

    nodes = list(graph.nodes())[:limit]
    return graph.subgraph(nodes).copy()


display_graph = choose_subgraph(
    G,
    events,
    graph_scope,
    selected_attack_type,
    selected_event_id,
    max_nodes,
)


# ============================================================
# GRAPH LAYOUT
# ============================================================

if display_graph.number_of_nodes() == 0:
    st.warning("No nodes match the selected filters.")
    st.stop()

try:
    if layout_choice == "Kamada-Kawai":
        pos = nx.kamada_kawai_layout(display_graph)
    else:
        pos = nx.spring_layout(
            display_graph,
            seed=42,
            k=1.2,
            iterations=50,
        )
except Exception:
    pos = nx.spring_layout(display_graph, seed=42)


# ============================================================
# EDGE TRACE
# ============================================================

edge_x = []
edge_y = []

for source, target in display_graph.edges():
    if source not in pos or target not in pos:
        continue
    x0, y0 = pos[source]
    x1, y1 = pos[target]
    edge_x.extend([x0, x1, None])
    edge_y.extend([y0, y1, None])

edge_trace = go.Scatter(
    x=edge_x,
    y=edge_y,
    mode="lines",
    line=dict(
        width=0.8,
        color="rgba(148,163,184,0.35)",
    ),
    hoverinfo="none",
)


# ============================================================
# NODE COLORS & SIZES
# ============================================================

NODE_COLORS = {
    "host": "#49a8ff",
    "event": "#a78bfa",
    "predicted_attack_type": "#f0a35a",
    "incident": "#f472b6",
    "unknown": "#94a3b8",
}

NODE_SIZES = {
    "host": 18,
    "event": 24,
    "predicted_attack_type": 21,
    "incident": 27,
    "unknown": 16,
}


# ============================================================
# CREATE ONE TRACE PER NODE TYPE
# ============================================================

node_traces = []

for node_type in [
    "host",
    "event",
    "predicted_attack_type",
    "incident",
    "unknown",
]:
    type_nodes = []
    for node, data in display_graph.nodes(data=True):
        if get_node_type(data) == node_type:
            type_nodes.append((node, data))

    if not type_nodes:
        continue

    node_x = []
    node_y = []
    node_text = []
    node_customdata = []

    for node, data in type_nodes:
        if node not in pos:
            continue
        x, y = pos[node]
        label = node_label(node, data)

        node_x.append(x)
        node_y.append(y)

        # Graph labels originate in CSV/GEXF data. Escape them before using
        # Plotly's HTML-capable hover template to prevent markup injection.
        node_text.append(
            f"<b>{escape_html(label, quote=True)}</b><br>"
            f"Type: {escape_html(node_type, quote=True)}<br>"
            f"Node ID: {escape_html(str(node), quote=True)}"
        )

        node_customdata.append([
            str(node),
            node_type,
            label,
            str(data.get("protocol", "")),
            str(data.get("start_time", "")),
            str(data.get("end_time", "")),
            str(data.get("flow_count", "")),
        ])

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        name={
            "source": "Source Host",
            "target": "Target Host",
            "event": "Attack Event",
            "attack_type": "Attack Type",
            "predicted_attack_type": "Predicted Attack Type",
            "incident": "Incident",
            "unknown": "Other",
        }.get(node_type, "Other"),
        hovertemplate="%{text}<extra></extra>",
        text=node_text,
        customdata=node_customdata,
        marker=dict(
            size=NODE_SIZES.get(node_type, 16),
            color=NODE_COLORS.get(node_type, NODE_COLORS["unknown"]),
            line=dict(
                width=1,
                color="rgba(255,255,255,0.55)",
            ),
        ),
    )
    node_traces.append(node_trace)


# ============================================================
# FIGURE
# ============================================================

fig = go.Figure()
fig.add_trace(edge_trace)
for trace in node_traces:
    fig.add_trace(trace)

fig.update_layout(
    height=680,
    margin=dict(l=10, r=10, t=10, b=10),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    showlegend=False,
    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    hoverlabel=dict(bgcolor="#111827", font_size=13),
)


# ============================================================
# GRAPH PANEL
# ============================================================

st.html(
    """
    <div style="
        font-size:1.25rem;
        font-weight:750;
        margin:20px 0 8px 0;
    ">
        Attack Relationship Map
    </div>
    """
)

st.caption(
    f"Displaying {display_graph.number_of_nodes():,} "
    f"nodes and {display_graph.number_of_edges():,} "
    f"edges from the actual attack graph."
)

st.plotly_chart(
    fig,
    use_container_width=True,
    config={
        "displaylogo": False,
        "scrollZoom": True,
        "modeBarButtonsToRemove": ["lasso2d", "select2d"],
    },
)


# ============================================================
# NODE TYPE LEGEND
# ============================================================

st.html(
    """
    <div class="legend">
        <div class="legend-item">
            <span class="legend-dot blue-dot"></span>
            Source Host
        </div>
        <div class="legend-item">
            <span class="legend-dot green-dot"></span>
            Target Host
        </div>
        <div class="legend-item">
            <span class="legend-dot purple-dot"></span>
            Attack Event
        </div>
        <div class="legend-item">
            <span class="legend-dot orange-dot"></span>
            Attack Type
        </div>
        <div class="legend-item">
            <span class="legend-dot gray-dot"></span>
            Other
        </div>
    </div>
    """
)


# ============================================================
# SELECTED EVENT DETAILS
# ============================================================

if selected_event_id != "All" and not events.empty:
    if "event_id" in events.columns:
        selected_rows = events[
            events["event_id"].astype(str) == str(selected_event_id)
        ]

        if not selected_rows.empty:
            row = selected_rows.iloc[0]
            st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
            st.html(
                f"""
                <div style="
                    font-size:1.2rem;
                    font-weight:750;
                    margin-bottom:15px;
                ">
                    Event Details — {selected_event_id}
                </div>
                """
            )

            detail_cols = st.columns(4)
            fields = [
                ("Source IP", "src_ip"),
                ("Destination IP", "dst_ip"),
                ("Protocol", "protocol"),
                ("Attack Type", "attack_type"),
            ]
            for col, (label, field) in zip(detail_cols, fields):
                value = row[field] if field in row.index else "—"
                with col:
                    st.metric(label, str(value))

            detail_cols2 = st.columns(3)
            fields2 = [
                ("Start Time", "start_time"),
                ("End Time", "end_time"),
                ("Flow Count", "flow_count"),
            ]
            for col, (label, field) in zip(detail_cols2, fields2):
                value = row[field] if field in row.index else "—"
                with col:
                    st.metric(label, str(value))


# ============================================================
# PIPELINE CONTEXT
# ============================================================

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.html(
    """
    <div style="
        font-size:1.15rem;
        font-weight:750;
        margin-bottom:8px;
    ">
        How this graph was constructed
    </div>
    """
)
st.markdown(
    """
    Suspicious network flows are grouped into events using
    source IP, destination IP, protocol and temporal proximity.
    Ground-truth labels are not used as production predictions.
    Attack-type nodes appear only when a separate classifier provides
    predicted_attack_type. Temporal precedes edges show observed
    ordering/correlation and do not prove causation. Events connected
    by shared-host temporal edges can be grouped into candidate incidents,
    which require analyst validation.
    """
)