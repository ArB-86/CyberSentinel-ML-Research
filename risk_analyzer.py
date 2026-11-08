import pandas as pd
import networkx as nx
from pathlib import Path

def get_attack_category_weight(attack_type: str) -> float:
    """Assign deterministic baseline risk weights based on attack categories."""
    if not isinstance(attack_type, str):
        return 40.0

    attack_lower = attack_type.lower()
    if any(k in attack_lower for k in ["heartbleed", "ddos", "bot"]):
        return 90.0
    elif any(k in attack_lower for k in ["patator", "brute", "sql", "injection"]):
        return 75.0
    elif any(k in attack_lower for k in ["portscan", "infiltration"]):
        return 60.0
    else:
        return 40.0

def calculate_incident_risks(events_csv_path, graph_gexf_path, output_csv_path):
    print("Loading events and attack graph for enhanced risk assessment...")

    events_path = Path(events_csv_path)
    if not events_path.exists():
        raise FileNotFoundError(f"Events file not found at {events_path}")

    df = pd.read_csv(events_path)

    # Load NetworkX graph
    graph = None
    graph_path = Path(graph_gexf_path)
    if graph_path.exists():
        graph = nx.read_gexf(graph_path)

    if_threshold = 0.032849
    risk_results = []

    # Pre-calculate max flow count for normalization
    max_flow_count = max(df['flow_count'].max(), 1) if 'flow_count' in df.columns else 1

    for _, row in df.iterrows():
        event_id = str(row['event_id'])
        anomaly_score = float(row['mean_anomaly_score']) if pd.notna(row['mean_anomaly_score']) else 0.0
        flow_count = int(row['flow_count']) if pd.notna(row['flow_count']) else 1
        attack_type = str(row.get('attack_type', 'Unknown'))

        # 1. Anomaly Severity Factor (A): Lower score below threshold = higher severity
        if anomaly_score < if_threshold:
            # Scale distance below threshold
            score_diff = if_threshold - anomaly_score
            factor_a = min(100.0, (score_diff / if_threshold) * 100.0 + 40.0)
        else:
            factor_a = max(0.0, 30.0 - ((anomaly_score - if_threshold) * 50.0))

        # 2. Event Frequency Factor (F): Normalized flow count
        factor_b = min(100.0, (flow_count / max_flow_count) * 100.0)
        if factor_b < 10.0:
            factor_b = 20.0 # baseline frequency weight

        # 3. Host Involvement / Topological Spread Factor (H)
        node_key = f"event:{event_id}"
        in_deg, out_deg = 0, 0
        if graph and node_key in graph:
            in_deg = graph.in_degree(node_key)
            out_deg = graph.out_degree(node_key)
        total_deg = in_deg + out_deg
        factor_h = min(100.0, total_deg * 25.0)

        # 4. Temporal Correlation Factor (T): Count events within 300s sharing src/dst IP
        src_ip = row.get('src_ip')
        dst_ip = row.get('dst_ip')
        start_time = pd.to_datetime(row.get('start_time'), errors='coerce', utc=True)

        temporal_matches = 0
        if pd.notna(start_time) and src_ip and not df.empty:
            # Check other rows sharing source or destination within temporal window
            time_diffs = pd.to_datetime(df['start_time'], errors='coerce', utc=True) - start_time
            mask = (time_diffs.dt.total_seconds().abs() <= 300) & ((df['src_ip'] == src_ip) | (df['dst_ip'] == dst_ip))
            temporal_matches = max(0, int(mask.sum()) - 1) # exclude self

        factor_t = min(100.0, temporal_matches * 20.0 + 10.0)

        # 5. Attack Category Risk Factor (C)
        factor_c = get_attack_category_weight(attack_type)

        # Weighted Multi-Factor Risk Score Calculation
        total_risk_score = round(
            0.30 * factor_a +
            0.20 * factor_b +
            0.15 * factor_h +
            0.20 * factor_t +
            0.15 * factor_c,
            2
        )

        # Severity Bands
        if total_risk_score >= 80.0:
            risk_level = "CRITICAL"
        elif total_risk_score >= 60.0:
            risk_level = "HIGH"
        elif total_risk_score >= 30.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        risk_results.append({
            "event_id": event_id,
            "attack_type": attack_type,
            "risk_score": total_risk_score,
            "risk_level": risk_level,
            "anomaly_severity_factor": round(factor_a, 2),
            "frequency_factor": round(factor_b, 2),
            "host_involvement_factor": round(factor_h, 2),
            "temporal_correlation_factor": round(factor_t, 2),
            "attack_category_factor": round(factor_c, 2),
            "in_degree": in_deg,
            "out_degree": out_deg,
            "flow_count": flow_count
        })

    out_df = pd.DataFrame(risk_results)
    Path(output_csv_path).parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_csv_path, index=False)
    print(f"Risk analysis successfully completed! Results saved to {output_csv_path}")

if __name__ == "__main__":
    calculate_incident_risks(
        events_csv_path="outputs/attack_events.csv",
        graph_gexf_path="outputs/attack_graph.gexf",
        output_csv_path="outputs/event_risk_scores.csv"
    )