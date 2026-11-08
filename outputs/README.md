# Generated outputs

This directory contains representative investigation reports and incident-risk results.

The attack-graph pipeline creates the flow-level and graph outputs used by the application. Run it against a directory of metadata-rich CICIDS2017 CSV files:

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/metadata-rich-csvs --output-dir outputs
```

The input files must retain the metadata required for event grouping, including timestamps, source and destination addresses, ports, protocol, labels and network-flow features.

The pipeline generates:

- `suspicious_flows_with_metadata.csv` — suspicious flow records with retained context.
- `attack_events.csv` — correlated events grouped from suspicious flows.
- `attack_graph.gexf` — graph representation for graph analysis tools.
- `attack_graph.png` — quick visual overview when graph size permits.
- `pipeline_summary.json` — execution summary and graph statistics.

The Streamlit application reads these generated files from `outputs/`. Generate the graph outputs before using the graph and incident-investigation pages.

The JSON investigation examples, Markdown reports and `event_risk_scores.csv` in this directory are representative project outputs. They are examples of report structure, not a substitute for running the pipeline on the traffic data being investigated.
