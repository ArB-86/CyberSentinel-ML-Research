# Generated outputs

This directory contains representative investigation reports and incident-risk results.

## Generate detection, events and graph outputs

Run the metadata-rich CICIDS2017 CSV pipeline:

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/metadata-rich-csvs --output-dir outputs
```

By default, the pipeline reads all rows from the input CSV files. The `--nrows` option is only for quick smoke tests because reading a prefix of each file is not suitable for temporal or incident analysis.

Required metadata includes timestamps, source and destination addresses, protocol and flow-level numeric features. Ground-truth `Label` is kept separate from model features and is never used to decide which events the detector flags or how events are grouped.

The detection pipeline:
- splits benign data into disjoint fit, calibration and held-out evaluation groups;
- groups exact duplicate numeric feature vectors so they cannot cross these partitions;
- fits the median imputer and Isolation Forest on the benign training partition only;
- calibrates the anomaly threshold using held-out benign calibration rows only;
- evaluates on held-out benign rows plus attack rows with no exact feature-hash overlap with fit/calibration;
- creates suspicious-flow outputs and downstream events/graphs only from the held-out evaluation rows.

Generated files:
- `suspicious_flows_with_metadata.csv` — held-out flows flagged by the detector, with ground-truth labels retained only for offline evaluation.
- `detection_metrics.json` — held-out ROC-AUC, Average Precision, precision, recall, F1, FPR/FNR and confusion counts.
- `per_attack_detection_evaluation.csv` — per-attack recall with support.
- `attack_events.csv` — label-independent flow groups; attack type remains Unclassified unless a separate classifier provides a prediction.
- `incident_groups.csv` — candidate multi-event groups formed from shared-host temporal-correlation edges. Each group requires analyst validation and is not a confirmed campaign.
- `attack_graph.gexf` — full host/event/incident graph.
- `attack_graph.png` — deterministic visual sample if the graph is too large for one layout.
- `pipeline_summary.json` — thresholds, calibration distribution, split counts, overlap checks, metrics, graph counts and run metadata.

## Generate event and incident triage scores

Risk scoring is a separate step:

```bash
python risk_analyzer.py \
  --events outputs/attack_events.csv \
  --graph outputs/attack_graph.gexf \
  --output outputs/event_risk_scores.csv
```

This generates:
- `event_risk_scores.csv` — transparent, heuristic event triage index, not an incident probability.
- `incident_risk_scores.csv` — maximum available event triage index per candidate incident, clearly marked as an unconfirmed correlation requiring analyst review.

The score uses observed anomaly scores relative to the benign calibration distribution, event volume, host involvement and temporal links where available. Missing factors are omitted and remaining configured weights are renormalised. At least two factors are required; otherwise the item is marked UNASSESSED. Current weights and normalisation caps are engineering defaults, not statistically learned or validated risk probabilities.

## Investigation reports

The application can generate evidence-grounded investigation reports using the retrieved event, flow, host and graph tools. Reports distinguish observed facts from hypotheses and explicitly state unknown fields. Analyst review is required before containment or other operational action.

The JSON investigation examples and Markdown reports in this directory are representative project outputs, not a substitute for running the workflow against the event data being investigated.
