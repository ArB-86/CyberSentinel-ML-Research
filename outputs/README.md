# Generated outputs and runtime workflows

This directory is the runtime output location for the metadata-rich detection, event-correlation, graph, risk-triage and investigation workflows. Large datasets and environment secrets must stay outside version control.

## 1. Train and evaluate the detector (benchmark mode)

Use metadata-rich CICIDS2017 CSV files with timestamps, source/destination addresses, protocol, numeric flow features and a ground-truth `Label` column:

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/metadata-rich-csvs \
  --mode benchmark \
  --output-dir outputs \
  --benign-sample-n 500000 \
  --calibration-rows 5000 \
  --evaluation-rows 160000 \
  --calibration-quantile 0.05
```

By default, the pipeline reads all rows. A positive `--nrows` is only for quick smoke tests; reading a prefix of each file is not suitable for temporal or incident analysis.

Benchmark mode uses labels only to construct benign-only fit/calibration pools and for held-out evaluation. Labels are not numeric features, detector predictions, event-group keys, graph classifications or risk weights.

The fit, calibration and evaluation roles are separated by exact numeric-feature hashes:
- fit: benign-only training groups;
- calibration: benign-only held-out groups for the threshold;
- evaluation: held-out benign groups plus attack rows whose exact feature hash does not occur in fit/calibration.

The median imputer and Isolation Forest are fitted on the benign training sample only. The benchmark output includes a reusable `isolation_forest_model.joblib` artifact containing the fitted detector, imputer, feature order, benign-calibrated threshold and calibration score quantiles. **Joblib artifacts are executable pickle-based files; load only artifacts from a trusted project environment.**

## 2. Score unlabeled network traffic (inference mode)

After a benchmark model artifact exists, a new metadata-rich CSV directory can be scored without any ground-truth `Label` column:

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/unlabeled-flow-csvs \
  --mode infer \
  --model-artifact outputs/isolation_forest_model.joblib \
  --output-dir outputs
```

Inference mode:
- does not require or read ground-truth labels;
- applies the stored imputer and feature order from training;
- applies the stored threshold calibrated on benign validation traffic;
- uses only `predicted_anomaly` to select suspicious flows;
- leaves attack type as `Unclassified` unless a separate classifier supplies `predicted_attack_type`.

Inference requires the same numeric feature schema and the metadata fields needed for event grouping (timestamp, source/destination and protocol). Missing or incompatible feature columns cause an explicit error rather than a silent feature substitution.

## 3. Generated files

Detection/graph outputs:
- `isolation_forest_model.joblib` — reusable fitted detector and preprocessing/threshold artifact (benchmark mode).
- `suspicious_flows_with_metadata.csv` — held-out benchmark detections or unlabeled inference detections. Ground-truth `Label` and `is_attack` fields are removed before this downstream artefact is written; benchmark annotations remain only in the evaluation calculation.
- `detection_metrics.json` — held-out benchmark metrics (benchmark mode only).
- `per_attack_detection_evaluation.csv` — per-attack held-out recall/support (benchmark mode only).
- `attack_events.csv` — label-independent time/connection event groups.
- `incident_groups.csv` — candidate multi-event groups from shared-host temporal-correlation edges. These require analyst validation and do not prove causality.
- `attack_graph.gexf` — full host/event/incident graph.
- `attack_graph.png` — deterministic visual sample if the graph is too large for one layout.
- `pipeline_summary.json` — split, threshold, model, detection, event and graph metadata.

Both benchmark and unlabeled inference modes automatically run the risk-triage stage after graph generation. They create `event_risk_scores.csv` and `incident_risk_scores.csv` and record output counts in `pipeline_summary.json`.

If event/graph files are edited manually and triage outputs need to be refreshed, the risk engine can also be run independently:

```bash
python risk_analyzer.py \
  --events outputs/attack_events.csv \
  --graph outputs/attack_graph.gexf \
  --output outputs/event_risk_scores.csv
```

This generates:
- `event_risk_scores.csv` — transparent heuristic event triage index, not a calibrated incident probability.
- `incident_risk_scores.csv` — maximum available event triage index per candidate incident, marked as an unconfirmed correlation requiring analyst review.

The risk index uses anomaly scores relative to the benign calibration distribution, event volume, host involvement and temporal links where available. Missing factors are omitted and remaining configured weights renormalised. At least two factors are required; otherwise an item is `UNASSESSED`. Current weights and normalisation caps are engineering defaults—not statistically learned or validated risk probabilities.

## 4. Investigation reports

The agentic investigator retrieves event, flow, host and graph evidence through predefined tools. The flow loader explicitly excludes `Label` and `is_attack`, and the flow-evidence tool never returns benchmark annotations to the LLM. Its report renderer is deterministic and reports unknown fields explicitly. Tool-grounded prompts and formatting reduce unsupported statements but do not prove LLM factual accuracy; independent analyst review remains required before containment or other operational action.

The JSON investigation examples and Markdown reports in this directory are representative outputs, not a substitute for running the workflow against the traffic data being investigated.
