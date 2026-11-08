# Project hardening report

**Working branch:** `research/project-hardening`  
**Scope:** detector data flow, event formation, graph semantics, candidate incident correlation, risk triage, agent report safety, label-free inference, dashboard truthfulness and automated regression checks.

## 1. Executive summary

The hardening work addresses correctness and deployment gaps found during a code audit. It does not change the detector in the existing application from Isolation Forest to another algorithm. Instead, it makes the current Isolation Forest path more defensible, adds a reusable model artifact and a separate label-free inference mode, and makes event/incident/risk outputs explicitly distinguish predictions, correlations and unknowns.

The default `main` branch and the other research branches were not changed by this work. All changes are isolated to `research/project-hardening`.

## 2. Defects fixed in code

### 2.1 Preprocessing and evaluation leakage

**Before:** numeric feature selection removed all-empty/constant columns using the complete metadata file, and the older metadata pipeline scored rows used during model fitting/calibration. That allowed the same flows to influence fitting and downstream graph construction.

**Now:**
- Numeric feature schema is retained; columns are not dropped because of statistics calculated across the complete file.
- The median imputer is fitted on the selected benign training sample only.
- When at least three distinct UTC calendar dates are present, benign data is split chronologically: earlier dates for fitting, middle dates for threshold calibration, and the latest dates for held-out evaluation.
- When fewer than three distinct dates exist, the pipeline falls back to a random exact-feature-hash group split and records that cross-day generalisation was not established.
- Exact numeric feature hashes are kept disjoint across fit, calibration and evaluation; later partitions drop hashes already assigned to earlier partitions.
- Attack rows are selected from the held-out calendar-day range when chronological splitting is available. Attack rows whose exact feature hash appears in fit/calibration or conflicts with a benign evaluation hash are excluded and counted.
- Training and calibration samples are deduplicated by exact feature hash.
- The median imputer and Isolation Forest are fitted on the selected benign training sample only.
- The threshold is calculated from benign calibration scores only.
- Detection metrics are calculated on held-out evaluation rows; suspicious-flow, event and graph outputs are constructed only from held-out evaluation flows.
- The benchmark output includes confusion counts, ROC-AUC, Average Precision, precision, recall, F1, FPR/FNR, per-attack support/recall, split date ranges and duplicate exclusions.

**What this establishes:** for multi-day metadata-rich datasets, the pipeline evaluates on later calendar days than the model-fit and threshold-calibration periods, while keeping exact numeric feature hashes disjoint.

**What it does not establish:** this is not a host/subnet/attack-scenario holdout, and it does not establish generalisation to an independent organisation or network. Exact-feature-hash separation is not equivalent to a full five-tuple connection-group split. The cleaned modelling Parquet lacks the timestamps and endpoint metadata required for calendar-day/event analysis; the metadata-rich CSV export is required.

### 2.2 Separate benchmark training from production-style inference

The earlier metadata pipeline required a ground-truth `Label` column to run. That is unsuitable for genuinely unlabeled network traffic.

Two modes now exist:

- `--mode benchmark`: labelled CICIDS2017 input is required to construct benign-only training/calibration and held-out evaluation partitions. The mode saves a fitted Isolation Forest artifact containing the model, imputer, feature order, benign-calibrated threshold and calibration score quantiles.
- `--mode infer`: loads the trusted artifact and scores CSV flow records without requiring a `Label` column. It uses the stored imputer, feature order and calibrated threshold. Ground-truth labels are not used or written to inference suspicious-flow outputs.

The inference mode requires the same numeric feature schema and the metadata required for event grouping. Missing model features fail explicitly instead of being silently replaced.

**Artifact security:** `joblib` is pickle-based. Load only model artifacts from a trusted project environment.

### 2.3 Ground-truth label leakage in event grouping

**Before:** the event key included the CICIDS ground-truth attack label. It also allowed the label to act as a fallback for suspicious-flow selection.

**Now:**
- Event selection requires the detector-produced `predicted_anomaly` flag or an explicitly supplied anomaly-score threshold.
- Ground-truth `Label` is never a detector fallback or event-group key.
- The pipeline groups events by source, destination, protocol and—when both are available—source/destination ports. It falls back to the three-field key only when port metadata is absent.
- Attack type remains `Unclassified` unless a separate model provides `predicted_attack_type`.
- A model-predicted type is tagged with its source; a dataset label is not represented as a production prediction.

This makes event grouping usable on unlabeled inference traffic and prevents a benchmark annotation from being presented as a model prediction.

### 2.4 Temporal graph edge correctness

**Before:** temporal linking compared only globally adjacent events. An unrelated event between two events sharing a host could prevent a relevant link from being created.

**Now:**
- Each host has its own event timeline.
- Candidate links are created between adjacent events in that host's timeline.
- A `precedes` edge requires the earlier event to finish before the later event starts and the configured gap to be within the limit.
- Edges record shared host/link basis, gap, `temporal_correlation=True` and `causal_claim=False`.
- Missing optional attributes are omitted from GEXF export instead of passing null values to NetworkX.

Temporal order is explicitly described as correlation, not causation.

### 2.5 Candidate incident formation

An actual candidate incident grouping stage is now present:
- Event-to-event graph edges marked as temporal correlations are converted into an undirected correlation graph.
- Connected components with at least two events receive an `INC-*` identifier.
- Isolated events remain standalone and are not promoted to incidents.
- `incident_groups.csv` records events, hosts, time span, flow count, temporal links and the grouping basis.
- Each group is marked `potential_correlation_requires_analyst_validation` and `causal_claim=False`.
- The attack graph includes incident membership nodes/edges.
- The investigation UI displays candidate incident groups and their confirmation status.

**Limit:** this is an explainable rule-based candidate grouping method. It is not a validated causal attack reconstruction model. Ground-truth incident/stage annotations and a measured event/incident correlation benchmark are still needed.

### 2.6 Risk scoring no longer uses fixed detector thresholds or attack-label weights

**Before:** the risk engine used a hard-coded Isolation Forest score threshold and attack-category weights. Those values were not calibrated for the metadata-rich feature space or validated as incident probabilities.

**Now:**
- Anomaly severity is derived from the benign calibration-score distribution saved by the detection pipeline.
- If calibration metadata is unavailable, relative batch rank is used only when multiple events exist; it is explicitly identified as relative.
- No ground-truth attack category is used as a production risk weight.
- Event volume, host involvement and temporal-link factors are explicit, configurable heuristic inputs.
- Missing evidence factors are omitted and the remaining weights are renormalised. Missing flow counts and missing graph degrees remain unavailable rather than becoming zero.
- At least two positively weighted evidence factors are required; zero-weight factors do not count as independent support. Otherwise the result is `UNASSESSED`.
- Risk outputs explicitly state `heuristic_triage_score_not_probability`.
- Candidate incident priority is aggregated from available event triage scores using the maximum event score and remains marked as an unconfirmed correlation.

**Limit:** the factor weights, normalisation reference caps and LOW/MEDIUM/HIGH/CRITICAL bands remain engineering heuristics. They are not learned from analyst-confirmed incident outcomes and must not be reported as calibrated probability or validated incident severity.

### 2.7 Investigation agent and report safety

- Benchmark `Label`/`is_attack` fields are removed from the downstream suspicious-flow CSV before event, graph, risk or agent processing.
- The shared agent flow loader excludes ground-truth label columns even if an older or manually prepared CSV still contains them.
- The `get_flow_evidence` tool reports flow metadata, ports, timestamps, packet/flag counts and anomaly scores, but never returns ground-truth labels or label counts.
- The tool matches the event's observed port pairs and exact event time interval; malformed port metadata fails closed instead of using a broad IP-only match.
- Event IDs are normalized without double-prefixing; report filenames are sanitized and hash-suffixed before writing or download to prevent path traversal/collisions.
- The agent system prompt separates observed facts from hypotheses and treats tool output as untrusted data, not instructions.
- Dataset labels and anomaly scores are described as indicators, not proof of compromise, authentication success, data loss or service impact.
- Temporal graph links are described as correlations, not causation.
- The final response is checked for the required structured JSON fields.
- Invalid or incomplete model output falls back to a deterministic evidence-only summary.
- Markdown reports are rendered deterministically from the investigation JSON; a second LLM formatting call no longer invents impact metrics or unsupported signatures.
- Analyst approval is required before operational response.

The manual response checklist no longer claims to execute SOAR, firewall blocks, host isolation or account disabling. These are recommendations only.

**Limit:** prompts and schema checks reduce risk but do not prove the LLM is factually correct. A human-labelled investigation benchmark is still required to measure evidence precision, unsupported-claim rate, tool-selection accuracy and abstention behaviour.

### 2.8 Dashboard and documentation truthfulness

- Hard-coded dataset counts and synthetic fallback flow counts were removed.
- Application pipeline status is derived from actual artefacts/summary values.
- Event and potential-incident stages are displayed separately.
- Missing risk/graph data is shown as unavailable rather than “system online”.
- CSV/GEXF-derived text is HTML-escaped before rendering inside event cards and graph hover tooltips.
- Risk pages call the score a heuristic triage index and state when it is unassessed.
- Generated-output instructions now distinguish benchmark training from unlabeled inference and document the separate risk-analysis command.

### 2.9 Research comparison preprocessing

**Before:** both model-comparison loaders removed all-empty and constant numeric columns using statistics calculated across the complete Parquet before creating train/validation/test partitions. Numeric event/incident identifiers were also not explicitly excluded.

**Now:**
- Both `compare_models.py` and `compare_model_scales.py` exclude labels, attack flags, flow/event/incident IDs, endpoints and timestamps by column name.
- They preserve the numeric feature schema; no full-dataset missingness or variance filter is applied before splitting.
- Every comparison model fits `SimpleImputer(strategy="median", keep_empty_features=True)` on its own training subset and applies that fitted imputer to calibration/test rows.
- New Parquet-fixture tests cover constant, all-missing and numeric identifier columns in both loaders.

**Limit:** the existing comparison CSVs and reported rankings are historical outputs generated before this preprocessing change. The processed Parquet is not committed to Git (see `DATASET_SOURCES.md`), so this session has not regenerated the full CICIDS2017 comparison metrics. Do not present the old numbers as results of the current hardened experiment until the exact verified Parquet is rerun.

### 2.10 Event/incident parameter sensitivity harness

A reproducible structural sensitivity runner is available at `experiments/event_correlation_sensitivity.py`. Its default grid evaluates 30/60/120-second flow-grouping windows against 60/180/300/600-second temporal graph gaps on detector-flagged metadata-rich flows. It records event counts, flows-per-event distributions, event durations, temporal-edge counts, candidate-incident counts and event coverage, along with the input SHA-256 and timestamp range.

The runner excludes ground-truth labels from grouping and calls every incident group a candidate correlation requiring analyst validation. It does not claim that one parameter setting is correct. **The full sensitivity sweep has not yet been run on the team's actual full metadata-rich export**; synthetic regression coverage validates the runner contract only.

## 3. How to run the two detector modes

Install development/runtime requirements:

```bash
python -m pip install -r requirements-dev.txt
```

### Benchmark mode (requires CICIDS ground-truth labels)

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/metadata-rich-cicids-csvs \
  --mode benchmark \
  --output-dir outputs \
  --benign-sample-n 500000 \
  --calibration-rows 5000 \
  --evaluation-rows 160000 \
  --calibration-quantile 0.05
```

This generates `outputs/isolation_forest_model.joblib`, detection metrics, per-attack held-out evaluation, suspicious flows, candidate incidents and graph artefacts.

### Unlabeled inference mode

```bash
python attack_graph/if_attack_graph_pipeline.py /path/to/unlabeled-flow-csvs \
  --mode infer \
  --model-artifact outputs/isolation_forest_model.joblib \
  --output-dir outputs
```

No ground-truth `Label` column is required. The input must contain the same numeric feature columns and event metadata (timestamp, source/destination and protocol) used by the trained pipeline.

### Event and incident risk triage

Both benchmark and unlabeled inference modes automatically run the risk-triage stage after graph generation. They write `event_risk_scores.csv` and `incident_risk_scores.csv`, and record the generated counts in `pipeline_summary.json`. The CLI supports both the documented direct-script invocation and package-module invocation.

The risk engine uses observed anomaly scores relative to the benign calibration distribution, event volume, host involvement and temporal links where available. Missing factors are omitted and remaining configured weights are renormalised. At least two factors are required; otherwise the result is `UNASSESSED`. Current weights, normalization caps and triage bands are engineering heuristics, not statistically learned or validated risk probabilities.

The standalone `python risk_analyzer.py` command remains available to refresh triage outputs after events/graphs have been manually edited.
## 4. Automated regression checks

GitHub Actions workflow: `.github/workflows/reliability-checks.yml`.

Latest completed green validation on the working branch:
- Python module compile check: passed.
- Direct CLI smoke tests for `python attack_graph/if_attack_graph_pipeline.py --help` and `python risk_analyzer.py --help`: passed.
- Pytest: **33 passed**.

The tests cover label-independent and port-aware event creation, detector-output requirements, interleaved host timelines, non-overlapping temporal links, GEXF null handling, candidate incident grouping, chronological day holdout and single-day fallback, risk-score missing evidence semantics, unknown graph degrees, zero-weight risk factors, valid empty incident outputs, stale benchmark-output cleanup during inference, train-only preprocessing, benchmark-to-artifact-to-unlabeled-inference flow, ground-truth-label separation from downstream artefacts and agent evidence, exact port/time flow matching, malformed metadata fail-closed behaviour, safe artifact filenames, event ID formatting, structural event-window/temporal-gap sensitivity reporting, stale metric suppression, numeric identifier exclusion and all-missing feature handling in both comparison loaders, missing-label handling, and deterministic report rendering.

These are unit/integration tests on synthetic fixtures. They do not constitute a full-scale end-to-end evaluation on all metadata-rich CICIDS2017 files or a live enterprise network.

## 5. Limitations that remain open (not claimed as solved)

1. **Attack-family classification:** the current detector is binary anomaly detection. Event attack type remains `Unclassified` unless a separately trained and evaluated multiclass classifier supplies `predicted_attack_type`. Ground-truth labels are not substituted for predictions.
2. **Temporal/connection-level generalisation:** chronological calendar-day holdout is now used when at least three dates exist; one-day/single-day exports use an explicitly labelled random duplicate-group fallback. The current split does not hold out by host, subnet or attack scenario, and exact feature hashes are not the same as connection-group IDs. The cleaned 69-feature Parquet lacks timestamps/endpoints; the metadata-rich original traffic export is required for temporal and event-level analysis.
3. **Event window/gap sensitivity:** a reproducible 30/60/120-second grouping × 60/180/300/600-second temporal-gap structural sensitivity harness is implemented and tested. The full sweep still needs to be run on the team's complete metadata-rich export. Without analyst-labelled incident/stage ground truth, this measures structural fragmentation/merging only—not incident accuracy or causal validity.
4. **Incident correlation validity:** connected components represent candidate shared-host temporal correlations. They are not confirmed incidents, causal chains or multi-stage attack ground truth. A labelled incident/stage benchmark and analyst adjudication are needed.
5. **Risk-score calibration:** current factor weights, normalization references and bands are heuristic. They need calibration/validation against analyst-confirmed incident severity and operational outcomes before they can be used as severity estimates.
6. **Agent factuality:** evidence prompts and deterministic rendering are safeguards, not a measured factuality guarantee. Evaluate on analyst-labelled investigations and measure unsupported claims, evidence citation precision, tool success and abstention.
7. **Live telemetry / automated response:** the current source data is flow metadata. Endpoint, authentication, DNS and firewall telemetry are not guaranteed. Response actions remain manual recommendations; no containment integration is claimed.
8. **Domain shift and threshold drift:** the stored threshold is calibrated on benign CICIDS2017 calibration traffic. A new organisation/network requires a trusted benign calibration sample, drift monitoring and re-validation. Do not assume the CICIDS threshold transfers unchanged.
9. **Independent dataset / strict FPR evaluation:** no independent external dataset run or 1%, 0.5% and 0.1% operating-point validation is included in this hardening change.
10. **Large-scale metadata pipeline validation:** the new benchmark/inference code is covered by synthetic end-to-end integration tests; the whole metadata-rich 2.3-million-row graph pipeline still needs a full execution on the team's actual metadata-rich files and target hardware.

## 6. Recommended next research sequence

1. Run benchmark mode on the full metadata-rich CICIDS2017 flow export and inspect the saved split counts, excluded duplicate counts, metrics and graph outputs.
2. Run unlabeled inference mode against a separate capture or a held-out export with the `Label` column removed.
3. Run `experiments/event_correlation_sensitivity.py` on the complete metadata-rich export; then compare the candidate groups with documented CICIDS scenarios and analyst adjudication where a valid reference mapping exists.
4. Add a separate multiclass attack-family model only if it can be evaluated with a duplicate/group-aware split and per-class support reporting.
5. Create an analyst-reviewed investigation set for the agent; measure evidence accuracy and unsupported claims.
6. Recalibrate the heuristic risk index with confirmed incident outcomes before treating it as a prioritisation score beyond a demonstration.

## 7. Scope of this branch

This branch contains code, tests and documentation hardening. It does not replace the existing model-comparison experiment results and does not modify the default branch. Merge/release only after the team has run benchmark and unlabeled inference on the actual metadata-rich dataset and reviewed the resulting graph and risk outputs.
