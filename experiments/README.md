# Model comparison experiments

This folder contains a reproducible, label-disciplined comparison harness for CICIDS2017.

## Models

- **Isolation Forest** — project baseline; fit on benign training flows only.
- **Local Outlier Factor (LOF)** — novelty mode; fit on benign training flows only and score unseen flows.
- **RBF One-Class SVM** — fit on benign training flows only.
- **Random Forest** — supervised reference only; it is deliberately reported separately because it learns from attack labels.

## Dataset

Download the processed CICIDS2017 Parquet asset using the links and checksums in [DATASET_SOURCES.md](../DATASET_SOURCES.md). Keep the data outside Git (the file is hundreds of MB). Verify its SHA-256 before running.

## Environment

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r experiments/requirements.txt
```

## Run

From the repository root:

```bash
python experiments/compare_models.py \
  --data data/cleaned_cicids2017.parquet \
  --outdir experiments/results \
  --seed 42 \
  --train-benign 5000 \
  --calibration-rows 5000 \
  --evaluation-rows 15000 \
  --target-fpr 0.05
```

For a first research report, repeat at least three fixed seeds and keep each output directory separate so later runs do not overwrite earlier evidence:

```bash
for seed in 42 43 44; do
  python experiments/compare_models.py \
    --data data/cleaned_cicids2017.parquet \
    --outdir experiments/results/seed-${seed} \
    --seed ${seed} \
    --train-benign 5000 \
    --calibration-rows 5000 \
    --evaluation-rows 15000 \
    --target-fpr 0.05
done
```

After this controlled pilot, repeat with a larger shared benign training cap (for example 10,000) as a sensitivity check. Record the increased LOF/One-Class SVM runtime; do not silently change the cap for only one unsupervised model.

The script creates:

- `metrics.csv` — binary metrics, confusion counts, runtime and throughput.
- `per_attack_recall.csv` — per-attack detection recall and support.
- `predictions.csv` — shared test predictions and continuous anomaly scores.
- `run_metadata.json` — split, feature, data and software metadata.
- `roc_pr_curves.png` — optional plot (when Matplotlib is installed).

## Experimental discipline

1. Exact duplicate numeric feature vectors are assigned to one split using `StratifiedGroupKFold`. Validation is fold 0, test is fold 1, and remaining folds are training.
2. All three unsupervised models see benign training rows only. They use the same benign training cap and same test evaluation rows.
3. A held-out benign-only validation calibration subset sets each threshold to the same nominal false-positive target. Test labels are not used for threshold choice.
4. Random Forest uses labelled training data and is a distinct supervised reference—not a like-for-like unsupervised competitor.
5. The cleaned Parquet has no connection five-tuple identifiers; this experiment therefore controls exact feature duplicates, not connection-level grouping.
6. Run multiple seeds and report mean ± standard deviation before making a final research claim. A single run is an exploratory result, not strong statistical evidence.

The default training/evaluation caps are intentionally modest because LOF and RBF One-Class SVM are much more computationally expensive than Isolation Forest. Increase caps only after the first run completes and document the exact configuration. Never silently compare results from different test rows or thresholds.


## Event and candidate-incident sensitivity

The event builder uses a 60-second default grouping window and the temporal graph uses a 300-second default maximum gap. These are configurable engineering parameters, not validated universal settings. To measure how the structure changes on a detector-flagged metadata-rich flow export, run:

```bash
python experiments/event_correlation_sensitivity.py \
  --input outputs/suspicious_flows_with_metadata.csv \
  --output-dir experiments/results/event-sensitivity \
  --time-windows 30,60,120 \
  --sequence-gaps 60,180,300,600
```

The input must contain `predicted_anomaly`, timestamps, source/destination addresses and protocol. When both port columns are present they are included in the event key. Ground-truth labels are excluded before grouping.

Outputs:
- `event_correlation_sensitivity.csv` — one row per parameter combination, including event counts, flows per event, event durations, temporal edges, candidate-incident counts and event coverage.
- `event_correlation_sensitivity_metadata.json` — input SHA-256, data time range, parameter grid and interpretation limits.

This is a **structural sensitivity** experiment only. Without analyst-labelled incident/stage ground truth it does not measure event precision/recall, causal reconstruction or which setting is correct. Run on the full detector-flagged metadata-rich export; do not treat a prefix-limited smoke-test file as representative.

## Temporal validation and Isolation Forest tuning

Run this experiment on the original metadata-rich CICIDS2017 CSV archive (not
the cleaned Parquet, which does not retain the required timestamps and host
metadata):

```powershell
.\.venv\Scripts\python.exe experiments\temporal_threshold_optimization.py \
  --data-dir data\cicids2017_metadata \
  --outdir experiments\results\temporal-threshold-v1 \
  --train-rows 25000 \
  --validation-rows 120000 \
  --test-rows 0 \
  --target-fpr 0.01
```

The script parses CICIDS timestamps day-first (so 03/07/2017 means 3 July),
uses all earlier capture days for benign-only fitting, the penultimate day for
hyperparameter/threshold selection, and the final day as an untouched temporal
test. Exact duplicate numeric-feature rows are retained in their earliest
chronological partition only. All detectors use the same benign training rows.

Isolation Forest searches the configured grid of tree count, max_samples and
max_features. It selects the configuration with the highest validation attack
recall at the primary FPR budget (ties: F1, AP, then fit time). LOF novelty and
RBF One-Class SVM are fitted as comparators. Thresholds at 0.5%, 1%, 2% and 5%
FPR are set from validation-benign scores only, then frozen for final test
evaluation. No test label is used for tuning.

Outputs:
- `isolation_forest_validation_grid.csv` — IF hyperparameter search.
- `validation_threshold_sweep.csv` — validation metrics at each FPR budget.
- `temporal_test_metrics.csv` — final later-day comparison at identical frozen thresholds.
- `per_attack_recall_at_target_fpr.csv` — attack-class recall and support at the primary FPR.
- `isolation_forest_temporally_tuned.joblib` — selected IF model, imputer and validation thresholds.
- `temporal_validation_summary.json` — split dates, selected configuration, test result and run metadata.

The final test date is one chronological CICIDS2017 holdout, not independent
evidence across networks or future years. Precision/AP depend on test prevalence;
with `--test-rows 0`, the full final capture day is evaluated. The script never
forces Isolation Forest to win: report the detector that actually leads at the
chosen false-positive budget.
