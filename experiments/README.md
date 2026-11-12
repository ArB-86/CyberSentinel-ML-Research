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

## Rolling temporal validation and Isolation Forest tuning

Run this experiment on the original metadata-rich CICIDS2017 CSV archive (not
the cleaned Parquet, which does not retain the required timestamps and host
metadata):

```powershell
.\.venv\Scripts\python.exe experiments\temporal_threshold_optimization.py --data-dir data\cicids2017_metadata --outdir experiments\results\temporal-rolling-v1 --folds 3 --train-rows 25000 --validation-rows 120000 --test-rows 0 --target-fpr 0.01
```

The default three folds use expanding-window forward chaining:

| Fold | Benign-only training period | Validation / threshold calibration | Untouched test |
|---|---|---|---|
| 1 | Monday (3 July) | Tuesday (4 July) | Wednesday (5 July) |
| 2 | Monday–Tuesday | Wednesday (5 July) | Thursday (6 July) |
| 3 | Monday–Wednesday | Thursday (6 July) | Friday (7 July) |

The script parses CICIDS timestamps day-first (so 03/07/2017 means 3 July).
Exact duplicate numeric-feature rows are retained in their earliest temporal
partition only. The same benign training rows are used by all four detectors
within a fold. The `--folds` option may be reduced for a shorter run, but cannot
exceed the number of possible forward-chaining windows.

Within each fold:
- Isolation Forest searches the configured tree-count, max-samples and max-features grid. The selected configuration maximizes validation attack recall at the primary FPR budget (ties: F1, AP, then fit time).
- Novelty LOF and RBF One-Class SVM are fitted on the same benign training sample.
- Thresholds at 0.5%, 1%, 2% and 5% FPR are calibrated from validation-benign scores only, then frozen for that fold's later test day.
- Test labels are never used for model or threshold selection. Actual test FPR is measured and may exceed the validation budget under temporal distribution shift.

Outputs:
- `rolling_if_validation_grid.csv` — all IF configurations and validation metrics per fold.
- `rolling_validation_threshold_sweep.csv` — validation metrics at each FPR budget.
- `rolling_test_metrics.csv` — per-fold later-day metrics at frozen thresholds.
- `rolling_per_attack_recall.csv` — attack-family recall and support per fold.
- `rolling_macro_metrics.csv` — fold-macro mean and standard deviation by detector/FPR.
- `rolling_pooled_confusion_metrics.csv` — precision, recall, F1 and FPR from summed confusion counts; AP/ROC-AUC are intentionally not pooled across score scales.
- `fold_1/`, `fold_2/`, `fold_3/` — fold-specific tuned Isolation Forest artifacts.
- `rolling_temporal_summary.json` — fold dates, row counts, test prevalence, selected configurations, metrics and interpretation limits.

The three test windows come from one CICIDS2017 capture, not three independent
datasets. They provide a stronger temporal-shift check than a single holdout,
but do not prove generalization to another network or future years. Precision
and AP depend on each test window's attack prevalence. Do not call a detector
the overall winner from one metric alone; inspect per-fold false-positive
rates, recall and attack-family coverage together.
