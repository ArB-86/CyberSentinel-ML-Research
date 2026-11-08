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
