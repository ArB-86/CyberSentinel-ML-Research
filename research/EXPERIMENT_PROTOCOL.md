# Experimental protocol: anomaly-detector comparison

## Research questions

- **RQ1:** Under the same benign-only training budget and a fixed nominal false-positive budget, how do Isolation Forest, Local Outlier Factor and RBF One-Class SVM compare on CICIDS2017?
- **RQ2:** How much does a supervised Random Forest reference improve detection when labelled attack examples are available during training?
- **RQ3:** What are the trade-offs in false alarms, attack recall, minority-attack coverage, training time and inference throughput?

## Dataset and target

Use the exact processed `cleaned_cicids2017.parquet` release referenced in [DATASET_SOURCES.md](../DATASET_SOURCES.md). The existing notebook describes 2,228,970 records and 69 numerical flow features plus the `Label` target. It reports 1,892,671 benign flows (84.91%) and 336,299 attack flows (15.09%) in the binary target.

The experiment predicts a binary outcome: `Benign` versus any non-benign label. The original multi-class label is retained only for per-attack recall reporting. Labels are excluded from the unsupervised feature matrix and benign-only model fitting.

## Split and leakage controls

The script computes a hash from numeric modelling features only (no label) and uses `StratifiedGroupKFold`:

Before splitting, the loader excludes identifiers and labels by column name but preserves the numeric feature schema. It does not drop columns based on missingness or variance measured across the entire dataset. Each model's median imputer is fitted only on that model's training subset, with `keep_empty_features=True`, and then applied unchanged to calibration/test rows. This avoids using held-out feature distributions to decide which numeric features exist.

- Fold 0: validation, used only to obtain benign calibration observations.
- Fold 1: held-out test.
- Remaining folds: training.

Rows with identical numeric feature vectors are kept in one fold. The script asserts zero exact-feature hash overlap between train, validation and test. A binary-stratified sample of the held-out test fold is shared by every model.

This is stricter than the row-wise random 70/15/15 split used by the existing Isolation Forest notebook, but it is not a complete connection-level split. The processed Parquet has removed flow IDs, IPs, ports and timestamps; this prevents a five-tuple or temporal grouping audit. A later experiment on metadata-rich data should group by directional five-tuple and/or time window as a separate sensitivity analysis.

A 2026 CIC-IDS2017 study reports that in its own record-level split, 18.3% of flows had an exact duplicate feature vector and about 20.5% of test rows also appeared in training. Its exact dataset representation and feature set are not assumed to be identical to this repository's Parquet. The result motivates measuring and controlling duplication in our own split rather than importing its numbers as our result.

## Models and fitting rules

| Model | Training regime | Key configuration | Rationale |
|---|---|---|---|
| Isolation Forest | Benign-only | 200 trees; max_samples up to 1,024; seed 42 | Existing project's scalable isolation-based baseline |
| Local Outlier Factor | Benign-only novelty detection | StandardScaler; novelty=True; k=35 | Tests whether local density deviations reveal attacks missed by a global isolation score |
| RBF One-Class SVM | Benign-only novelty detection | StandardScaler; RBF kernel; nu=0.05; gamma=scale | Tests a learned boundary around normal traffic |
| Random Forest | Supervised reference | Labelled training rows; class_weight=balanced_subsample; 300 trees | Estimates performance when attack labels are available; not an unsupervised competitor |

All three unsupervised models receive the same benign-only training sample cap. The default is 5,000 flows to keep LOF and exact RBF One-Class SVM tractable. Every model is scored on the same test rows. The sample counts are saved in `run_metadata.json`.

Random Forest receives labelled rows from the training partition and is presented separately. Do not claim that it is a like-for-like unsupervised detector.

## Threshold calibration

A common alert budget is used to compare decision metrics fairly. For each model, compute scores on a held-out calibration sample containing benign observations only. Choose the threshold at the upper `target_fpr` tail of anomaly scores (default 5%). Predict attack when test score is at least this threshold.

This procedure does not use validation attack labels to tune F1. Test labels are used only after all model and threshold choices are frozen. The realised test false-positive rate can differ from the nominal 5% because of sampling variation and distribution shift; report the measured value.

## Metrics

Report all of the following:

- **ROC-AUC:** ranking quality across thresholds.
- **PR-AUC / Average Precision:** precision-recall ranking quality; important when attacks are the minority class.
- **Attack precision, recall and F1:** thresholded attack detection.
- **False-positive rate (FPR) and false-negative rate (FNR):** alert burden and missed attacks.
- **Balanced accuracy and Matthews correlation coefficient (MCC):** less dominated by majority-class prevalence than raw accuracy.
- **Per-attack recall with support:** exposes classes such as Heartbleed and SQL Injection that have extremely few examples.
- **Training time, calibration time, test scoring time and rows/second:** computational cost.

Accuracy alone is insufficient. A model can achieve high accuracy by classifying most flows as benign while missing rare attacks. For PR-AUC, state that scikit-learn's Average Precision is used; it is not the trapezoidal area under a linearly interpolated PR curve.

## Repetition and reporting

The default CLI run is one deterministic seed. For a defensible final report, repeat with at least seeds 42, 43 and 44, then report mean and standard deviation for ROC-AUC, Average Precision, F1, recall, FPR and runtime. Retain each run's metadata and predictions. Do not cherry-pick the best seed.

For stronger claims about generalisation, also run a connection-grouped/temporal split on the metadata-rich source data. The current cleaned Parquet cannot support this because identifiers and timestamps are absent.

## Reproduction command

See [experiments/README.md](../experiments/README.md). The script does not populate pre-decided performance values: metrics are generated only after a real run against the verified Parquet file.
