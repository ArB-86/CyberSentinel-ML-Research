# Extended training-size validation protocol

## Purpose

The initial three-seed pilot compared Isolation Forest, novelty-LOF and RBF One-Class SVM with 5,000 benign training flows. This follow-up tests whether that ranking and the measured operating characteristics persist as the benign-only training budget increases.

## Experimental design

This is a paired, nested-sample sensitivity study.

- Training sizes: 5,000, 25,000 and 50,000 benign flows.
- Repetition seeds: 42, 43 and 44.
- One duplicate-grouped train/validation/test partition is created using split seed 42.
- One fixed benign-only calibration sample (5,000 rows) is used for every model, training size and repetition.
- One fixed binary-stratified test sample (15,000 rows) is used for every model, training size and repetition.
- For each repetition seed, the 5k training set is nested inside the 25k set, which is nested inside the 50k set.
- The three unsupervised models are fitted on benign rows only: Isolation Forest, LOF in novelty mode, and exact RBF One-Class SVM.
- Each model's threshold is calibrated on the same held-out benign calibration rows to target 5% nominal FPR. Test labels are used only for final scoring.

This design differs from the initial pilot, where each seed generated a different split and test sample. Here the holdout is deliberately fixed so that training-set size and model stochasticity can be examined without changing test observations.

## Metrics

For every model, training size and seed, the runner records:

- ROC-AUC and Average Precision (PR-AUC).
- Attack precision, recall, F1, FPR, FNR, balanced accuracy and MCC.
- Confusion counts and alert rate.
- Fit time, calibration scoring time, test scoring time and test throughput.
- Per-attack recall with test support.

The summary table reports mean and sample standard deviation across three repetitions. Plots show Average Precision, F1 and fit time versus benign training size.

## Interpretation rules

1. Compare models at the same training size; do not compare a 50k model against a 5k model and call the difference an algorithm effect.
2. The same calibration and test rows are used for every run. The 5k/25k/50k training samples are nested within each seed.
3. RBF One-Class SVM is an exact kernel SVM in this experiment, not a Nyström approximation. Its time and memory costs must be reported as observed.
4. LOF is run in novelty mode because the test rows are unseen observations.
5. A higher training budget does not automatically mean better generalisation. Review PR-AUC, thresholded recall/F1, FPR, per-attack coverage and runtime together.
6. Three repetitions on a single fixed test sample quantify training-sample/model randomness, not independent test-set uncertainty. This is a sensitivity analysis, not a substitute for external validation.
7. Exact duplicate numeric feature vectors are grouped into one split. The cleaned Parquet omits five-tuple identifiers and timestamps, so the study cannot guarantee connection-level or temporal separation.
8. Rare attack classes have very small support. A zero or perfect score from a handful of records is not a stable generalisation claim.
9. If an exact LOF or RBF One-Class SVM run is computationally impractical at 50k, report that outcome transparently. Do not silently switch to an approximate method while retaining the same model name.

## Reproduction

The dedicated runner is `experiments/compare_model_scales.py`. The workflow uses the SHA-256-verified processed CICIDS2017 Parquet and writes outputs to `experiments/results/scaling-validation-v1/`.

The generated files are:

- `metrics_by_seed.csv`
- `summary_mean_std.csv`
- `per_attack_by_seed.csv`
- `per_attack_pooled.csv`
- `run_metadata.json`
- `scaling_pr_auc.png`
- `scaling_f1.png`
- `scaling_fit_time.png`

No result value should be entered in a report until the corresponding run output exists.
