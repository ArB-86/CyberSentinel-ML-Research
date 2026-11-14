# Experiment status

**Historical pre-hardening pilot:** the CICIDS2017 model-comparison run was executed across three seeds (42, 43 and 44). The archived metrics have not yet been regenerated after the current train-only feature-schema/imputation hardening; do not present the old rankings as validated current results.

The repository contains the per-seed metrics, predictions, per-attack recall, run metadata and ROC/PR plots under `experiments/results/processed-v1.0.1/`.

The consolidated findings are in [EXPERIMENT_RESULTS.md](EXPERIMENT_RESULTS.md). The report includes mean ± sample standard deviation, the benign-only training and calibration protocol, the separate supervised Random Forest reference, and the study limitations.

**Historical pilot finding only:** RBF One-Class SVM achieved the strongest unsupervised PR-AUC and F1 at the tested operating point. Isolation Forest remains the detector in the current application until larger-sample and metadata-rich evaluation justify a model change.

Next research steps are larger training-sample sensitivity checks, tie-aware supervised threshold calibration, temporal or connection-grouped evaluation, and improved assessment of rare attack classes.


## Metadata-rich temporal host-history result (13 November 2026)

A three-fold forward-chaining CICIDS2017 run compared the raw Isolation Forest with the same detector using 18 causal host-history features. Each fold used 25,000 benign training rows, 120,000 validation rows and a full later test day. The features use previous completed 1-minute and 5-minute source/destination host aggregates; the current minute is excluded.

Pooled confusion-count metrics from the recorded run:

| Metric | Raw IF | Raw IF + host history |
|---|---:|---:|
| Precision | 86.56% | 86.04% |
| Recall | 29.85% | 48.45% |
| F1 | 0.444 | 0.620 |
| FPR | 1.93% | 3.27% |

Host history materially improved attack recall, particularly DoS and DDoS traffic, but false positives also increased. The Thursday test fold still detected 0% of the Brute Force, SQL Injection and XSS samples; Friday host-history FPR was 8.12% despite a 1% validation calibration target. This candidate is **not approved for unattended deployment**.

The benchmark/inference CLI now builds the same host-history feature schema in both modes and persists it in a version-2 model artifact. Automated tests cover causal time windows, row alignment, schema persistence and label-free inference. The complete metadata-rich benchmark must be rerun through this integrated CLI on the local CSV archive before treating the final artifact as validated. No live-streaming state persistence is implemented.
