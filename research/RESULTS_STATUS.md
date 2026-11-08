# Experiment status

**Historical pre-hardening pilot:** the CICIDS2017 model-comparison run was executed across three seeds (42, 43 and 44). The archived metrics have not yet been regenerated after the current train-only feature-schema/imputation hardening; do not present the old rankings as validated current results.

The repository contains the per-seed metrics, predictions, per-attack recall, run metadata and ROC/PR plots under `experiments/results/processed-v1.0.1/`.

The consolidated findings are in [EXPERIMENT_RESULTS.md](EXPERIMENT_RESULTS.md). The report includes mean ± sample standard deviation, the benign-only training and calibration protocol, the separate supervised Random Forest reference, and the study limitations.

**Historical pilot finding only:** RBF One-Class SVM achieved the strongest unsupervised PR-AUC and F1 at the tested operating point. Isolation Forest remains the detector in the current application until larger-sample and metadata-rich evaluation justify a model change.

Next research steps are larger training-sample sensitivity checks, tie-aware supervised threshold calibration, temporal or connection-grouped evaluation, and improved assessment of rare attack classes.
