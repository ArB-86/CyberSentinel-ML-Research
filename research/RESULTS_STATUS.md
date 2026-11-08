# Experiment status

**Completed:** the CICIDS2017 model-comparison pilot has been executed across three independent seeds (42, 43 and 44).

The repository contains the per-seed metrics, predictions, per-attack recall, run metadata and ROC/PR plots under `experiments/results/processed-v1.0.1/`.

The consolidated findings are in [EXPERIMENT_RESULTS.md](EXPERIMENT_RESULTS.md). The report includes mean ± sample standard deviation, the benign-only training and calibration protocol, the separate supervised Random Forest reference, and the study limitations.

**Pilot finding:** RBF One-Class SVM achieved the strongest unsupervised PR-AUC and F1 at the tested operating point. Isolation Forest remains the detector in the current application until larger-sample and metadata-rich evaluation justify a model change.

Next research steps are larger training-sample sensitivity checks, tie-aware supervised threshold calibration, temporal or connection-grouped evaluation, and improved assessment of rare attack classes.
