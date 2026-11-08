# Results status

<badge>Completed — pilot results committed</badge>

The three-seed CICIDS2017 comparison completed successfully and its metrics, predictions, per-attack recall, metadata and plots are committed under `experiments/results/processed-v1.0.1/` on `research/model-comparison`.

Read the consolidated analysis in [EXPERIMENT_RESULTS.md](EXPERIMENT_RESULTS.md). It reports mean ± sample standard deviation across seeds 42, 43 and 44, states the fixed benign-only threshold protocol, separates the supervised Random Forest reference, and explains the false-positive calibration tie issue observed for Random Forest.

Key pilot finding: RBF One-Class SVM achieved the strongest unsupervised PR-AUC and F1 at the tested operating point; Isolation Forest was intermediate; LOF had the strongest ROC-AUC but weaker PR-AUC and F1. This is a bounded 5,000-benign-training-row pilot, not a production winner claim.

**Important execution detail:** The initial training workflow completed all model runs and uploaded its 15 output files but failed at its last commit step because `experiments/results/` is intentionally ignored by Git. The results were recovered from that run's GitHub Actions artifact and published by a separate workflow using `git add -f`. No model retraining occurred during publication.

Next work: larger training-sample sensitivity checks; a tie-aware supervised reference threshold; metadata-rich temporal/connection-grouped evaluation; and better support for rare attack types.
