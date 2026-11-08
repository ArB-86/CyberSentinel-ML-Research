# Research workspace

This folder contains the literature review, baseline audit, experimental protocol and viva preparation for the model-comparison study.

## Documents

- [Literature review](LITERATURE_REVIEW.md) — peer-reviewed foundations and CICIDS2017-specific comparative work.
- [Experimental protocol](EXPERIMENT_PROTOCOL.md) — research questions, split design, models, threshold calibration and metrics.
- [Baseline evaluation](BASELINE_EVALUATION.md) — what the original notebook already proves and what it does not.
- [Viva preparation](VIVA_PREPARATION.md) — evidence-based panel questions and answers.
- [Experiment results](EXPERIMENT_RESULTS.md) — three-seed metrics, per-attack detection and limitations.
- [Scaling validation protocol](SCALING_VALIDATION_PROTOCOL.md) — paired 5k/25k/50k training-size study.
- [Scaling validation status](SCALING_VALIDATION_STATUS.md) — current run state and results location.
- [Results status](RESULTS_STATUS.md) — completed pilot and current validation stages.

## Key research decision

Isolation Forest remains the existing unsupervised baseline. LOF and RBF One-Class SVM are the primary unsupervised comparators. Random Forest is a separate supervised reference and must not be presented as an equivalent unsupervised detector.

In the three-seed pilot, RBF One-Class SVM achieved the strongest mean PR-AUC and F1 among the unsupervised models. Treat this as a bounded benchmark finding; larger-sample and temporal/connection-grouped evaluation remain necessary before production model selection.
