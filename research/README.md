# Research workspace

This folder contains the literature review, baseline audit, experimental protocol and viva preparation for the model-comparison study.

## Documents

- [Literature review](LITERATURE_REVIEW.md) — peer-reviewed foundations and CICIDS2017-specific comparative work.
- [Experimental protocol](EXPERIMENT_PROTOCOL.md) — research questions, split design, models, threshold calibration and metrics.
- [Existing baseline audit](EXISTING_BASELINE_AUDIT.md) — what the original notebook already proves and what it does not.
- [Viva preparation](VIVA_PREPARATION.md) — evidence-based panel questions and answers.
- [Experiment results](EXPERIMENT_RESULTS.md) — three-seed metrics, per-attack detection and limitations.
- [Results status](RESULTS_STATUS.md) — current execution status and remaining work.

## Key research decision

Isolation Forest remains the existing unsupervised baseline. LOF and RBF One-Class SVM are the primary unsupervised comparators. Random Forest is a separate supervised reference and must not be presented as an equivalent unsupervised detector.

No winner is preselected. Claims must be based on repeated runs of the committed experiment harness and its saved result files.
