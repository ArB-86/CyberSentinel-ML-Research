# Research workspace

This folder contains the literature review, baseline audit, experimental protocol and viva preparation for the model-comparison study.

## Documents

- [Literature review](LITERATURE_REVIEW.md) — peer-reviewed foundations and CICIDS2017-specific comparative work.
- [Experimental protocol](EXPERIMENT_PROTOCOL.md) — research questions, split design, models, threshold calibration and metrics.
- [Baseline evaluation](BASELINE_EVALUATION.md) — what the original notebook already proves and what it does not.
- [Viva preparation](VIVA_PREPARATION.md) — evidence-based panel questions and answers.
- [Experiment results](EXPERIMENT_RESULTS.md) — three-seed metrics, per-attack detection and limitations.
- [Scaling validation protocol](SCALING_VALIDATION_PROTOCOL.md) — paired 5k/25k/50k training-size study.
- [Scaling validation results](SCALING_VALIDATION_RESULTS.md) — measured mean/std, per-model trade-offs and limitations.
- [Research evidence and model selection](RESEARCH_EVIDENCE_AND_MODEL_SELECTION.md) — paper-by-paper justification for the design.
- [Viva design-decision matrix](VIVA_DESIGN_DECISION_MATRIX.md) — paper-backed rationale for every major implementation choice.
- [Deep viva Q&A](DEEP_VIVA_QA.md) — technical questions and grounded answers.
- [Scaling validation status](SCALING_VALIDATION_STATUS.md) — completed run and outputs.
- [Project hardening report](PROJECT_HARDENING_REPORT.md) — code fixes, validation evidence and limitations still open.
- [Event-correlation sensitivity runner](../experiments/event_correlation_sensitivity.py) — parameter sweep for event windows and shared-host temporal gaps.
- [Results status](RESULTS_STATUS.md) — completed pilot and current validation stages.

## Key research decision

Isolation Forest remains the existing unsupervised baseline. LOF and RBF One-Class SVM are the primary unsupervised comparators. Random Forest is a separate supervised reference and must not be presented as an equivalent unsupervised detector.

In the historical pre-hardening three-seed pilot, RBF One-Class SVM achieved the strongest mean PR-AUC and F1 among the unsupervised models. These metrics have not yet been regenerated under the current train-only feature preprocessing; treat the ranking as provisional until the checksum-verified Parquet is rerun.
