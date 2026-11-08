# Extended validation status

**Historical pre-hardening run completed successfully; current scripts have since changed.** The larger-sample CICIDS2017 validation ran with three fixed repetitions and all three training sizes, but the archived metrics have not yet been regenerated after train-only feature-schema and imputation fixes. Treat the numerical rankings as historical until rerun.

## Final configuration

- Detectors: Isolation Forest, LOF (novelty mode), RBF One-Class SVM.
- Benign training sizes: 5,000; 25,000; 50,000.
- Repetition seeds: 42, 43, 44.
- One fixed duplicate-grouped train/validation/test partition.
- One fixed benign-only calibration sample of 5,000 rows.
- One shared held-out test sample of 15,000 rows.
- Nested training subsets within each repetition.

The dataset's SHA-256 verification passed. Model fitting, evaluation and artifact upload all completed. The first results push was rejected because the branch advanced while the job was running; the already-uploaded artifact was published successfully by a separate workflow. No model retraining was required for publication.

## Results

- [Scaling validation results](SCALING_VALIDATION_RESULTS.md) — mean ± standard deviation, metric and runtime analysis.
- [Research evidence and model-selection rationale](RESEARCH_EVIDENCE_AND_MODEL_SELECTION.md) — source-by-source evidence mapping and design justifications.
- [Deep viva Q&A](DEEP_VIVA_QA.md) — technical questions and evidence-backed answers.
- [Scaling validation protocol](SCALING_VALIDATION_PROTOCOL.md) — split design and interpretation rules.

Raw outputs are committed under `experiments/results/scaling-validation-v1/`.
