# CyberSentinel ML Research

An ML-based cybersecurity platform for network attack detection, incident correlation, graph-based reconstruction, risk assessment, and evidence-led AI investigation.

## Overview

CyberSentinel processes network-flow telemetry to identify suspicious activity and organize related detections into incidents. It combines machine-learning detection with event correlation, attack-graph representations, incident risk scoring, and an AI investigation workflow.

## Architecture

```text
CICIDS2017 Network Flows
        |
Data Validation and Preprocessing
        |
Anomaly / Attack Detection
        |
Suspicious Flow Events
        |
Temporal and Entity Correlation
        |
Incident Formation
        |
Attack Graph Construction
        |
Incident Risk Assessment
        |
AI-assisted Investigation
        |
Evidence-backed Findings
```

## Detection research

The detection study evaluates three unsupervised anomaly-detection approaches:

- Isolation Forest — isolation-based detection.
- Local Outlier Factor — local-density-based detection.
- RBF One-Class SVM — boundary-based novelty detection.

A supervised Random Forest model is evaluated separately as a labelled reference. It is not treated as an unsupervised alternative.

The current CICIDS2017 pilot uses benign-only fitting and benign-only threshold calibration for unsupervised models. See [the experiment report](research/EXPERIMENT_RESULTS.md) for the measured results, uncertainty across three seeds, class-level limitations, and next steps.

## Repository layout

- `agent/` — investigation agent and analysis tools.
- `attack_graph/` — event construction and graph logic.
- `pages/` — interactive application pages.
- `notebooks/` — dataset preparation and detector experiments.
- `experiments/` — reproducible comparison harness and measured outputs.
- `research/` — literature review, protocol, baseline audit, and viva notes.
- `outputs/` — representative project outputs.

## Research reproducibility

The comparison harness is in `experiments/compare_models.py`. Install dependencies using `experiments/requirements.txt` and follow `experiments/README.md`.

Dataset source, release version, checksum, and data preparation notes are documented in [DATASET_SOURCES.md](DATASET_SOURCES.md). Large data files are kept outside the Git source tree.

## Evaluation principles

- Keep training, calibration, validation, and test roles separate.
- Fit unsupervised detectors on benign observations only.
- Report PR-AUC alongside ROC-AUC for imbalanced attack data.
- Report false-positive rate, attack recall, F1, per-attack support, and runtime.
- Distinguish supervised reference models from unsupervised novelty detectors.
- Do not claim production generalisation from one benchmark or a small pilot.

## References

Core papers and supporting cybersecurity research are catalogued in [the literature review](research/LITERATURE_REVIEW.md).

## Development

Python 3.11 is used in the reproducibility workflow. The application dependencies and local configuration are described in the project files. API keys and credentials must be supplied through environment variables and must never be committed.
