# CyberSentinel

**Machine-learning-based cyber attack detection and incident investigation**

CyberSentinel is a cybersecurity analysis platform that processes network-flow data, identifies anomalous activity, correlates related events, reconstructs observed relationships as a graph, provides heuristic event/incident triage, and assists investigations with an AI-powered workflow.

## System architecture

```text
CICIDS2017 Network Flows
        |
Data Validation and Preprocessing
        |
ML-Based Attack Detection
        |
Suspicious Network Events
        |
Temporal and Entity Correlation
        |
Potential Incident Correlation
        |
Attack Graph Construction
        |
Heuristic Risk Triage
        |
Agentic AI Investigation
        |
Evidence-Backed Findings
```

## Core capabilities

- Flow-level anomaly detection using Isolation Forest with causal host-history features (completed prior-minute source/destination aggregates).
- Event grouping and temporal correlation.
- Graph representation of hosts, attack events, targets and observed relationships.
- Heuristic event and candidate-incident triage indexes (not calibrated incident probabilities or validated severity scores).
- AI-assisted incident investigation using predefined tools and retrieved evidence.
- Streamlit interface for attack detection, investigation, graph exploration and risk assessment.

## Technology stack

| Layer | Technologies |
|---|---|
| Application | Python, Streamlit |
| Data processing | Pandas, NumPy, SciPy |
| Machine learning | scikit-learn |
| Agent orchestration | LangChain, LangGraph |
| LLM integration | Google Gemini, Groq |
| Graph analysis | NetworkX, PyVis |
| Experiment tracking | CSV metrics, JSON run metadata, Matplotlib |

## Setup

Use Python 3.11.

```bash
python -m venv .venv
```

Activate the virtual environment, then install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create a local environment file from the template:

```bash
cp .env.example .env
```

Add the API credentials to `.env`. Never commit real API keys.

Start the application:

```bash
streamlit run app.py
```

## Dataset

The primary benchmark is CICIDS2017 from the Canadian Institute for Cybersecurity, University of New Brunswick.

- Official dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- Dataset paper: Sharafaldin, Lashkari & Ghorbani (2018), [Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization](https://doi.org/10.5220/0006639801080116).

Dataset preparation details and the processed experiment artifact checksum are documented in [DATASET_SOURCES.md](DATASET_SOURCES.md). Keep large data files under `data/`; the directory is excluded from Git.

## Model comparison study

The research study evaluates three unsupervised approaches:

1. **Isolation Forest** — isolation-based anomaly detection; the system's current detector and experimental baseline.
2. **Local Outlier Factor (LOF)** — local-density-based novelty detection.
3. **RBF One-Class SVM** — boundary-based novelty detection.

Random Forest is reported separately as a supervised reference because it is trained using labelled attack examples.

### Historical three-seed pilot results

**Historical pre-hardening metrics — not yet re-run under the current feature-schema and train-only imputation code.** Treat the numerical ranking below as provisional; see [the results report](research/EXPERIMENT_RESULTS.md) for the exact limitation.

Mean ± sample standard deviation across seeds 42, 43 and 44:

| Model | ROC-AUC | PR-AUC / AP | Attack precision | Attack recall | F1 |
|---|---:|---:|---:|---:|---:|
| Isolation Forest | 0.8900 ± 0.0010 | 0.6794 ± 0.0112 | 0.6989 ± 0.0054 | 0.6531 ± 0.0623 | 0.6743 ± 0.0348 |
| LOF (novelty) | **0.8984 ± 0.0028** | 0.5647 ± 0.0118 | 0.6210 ± 0.0475 | 0.4659 ± 0.0807 | 0.5315 ± 0.0709 |
| RBF One-Class SVM | 0.8389 ± 0.0096 | **0.7670 ± 0.0108** | **0.7346 ± 0.0073** | **0.7505 ± 0.0058** | **0.7424 ± 0.0038** |

RBF One-Class SVM is the strongest unsupervised candidate in this bounded pilot by PR-AUC and thresholded F1. Isolation Forest remains the detector in the current application; replacement should follow larger-sample sensitivity checks and evaluation on metadata-rich, temporally separated traffic. This pilot is not a production-performance guarantee.

Full metrics, false-positive rates, runtime, per-attack recall, limitations and reproducibility outputs are in [research/EXPERIMENT_RESULTS.md](research/EXPERIMENT_RESULTS.md).

## Reproduce the model comparison

Install the experiment dependencies:

```bash
python -m pip install -r experiments/requirements.txt
```

Place the checksum-verified Parquet file at `data/cleaned_cicids2017.parquet`, then run:

```bash
python experiments/compare_models.py \
  --data data/cleaned_cicids2017.parquet \
  --outdir experiments/results/local-run \
  --seed 42 \
  --train-benign 5000 \
  --calibration-rows 5000 \
  --evaluation-rows 15000 \
  --target-fpr 0.05
```

The experiment guide documents repeated-seed runs and the evaluation protocol.

## Project structure

- `agent/` — investigation workflow, state and analysis tools.
- `attack_graph/` — event construction, graph building and graph-based investigation.
- `pages/` — Streamlit application pages.
- `notebooks/` — preprocessing and Isolation Forest experiments.
- `experiments/` — comparison harness, metrics, predictions and plots.
- `research/` — literature review, experiment protocol, evaluation and viva preparation.
- `outputs/` — representative investigation reports and risk assessment outputs.
- `utils/` — shared file-cache signatures and application support utilities.

## Extended training-size validation

A paired sensitivity study has completed on `research/extended-validation`. It evaluates Isolation Forest, LOF and exact RBF One-Class SVM at 5,000, 25,000 and 50,000 benign training rows. All configurations share one fixed duplicate-grouped split, one benign calibration sample and one held-out test sample; training subsets are nested within each repetition.

- [Scaling validation protocol](research/SCALING_VALIDATION_PROTOCOL.md)
- [Measured scaling results](research/SCALING_VALIDATION_RESULTS.md)
- [Research evidence and model-selection rationale](research/RESEARCH_EVIDENCE_AND_MODEL_SELECTION.md)
- [Deep viva Q&A](research/DEEP_VIVA_QA.md)
- [Extended experiment runner](experiments/compare_model_scales.py)
- [Event/incident sensitivity runner](experiments/event_correlation_sensitivity.py)
- [Event/incident sensitivity runner](experiments/event_correlation_sensitivity.py)

## Project hardening

A separate engineering pass addresses data leakage, held-out detection evaluation, label-free inference, event grouping, graph chronology, candidate incident formation, risk triage and evidence-grounded reporting.

- [Project hardening report](research/PROJECT_HARDENING_REPORT.md) — fixes, tests and remaining research limitations.
- [Output workflows](outputs/README.md) — benchmark training, artifact creation, unlabeled inference, graph and risk-triage commands.
- [Regression tests](tests/) — 39 unit/integration checks, plus compile and CLI smoke tests in GitHub Actions.

Hardening changes are isolated to the `research/project-hardening` branch. The metadata-rich benchmark/inference pipeline now uses one Isolation Forest with raw numeric flow features plus 18 causal host-history features. The model is fitted on benign-only traffic, and its default threshold is calibrated on a held-out benign partition at a nominal 1% FPR target. This nominal target is not a guarantee under distribution shift. Batch inference requires timestamps, source/destination metadata, destination ports and packet/byte totals; persistent live-stream state is not yet implemented. See [the generated-output workflow](outputs/README.md) for exact training and inference commands.

## Research documentation

- [Literature review](research/LITERATURE_REVIEW.md)
- [Experimental protocol](research/EXPERIMENT_PROTOCOL.md)
- [Baseline evaluation](research/BASELINE_EVALUATION.md)
- [Three-seed experimental results](research/EXPERIMENT_RESULTS.md)
- [Viva preparation](research/VIVA_PREPARATION.md)
- [Dataset and reproducibility](DATASET_SOURCES.md)

## Evaluation principles

- Train unsupervised detectors on benign observations only.
- Select anomaly thresholds using a held-out benign calibration set.
- Keep validation and test roles separate.
- Report PR-AUC together with ROC-AUC for imbalanced labels.
- Include false-positive rate, precision, recall, F1, per-attack support and runtime.
- Keep supervised baselines separate from unsupervised novelty detectors.
- Treat results on CICIDS2017 as benchmark evidence, not proof of generalisation to all network environments.
