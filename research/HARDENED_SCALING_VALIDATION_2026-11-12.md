# Hardened CICIDS2017 paired scaling validation

**Execution date:** 12 November 2026  
**Workflow:** [GitHub Actions run 43156530860](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860)  
**Execution branch:** `research/cicids2017-hardened-rerun`  
**Code snapshot:** `research/project-hardening` at `be16972bbf039e8c9a38d4ab323a79a215225990`  
**Status:** completed successfully; dataset checksum verification, benchmark execution and artifact upload passed.

## 1. Dataset identity

The run downloaded `cleaned_cicids2017.parquet` from the CyberSentinel `v1.0.1` GitHub Release asset. Before reading the dataset, the workflow verified:

| Check | Expected | Result |
|---|---:|---|
| File size | 257,156,788 bytes | Passed |
| SHA-256 | `9401495356b1b6f360d6aebf0ad7ddc18a39cbf02c02f7461338dea02a747146` | Passed |

The loaded dataset contains 2,228,970 rows and 69 numeric modelling features. The label distribution is 1,892,671 benign and 336,299 attack rows.

## 2. Protocol

The experiment used the hardened `experiments/compare_model_scales.py` from the `research/project-hardening` code snapshot.

- Split: `StratifiedGroupKFold`, 7 folds, seed 42, grouping by exact numeric-feature hashes.
- Partitions: 1,592,120 training rows, 318,425 validation-fold rows and 318,425 test-fold rows.
- Exact duplicate feature groups had zero overlap across train, validation and test.
- One held-out benign calibration sample of 5,000 rows was shared across every model, training size and seed.
- One binary-stratified 15,000-row test sample was shared across every model, training size and seed.
- Benign-only training sizes: 5,000, 25,000 and 50,000 rows. Within each seed, subsets were nested.
- Repetition seeds: 42, 43 and 44.
- Threshold: upper 5% tail of each model's anomaly scores on the shared benign calibration sample.
- The three unsupervised models were fitted using benign training rows only.

| Detector | Configuration |
|---|---|
| Isolation Forest | 200 trees; max_samples=1,024; contamination=auto |
| LOF novelty | 35 neighbours; novelty=True; StandardScaler |
| RBF One-Class SVM | RBF kernel; nu=0.05; gamma=scale; StandardScaler; 512 MB cache |

Each model's median imputer was fitted only on its own benign training subset. Numeric feature schema was preserved until fit-time preprocessing; identifiers and labels were excluded by column name. No full-dataset missingness or variance filtering was performed before splitting.

## 3. Main results

Values are **mean ± sample standard deviation over three seeds**. All configurations share the same 15,000 held-out test rows. Average Precision (AP) is scikit-learn's average precision summary of the precision-recall curve.

| Model | Benign train rows | ROC-AUC | AP / PR-AUC | Precision | Recall | F1 | Test FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 5,000 | 0.8874 ± 0.0023 | 0.6793 ± 0.0114 | 0.7046 ± 0.0151 | 0.6786 ± 0.0391 | 0.6912 ± 0.0275 | 5.05% ± 0.08% |
| Isolation Forest | 25,000 | 0.8866 ± 0.0027 | 0.6725 ± 0.0070 | 0.6978 ± 0.0088 | 0.6642 ± 0.0395 | 0.6803 ± 0.0246 | 5.10% ± 0.11% |
| Isolation Forest | 50,000 | 0.8848 ± 0.0039 | 0.6736 ± 0.0185 | 0.7048 ± 0.0103 | 0.6855 ± 0.0429 | 0.6948 ± 0.0269 | 5.09% ± 0.07% |
| LOF novelty | 5,000 | 0.8899 ± 0.0136 | 0.5624 ± 0.0290 | 0.6170 ± 0.0657 | 0.4314 ± 0.1245 | 0.5053 ± 0.1072 | 4.60% ± 0.09% |
| LOF novelty | 25,000 | 0.9084 ± 0.0034 | 0.5576 ± 0.0161 | 0.6380 ± 0.0091 | 0.4588 ± 0.0304 | 0.5335 ± 0.0237 | 4.62% ± 0.16% |
| LOF novelty | 50,000 | **0.9087 ± 0.0052** | 0.5687 ± 0.0120 | 0.6553 ± 0.0297 | 0.5129 ± 0.0863 | 0.5740 ± 0.0646 | 4.74% ± 0.18% |
| RBF One-Class SVM | 5,000 | 0.8514 ± 0.0051 | **0.7486 ± 0.0023** | **0.7293 ± 0.0004** | **0.7436 ± 0.0009** | **0.7363 ± 0.0005** | 4.90% ± 0.01% |
| RBF One-Class SVM | 25,000 | 0.8439 ± 0.0084 | **0.7620 ± 0.0013** | **0.7222 ± 0.0061** | **0.7430 ± 0.0005** | **0.7324 ± 0.0032** | 5.08% ± 0.15% |
| RBF One-Class SVM | 50,000 | 0.8430 ± 0.0104 | **0.7665 ± 0.0029** | **0.7225 ± 0.0036** | **0.7446 ± 0.0023** | **0.7334 ± 0.0014** | 5.08% ± 0.10% |

### Interpretation

1. **RBF One-Class SVM leads AP and F1 at all three training sizes.** At 50k, AP is 0.7665 and F1 is 0.7334, compared with 0.6736 and 0.6948 for Isolation Forest.
2. **LOF leads ROC-AUC at 25k and 50k**, reaching 0.9087 at 50k. Its AP and F1 remain materially lower than the other two detectors at the tested threshold.
3. **Isolation Forest does not win the flow-level quality ranking.** Its performance is relatively stable as the benign training budget grows, and it has much lower measured fit and scoring cost.
4. The test FPRs remain close to the common nominal 5% calibration target. These are held-out test FPR measurements, not values forced to exactly 5%.

## 4. Runtime and scale

Mean ± sample standard deviation wall-clock timings on the GitHub Actions runner:

| Model | Benign train rows | Fit time (s) | Score 15,000 test rows (s) |
|---|---:|---:|---:|
| Isolation Forest | 5,000 | 0.274 ± 0.008 | 0.104 ± 0.003 |
| Isolation Forest | 25,000 | 0.338 ± 0.005 | 0.103 ± 0.001 |
| Isolation Forest | 50,000 | 0.411 ± 0.002 | 0.104 ± 0.001 |
| LOF novelty | 5,000 | 0.106 ± 0.011 | 0.290 ± 0.003 |
| LOF novelty | 25,000 | 1.966 ± 0.003 | 1.253 ± 0.101 |
| LOF novelty | 50,000 | 7.576 ± 0.031 | 2.313 ± 0.019 |
| RBF One-Class SVM | 5,000 | 0.096 ± 0.003 | 0.230 ± 0.007 |
| RBF One-Class SVM | 25,000 | 2.383 ± 0.012 | 1.024 ± 0.003 |
| RBF One-Class SVM | 50,000 | 19.484 ± 2.168 | 2.106 ± 0.065 |

At 50k, Isolation Forest's mean fit time is about 47× lower than RBF One-Class SVM's; scoring the same 15k test rows is about 20× faster. This is a substantial operational difference, but these timings are hardware-specific and do not replace target-machine throughput, latency and peak-memory tests.

## 5. Per-attack recall at 50k

The table below reports recall pooled across the three seeds. The unique test support is shown once for the shared 15k test sample; the same observations are re-evaluated for each seed.

| Attack family | Unique test support | Isolation Forest | LOF | RBF One-Class SVM |
|---|---:|---:|---:|---:|
| Bot | 11 | 0.0% | 0.0% | 0.0% |
| DDoS | 849 | 55.9% | 58.5% | 63.6% |
| DoS GoldenEye | 61 | 49.2% | 31.7% | 78.7% |
| DoS Hulk | 1,164 | 85.5% | 51.1% | 89.2% |
| DoS Slowhttptest | 38 | 76.3% | 26.3% | 81.6% |
| DoS slowloris | 43 | 48.1% | 20.2% | 55.8% |
| FTP-Patator | 42 | 0.0% | 23.8% | 0.0% |
| PortScan | 17 | 11.8% | 7.8% | 23.5% |
| SSH-Patator | 22 | 0.0% | 86.4% | 0.0% |
| Web Attack - Brute Force | 10 | 0.0% | 0.0% | 0.0% |
| Web Attack - SQL Injection | 1 | 0.0% | 0.0% | 0.0% |
| Web Attack - XSS | 5 | 0.0% | 6.7% | 0.0% |

This shows why aggregate AP/F1 must not be treated as universal attack-family coverage. SVM is strong on the sampled DoS/DDoS families but misses all sampled FTP-Patator and SSH-Patator observations; LOF captures SSH-Patator and some FTP-Patator rows. The smallest supports are too low for stable class-level generalisation claims.

## 6. Model-selection decision

**Keep Isolation Forest as the currently integrated application detector for now, but do not describe it as the best-quality model.**

The case for retaining it is operational: it is already consumed by the detection → event → graph → risk pipeline, and its measured fit/scoring costs at 50k are much lower. The aggregate flow-level quality leader is RBF One-Class SVM by AP/F1; LOF is strongest by ROC-AUC at larger sample sizes and shows different attack-family coverage.

Before replacing the integrated detector:
- shadow-run SVM and LOF against the same metadata-rich traffic without affecting production decisions;
- compare alert volume, analyst review burden, false positives per unit time, memory and tail latency on deployment hardware;
- evaluate temporal and connection-grouped holdouts, and a second independent dataset;
- investigate the weak/zero recall for Bot, FTP-Patator and web attack families;
- validate effects on event grouping, graph construction, incident triage and analyst investigation outcomes.

No real-world production superiority has been established by this CICIDS2017 experiment.

## 7. Limitations

- The same fixed 15k test sample is reused across the three seeds. Reported standard deviations measure variation from training-sample/model randomness on that fixed holdout; they are **not** independent test-set confidence intervals.
- The split keeps exact duplicate numeric-feature vectors in one partition, but the cleaned Parquet lacks timestamps, five-tuple identifiers, source/destination IP addresses and ports. It is not a temporal or connection-level holdout.
- Rare attack classes have very small support. SQL Injection has one row and XSS five rows in the shared test sample; Heartbleed is absent from this sample. Their results cannot support stable recall claims.
- One dataset and one primary hyperparameter configuration per detector were used. This is a paired training-size sensitivity experiment, not exhaustive hyperparameter optimisation.
- Runtime was measured on a GitHub Actions runner. No deployment-hardware latency, throughput, memory or analyst-workload benchmark was performed.
- The experiment measures flow-level detection only. It does not establish event/incident accuracy, graph fidelity, agent factuality or response effectiveness.

## 8. Reproducibility

- [Completed workflow](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/43156530860)
- [Execution-only PR](https://github.com/ArB-86/CyberSentinel-ML-Research/pull/2) (not merged)
- Workflow artifact: `cicids2017-hardened-scaling-validation-43156530860`
- Artifact SHA-256: `d4ac9de9011ad364620dfbd2a2e0e742b05d8b2e948dd1597c0559e006fc5513`
- Artifact files: `summary_mean_std.csv`, `metrics_by_seed.csv`, `per_attack_by_seed.csv`, `per_attack_pooled.csv`, `run_metadata.json`, `environment.txt`, and three plots.
- Software: Python 3.11.18, NumPy 2.4.6, pandas 3.1.1, scikit-learn 1.9.1, PyArrow 26.0.1.

The workflow artifact is retained by GitHub Actions for 30 days. This report records the measured summary and protocol; retain the artifact archive alongside project research records when long-term raw-output preservation is required.
