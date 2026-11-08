# Extended CICIDS2017 validation — measured results

## Execution status

**Status: historical pre-hardening pilot; not yet re-run under the current feature-preprocessing code.** The archived paired experiment completed on the SHA-256-verified processed CICIDS2017 Parquet, but its metrics were produced before the comparison script stopped filtering columns using full-dataset missingness/variance statistics. The current script preserves the numeric feature schema, excludes numeric identifiers and uses a training-fitted imputer with `keep_empty_features=True`. Feature count and measured rankings may change. Treat the tables below as historical pilot results until a fresh run is generated from the exact same Parquet using the current script.

The training job completed model fitting, evaluation, plots and artifact upload. Its first Git push was rejected because the remote branch had advanced while the job was running. The uploaded artifact was published by a separate workflow, without repeating the model training.

- Training workflow: [run 42521225029](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/42521225029)
- Results publication: [run 42522819745](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/42522819745)

## 1. Research question

Does the relative performance of Isolation Forest, Local Outlier Factor and RBF One-Class SVM change when the benign-only training set increases from 5,000 to 25,000 and 50,000 flows?

This is a sensitivity/scaling experiment, not a new independent benchmark and not a production-deployment test.

## 2. Dataset and split

| Item | Value |
|---|---:|
| Processed records | 2,228,970 |
| Numeric modelling features | 69 |
| Benign records | 1,892,671 |
| Attack records | 336,299 |
| Benign share | 84.91% |
| Attack share | 15.09% |
| Split algorithm | StratifiedGroupKFold |
| Folds | 7 |
| Split seed | 42 |
| Train partition | 1,592,120 rows |
| Validation fold | 318,425 rows |
| Test fold | 318,425 rows |
| Benign calibration sample | 5,000 rows |
| Shared binary-stratified test sample | 15,000 rows |

The grouping key is a hash of the 69 numeric modelling features, excluding labels. The run metadata reports zero exact duplicate-feature group overlap between train, validation and test.

**Scope of the leakage control:** exact duplicate numeric feature vectors are kept in one partition. This processed Parquet does not retain flow IDs, timestamps, source/destination IP addresses or ports, so this run cannot claim connection-level or temporal separation. A future metadata-rich temporal/connection-grouped evaluation remains necessary.

## 3. Controlled comparison design

All three detectors are unsupervised and are fitted on benign-only network flows.

| Model | Mechanism | Main configuration |
|---|---|---|
| Isolation Forest | Random isolation trees; short path lengths indicate unusual observations | 200 trees; max_samples=1,024; max_features=1.0 |
| LOF (novelty mode) | Local reachability-density comparison against neighbours | n_neighbors=35; StandardScaler; novelty=True |
| RBF One-Class SVM | Nonlinear support/boundary estimate around normal traffic | RBF kernel; nu=0.05; gamma=scale; StandardScaler |

For each seed (42, 43, 44), the training sample is **nested**: the 5,000-row benign subset is contained within the 25,000-row subset, which is contained within the 50,000-row subset.

The calibration sample and test sample are fixed across every model, training size and repetition. This is a paired design intended to isolate the effect of increasing the training budget.

Each unsupervised threshold is the upper 5% tail of that model's anomaly scores on the same held-out benign-only calibration sample. Test labels are used only for final scoring. The target 5% calibration FPR is an operating-point choice, not a claim that test FPR must equal exactly 5%.

Random Forest is intentionally not included in this scaling run because the question here is about the three unsupervised detectors. Its previous results remain a separate supervised reference.

## 4. Main results

Values are **mean ± sample standard deviation across the three training seeds**, all evaluated on the same held-out test rows. PR-AUC is scikit-learn Average Precision.

| Model | Benign train rows | ROC-AUC | PR-AUC / AP | Precision | Recall | F1 | Test FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 5,000 | 0.8874 ± 0.0023 | 0.6793 ± 0.0114 | 0.7046 ± 0.0151 | 0.6786 ± 0.0391 | 0.6912 ± 0.0275 | 5.05% |
| Isolation Forest | 25,000 | 0.8866 ± 0.0027 | 0.6725 ± 0.0070 | 0.6978 ± 0.0088 | 0.6642 ± 0.0395 | 0.6803 ± 0.0246 | 5.10% |
| Isolation Forest | 50,000 | 0.8848 ± 0.0039 | 0.6736 ± 0.0185 | 0.7048 ± 0.0103 | 0.6855 ± 0.0429 | 0.6948 ± 0.0269 | 5.09% |
| LOF | 5,000 | 0.8899 ± 0.0136 | 0.5624 ± 0.0290 | 0.6170 ± 0.0657 | 0.4314 ± 0.1245 | 0.5053 ± 0.1072 | 4.60% |
| LOF | 25,000 | 0.9084 ± 0.0033 | 0.5576 ± 0.0161 | 0.6380 ± 0.0091 | 0.4588 ± 0.0304 | 0.5335 ± 0.0237 | 4.62% |
| LOF | 50,000 | **0.9087 ± 0.0052** | 0.5687 ± 0.0120 | 0.6553 ± 0.0297 | 0.5129 ± 0.0863 | 0.5740 ± 0.0646 | 4.74% |
| RBF One-Class SVM | 5,000 | 0.8514 ± 0.0051 | **0.7486 ± 0.0023** | **0.7293 ± 0.0004** | **0.7436 ± 0.0009** | **0.7363 ± 0.0005** | 4.90% |
| RBF One-Class SVM | 25,000 | 0.8439 ± 0.0084 | **0.7620 ± 0.0013** | **0.7222 ± 0.0061** | **0.7430 ± 0.0005** | **0.7324 ± 0.0032** | 5.08% |
| RBF One-Class SVM | 50,000 | 0.8430 ± 0.0104 | **0.7665 ± 0.0029** | **0.7225 ± 0.0036** | **0.7446 ± 0.0023** | **0.7334 ± 0.0014** | 5.08% |

### What the table actually says

1. **RBF One-Class SVM leads on PR-AUC and F1 at all three training sizes.** Its AP increases from 0.7486 at 5k to 0.7665 at 50k. F1 remains stable around 0.73–0.74.
2. **LOF leads on ROC-AUC at 25k and 50k**, reaching 0.9087 at 50k, but its AP and F1 remain below Isolation Forest and One-Class SVM. It ranks many positives above negatives reasonably well overall, yet at the chosen 5% alert operating point it misses more attacks.
3. **Isolation Forest is comparatively stable as the benign training pool grows.** AP changes only from 0.6793 to approximately 0.6736, and F1 stays around 0.68–0.69. Increasing the supplied training pool does not automatically improve its results.
4. **The ranking depends on the metric.** If a panel member chooses ROC-AUC, LOF is the winner at 25k/50k. If the operational objective is precision-recall performance and F1 at the specified alert budget, RBF One-Class SVM is strongest in this experiment. Do not say that one model wins every metric.
5. **All test FPR values are close to the common nominal 5% target.** They differ slightly because the calibration and test samples are finite and the test observations are held out.

## 5. Runtime and scaling trade-off

Mean observed wall-clock times on this GitHub Actions runner:

| Model | Training rows | Fit time | Test scoring time (15k rows) |
|---|---:|---:|---:|
| Isolation Forest | 5,000 | 0.268 s | 0.103 s |
| Isolation Forest | 25,000 | 0.338 s | 0.102 s |
| Isolation Forest | 50,000 | 0.408 s | 0.103 s |
| LOF | 5,000 | 0.195 s | 0.559 s |
| LOF | 25,000 | 3.865 s | 2.310 s |
| LOF | 50,000 | 14.820 s | 4.439 s |
| RBF One-Class SVM | 5,000 | 0.095 s | 0.235 s |
| RBF One-Class SVM | 25,000 | 2.375 s | 1.076 s |
| RBF One-Class SVM | 50,000 | 17.391 s | 2.082 s |

These values are hardware/runtime-specific, but the relative trend is informative:

- Isolation Forest is dramatically cheaper at 50k in both fitting and scoring.
- LOF fit time grows sharply as the reference neighbourhood set grows; it also has the slowest test scoring at 50k.
- RBF One-Class SVM retains the best AP/F1 in this benchmark, but its fit/scoring cost grows substantially with training size.

This is the central reason **not to replace Isolation Forest automatically** just because One-Class SVM has higher AP/F1. In an operational IDS, alert quality, throughput, memory, retraining schedule and analyst workload all matter.

## 6. Per-attack observations

The pooled per-attack output is in [`per_attack_pooled.csv`](../experiments/results/scaling-validation-v1/per_attack_pooled.csv). In this fixed test sample, the three unsupervised methods still fail to detect some low-support attack categories reliably.

Examples at the 50k training size:

- Isolation Forest: 0/33 Bot, 0/126 FTP-Patator, 0/66 SSH-Patator, 0/30 Web Brute Force, 0/3 SQL Injection, 0/15 XSS.
- LOF: 0/33 Bot, 30/126 FTP-Patator, 57/66 SSH-Patator, 0/30 Web Brute Force, 0/3 SQL Injection, 1/15 XSS.
- RBF One-Class SVM: 0/33 Bot, 0/126 FTP-Patator, 0/66 SSH-Patator, 0/30 Web Brute Force, 0/3 SQL Injection, 0/15 XSS.

These denominators are small, especially SQL Injection (3) and Bot (33). Do not make stable per-class generalisation claims from such low supports. Heartbleed is absent from this fixed test sample; its performance is unmeasured, not zero.

## 7. Research conclusion

A careful conclusion for the viva is:

> "We did not choose an alternative based on one isolated metric. We evaluated Isolation Forest, LOF and RBF One-Class SVM under a paired, duplicate-grouped split, the same benign-only calibration observations, the same 15,000 held-out test observations and nested benign training sizes of 5k, 25k and 50k. RBF One-Class SVM achieved the highest PR-AUC and F1 at all three sizes, while LOF achieved the highest ROC-AUC at 25k and 50k. Isolation Forest had by far the lowest training and test-scoring cost. So RBF One-Class SVM is the strongest candidate by AP/F1 on this CICIDS2017 pilot, whereas Isolation Forest remains attractive for throughput. We will retain the current Isolation Forest deployment until we validate the trade-off on metadata-rich, temporally separated traffic and evaluate incident-level outcomes."

## 8. Limitations and next experiments

1. The same 15k test sample is reused across three seeds. The reported standard deviations capture training-sample/model randomness under this fixed holdout; they are not independent test-set confidence intervals.
2. The current cleaned dataset lacks five-tuple IDs and timestamps. We grouped exact duplicate numeric feature vectors but cannot guarantee connection-level or temporal independence.
3. Rare attack classes have small test support. A separate rare-class evaluation with explicit sampling and confidence intervals is required.
4. Only one feature preprocessing configuration and one main hyperparameter setting per model was used in this scaling study. It is a controlled sample-size sensitivity analysis, not a full hyperparameter search.
5. The benchmark is CICIDS2017 only. A later evaluation should use metadata-rich time-separated traffic or an independent dataset.
6. The current study evaluates flow detection. It does not yet prove that model changes improve event correlation, graph reconstruction, incident risk prioritisation or AI-investigation correctness.

## 9. Reproducibility files

- [Mean/std summary](../experiments/results/scaling-validation-v1/summary_mean_std.csv)
- [Per-seed raw metrics](../experiments/results/scaling-validation-v1/metrics_by_seed.csv)
- [Pooled per-attack recall](../experiments/results/scaling-validation-v1/per_attack_pooled.csv)
- [Per-seed per-attack recall](../experiments/results/scaling-validation-v1/per_attack_by_seed.csv)
- [Run metadata](../experiments/results/scaling-validation-v1/run_metadata.json)
- [PR-AUC vs training size](../experiments/results/scaling-validation-v1/scaling_pr_auc.png)
- [F1 vs training size](../experiments/results/scaling-validation-v1/scaling_f1.png)
- [Fit time vs training size](../experiments/results/scaling-validation-v1/scaling_fit_time.png)
