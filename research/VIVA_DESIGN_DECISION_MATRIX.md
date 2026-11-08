# Viva defence matrix: rationale for every major project choice

This document is a technical defence guide. For each decision it separates (1) the research principle, (2) what we implemented, (3) what the paper actually supports, (4) our measured evidence, and (5) what remains an engineering choice or limitation.

**Rule for the viva:** a paper can justify a method or research direction. It does not automatically prove that our exact hyperparameter, time window, threshold, or implementation is optimal. Exact numerical choices require our own sensitivity experiments.

---

## 1. Why Isolation Forest is the detector in the current application

### Research basis

Liu, Ting and Zhou (2008), *Isolation Forest*, DOI: https://doi.org/10.1109/ICDM.2008.17.

The original paper's core idea is to isolate observations directly rather than first construct a full normal profile. Random feature and split selection produce isolation trees; unusual observations tend to have shorter path lengths. The paper emphasises sub-sampling, low computational cost and suitability for large/high-dimensional datasets. It reports favourable comparisons with LOF and Random Forest in its own test settings, and notes that iForest can work when training data contains no anomalies.

The extended paper is: Liu, Ting and Zhou (2012), *Isolation-Based Anomaly Detection*, DOI: https://doi.org/10.1145/2133360.2133363.

### Connection to our project

- Our processed CICIDS2017 file has 2,228,970 flow rows and 69 numeric modelling features.
- The detector is fit on benign-only flows, so it does not need labelled examples of every attack family during fitting.
- A large benign sampling pool exposes the detector to diverse normal-flow patterns.
- Each tree only uses a bounded subsample, which is the efficiency mechanism behind Isolation Forest.
- The detector generates suspicious flows for the later event-correlation and attack-graph stages.

### What our experiments say

In the paired 50k training-size experiment:
- Isolation Forest mean F1: 0.6948.
- Mean PR-AUC / Average Precision: 0.6736.
- Mean ROC-AUC: 0.8848.
- Mean fit time: 0.408 seconds.
- Mean scoring time for 15,000 test flows: 0.103 seconds.

At the same sample size, RBF One-Class SVM had higher PR-AUC/F1, but substantially higher fit and scoring time. This means our evidence supports Isolation Forest as a fast, defensible baseline/current implementation—not as the best detector on every metric.

### Viva answer

"We chose Isolation Forest as the initial detector because the original research proposes a computationally efficient, subsampling-based anomaly detector that can be trained without attack examples. This matches our large flow dataset and benign-only training setup. We did not assume it was universally best: we benchmarked LOF and One-Class SVM. The results show a detection-quality versus throughput trade-off, so Isolation Forest remains the current application detector while One-Class SVM is the leading alternative for further evaluation."

### What not to claim

- Do not say the original paper proves Isolation Forest is best on our CICIDS2017 file.
- Do not say it detects every unseen/zero-day attack.
- Do not say lower runtime alone proves it is the best operational IDS. The actual required throughput/alert budget must be established for the target deployment.

---

## 2. Why CICIDS2017

### Research basis

Sharafaldin, Lashkari and Ghorbani (2018), *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP. DOI: https://doi.org/10.5220/0006639801080116.

The paper documents the dataset-generation methodology, testbed, attack traffic and flow-characterization process.

Official dataset page: https://www.unb.ca/cic/datasets/ids-2017.html

### Connection to our project

CICIDS2017 supplies labelled benign and malicious flow records and multiple attack categories. This allows:
1. benign-only training for anomaly detectors;
2. labelled validation/test evaluation;
3. per-attack recall analysis;
4. an input source for event grouping and graph experiments when metadata-rich flow files are available.

The raw/original CICIDS2017 distribution and our cleaned modelling file are not the same count. Our processed Parquet has 2,228,970 rows, 69 numeric modelling features, and one label column. The label distribution in that file is 1,892,671 benign and 336,299 attacks (approximately 84.91%/15.09%).

### Why it is not a perfect production proxy

CICIDS2017 is a controlled benchmark and has class imbalance, repeated flow patterns, finite attack scenarios and limited temporal/environment coverage. Verkerken et al. (2022) show why inter-dataset generalisation is important: models that score well within one dataset can lose performance on a second related dataset.

Paper: https://doi.org/10.1007/s10922-021-09615-7

### Viva answer

"We selected CICIDS2017 because the dataset paper documents a labelled network-intrusion benchmark containing benign traffic, multiple attack scenarios and flow-level features. It supports both normal-only model fitting and labelled evaluation. We acknowledge it is a benchmark, not a guarantee of performance on live enterprise traffic; therefore cross-dataset and temporal validation are future requirements."

---

## 3. Why benign-only model fitting

### Research basis

- Isolation Forest (Liu et al., 2008) explicitly describes isolation detection as useful even where the training sample contains no anomalies.
- One-Class SVM (Schölkopf et al., 2001) estimates the support/region of a reference distribution.
- LOF (Breunig et al., 2000) estimates local density deviation relative to neighbours.

### Connection to our project

The three primary detectors are trained on benign rows only. The label column is excluded from the feature matrix. Attack labels remain available separately for stratification and final evaluation.

### Viva answer

"The model learns the normal traffic distribution, not a closed list of attack signatures. This is useful when some attack families are rare or absent during fitting. It does not guarantee detection of every novel attack: an attack whose flow features resemble benign traffic can be missed."

### Important terminology

Call this a **benign-only unsupervised anomaly/novelty-detection protocol**. Do not claim that all stages of the experiment are fully label-free: labels are used to build stratified folds and to evaluate test predictions. In the original notebook, attack labels also informed validation F1 threshold selection; the later comparative experiments use benign-only threshold calibration.

---

## 4. Why 500,000 benign rows in the original notebook

### Connection to our implementation

The original notebook sampled 500,000 benign rows as the available training pool. This is not the number of rows used by every tree. With `max_samples=1024`, each isolation tree samples at most 1,024 observations from that pool.

### Defensible rationale

- The benign pool can represent a broader range of normal-flow variability than a very small sample.
- A large pool is computationally manageable because each tree uses a bounded subsample.
- The choice avoids passing every benign record into every tree.

### Evidence qualification

The Isolation Forest paper supports subsampling as an efficiency mechanism. It does **not** prove that 500,000 is the optimal benign pool for our dataset. Our additional controlled sensitivity test used 5k, 25k and 50k rows, not 500k. If asked why exactly 500k, describe it as the original engineering/sample-budget choice and say a 500k-vs-lower-budget ablation would be needed to prove optimality.

---

## 5. Why the Isolation Forest hyperparameters

| Parameter | Implemented value | Defensible reason | Evidence status |
|---|---:|---|---|
| `n_estimators` | 200 | Average over many random isolation trees; chosen as the fixed ensemble configuration. | 200 was not proven optimal by a full tree-count search. |
| `max_samples` | 1,024 | Bounds the data used by each tree and preserves the subsampling efficiency central to iForest. | Literature supports subsampling, not the exact value 1,024 for this dataset. |
| `max_features` | 1.0 | Each tree can use the complete feature set; straightforward baseline with 69 numeric features. | Full-feature choice; no feature-fraction ablation is claimed. |
| `contamination` | `auto` | Uses the estimator's built-in decision offset convention rather than imposing dataset attack prevalence. | It is not the same as our separately calibrated 5% test operating point. |
| `random_state` | 42 | Reproducibility of random sampling/tree construction. | Reproducibility setting, not a research-performance parameter. |
| `n_jobs` | -1 | Uses available CPU workers. | Runtime engineering setting, not a detector-theory choice. |

Scikit-learn reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

### Frequent panel trap: contamination='auto'

It does not mean that the dataset has 15% attacks, nor does it guarantee 5% test false positives. It controls the estimator's internal offset convention. In the comparative protocol, a separate threshold is selected using a benign-only calibration sample.

### Frequent panel trap: max_samples=1024

It does not mean that the whole forest uses only 1,024 rows in total. Each tree samples up to 1,024 rows from the 500,000-row pool. Different trees can use different subsamples.

---

## 6. Why LOF

### Research basis

Breunig, Kriegel, Ng and Sander (2000), *LOF: Identifying Density-Based Local Outliers*. DOI: https://doi.org/10.1145/342009.335388.

LOF measures local reachability density and compares a point's density with those of its neighbours.

### Why this is a meaningful comparator

Isolation Forest measures how readily a point can be isolated by random partitions. LOF measures whether it is sparse relative to its local neighbourhood. Network traffic can have multiple local behaviour patterns, so a locally abnormal flow may not be globally extreme.

### Why `novelty=True`

Our model is fit on benign training flows and must score new validation/test flows. Scikit-learn says novelty mode is intended for unseen observations; its novelty-mode scoring functions should not be applied to the training rows.

Documentation: https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html

### Why StandardScaler

LOF uses nearest-neighbour distances. A high-magnitude feature can dominate Euclidean distance if feature scales are not made comparable. The scaler is fit only on training rows and then applied to calibration/test rows.

### Why 35 neighbours

35 is a fixed benchmark setting, not a proven optimum for this dataset. Scikit-learn's outlier-detection guide uses 35 neighbours in an example with an outlier fraction above 10%, but the appropriate k depends on neighbourhood/cluster structure. We did not perform a k-grid search in this experiment. A sensitivity study for k=10,20,35,50 would be required before saying 35 is optimal.

### Viva answer

"We included LOF because it represents a local-density anomaly assumption, different from Isolation Forest's isolation principle. We used novelty mode because the operational task is to score previously unseen flows, and scaled the features because nearest-neighbour distance is scale-sensitive. The value k=35 is our fixed comparison configuration, not a literature-proven optimum."

---

## 7. Why RBF One-Class SVM

### Research basis

Schölkopf et al. (2001), *Estimating the Support of a High-Dimensional Distribution*. DOI: https://doi.org/10.1162/089976601750264965.

The paper formulates one-class support estimation: learn a decision region for observations drawn from a reference distribution, then identify observations outside that region.

Verkerken et al. (2022) also evaluate One-Class SVM on CICIDS2017 and CSE-CIC-IDS2018: https://doi.org/10.1007/s10922-021-09615-7.

Xu and Liu (2025) compare OCSVM and LOF on CICIDS2017 in known-attack and unseen-attack scenarios: https://doi.org/10.1109/ICETIS66286.2025.11144025.

### Why RBF

RBF is a nonlinear kernel and can represent a curved decision boundary around benign traffic. Network-flow feature relationships need not be linearly separable. RBF is a reasonable kernel baseline, not proof that RBF is the best kernel.

### Why StandardScaler

RBF kernels are based on distances. Feature scale affects those distances, so standardisation is important. The scaler is fitted on benign training rows only.

### Why `nu=0.05`

Scikit-learn defines `nu` as an upper bound on the fraction of training errors and a lower bound on the support-vector fraction. It is not a guarantee that test FPR equals 5%.

The experimental 5% FPR target is a separate threshold-calibration procedure on held-out benign observations.

Scikit-learn reference: https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html

### Viva answer

"We included RBF One-Class SVM because it estimates the support of normal traffic using a nonlinear kernel boundary. It tests a third assumption—support/boundary estimation—alongside isolation and local density. We standardise the features because the RBF kernel depends on distances. We calibrate the final alert threshold separately on benign validation traffic; nu=0.05 is not itself a 5% test-FPR guarantee."

---

## 8. Why we selected only three primary unsupervised detectors

The selection is a focused comparison across distinct model families:

| Detector | Core question |
|---|---|
| Isolation Forest | Are attacks easy to isolate with random partitions? |
| LOF | Are attacks locally sparse relative to neighbouring flows? |
| RBF One-Class SVM | Do attacks fall outside a learned nonlinear region of normal traffic? |

Research support:
- Liu et al. (2008/2012) discuss Isolation Forest and compare with alternative anomaly detectors including LOF.
- Verkerken et al. (2022) compare Isolation Forest and One-Class SVM on CICIDS datasets.
- Xu and Liu (2025) directly evaluate LOF and OCSVM on CICIDS2017.

### Why not call this exhaustive?

Autoencoder and PCA reconstruction are legitimate unsupervised alternatives. Verkerken et al. include both. DBSCAN, HBOS and Deep SVDD are also possible. They were outside the scope of this focused three-paradigm study; we do not claim the chosen three are the only valid methods.

### Why Random Forest is separate

Random Forest was trained using attack labels and is a supervised reference. The three main detectors were trained on benign flows only. Comparing RF as if it had the same learning information would be methodologically unfair. Its result answers a different question: how well can a supervised classifier work when labelled attack examples are available?

---

## 9. Why the 5% threshold and these metrics

### Why a common 5% nominal calibration FPR

A common alert budget makes thresholded metrics more comparable across unsupervised models. Each score threshold is calibrated from the upper 5% tail of the same held-out benign-only calibration sample.

5% is an experimental operating point, not a universal SOC policy. In production it may still create too many false alerts. Evaluate stricter rates such as 1%, 0.5% and 0.1% according to analyst capacity and the cost of missing attacks.

### Why PR-AUC as well as ROC-AUC

Saito and Rehmsmeier (2015), *The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets*. DOI: https://doi.org/10.1371/journal.pone.0118432.

Our processed file is approximately 84.91% benign and 15.09% attack, with several very rare attack families. PR analysis exposes the fraction of alerts that are actually attacks (precision) and the fraction of attacks found (recall). ROC-AUC remains useful for ranking, but it is not enough on its own.

### Why precision, recall, F1 and FPR

- Precision: of the alerts raised, how many were attacks?
- Recall: of the attacks present, how many were found?
- F1: harmonic mean balancing precision and recall.
- FPR: of benign flows, how many were falsely flagged?
- Per-attack recall: checks whether the binary aggregate hides missed attack families.
- Runtime: measures whether the detector can score data at an operationally useful speed.

We report scikit-learn Average Precision. Do not claim it is exactly the trapezoidal area of a linearly interpolated precision-recall curve.

### Why accuracy is insufficient

With a high benign majority, a detector can achieve high accuracy by predicting mostly benign. This is why the report uses PR-AUC, recall, F1, FPR and per-attack metrics rather than selecting a model from accuracy alone.

---

## 10. Why our duplicate-grouped split

Franco-Valiente et al. (2026), *Scaling and Validating a Distributed Training and Retraining Pipeline for Network Intrusion Detection*. DOI: https://doi.org/10.3390/electronics15184074.

Their audit of their CIC-IDS2017 representation reports substantial duplicate-vector and five-tuple overlap under a record-level split. Those exact percentages belong to their evaluated representation, not automatically to our Parquet.

Our experiment hashes the 69 numeric modelling features without labels and uses StratifiedGroupKFold. The run metadata confirms zero exact feature-hash group overlap across train, validation and test.

**Limitation:** our processed Parquet does not retain timestamps or five-tuple connection identifiers, so we cannot claim temporal or connection-level grouping. Our current statement is only exact-duplicate-feature separation.

---

## 11. Why event correlation and attack graphs

### Research basis

Lyu et al. (2024), *AGCM: A multi-stage attack correlation and scenario reconstruction method based on graph aggregation*. Computer Communications, 224, 302–313. DOI: https://doi.org/10.1016/j.comcom.2024.06.016.

AGCM motivates correlating abnormal flows into a graph, aggregating related stages and reconstructing attack paths, rather than investigating each alert independently.

### Our implementation

- Suspicious flows are grouped using available source/destination, protocol, attack label and time context.
- A 60-second grouping window is used to build attack events.
- The graph represents hosts, events, attack types and targets.
- Relationship types include `initiates`, `classified_as`, `targets` and temporal `precedes`.
- Candidate temporal relationships are checked with a maximum gap of 300 seconds.

### Critical qualification

AGCM uses its own abnormal-state relationship graph, graph aggregation/clustering and weighted attack-path search. Our implementation is a simpler rule/entity/time-based NetworkX graph. Do not claim we implemented AGCM itself.

The exact 60-second grouping window and 300-second edge gap are project heuristics, not values proven optimal by AGCM. To justify them rigorously, run sensitivity tests (e.g. 30/60/120-second grouping and 60/180/300/600-second temporal links) and measure event fragmentation, event merging, graph size and alignment to available attack labels. A `precedes` edge records temporal order under rules; it does not prove causation.

### Viva answer

"We use an attack graph because a flat list of alerts does not show how observed events and hosts are related. AGCM provides research precedent for graph-based correlation and multi-stage scenario reconstruction. Our implementation uses a simpler, explainable rule-based grouping and NetworkX graph. We use 60 seconds and 300 seconds as configurable temporal heuristics, not universal research constants."

---

## 12. Why an agentic AI investigator

### Research basis

Lazer, Aryal, Gupta and Bertino (2026), *A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes*, arXiv:2601.05293: https://arxiv.org/abs/2601.05293.

The survey discusses planning, tool use, memory and iterative cybersecurity workflows, while emphasising governance, oversight, security and reliability risks.

Adabara et al. (2026), *The Agentic AI Framework (AAIF): a policy-enforced architecture for accountable and high-performance intrusion detection*, Frontiers in Artificial Intelligence. DOI: https://doi.org/10.3389/frai.2026.1755696.

AAIF proposes policy-enforced, auditable AI inference and reports its own benchmark/governance evaluation. It supports the importance of accountable controls; it does not prove all agentic systems are safe or accurate.

### Our implementation

The investigator uses predefined tools to retrieve event details, flow evidence, host history, temporal paths and graph context. The LLM generates an investigation summary from retrieved project evidence. The agent is not the primary attack detector.

### What still needs measurement

To substantiate "evidence-backed" and reduce hallucination risk, evaluate:
- event/field citation correctness;
- unsupported-claim rate;
- tool-selection and tool-execution success;
- correct abstention when evidence is missing;
- consistency with analyst-labelled expected findings;
- human review for high-impact response recommendations.

LangChain and Gemini are implementation/tooling choices. A research paper can support the agentic workflow concept, but it does not prove those specific libraries or model providers are uniquely best.

---

## 13. How to answer "why this entire architecture?"

"Our project addresses two different levels of cybersecurity analysis. At the flow level, a normal-only anomaly detector identifies suspicious traffic. At the incident level, correlation and graph representation organise related detections so an analyst can inspect a possible multi-stage scenario. A risk layer prioritises incidents, and the investigation agent retrieves event/graph evidence to prepare an explanation. CICIDS2017 provides labelled flow data for the detection benchmark; Isolation Forest, LOF and One-Class SVM cover three distinct unsupervised assumptions; AGCM motivates graph-based correlation; agentic-AI research motivates tool-using investigation while also requiring governance and evidence evaluation."

---

## 14. Model choice: why keep Isolation Forest if One-Class SVM scores higher?

Extended paired-sample experiment, 50k benign training rows, mean over seeds 42, 43, 44:

| Metric | Isolation Forest | LOF | RBF One-Class SVM |
|---|---:|---:|---:|
| ROC-AUC | 0.8848 | **0.9087** | 0.8430 |
| PR-AUC / AP | 0.6736 | 0.5687 | **0.7665** |
| Precision | 0.7048 | 0.6553 | **0.7225** |
| Recall | 0.6855 | 0.5129 | **0.7446** |
| F1 | 0.6948 | 0.5740 | **0.7334** |
| Fit time | **0.408 s** | 14.820 s | 17.391 s |
| Test scoring time, 15k rows | **0.103 s** | 4.439 s | 2.082 s |

Interpretation:
- One-Class SVM is strongest by AP/F1 at the tested 5% calibration alert budget.
- LOF is strongest by ROC-AUC at 50k.
- Isolation Forest is far faster in this runner benchmark.
- The standard deviations across seeds describe training-sample/model randomness on a fixed test set; they are not independent test-set confidence intervals.

The defensible current decision is to keep Isolation Forest in the existing application and evaluate One-Class SVM in shadow/parallel mode before switching. A final production decision needs stricter-FPR, memory, live throughput, temporal/connection-grouped and incident-level evaluation.

---

## 15. Core reference list

1. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. IEEE ICDM. https://doi.org/10.1109/ICDM.2008.17
2. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2012). Isolation-Based Anomaly Detection. ACM TKDD. https://doi.org/10.1145/2133360.2133363
3. Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000). LOF: Identifying Density-Based Local Outliers. ACM SIGMOD. https://doi.org/10.1145/342009.335388
4. Schölkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001). Estimating the Support of a High-Dimensional Distribution. Neural Computation. https://doi.org/10.1162/089976601750264965
5. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP. https://doi.org/10.5220/0006639801080116
6. Verkerken, M., D'hooge, L., Wauters, T., Volckaert, B., & De Turck, F. (2022). Towards Model Generalization for Intrusion Detection: Unsupervised Machine Learning Techniques. Journal of Network and Systems Management. https://doi.org/10.1007/s10922-021-09615-7
7. Xu, Z., & Liu, Y. (2025). Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017. ICETIS. https://doi.org/10.1109/ICETIS66286.2025.11144025
8. Saito, T., & Rehmsmeier, M. (2015). The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets. PLOS ONE. https://doi.org/10.1371/journal.pone.0118432
9. Lyu, H., Liu, J., Lai, Y., Mao, B., & Huang, X. (2024). AGCM: A multi-stage attack correlation and scenario reconstruction method based on graph aggregation. Computer Communications. https://doi.org/10.1016/j.comcom.2024.06.016
10. Franco-Valiente, J. M., Calle-Cancho, J., Serrano-Martín, A., & Haut, J. M. (2026). Scaling and Validating a Distributed Training and Retraining Pipeline for Network Intrusion Detection. Electronics. https://doi.org/10.3390/electronics15184074
11. Lazer, S. J., Aryal, K., Gupta, M., & Bertino, E. (2026). A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes. arXiv:2601.05293. https://arxiv.org/abs/2601.05293
12. Adabara, I., Sadiq, B. O., Shuaibu, A. N., Danjuma, Y. I., Maninti, V., & Joe, M. (2026). The Agentic AI Framework (AAIF): a policy-enforced architecture for accountable and high-performance intrusion detection. Frontiers in Artificial Intelligence. https://doi.org/10.3389/frai.2026.1755696

Implementation references:
- Isolation Forest: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- LOF: https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html
- One-Class SVM: https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html
- Novelty/outlier detection guide: https://scikit-learn.org/stable/modules/outlier_detection.html
