# Research evidence and model-selection rationale

## Purpose

This document links the project's design choices to primary research, explains why the three anomaly detectors were selected, and states the limits of what each citation supports. It is intended for a technical viva: a paper title alone is not evidence; the relevant contribution, its connection to the implementation, and the qualification must be understood.

---

## 1. Why Isolation Forest was selected as the initial detector

### Primary reference

**Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008).** "Isolation Forest." *2008 Eighth IEEE International Conference on Data Mining*, 413–422. DOI: [10.1109/ICDM.2008.17](https://doi.org/10.1109/ICDM.2008.17).

The paper introduces isolation-based anomaly detection. It explicitly isolates observations rather than first learning a complete profile of normal instances. Random feature selection and random split values create isolation trees; observations that are unusual tend to be separated in fewer splits. The paper highlights subsampling as an efficiency advantage and reports favourable performance against ORCA, LOF and Random Forest in its experiments, especially on large datasets and high-dimensional data. It also explains that the method can work when the training sample contains no anomalies.

**Project connection:** the detector is trained using benign CICIDS2017 flows only. This matches the normal-only setting and avoids requiring examples of every malicious category during model fitting. The dataset has about 2.23 million rows and 69 numerical flow features; a scalable, subsampling-based detector is a defensible first baseline.

**What this paper does not prove:** it does not prove Isolation Forest is best on this exact processed CICIDS2017 version, under our split, threshold, or operational requirements. That requires a project-specific experiment—which is why LOF and One-Class SVM were trained as alternatives.

### Extended reference

**Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2012).** "Isolation-Based Anomaly Detection." *ACM Transactions on Knowledge Discovery from Data*, 6(1), Article 3. DOI: [10.1145/2133360.2133363](https://doi.org/10.1145/2133360.2133363).

This extended paper develops the isolation principle, subsampling, computational efficiency, and masking/swamping discussion. It directly compares Isolation Forest with methods including LOF, One-Class SVM and Random Forest in its own experimental evaluation.

**Viva use:** this is strong methodological evidence that Isolation Forest, LOF and One-Class SVM are reasonable contrasting algorithms to evaluate. Do not transfer its numerical ranking to CICIDS2017; the datasets and experimental protocol are different.

### Why the original hyperparameters were reasonable starting points

| Setting | Project value | Reason and qualification |
|---|---:|---|
| `n_estimators` | 200 | A forest ensemble averages random isolation trees. 200 is the project's fixed baseline configuration; it is not claimed to be a globally optimal tree count. A tree-count sensitivity experiment would be needed to establish that. |
| `max_samples` | 1,024 | Each tree is fit on at most 1,024 sampled rows. This is consistent with the isolation-forest paper's emphasis on subsampling. The 500,000 benign rows in the original notebook provide a large benign sampling pool; they do not mean every tree uses all 500,000 rows. |
| `max_features` | 1.0 | Each tree can use the full feature set. This is a baseline choice, not a feature-subset ablation result. |
| `contamination` | `auto` | Lets the estimator use its built-in offset convention. It does not assert that exactly 15% of live traffic is malicious. The comparative study calibrates an operational threshold separately on benign validation observations. |
| `random_state` | 42 | Makes the estimator's random sampling reproducible. |
| `n_jobs` | -1 | Allows scikit-learn to use available CPU workers. |

The current scikit-learn documentation describes Isolation Forest's random feature and split selection, path-length scoring, and `max_samples` behaviour: [IsolationForest documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).

**Important distinction about the original notebook:** its model was fit on benign-only observations, but the original validation threshold was selected using attack labels to maximise validation F1. That makes the *model fitting* unsupervised while the *threshold selection* is label-informed. This is a legitimate labelled validation strategy if disclosed; it is not a completely label-free deployment calibration. The new comparison instead chooses thresholds using only held-out benign calibration rows.

---

## 2. Why Local Outlier Factor was selected as the first alternative

**Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000).** "LOF: Identifying Density-Based Local Outliers." *Proceedings of the ACM SIGMOD International Conference on Management of Data*, 93–104. DOI: [10.1145/342009.335388](https://doi.org/10.1145/342009.335388).

LOF estimates the local reachability density of a point and compares it with the densities of its neighbours. A flow may be an outlier because it is sparse relative to its local neighbourhood—even if it is not globally extreme.

**Why this is a useful contrast:** Isolation Forest asks how easily a point can be isolated by random partitions. LOF asks whether a point's local density is unusually low relative to its neighbours. These are different anomaly assumptions. Network traffic has different normal operating modes and local traffic patterns, so a local-density detector is a relevant comparator rather than a duplicate of Isolation Forest.

### Why `novelty=True`

The system fits on benign training flows and must score unseen validation/test flows. Scikit-learn distinguishes LOF outlier detection on the fitted data from novelty detection on new observations. With `novelty=True`, the documented scoring methods are intended for unseen observations; applying them to training data can give different/wrongly interpreted results. See [LOF documentation](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html).

### Why standardise the input

LOF uses nearest-neighbour distances. When one flow feature has a much larger numeric scale than another, it can dominate the distance calculation. StandardScaler fits means and standard deviations on the training data and applies those learned values to calibration/test rows. Scikit-learn explains this scale dependence in its [StandardScaler documentation](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html).

### Why 35 neighbours

The experiment uses `n_neighbors=35` as a fixed comparison setting. The scikit-learn outlier-detection guide notes that the neighbourhood size should reflect the size of local clusters and discusses larger neighbourhoods in examples with a relatively high outlier fraction. However, the 35-neighbour setting has **not** been established as optimal for this dataset by a full search. Treat it as a controlled benchmark configuration; a (k)-sensitivity analysis (for example 10, 20, 35 and 50) is a valid follow-up.

---

## 3. Why RBF One-Class SVM was selected as the second alternative

**Schölkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001).** "Estimating the Support of a High-Dimensional Distribution." *Neural Computation*, 13(7), 1443–1471. DOI: [10.1162/089976601750264965](https://doi.org/10.1162/089976601750264965).

This paper develops a one-class support-vector method to estimate a region (support) of feature space containing observations from a reference distribution. It is a principled normal-only/boundary-estimation alternative to a tree-isolation or local-density detector.

**Why RBF:** network-flow relationships can be nonlinear. An RBF kernel allows a nonlinear boundary in the transformed feature space. We use it as a representative kernel-based novelty detector; this does not prove the RBF kernel is always superior to linear or polynomial kernels.

### Why scale the features

The RBF kernel is based on distances in feature space. Large-range numerical columns can dominate those distances unless features are scaled. StandardScaler is fit on benign training data only, then reused for calibration and test. See [StandardScaler documentation](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html).

### What `nu=0.05` means—and what it does not mean

Scikit-learn documents `nu` as an upper bound on the fraction of training errors and a lower bound on the fraction of support vectors. It is **not** a guarantee that the test false-positive rate will be exactly 5%. The project's 5% alert target is achieved separately by selecting a score threshold on held-out benign calibration rows. See [OneClassSVM documentation](https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html).

### Why SVM needs a runtime comparison

Kernel One-Class SVM is more computationally sensitive to training-set size than Isolation Forest. The 5k/25k/50k experiment records fit and scoring times explicitly. That cost is part of model selection, not a footnote.

---

## 4. Direct intrusion-detection evidence for comparing these methods

These papers are particularly valuable for the panel because they move beyond general anomaly-detection theory.

### CICIDS2017 unsupervised model generalisation

**Verkerken, M., D'hooge, L., Wauters, T., Volckaert, B., & De Turck, F. (2022).** "Towards Model Generalization for Intrusion Detection: Unsupervised Machine Learning Techniques." *Journal of Network and Systems Management*, 30(1), Article 12. DOI: [10.1007/s10922-021-09615-7](https://doi.org/10.1007/s10922-021-09615-7).

This study evaluates PCA, Isolation Forest, Autoencoder and One-Class SVM on CIC-IDS-2017 and CSE-CIC-IDS-2018. It also tests inter-dataset generalisation rather than relying only on a train/test split within one dataset. The authors report substantial performance degradation when transferring between related datasets and highlight generalisation as a key limitation of anomaly-based NIDS.

**Why it matters here:** it supports the relevance of Isolation Forest and One-Class SVM for CICIDS2017, and it shows why a high score on one benchmark is not proof of production generalisation. It does not include LOF in its main four-model experiment, and its numeric results must not be presented as our own.

### Direct CICIDS2017 comparison including LOF and One-Class SVM

**Xu, Z., & Liu, Y. (2025).** "Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017." *2025 10th International Conference on Electronic Technology and Information Science (ICETIS)*. DOI: [10.1109/ICETIS66286.2025.11144025](https://doi.org/10.1109/ICETIS66286.2025.11144025). Preprint: [arXiv:2506.19877](https://arxiv.org/abs/2506.19877).

The paper compares MLP, 1D CNN, One-Class SVM and LOF on CICIDS2017 in known-attack and unseen-attack scenarios. Its abstract reports different trade-offs: supervised models perform strongly on familiar attack types but lose recall on unseen threats; LOF can improve unknown-attack recall at the cost of more false alarms; OCSVM has a different precision/recall balance.

**Why it matters:** it is direct evidence that LOF and OCSVM are relevant candidates on CICIDS2017, and that unseen-attack evaluation matters. Its results do not establish which model wins under our feature set, split, training sample, calibration threshold or test sample.

### CICIDS2017 dataset foundation

**Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).** "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *Proceedings of ICISSP 2018*, 108–116. DOI: [10.5220/0006639801080116](https://doi.org/10.5220/0006639801080116).

This paper describes the dataset-generation methodology and traffic/attack characterization behind CICIDS2017. It is the correct source for explaining why CICIDS2017 contains multiple labelled attack scenarios and flow-level features. It is a dataset paper, not evidence that Isolation Forest is the best classifier.

---

## 5. Why PR-AUC is a primary metric

**Saito, T., & Rehmsmeier, M. (2015).** "The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets." *PLOS ONE*, 10(3), e0118432. DOI: [10.1371/journal.pone.0118432](https://doi.org/10.1371/journal.pone.0118432).

The paper explains that ROC plots can look reassuring in imbalanced settings while hiding the practical fraction of correct alerts among all positive predictions. Precision-recall analysis makes the positive-class alert quality visible.

**Project connection:** the processed CICIDS2017 data contains approximately 84.9% benign flows and 15.1% attack flows, and some attack families have very low support. We therefore report Average Precision (the scikit-learn PR-AUC summary used in the code), precision, recall, F1 and FPR in addition to ROC-AUC.

**Metric precision:** our result file labels the measure `pr_auc_average_precision`. Scikit-learn Average Precision is not the trapezoidal area under a linearly interpolated PR curve; do not conflate the definitions in a viva.

---

## 6. Why duplicate-aware splitting is necessary

**Franco-Valiente, J. M., Calle-Cancho, J., Serrano-Martín, A., & Haut, J. M. (2026).** "Scaling and Validating a Distributed Training and Retraining Pipeline for Network Intrusion Detection." *Electronics*, 15(18), 4074. DOI: [10.3390/electronics15184074](https://doi.org/10.3390/electronics15184074).

Their CIC-IDS2017 audit reports substantial exact duplicate-vector overlap and connection-level overlap in a record-level split in their evaluated representation. They show that an ordinary row split can let repeated flows or related connections cross between train and test.

**Project connection:** our split groups exact duplicates based on the 69 numeric modelling features, with labels excluded from the hash, and asserts zero exact feature-hash overlap across train/validation/test.

**Critical qualification:** the paper's percentages describe its own data representation and split, not automatically this processed Parquet. Our cleaned Parquet lacks the five-tuple identifiers and timestamps needed to perform a connection-level or temporal split. We therefore claim exact-duplicate separation, not complete leakage elimination.

---

## 7. Why graph-based attack correlation is part of the system

**Lyu, H., Liu, J., Lai, Y., Mao, B., & Huang, X. (2024).** "AGCM: A multi-stage attack correlation and scenario reconstruction method based on graph aggregation." *Computer Communications*, 224, 302–313. DOI: [10.1016/j.comcom.2024.06.016](https://doi.org/10.1016/j.comcom.2024.06.016).

AGCM motivates correlating abnormal flows rather than treating every IDS alert as an independent incident. It constructs an abnormal-states relationship graph, applies graph aggregation and clustering to identify attack stages, and uses weighted attack-path search to reconstruct scenarios.

**Project connection:** the project groups suspicious flows into events using host/protocol/label/time context and represents source hosts, events, attack types and targets as a NetworkX graph. Time-ordered relationships make related activity easier to inspect than a flat alert list.

**Do not overclaim:** the current project is not a reimplementation of AGCM's graph aggregator, clustering or weighted attack-path algorithm. It uses a simpler rule/entity/time-based event-grouping and graph representation. A timestamp-based `precedes` edge records observed order; it does not prove causation or that one event caused another.

---

## 8. Why agentic AI is used for investigation—and what evidence is still needed

### Agentic cybersecurity survey

**Lazer, S. J., Aryal, K., Gupta, M., & Bertino, E. (2026).** "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes." arXiv: [2601.05293](https://arxiv.org/abs/2601.05293).

The survey discusses planning, tool use, memory and iterative task execution in cyber defence, while also identifying governance, accountability, adversarial and reliability risks.

### Policy-enforced IDS architecture

**Adabara, I., Sadiq, B. O., Shuaibu, A. N., Danjuma, Y. I., Maninti, V., & Joe, M. (2026).** "The Agentic AI Framework (AAIF): a policy-enforced architecture for accountable and high-performance intrusion detection." *Frontiers in Artificial Intelligence*, 9, 1755696. DOI: [10.3389/frai.2026.1755696](https://doi.org/10.3389/frai.2026.1755696).

This paper proposes a policy-enforced architecture combining a detection model with an executable governance/policy layer. Its CICIDS2017 evaluation reports AUROC 0.978 and weighted F1 0.483, alongside governance-compliance measures.

**Why it matters:** it supports the research direction of pairing detection with accountable, policy-governed AI workflows.

**What it does not prove:** it does not establish that any generic LLM agent is automatically safe, accurate or a "gold standard". Its measured weighted F1 and governance metrics are specific to its implementation and evaluation. Our project must separately assess whether the agent's investigation claims are grounded in retrieved event/graph evidence, whether it cites the evidence used, and whether it abstains when evidence is missing.

---

## 9. Why these three detectors—and why not every possible algorithm?

The three-model set was selected because the methods make materially different assumptions:

| Detector | Core assumption | Question being tested |
|---|---|---|
| Isolation Forest | Unusual points are easier to isolate with random partitions | Is an efficient, global isolation mechanism sufficient? |
| LOF | Anomalies have lower local density than their neighbours | Does local neighbourhood structure catch patterns missed by a global method? |
| RBF One-Class SVM | Normal observations occupy a learnable nonlinear support region | Does a nonlinear boundary around benign traffic yield better attack ranking at a fixed alert budget? |

The choice is also supported by the literature: Isolation Forest's original/extended research compares it against other anomaly detectors; Verkerken et al. evaluate Isolation Forest and One-Class SVM on CICIDS datasets; Xu and Liu directly compare LOF and OCSVM on CICIDS2017 under known and unseen attack scenarios.

This is a focused study, **not an exhaustive survey of all anomaly-detection algorithms**.

### Why not use these as primary alternatives in this experiment?

- **Autoencoder:** a legitimate next comparator, supported by Verkerken et al. It introduces architecture, bottleneck size, loss function, epochs, optimiser, early stopping and reconstruction-threshold choices. It deserves a controlled experiment of its own rather than a hastily tuned neural baseline.
- **PCA reconstruction:** a valid linear reconstruction baseline and included by Verkerken et al. It tests whether linear normal-subspace reconstruction is enough. It is a good fourth unsupervised model for a later extension.
- **Random Forest:** included previously as a separate supervised reference. It learns from labelled attack examples, so it answers a different question and must not be presented as a like-for-like unsupervised competitor.
- **MLP/CNN:** direct supervised alternatives that generally need labelled attack examples; sequence/CNN designs may also need an explicit packet, time-window or sequence representation. They are valuable supervised extensions, not replacements for the normal-only comparison.
- **DBSCAN/HBOS/Deep SVDD/Isolation-based variants:** also plausible methods. They were outside the initial bounded comparison scope. We do not claim the selected three are the only valid algorithms.

### Viva-ready answer: "Why only these three?"

"We selected three complementary unsupervised paradigms, not three arbitrary algorithms. Isolation Forest is the scalable isolation-based baseline already used by the system. LOF tests local-density deviations. RBF One-Class SVM tests nonlinear support estimation of benign traffic. The choice is grounded in the original Isolation Forest literature, the LOF and One-Class SVM foundations, and CICIDS2017-related comparative studies by Verkerken et al. and Xu and Liu. We also included a supervised Random Forest reference separately. Autoencoders and PCA are valid future extensions; this experiment is a focused, controlled comparison rather than an exhaustive leaderboard."

---

## 10. Evidence-to-implementation map

| Project decision | Primary supporting evidence | What the viva answer should say |
|---|---|---|
| Use CICIDS2017 | Sharafaldin et al. (2018) | Benchmark has labelled benign and multiple attack scenarios with flow features; it is a benchmark, not a perfect production network. |
| Start with Isolation Forest | Liu et al. (2008, 2012) | Normal-only fitting, isolation paths, subsampling and efficiency make it a defensible baseline. |
| Compare LOF | Breunig et al. (2000) | Tests local-density abnormality, a different anomaly assumption. |
| Compare RBF One-Class SVM | Schölkopf et al. (2001) | Tests a nonlinear support boundary learned from benign data. |
| Standardise LOF/OCSVM | scikit-learn StandardScaler documentation | Neighbour and RBF distances are scale-sensitive; fit scaler only on training data. |
| Use LOF novelty mode | scikit-learn LOF documentation | The task is scoring unseen validation/test flows, not re-labelling fitted training points. |
| Use a benign-only 5% calibration threshold | Study protocol | Equal nominal false-alert budget without using attack labels to tune unsupervised threshold. |
| Prioritise PR-AUC with ROC-AUC | Saito & Rehmsmeier (2015) | Positive-class alerts matter in imbalanced detection; ROC-AUC remains useful but is not sufficient. |
| Group exact duplicates | Franco-Valiente et al. (2026) | Reduces exact-vector train/test leakage; still not a temporal/connection split. |
| Correlate alerts as a graph | Lyu et al. (2024) | Graphs expose relationships and candidate multi-stage paths; our implementation is a simpler rule-based graph. |
| Use an investigation agent | Lazer et al. (2026); Adabara et al. (2026) | Tool-using investigation is a research direction; evidence traceability and governance must be evaluated. |

## 11. The model-selection decision for this project

Do not replace Isolation Forest just because One-Class SVM scored higher in one table.

The measured paired 5k/25k/50k study shows:

- RBF One-Class SVM is strongest by PR-AUC and F1 at all three tested training sizes.
- LOF is strongest by ROC-AUC at 25k and 50k, but has lower AP/F1 at the calibrated operating point.
- Isolation Forest has dramatically lower training and scoring time.

The defensible present decision is to **retain Isolation Forest as the current application detector and treat RBF One-Class SVM as the leading alternative for a shadow/parallel evaluation**. A replacement decision should use metadata-rich, temporally separated traffic, operational throughput, memory, alert burden, per-attack performance and incident-level outcomes—not only a benchmark F1 score.

This distinction directly answers both sides of the panel's question: the original model had a research-based rationale, and the team subsequently tested whether alternatives were empirically better under the project's data and evaluation protocol.
