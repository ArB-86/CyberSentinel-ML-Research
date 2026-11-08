# Literature review: anomaly detection for network traffic

This review supports the choice of comparison models. It is a research rationale, not a claim that any model has already won on this project's data.

## 1. Isolation Forest — original baseline

**Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008).** "Isolation Forest." *Proceedings of the 8th IEEE International Conference on Data Mining*, 413–422. DOI: [10.1109/ICDM.2008.17](https://doi.org/10.1109/ICDM.2008.17).

The paper proposes isolating observations rather than explicitly building a detailed profile of normal observations. The method relies on random feature selection and random split points; anomalies tend to require shorter paths to isolate. Its use of sub-sampling is a central reason to consider it for large, high-dimensional data.

**Relevance to CyberSentinel:** CICIDS2017 is large and the project's existing model is Isolation Forest. It is therefore the natural reference model. The original paper also evaluates iForest against LOF and other detectors, so a cross-algorithm comparison is consistent with the method's research lineage.

## 2. Isolation-Based Anomaly Detection — extended analysis

**Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2012).** "Isolation-Based Anomaly Detection." *ACM Transactions on Knowledge Discovery from Data*, 6(1), Article 3. DOI: [10.1145/2133360.2133363](https://doi.org/10.1145/2133360.2133363).

This extended article develops the isolation principle and discusses computational efficiency, subsampling, masking and swamping. It is useful for defending the practical motivation for retaining Isolation Forest as a scalable benchmark, rather than assuming it is universally the most accurate detector.

## 3. Local Outlier Factor — density-based local anomalies

**Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000).** "LOF: Identifying Density-Based Local Outliers." *Proceedings of the ACM SIGMOD International Conference on Management of Data*, 93–104. DOI: [10.1145/342009.335388](https://doi.org/10.1145/342009.335388).

LOF assigns a degree of outlierness by comparing an observation's local reachability density with the densities of its neighbours. This is distinct from the global isolation mechanism: an observation can be unusual relative to a local region even when it is not globally extreme.

**Relevance to CyberSentinel:** network attacks can form clusters with different densities and behaviour profiles. LOF tests whether local neighbourhood structure adds value. It is computationally more expensive on large, high-dimensional data, so training/inference time and the fixed sample budget must be reported.

For a novelty-detection comparison on unseen flows, scikit-learn requires `novelty=True`; its documentation explicitly warns that `predict`, `decision_function` and `score_samples` must be used on new unseen data, not the fitted training points: [scikit-learn LOF documentation](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html).

## 4. One-Class SVM — boundary estimation

**Schölkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001).** "Estimating the Support of a High-Dimensional Distribution." *Neural Computation*, 13(7), 1443–1471. DOI: [10.1162/089976601750264965](https://doi.org/10.1162/089976601750264965).

One-Class SVM estimates a region of feature space containing most observations from a reference distribution. With a kernel such as RBF, it can represent a nonlinear boundary around normal traffic. The parameter `nu` controls an upper bound on the fraction of training errors and a lower bound on the fraction of support vectors.

**Relevance to CyberSentinel:** train only on benign flows and examine whether a learned normality boundary detects attacks. Standardisation is important because an RBF kernel depends on feature distances. Exact kernel One-Class SVM has substantially higher computational cost than Isolation Forest; the experiment therefore caps its common benign training sample and reports that count.

## 5. CICIDS2017 — dataset source

**Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).** "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108–116. DOI: [10.5220/0006639801080116](https://doi.org/10.5220/0006639801080116).

This is the dataset paper to cite when describing CICIDS2017's capture environment, attack scenarios and flow-level features. Cite the dataset's originating paper, not only third-party repositories that redistribute processed files.

## 6. Directly relevant CICIDS2017 comparison (2025)

**Xu, Z., & Liu, Y. (2025).** "Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017." *2025 10th International Conference on Electronic Technology and Information Science (ICETIS)*. DOI: [10.1109/ICETIS66286.2025.11144025](https://doi.org/10.1109/ICETIS66286.2025.11144025). Preprint: [arXiv:2506.19877](https://arxiv.org/abs/2506.19877).

The paper compares MLP, 1D CNN, One-Class SVM and LOF on CICIDS2017 under known-attack and unseen-attack scenarios. Its abstract reports that supervised models perform very strongly on familiar attacks but lose recall on novel threats; LOF reports high recall on unknown attacks at the cost of more false alarms, while OCSVM offers a different precision/recall trade-off.

**Relevance to CyberSentinel:** this is direct precedent for comparing LOF and OCSVM on CICIDS2017, and for discussing unseen-attack generalisation rather than relying exclusively on random in-distribution test metrics. Its numerical results must not be copied into this project's result table; datasets, splits, preprocessing and parameters must be checked before any quantitative comparison.

## 7. Dataset duplication and split design (2026)

**Franco-Valiente, J. M., Calle-Cancho, J., Serrano-Martín, A., & Haut, J. M. (2026).** "Scaling and Validating a Distributed Training and Retraining Pipeline for Network Intrusion Detection." *Electronics*, 15(18), 4074. DOI: [10.3390/electronics15184074](https://doi.org/10.3390/electronics15184074).

The authors compare record-level, exact-duplicate-grouped and connection-grouped splits on their CIC-IDS2017 representation. Their audit reports that exact duplicate feature vectors accounted for 18.3% of flows in the evaluated snapshot, and about 20.5% of record-level test rows had an identical modelling-feature vector in training. They show why record-level random splits can overstate generalisation and why grouping must be made explicit.

**Qualification:** these percentages describe the authors' evaluated dataset representation and split, not necessarily the exact cleaned Parquet distributed with CyberSentinel. This project uses exact numeric-feature hash groups because the cleaned Parquet has no flow identifiers or five-tuple fields. It does not claim to eliminate connection-level or temporal leakage.

## Synthesis and research gap

The methods represent complementary notions of abnormality:

- Isolation Forest: short isolation path.
- LOF: local density deviation relative to neighbours.
- One-Class SVM: boundary around normal observations.
- Random Forest: supervised classification from labelled examples (reference track only).

The original repository justifies Isolation Forest as the chosen baseline, but it does not provide an algorithm-level comparison. The research gap is therefore empirical and project-specific: evaluate the three unsupervised approaches under the same benign-only training budget, duplicate-group split, benign-only threshold calibration and shared test rows; then show a separate supervised Random Forest reference. The best model must be selected from reproducible local results, not from the literature's results or assumptions.
