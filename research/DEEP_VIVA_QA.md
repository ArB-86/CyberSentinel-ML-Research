# Deep technical viva questions and evidence-backed answers

This document is a speaking-preparation guide. Keep answers tied to the actual implementation and measured results. If a value or capability was not evaluated, say so rather than improvising.

---

## A. Problem formulation and model choice

### Q1. What problem does your project solve?

**Answer:** Traditional intrusion-detection systems can produce many individual alerts. A single alert does not necessarily reveal whether it belongs to a larger multi-stage incident. The system first detects suspicious network flows, then groups related flows into events, links events and hosts in an attack graph, calculates incident risk, and uses an AI investigator to examine the available evidence. The objective is to help an analyst understand what happened, how observed events are related, and what evidence supports the incident assessment.

### Q2. Why did you originally select Isolation Forest?

**Answer:** We needed a normal-only anomaly detector because the system should learn benign traffic without requiring labelled examples of every attack family. Isolation Forest isolates observations using random feature splits; unusual observations often have shorter isolation paths. Its subsampling design is attractive for large, high-dimensional flow datasets. These are the central ideas in Liu, Ting and Zhou (2008), with a fuller treatment in their 2012 paper. We therefore selected it as a defensible, computationally efficient baseline—not because we assumed it must be the best model.

### Q3. Is Isolation Forest an unsupervised model if you used CICIDS2017 labels?

**Answer:** The Isolation Forest estimator is fitted only on benign training flows. The attack label is excluded from the feature matrix. Labels are retained separately for experimental split stratification and final evaluation. In the new comparison, a held-out benign-only sample calibrates the threshold. So the detector fitting is unsupervised/normal-only novelty detection, while the benchmark evaluation uses known labels.

### Q4. Why use only benign flows for training?

**Answer:** The target use case is anomaly/novelty detection: model normal traffic and flag deviations. A supervised model needs representative attack labels during training, but new or rare attacks may not have labelled examples. Benign-only training is a way to investigate whether the system can identify suspicious deviations without learning every known attack signature. It does not guarantee detection of all zero-day attacks; attacks that resemble benign traffic may be missed.

### Q5. Why did you compare these three models only?

**Answer:** They represent three different anomaly-detection assumptions:
- Isolation Forest: how easily a point can be isolated by random partitions.
- LOF: whether a point has substantially lower local density than its neighbours.
- RBF One-Class SVM: whether a point falls outside a learned nonlinear support region of normal traffic.

They are not three arbitrary variants of the same method. The original Isolation Forest literature compares it with alternatives such as LOF, and its extended paper discusses one-class SVM. Verkerken et al. evaluate Isolation Forest and One-Class SVM on CICIDS2017/CSE-CIC-IDS2018. Xu and Liu (2025) directly compare LOF and OCSVM on CICIDS2017 under known-attack and unseen-attack scenarios. The three-model set therefore has both conceptual and IDS-literature support.

This is a focused comparative experiment, not a claim that these are the only possible algorithms. Autoencoder and PCA reconstruction are valid next comparators; supervised RF/MLP/CNN models answer a different labelled-learning question.

### Q6. Why not compare Autoencoder, PCA, CNN, DBSCAN or HBOS too?

**Answer:** They are valid alternatives, but a controlled study needs enough time to implement, tune, validate and report each method fairly. We prioritised three classical unsupervised paradigms directly aligned with benign-only training. Verkerken et al. also evaluate autoencoder and PCA reconstruction, so those are natural extensions. A CNN would require a well-defined sequence/window/packet representation rather than simply inserting a neural model into a tabular flow benchmark. We are not claiming an exhaustive algorithm leaderboard.

### Q7. Why not replace Isolation Forest immediately because One-Class SVM scored higher?

**Answer:** A model should not be changed based on one metric alone. In the paired scaling study, One-Class SVM led in PR-AUC and F1, LOF led in ROC-AUC at larger training sizes, and Isolation Forest was substantially faster. The application has a throughput and analyst-alert requirement as well as a detection-quality requirement. We retain Isolation Forest as the current detector and treat One-Class SVM as the leading alternative for a shadow/parallel evaluation on metadata-rich traffic. A final switch requires operational and temporal validation.

---

## B. Research papers and their exact relevance

### Q8. Which paper supports Isolation Forest?

**Answer:** Liu, Ting and Zhou (2008), "Isolation Forest", DOI 10.1109/ICDM.2008.17. It introduces isolation-based anomaly detection and explains why subsampling makes the method efficient. Their 2012 extended article, DOI 10.1145/2133360.2133363, provides a deeper theoretical/empirical analysis and compares iForest with methods including LOF and One-Class SVM.

### Q9. Which paper supports LOF?

**Answer:** Breunig et al. (2000), "LOF: Identifying Density-Based Local Outliers", DOI 10.1145/342009.335388. It introduces local reachability density and a local outlier factor. It supports LOF as a method that can detect observations unusual relative to their neighbours, which is a different assumption from global isolation.

### Q10. Which paper supports One-Class SVM?

**Answer:** Schölkopf et al. (2001), "Estimating the Support of a High-Dimensional Distribution", DOI 10.1162/089976601750264965. It establishes a one-class support-estimation formulation: learn a region of feature space containing normal observations, then flag observations outside the estimated support.

### Q11. Which research paper directly compares models on CICIDS2017?

**Answer:** Xu and Liu (2025), "Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017", DOI 10.1109/ICETIS66286.2025.11144025. It compares MLP, 1D CNN, OCSVM and LOF and examines known versus unseen attacks. It provides direct precedent for evaluating LOF and OCSVM on this dataset. Its numeric results are not our results because its preprocessing, split and configurations differ.

### Q12. Is there a paper comparing Isolation Forest and One-Class SVM on CICIDS datasets?

**Answer:** Verkerken et al. (2022), "Towards Model Generalization for Intrusion Detection: Unsupervised Machine Learning Techniques", DOI 10.1007/s10922-021-09615-7. It evaluates PCA, Isolation Forest, autoencoder and One-Class SVM on CIC-IDS-2017 and CSE-CIC-IDS-2018 and studies inter-dataset generalisation. The paper is important because it shows that high within-dataset scores may not transfer to a second related dataset.

### Q13. Which paper justifies the CICIDS2017 dataset?

**Answer:** Sharafaldin, Habibi Lashkari and Ghorbani (2018), "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", DOI 10.5220/0006639801080116. It documents the dataset-generation methodology and traffic/attack characterization. It justifies the benchmark source and its scope; it does not prove that one particular classifier is best.

### Q14. Which paper supports your attack-graph stage?

**Answer:** Lyu et al. (2024), "AGCM: A multi-stage attack correlation and scenario reconstruction method based on graph aggregation", DOI 10.1016/j.comcom.2024.06.016. It converts abnormal flows into an abnormal-states relationship graph, applies graph aggregation/clustering to identify attack stages, and searches for weighted attack paths. Our system uses a simpler entity/time-based event grouping and NetworkX graph, so we use AGCM as methodological motivation—not as a claim that our implementation reproduces their algorithm.

### Q15. Which paper supports the agentic AI investigation direction?

**Answer:** Lazer et al. (2026), "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes", arXiv:2601.05293, discusses tool use, memory, planning and iterative defensive workflows, alongside risks such as adversarial manipulation, governance and oversight. Adabara et al. (2026), "The Agentic AI Framework (AAIF): a policy-enforced architecture for accountable and high-performance intrusion detection", DOI 10.3389/frai.2026.1755696, proposes an IDS architecture with policy-enforced governance. These papers support the research direction, not a claim that an LLM agent is automatically correct or that the architecture is a universal gold standard.

### Q16. Why did you use PR-AUC and not accuracy alone?

**Answer:** The dataset is imbalanced: about 84.9% benign and 15.1% attack traffic. Accuracy can look high even when many attacks are missed. Saito and Rehmsmeier (2015), DOI 10.1371/journal.pone.0118432, explain why precision-recall curves are more informative than ROC curves for imbalanced classification in many practical settings. We report PR-AUC/Average Precision, precision, recall, F1 and FPR alongside ROC-AUC. ROC-AUC is still useful because it measures ranking across thresholds; it is just not sufficient by itself.

### Q17. Why did you group exact duplicate feature vectors?

**Answer:** Duplicate flow vectors can occur in CICIDS2017. If identical feature vectors appear in train and test, the test may reward memorisation rather than generalisation. Franco-Valiente et al. (2026), DOI 10.3390/electronics15184074, document exact-vector and connection overlap under a record-level split in their evaluated CIC-IDS2017 representation. We therefore group exact numeric-feature hashes before assigning train/validation/test folds. Our processed Parquet has no five-tuple or timestamp fields, so we cannot claim full connection or temporal separation.

---

## C. Hyperparameters, preprocessing and threshold

### Q18. Why did you train Isolation Forest on 500,000 benign flows originally?

**Answer:** The model learns the normal traffic pattern. The large benign pool provides coverage of normal-flow variability, while `max_samples=1024` limits the number of rows used by each isolation tree. The 500,000 value was a practical sampling-pool choice for the original notebook, not a mathematically proven optimum. The extended experiment explicitly tests 5k, 25k and 50k training pools to examine how results change.

### Q19. Does `max_samples=1024` mean the whole forest sees only 1,024 rows?

**Answer:** No. It means each base tree draws at most 1,024 rows from the training pool. Across 200 trees, each tree can see a different random subset, so the forest samples from the larger benign pool.

### Q20. Why 200 trees?

**Answer:** More trees reduce variation in the random forest of isolation trees but increase training/scoring cost. Two hundred is the project's fixed baseline configuration. We have not claimed a full hyperparameter search proves 200 is optimal; a tree-count sensitivity study would be needed for that claim.

### Q21. Does `contamination='auto'` mean you assume 15% attacks?

**Answer:** No. In scikit-learn, `contamination` is used to define an estimator's decision offset. With `auto`, the estimator uses its built-in convention; it does not read the dataset's 15% attack prevalence as the expected attack rate. In the comparative experiments, a separate threshold is calibrated to a nominal 5% false-positive rate using benign-only calibration rows.

### Q22. Why use StandardScaler for LOF and One-Class SVM but not Isolation Forest?

**Answer:** LOF relies on nearest-neighbour distances and RBF One-Class SVM relies on distances in a kernel. Features with larger numeric scales could dominate those calculations, so scaling is important. Isolation Forest partitions each feature using random split points within its feature range and does not depend on Euclidean distance in the same way. The scaler and imputer are fitted only on training data, then applied to calibration and test data.

### Q23. Why is LOF set to `novelty=True`?

**Answer:** The model is fitted on benign training rows and must score unseen calibration/test flows. Scikit-learn documents `novelty=True` for this case and warns that novelty-mode scoring methods should be used on new unseen samples, not on the training data.

### Q24. Why did you choose 35 neighbours for LOF?

**Answer:** It is a fixed reference setting for the controlled comparison, not a claimed optimum. The neighbour count controls the locality scale. Too few neighbours can be noisy; too many can smooth out local differences. We should test a range of values (e.g., 10, 20, 35, 50) as a hyperparameter sensitivity experiment before claiming 35 is optimal.

### Q25. What does `nu=0.05` mean in One-Class SVM?

**Answer:** In scikit-learn, `nu` is an upper bound on the fraction of training errors and a lower bound on the fraction of support vectors. It is not a direct guarantee of 5% test FPR. Our test operating point is chosen separately by thresholding the scores at the upper 5% tail of benign calibration scores.

### Q26. Why choose an RBF kernel?

**Answer:** It provides a nonlinear boundary around benign traffic. Network-flow relationships may be nonlinear, so RBF is a reasonable representative kernel. It is not the only valid kernel; linear and polynomial kernels should be included in a later kernel sensitivity analysis if we need to justify RBF as the best One-Class SVM kernel.

### Q27. Why set a 5% false-positive target?

**Answer:** It creates a shared nominal alert budget so the three unsupervised models can be compared at a comparable operating point. The 5% value is an experimental choice, not a universal SOC requirement. In a real deployment, 5% false positives may still be too many; the detector should be evaluated at stricter alert budgets such as 1%, 0.5% or 0.1%, depending on analyst capacity and the cost of missed attacks.

### Q28. Why not tune threshold to maximise F1 on the test set?

**Answer:** That would leak test labels into model selection and produce an optimistic estimate. The new study freezes thresholds using a benign-only calibration sample, then evaluates once on the held-out test sample. The original Isolation Forest notebook used attack labels in validation to maximise F1; that difference is disclosed in the baseline evaluation.

---

## D. Results and what they mean

### Q29. What did the first comparison show?

**Answer:** In the three-seed pilot, RBF One-Class SVM had the highest mean PR-AUC (0.7670) and F1 (0.7424) among the unsupervised models. LOF had the highest mean ROC-AUC (0.8984) but lower PR-AUC/F1. Isolation Forest was intermediate and fast. These values are in `research/EXPERIMENT_RESULTS.md`.

### Q30. What did the extended 5k/25k/50k study show?

**Answer:** Under a fixed duplicate-grouped split, common benign calibration sample and shared test sample:
- RBF One-Class SVM had the highest PR-AUC and F1 at all three training sizes.
- LOF had the highest ROC-AUC at 25k and 50k.
- Isolation Forest remained substantially faster.
- Increasing One-Class SVM training rows from 5k to 50k modestly improved AP (0.7486 to 0.7665), while F1 remained broadly stable (0.7363 to 0.7334).
- LOF AP/F1 improved somewhat at 50k but remained below the other two methods.

Read `research/SCALING_VALIDATION_RESULTS.md` for exact means, standard deviations, runtime and limitations.

### Q31. Why can LOF have the highest ROC-AUC but lower PR-AUC/F1?

**Answer:** ROC-AUC evaluates ranking across all thresholds using TPR and FPR. Average Precision focuses on precision and recall for the positive class. In an imbalanced dataset, a model may rank positives above negatives fairly well overall but still generate too many false alerts or fail to reach strong precision at the selected operating point. The results show why we report several metrics and define a thresholded operating point.

### Q32. Why is One-Class SVM the best candidate if its ROC-AUC is lower?

**Answer:** “Best” depends on the objective. In our extended experiment, One-Class SVM's ROC-AUC is lower than LOF, but its PR-AUC and F1 are higher at all tested training sizes, with test FPR near the common 5% target. If the priority is precision-recall quality at this alert budget, OCSVM is the strongest candidate. If the priority is ROC ranking alone, LOF is stronger at 25k/50k. If throughput is critical, Isolation Forest is attractive.

### Q33. Why not compare the original Isolation Forest notebook metrics directly with the new comparison table?

**Answer:** They were produced under different protocols. The original notebook used a random stratified 70/15/15 split and chose the threshold on validation labels to maximise F1. The new study uses exact-duplicate-grouped folds and a benign-only calibration threshold. Its test rows are different. A difference in score can come from split, threshold policy and sample selection, not only model choice. We report the two studies separately.

### Q34. Why is the Random Forest result not included as an unsupervised winner?

**Answer:** Random Forest was trained with labelled attack and benign examples. The three primary models were trained on benign rows only. Random Forest therefore answers a different research question: how well can a supervised model perform when labelled attack examples are available? It is a separate reference, not a like-for-like unsupervised competitor.

### Q35. Why is Isolation Forest attractive even if it has lower F1?

**Answer:** At 50k benign training rows, the extended experiment recorded mean fitting time around 0.408 seconds and 15k-row test scoring around 0.103 seconds. At the same size, RBF One-Class SVM took around 17.39 seconds to fit and 2.08 seconds to score; LOF took around 14.82 seconds to fit and 4.44 seconds to score. These are runner-specific values, but they show the detection-quality/throughput trade-off. An IDS must meet latency and alert-volume requirements, not only maximise F1.

### Q36. What attack types did the unsupervised models miss?

**Answer:** Several low-support categories remained difficult. In the 50k pooled test output, all three unsupervised methods missed all sampled Bot, Web Brute Force and SQL Injection flows; One-Class SVM also missed the sampled FTP-Patator and SSH-Patator rows, while LOF detected some of those. These test supports are small—for example SQL Injection has only 3 sampled test rows—so we cannot make stable per-class claims. The detailed denominators are in `per_attack_pooled.csv`.

### Q37. Does a 5% test FPR mean the model is safe to deploy?

**Answer:** No. It is only the observed operating point on this benchmark test sample. A 5% FPR means roughly 50 false alerts per 1,000 benign flows at that operating point, which may be too high operationally. We need stricter-FPR testing, realistic traffic volume, temporal evaluation, and alert triage measurements before deployment.

---

## E. Data, graph and agentic investigation

### Q38. Why is CICIDS2017 suitable for this project?

**Answer:** It contains labelled benign traffic and multiple attack scenarios, with flow-level features suitable for tabular anomaly detection. Sharafaldin et al. (2018) describe the dataset generation and traffic characterization. We use it as a reproducible benchmark, while acknowledging it is a controlled dataset rather than a complete substitute for live enterprise traffic.

### Q39. What is the main limitation of CICIDS2017?

**Answer:** It is a fixed benchmark with class imbalance, repeated flow patterns and finite attack scenarios. It does not by itself prove generalisation to current production networks or novel attacks. Verkerken et al. show that intra-dataset performance can drop substantially in inter-dataset evaluation. We therefore need a second dataset or temporally separated metadata-rich traffic.

### Q40. How do you turn suspicious flows into attack events?

**Answer:** The current pipeline groups suspicious flows using available entity/context fields such as source, destination, protocol, attack label and time proximity. A 60-second grouping window is used for event construction. It then represents hosts, events, attack types and targets as graph nodes/relationships. Events are ordered in time and candidate `precedes` edges are added when the configured relationship conditions and maximum time gap are met.

### Q41. Does an edge called `precedes` prove that one attack caused another?

**Answer:** No. It records an observed temporal/relationship ordering under our rule set. It is evidence of correlation, not proof of causality. A real causal conclusion would require stronger contextual evidence, authentication/process/host telemetry, and validation of the relationship.

### Q42. How is our graph work related to AGCM?

**Answer:** AGCM provides research support for correlating abnormal flows as a graph and reconstructing multi-stage scenarios. Our current system uses explicit entity/time rules and a NetworkX graph. It does not implement AGCM's graph aggregation/clustering or weighted path-search algorithm. We should describe it as graph-based event correlation inspired by related research, not as an exact reproduction.

### Q43. What exactly does the agentic AI investigator do?

**Answer:** After events and the graph are available, the agent uses predefined tools to retrieve relevant event details, flow evidence, host history, temporal paths and graph context. It then produces an investigation narrative and recommended next steps based on those retrieved artefacts. It is an investigation layer, not the primary anomaly detector.

### Q44. How do you prevent the agent from hallucinating?

**Answer:** The intended control is tool-grounded evidence: the agent should retrieve event/graph data through predefined tools and each finding should cite or identify the supporting event/field. But a tool-grounded architecture alone does not prove correctness. We need an evaluation set with analyst-reviewed expected findings, evidence precision, unsupported-claim rate, tool-call accuracy, abstention behaviour and human review of high-impact recommendations.

### Q45. Does the literature prove that an agentic IDS is the gold standard?

**Answer:** No. The 2026 Lazer et al. survey describes opportunities and risks for agentic cybersecurity. Adabara et al. propose one policy-enforced IDS architecture and report its own benchmark and governance results. These are evidence that the area is being researched, not proof that every agentic design is best or that our system is production-ready. We must evaluate our own tool reliability, policy controls and evidence grounding.

---

## F. Study limitations and next steps

### Q46. What are the main limitations of your model comparison?

**Answer:** It uses one processed CICIDS2017 dataset, fixed model configurations, three training repetitions and a 15,000-row sampled test set. The test set is reused across seeds, so seed standard deviation measures training-sample/model variation, not independent test uncertainty. Exact duplicate vectors are grouped, but timestamp/five-tuple grouping is not possible with this cleaned feature set. Rare attack categories have small test support.

### Q47. What would you do next to strengthen the research?

**Answer:**
1. Run hyperparameter sensitivity for Isolation Forest tree count/max_samples, LOF neighbour count and One-Class SVM nu/gamma/kernel.
2. Test stricter operational FPR targets (1%, 0.5%, 0.1%).
3. Evaluate on metadata-rich temporal and connection-grouped splits.
4. Add Autoencoder/PCA as an additional unsupervised comparator with a fair normal-only training and threshold protocol.
5. Evaluate the correlation graph against labelled incident/attack-stage ground truth.
6. Evaluate the agent's evidence precision, unsupported claims, tool success and analyst review outcomes.
7. Validate on an independent dataset or later network capture.

### Q48. What is the honest final conclusion?

**Answer:** Isolation Forest was a research-supported and computationally sensible initial baseline. The comparison confirmed that model choice is metric- and resource-dependent: RBF One-Class SVM led on PR-AUC/F1 in our bounded paired CICIDS2017 study; LOF led on ROC-AUC at larger training sizes; Isolation Forest was much faster. We therefore retain Isolation Forest in the current application while treating One-Class SVM as the leading alternative for a shadow evaluation. We will change the deployed detector only after stricter-FPR, metadata-rich, temporally separated and incident-level validation.

---

## One-minute viva answer

"We initially selected Isolation Forest because the original research establishes it as an efficient isolation-based anomaly detector that can use subsampling and train without attack examples. The panel's question about alternatives was valid, so we added LOF and RBF One-Class SVM to compare three different anomaly-detection assumptions: isolation, local density and nonlinear support estimation. The choices are grounded in the original IF, LOF and One-Class SVM papers and in CICIDS2017-related comparative studies. In a paired 5k/25k/50k study with benign-only training, a shared benign calibration set and a shared held-out test set, One-Class SVM led on PR-AUC and F1, LOF led on ROC-AUC at larger sizes, and Isolation Forest was much faster. We therefore do not claim one universal winner. Isolation Forest remains our current detector, and One-Class SVM is the leading alternative for further operational validation."
