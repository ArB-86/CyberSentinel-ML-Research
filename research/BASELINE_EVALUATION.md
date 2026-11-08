# Audit of the original Isolation Forest evidence

## What the repository already contains

The original `notebooks/isolation_forest.ipynb` does more than a single model fit: it compares several **Isolation Forest configurations** (tree count and max_samples) and evaluates one final model on a held-out test partition. It does **not** train and compare distinct anomaly-detection algorithms such as LOF or One-Class SVM. That is the gap the research branch addresses.

The notebook reports:

| Item | Existing configuration |
|---|---|
| Dataset | CICIDS2017 processed Parquet |
| Rows | 2,228,970 |
| Numeric flow features | 69 |
| Binary distribution | 1,892,671 benign (84.91%); 336,299 attacks (15.09%) |
| Split | Random stratified 70% train / 15% validation / 15% test |
| Model-fit data | Benign rows only |
| Benign training sample | 500,000 |
| Isolation Forest | 200 estimators; max_samples=1,024; max_features=1.0; random_state=42 |
| Threshold | 0.032042 on the notebook's decision_function score convention |

## Recorded held-out test results

| Metric | Value |
|---|---:|
| Accuracy | 0.8966 |
| ROC-AUC | 0.8862 |
| PR-AUC / Average Precision | 0.6801 |
| Attack precision | 0.6386 |
| Attack recall | 0.7250 |
| Attack F1 | 0.6791 |
| False-positive rate | 0.0729 |
| False-negative rate | 0.2750 |

These values are **existing notebook outputs**, not new experiments from this branch. Do not describe them as results produced by the new comparison harness.

## Important methodological qualifications

1. **No cross-algorithm comparison exists in the original notebook.** Its experiment table changes Isolation Forest hyperparameters only.
2. **The original split is row-wise random.** Identical feature vectors or related network connections may be split across training and test partitions. A recent 2026 CIC-IDS2017 study has documented material duplicate overlap under a record-level split on its own dataset snapshot. This is a risk to test for, not proof of the exact leakage rate in this Parquet.
3. **Threshold selection is label-informed.** The notebook searches validation thresholds and selects the one maximizing attack F1, using validation attack labels. This is legitimate for a labelled validation/model-selection protocol, but should not be called a fully label-free operational threshold. The research harness instead calibrates on held-out benign observations only.
4. **Binary metrics hide minority attack failures.** The notebook itself shows major variation by attack category. Classes represented by only a handful of records cannot support confident generalisation claims.
5. **A separate attack-graph prototype is not the same benchmark.** `attack_graph/if_attack_graph_pipeline.py` reads metadata-rich CSVs, uses a reduced prototype configuration, and calibrates its own threshold. Its feature space and score distribution differ from the 69-feature notebook. The notebook threshold must not be reused in that prototype.
6. **The repository has large external artifacts.** Dataset assets are distributed through upstream Releases and several output files are Git LFS pointers. The source tree snapshot alone does not contain the dataset or LFS binary payloads; see [DATASET_SOURCES.md](../DATASET_SOURCES.md).

## Correct viva statement

"The initial project selected Isolation Forest and compared some of its hyperparameters. It did not establish superiority over other anomaly-detection algorithms. We identified that as a limitation and created a separate, reproducible comparison with LOF and One-Class SVM under a common benign-only training protocol, plus Random Forest as a clearly separated supervised reference. We report the historical Isolation Forest result separately because its random split and label-informed threshold-selection protocol differ from the new duplicate-grouped, benign-calibrated protocol."
