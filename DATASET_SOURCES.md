# Dataset and reproducibility

## CICIDS2017

The primary dataset is CICIDS2017, published by the Canadian Institute for Cybersecurity at the University of New Brunswick.

- Official dataset page: https://www.unb.ca/cic/datasets/ids-2017.html
- Dataset paper: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018), "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP. DOI: https://doi.org/10.5220/0006639801080116

CICIDS2017 contains benign traffic and multiple attack families captured in a controlled network environment. The processed flow dataset used in the experiments contains 2,228,970 records, 69 numeric modelling features and a label column.

## Processed experiment dataset

The model-comparison runs used the following processed Parquet artifact:

- Filename: `cleaned_cicids2017.parquet`
- Format: Apache Parquet
- Size: 257,156,788 bytes
- SHA-256: `9401495356b1b6f360d6aebf0ad7ddc18a39cbf02c02f7461338dea02a747146`

Store this file locally at `data/cleaned_cicids2017.parquet`. It is not committed to Git because it is a large dataset asset. Verify the checksum before running experiments.

The preprocessing notebook is [`notebooks/dataset_preprocessing.ipynb`](notebooks/dataset_preprocessing.ipynb). The model comparison harness and exact command are documented in [`experiments/README.md`](experiments/README.md).

## Data handling

- Keep raw and processed datasets outside the Git source tree.
- Do not include live credentials, personally identifying traffic metadata, or access tokens in committed files.
- Preserve the original CICIDS2017 labels for evaluation, while excluding labels from the unsupervised feature matrix.
- Record preprocessing steps, feature selection, dataset version and checksum with each experiment.

## Dashboard reference counts

The dashboard includes two small, checked-in CICIDS2017 reference files:

- `research/cicids2017_attack_distribution.csv`: counts for all 14 non-benign attack families, derived from the final cleaned label counts in `notebooks/dataset_preprocessing.ipynb`.
- `research/cicids2017_traffic_summary.csv`: aggregate counts from the same cleaned dataset — **2,228,970 total flows**, **1,892,671 benign**, and **336,299 attack**.

When the local Parquet is absent, the dashboard cross-checks the sum of the 14 attack-family counts against the aggregate attack total before using the reference figures for its KPI cards and benign-versus-attack pie chart. These are full-dataset ground-truth statistics, not benchmark holdout results, current inference-batch counts, model predictions, or live detections.
