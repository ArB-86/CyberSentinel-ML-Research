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

## Dashboard attack-distribution reference

The dashboard includes a small, checked-in reference table at
`research/cicids2017_attack_distribution.csv`. Its 14 attack-family counts
are taken from the final cleaned-data label-count output in
`notebooks/dataset_preprocessing.ipynb` (after duplicate removal), and sum to
336,299 attack rows. The dashboard prefers the local Parquet labels when that
file is available; otherwise it displays this static CICIDS2017 dataset profile.
The reference is not a live inference result and must not be interpreted as
predictions from an unlabeled traffic batch.
