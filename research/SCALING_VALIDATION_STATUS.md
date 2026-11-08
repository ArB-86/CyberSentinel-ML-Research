# Extended validation status

**Status: running**

The paired larger-sample CICIDS2017 validation is running in GitHub Actions:

[View validation run](https://github.com/ArB-86/CyberSentinel-ML-Research/actions/runs/42521225029)

## Configurations

- Detectors: Isolation Forest, LOF (novelty mode), exact RBF One-Class SVM.
- Benign training sizes: 5,000; 25,000; 50,000.
- Repetition seeds: 42, 43, 44.
- One fixed duplicate-grouped train/validation/test split.
- One fixed benign-only calibration sample of 5,000 rows.
- One fixed shared test sample of 15,000 rows.
- The training subsets are nested within each repetition seed.

The dataset download, SHA-256 verification and dependency installation have passed. The model-training/evaluation step is currently running.

No extended-validation metric is reported until the workflow finishes and the output files are committed. See [SCALING_VALIDATION_PROTOCOL.md](SCALING_VALIDATION_PROTOCOL.md) for the design and interpretation rules.
