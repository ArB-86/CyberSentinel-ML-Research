from __future__ import annotations

import pandas as pd


def build_attack_distribution(labels_df: pd.DataFrame | None) -> pd.DataFrame:
    """Build the CICIDS2017 dataset-level attack distribution from ground-truth labels.

    This is intentionally independent of the current pipeline mode: an
    unlabeled inference run must not suppress the static labelled-dataset
    profile. Missing and blank labels are excluded, and BENIGN is matched
    case-insensitively.
    """
    columns = ["Attack Type", "Flows"]
    if labels_df is None or "Label" not in labels_df.columns:
        return pd.DataFrame(columns=columns)

    labels = labels_df["Label"].astype("string").str.strip().dropna()
    labels = labels[labels.ne("")]
    attack_labels = labels[~labels.str.casefold().eq("benign")]

    if attack_labels.empty:
        return pd.DataFrame(columns=columns)

    return (
        attack_labels.value_counts()
        .rename_axis("Attack Type")
        .reset_index(name="Flows")
    )
