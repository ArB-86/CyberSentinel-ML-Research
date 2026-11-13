from __future__ import annotations

from pathlib import Path

import pandas as pd


DISTRIBUTION_COLUMNS = ["Attack Type", "Flows"]


def build_attack_distribution(labels_df: pd.DataFrame | None) -> pd.DataFrame:
    """Build an attack-family distribution from a dataframe's ground-truth labels."""
    if labels_df is None or "Label" not in labels_df.columns:
        return pd.DataFrame(columns=DISTRIBUTION_COLUMNS)

    labels = labels_df["Label"].astype("string").str.strip().dropna()
    labels = labels[labels.ne("")]
    attack_labels = labels[~labels.str.casefold().eq("benign")]

    if attack_labels.empty:
        return pd.DataFrame(columns=DISTRIBUTION_COLUMNS)

    return (
        attack_labels.value_counts()
        .rename_axis("Attack Type")
        .reset_index(name="Flows")
    )


def load_reference_attack_distribution(path: str | Path) -> pd.DataFrame:
    """Load the checked-in CICIDS2017 reference counts when the Parquet is absent.

    The reference CSV is derived from the repository's preprocessing notebook,
    after row de-duplication and final dataset cleaning. It is a static dataset
    profile, never a prediction or a count from the current inference batch.
    """
    source = Path(path)
    if not source.is_file():
        return pd.DataFrame(columns=DISTRIBUTION_COLUMNS)

    frame = pd.read_csv(source)
    if not set(DISTRIBUTION_COLUMNS).issubset(frame.columns):
        raise ValueError(
            "Reference attack distribution must contain Attack Type and Flows columns."
        )

    names = frame["Attack Type"].astype("string").str.strip()
    counts = pd.to_numeric(frame["Flows"], errors="coerce")
    valid = (
        names.notna()
        & names.ne("")
        & ~names.str.casefold().eq("benign")
        & counts.notna()
        & counts.ge(0)
    )
    cleaned = pd.DataFrame(
        {
            "Attack Type": names.loc[valid],
            "Flows": counts.loc[valid].astype("int64"),
        }
    )
    if cleaned.empty:
        return pd.DataFrame(columns=DISTRIBUTION_COLUMNS)

    return (
        cleaned.groupby("Attack Type", as_index=False)["Flows"]
        .sum()
        .sort_values("Flows", ascending=False)
        .reset_index(drop=True)
    )
