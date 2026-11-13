from __future__ import annotations

from pathlib import Path

import pandas as pd


DISTRIBUTION_COLUMNS = ["Attack Type", "Flows"]
TRAFFIC_SUMMARY_COLUMNS = ["Metric", "Flows"]


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



def build_traffic_counts(labels_df: pd.DataFrame | None) -> dict[str, int] | None:
    """Count benign and attack rows from cleaned ground-truth labels."""
    if labels_df is None or "Label" not in labels_df.columns:
        return None

    labels = labels_df["Label"].astype("string").str.strip().dropna()
    labels = labels[labels.ne("")]
    if labels.empty:
        return None

    benign_mask = labels.str.casefold().eq("benign")
    total_flows = int(len(labels))
    benign_flows = int(benign_mask.sum())
    return {
        "total_flows": total_flows,
        "benign_flows": benign_flows,
        "attack_flows": total_flows - benign_flows,
    }


def build_reference_traffic_counts(
    attack_distribution: pd.DataFrame | None,
    total_flows: int,
) -> dict[str, int] | None:
    """Derive a full-dataset traffic profile from verified attack counts.

    The reference attack CSV contains the 14 non-benign classes. The total
    cleaned row count is recorded from the preprocessing notebook. Benign
    rows are derived as total rows minus the sum of the attack classes.
    """
    if (
        attack_distribution is None
        or attack_distribution.empty
        or not {"Attack Type", "Flows"}.issubset(attack_distribution.columns)
    ):
        return None

    try:
        total = int(total_flows)
    except (TypeError, ValueError, OverflowError):
        return None
    if total <= 0 or total != total_flows:
        return None

    names = attack_distribution["Attack Type"].astype("string").str.strip()
    values = pd.to_numeric(attack_distribution["Flows"], errors="coerce")
    valid = (
        names.notna()
        & names.ne("")
        & ~names.str.casefold().eq("benign")
        & values.notna()
        & values.ge(0)
        & values.eq(values.round())
    )
    if not bool(valid.all()):
        return None

    attacks = int(values.sum())
    if attacks <= 0 or attacks > total:
        return None

    return {
        "total_flows": total,
        "benign_flows": total - attacks,
        "attack_flows": attacks,
    }


def load_reference_traffic_summary(path: str | Path) -> dict[str, int] | None:
    """Load verified dataset-level CICIDS2017 traffic totals.

    These counts describe the cleaned, labelled reference dataset. They are
    not current inference-batch counts or model predictions.
    """
    source = Path(path)
    if not source.is_file():
        return None

    frame = pd.read_csv(source)
    if not set(TRAFFIC_SUMMARY_COLUMNS).issubset(frame.columns):
        raise ValueError(
            "Reference traffic summary must contain Metric and Flows columns."
        )

    metrics = frame["Metric"].astype("string").str.strip()
    counts = pd.to_numeric(frame["Flows"], errors="coerce")
    valid = (
        metrics.notna()
        & metrics.ne("")
        & counts.notna()
        & counts.ge(0)
    )
    cleaned = pd.DataFrame(
        {
            "Metric": metrics.loc[valid],
            "Flows": counts.loc[valid].astype("int64"),
        }
    )
    summary = dict(zip(cleaned["Metric"], cleaned["Flows"]))
    required = {"Total Flows", "Benign Flows", "Attack Flows"}
    if not required.issubset(summary):
        raise ValueError(
            "Reference traffic summary is missing required CICIDS2017 totals."
        )

    result = {key: int(summary[key]) for key in required}
    if result["Total Flows"] != result["Benign Flows"] + result["Attack Flows"]:
        raise ValueError(
            "Reference traffic summary is inconsistent: total must equal benign plus attack flows."
        )
    return result
