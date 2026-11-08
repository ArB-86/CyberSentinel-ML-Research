from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupShuffleSplit

from .event_builder import EventConfig, build_attack_events, normalize_columns
from .graph_builder import add_sequence_edges, build_attack_graph, write_attack_graph_gexf


LABEL_MAP = {
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 XSS": "Web Attack - XSS",
    "Web Attack \x96 Sql Injection": "Web Attack - SQL Injection",
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack � Sql Injection": "Web Attack - SQL Injection",
}

# Identifiers/targets are not model features. Numeric source/destination ports
# and protocol remain available as flow features, matching CICIDS feature data.
NON_FEATURE_COLUMNS = {
    "flow id", "flow_id", "src_ip", "dst_ip", "source ip", "destination ip",
    "timestamp", "label", "is_attack", "predicted_anomaly",
    "predicted_attack_type", "anomaly_score", "attack_type",
}


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    out = normalize_columns(df)
    if "label" not in out.columns:
        raise ValueError("Metadata-rich CICIDS files must contain a Label column.")
    out["label"] = out["label"].astype(str).str.strip().replace(LABEL_MAP)
    return out


def prepare_features(
    df: pd.DataFrame,
    feature_columns: list[str] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Return raw numeric features with NaN preserved for train-only imputation."""
    work = clean_labels(df)
    drop = [c for c in work.columns if str(c).strip().casefold() in NON_FEATURE_COLUMNS]
    raw = work.drop(columns=drop, errors="ignore")
    x = raw.select_dtypes(include=np.number).copy()
    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.dropna(axis=1, how="all")
    x = x.loc[:, x.nunique(dropna=True) > 1]

    if feature_columns is None:
        feature_columns = x.columns.tolist()
    missing = [c for c in feature_columns if c not in x.columns]
    if missing:
        raise ValueError(f"Missing numeric model features: {missing}")
    x = x.reindex(columns=feature_columns)
    if x.empty or not feature_columns:
        raise ValueError("No usable numeric model features remain.")
    return work, x, feature_columns


def load_metadata_sample(data_dir: Path, nrows: int = 0) -> pd.DataFrame:
    """Load all metadata-rich CSV rows by default.

    A positive nrows value is an explicitly partial, per-file prefix read for
    quick smoke tests only. Do not use prefix-limited reads for temporal or
    incident-level evaluation because they can bias the time distribution.
    """
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    if nrows < 0:
        raise ValueError("nrows must be zero (all rows) or a positive per-file cap.")

    frames = []
    for path in files:
        print(f"Loading: {path.name}")
        frame = pd.read_csv(
            path,
            nrows=None if nrows == 0 else nrows,
            low_memory=False,
            encoding="latin1",
        )
        frames.append(clean_labels(frame))
    combined = pd.concat(frames, ignore_index=True)
    if combined.empty:
        raise ValueError(f"No flow rows were loaded from {data_dir}.")
    return combined


def _benign_train_validation_indices(
    x_benign: pd.DataFrame,
    validation_fraction: float = 0.2,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Group exact duplicate feature rows before separating fit/calibration data."""
    if not 0.05 <= validation_fraction <= 0.5:
        raise ValueError("validation_fraction must be between 0.05 and 0.5.")
    groups = pd.util.hash_pandas_object(x_benign, index=False).to_numpy(dtype=np.uint64)
    splitter = GroupShuffleSplit(
        n_splits=1, test_size=validation_fraction, random_state=random_state
    )
    train_idx, validation_idx = next(
        splitter.split(np.zeros(len(x_benign)), groups=groups)
    )
    overlap = np.intersect1d(
        np.unique(groups[train_idx]), np.unique(groups[validation_idx])
    )
    if overlap.size:
        raise RuntimeError("Exact duplicate benign feature rows crossed the calibration split.")
    return train_idx, validation_idx


def run(
    data_dir: str,
    output_dir: str,
    nrows: int = 0,
    benign_sample_n: int = 500_000,
    n_estimators: int = 200,
    calibration_quantile: float = 0.05,
    time_window_seconds: int = 60,
    max_sequence_gap_seconds: int = 300,
) -> None:
    """Run the metadata-rich detection, event-correlation and graph pipeline.

    The Isolation Forest threshold is fitted independently for this metadata-
    rich feature space using a held-out benign calibration partition. It must
    not be replaced with a threshold from the separate 69-feature notebook.
    """
    if benign_sample_n <= 0:
        raise ValueError("benign_sample_n must be positive.")
    if n_estimators <= 0:
        raise ValueError("n_estimators must be positive.")
    if not 0.0 < calibration_quantile < 0.5:
        raise ValueError("calibration_quantile must be between 0 and 0.5.")

    start_time = time.perf_counter()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    df = load_metadata_sample(Path(data_dir), nrows=nrows)
    work, x_raw, feature_columns = prepare_features(df)
    labels = work["label"].astype(str).str.strip()
    benign_mask = labels.str.casefold().eq("benign").to_numpy()
    benign_positions = np.flatnonzero(benign_mask)
    if len(benign_positions) < 100:
        raise ValueError(
            f"Only {len(benign_positions)} benign flows found; "
            "at least 100 are required for a train/calibration split."
        )

    x_benign_raw = x_raw.iloc[benign_positions].reset_index(drop=True)
    train_local, calibration_local = _benign_train_validation_indices(x_benign_raw)
    train_positions = benign_positions[train_local]
    calibration_positions = benign_positions[calibration_local]

    # Fit imputation ONLY on benign training data. Calibration and all inference
    # rows are transformed using these learned medians; no validation/test
    # statistics are allowed to influence preprocessing.
    imputer = SimpleImputer(strategy="median")
    x_train_pool = imputer.fit_transform(x_raw.iloc[train_positions])
    x_all = imputer.transform(x_raw)
    x_train_pool = np.asarray(x_train_pool, dtype=np.float64)
    x_all = np.asarray(x_all, dtype=np.float64)

    rng = np.random.default_rng(42)
    sample_n = min(int(benign_sample_n), len(train_positions))
    chosen_local = rng.choice(len(train_positions), size=sample_n, replace=False)
    x_train = x_train_pool[chosen_local]
    x_calibration = x_all[calibration_positions]

    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=min(1024, len(x_train)),
        max_features=1.0,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    fit_started = time.perf_counter()
    model.fit(x_train)
    fit_seconds = time.perf_counter() - fit_started

    calibration_scores = model.score_samples(x_calibration)
    threshold = float(np.quantile(calibration_scores, calibration_quantile))
    measured_calibration_fpr = float(np.mean(calibration_scores < threshold))

    score_started = time.perf_counter()
    scores = model.score_samples(x_all)
    scoring_seconds = time.perf_counter() - score_started
    df["anomaly_score"] = scores
    df["predicted_anomaly"] = scores < threshold

    suspicious = df.loc[df["predicted_anomaly"]].copy()
    suspicious.to_csv(output / "suspicious_flows_with_metadata.csv", index=False)

    events = build_attack_events(
        suspicious,
        anomalous_only=True,
        config=EventConfig(time_window_seconds=time_window_seconds),
    )
    events.to_csv(output / "attack_events.csv", index=False)

    graph = build_attack_graph(events)
    graph = add_sequence_edges(
        graph, events, max_gap_seconds=max_sequence_gap_seconds
    )
    gexf_path = output / "attack_graph.gexf"
    write_attack_graph_gexf(graph, str(gexf_path))
    gexf_written = gexf_path.exists() and gexf_path.stat().st_size > 0

    # A graph with tens of thousands of nodes cannot be usefully represented by
    # a single spring-layout plot. Draw a deterministic subgraph for inspection;
    # the full graph remains in GEXF.
    max_png_nodes = 800
    node_count = graph.number_of_nodes()
    png_status = "skipped_empty_graph"
    if node_count:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            if node_count > max_png_nodes:
                rng = np.random.default_rng(42)
                selected = rng.choice(list(graph.nodes()), max_png_nodes, replace=False)
                visual_graph = graph.subgraph(selected).copy()
                png_status = f"deterministic_sample_{max_png_nodes}_of_{node_count}"
            else:
                visual_graph = graph
                png_status = "full_graph"

            positions = nx.spring_layout(visual_graph, seed=42)
            fig, ax = plt.subplots(figsize=(12, 8))
            nx.draw_networkx(
                visual_graph, positions, node_size=70,
                with_labels=False, arrows=True, alpha=0.6, ax=ax
            )
            ax.set_title(f"Attack graph ({png_status})")
            ax.axis("off")
            fig.tight_layout()
            fig.savefig(output / "attack_graph.png", dpi=160)
            plt.close(fig)
        except ImportError:
            png_status = "matplotlib_unavailable"

    elapsed = time.perf_counter() - start_time
    unique_groups = int(pd.util.hash_pandas_object(x_benign_raw, index=False).nunique())
    summary = {
        "pipeline_version": "2.0",
        "dataset_rows": int(len(df)),
        "feature_count": int(len(feature_columns)),
        "feature_columns": feature_columns,
        "label_distribution_for_evaluation_only": {
            str(k): int(v) for k, v in labels.value_counts().items()
        },
        "training_rows_available": int(len(train_positions)),
        "benign_training_rows_used": int(len(x_train)),
        "benign_calibration_rows": int(len(calibration_positions)),
        "benign_exact_duplicate_groups": unique_groups,
        "exact_duplicate_overlap_train_calibration": 0,
        "threshold_source": "held_out_benign_only_calibration",
        "threshold_rule": f"lower {calibration_quantile:.1%} quantile of benign Isolation Forest score_samples",
        "isolation_forest_threshold": threshold,
        "calibration_quantile": calibration_quantile,
        "measured_calibration_fpr": measured_calibration_fpr,
        "score_direction": "lower score is more anomalous",
        "n_estimators": n_estimators,
        "max_samples": min(1024, len(x_train)),
        "imputer": "median; fitted on benign training partition only",
        "fit_seconds": fit_seconds,
        "all_flow_scoring_seconds": scoring_seconds,
        "sampled_prefix_per_file": nrows if nrows > 0 else None,
        "suspicious_flows": int(len(suspicious)),
        "attack_events": int(len(events)),
        "graph_nodes": int(graph.number_of_nodes()),
        "graph_edges": int(graph.number_of_edges()),
        "sequence_edge_semantics": "chronological shared-host correlation; not causation",
        "time_window_seconds": time_window_seconds,
        "max_sequence_gap_seconds": max_sequence_gap_seconds,
        "gexf_written": bool(gexf_written),
        "png_status": png_status,
        "elapsed_seconds": round(elapsed, 2),
        "limitations": [
            "CICIDS ground-truth labels are used only for descriptive evaluation counts; they are not used for model fitting, thresholding, flow selection, event grouping, or attack-type prediction.",
            "Exact duplicate feature vectors are separated between benign fitting and calibration; this run does not establish cross-day or external-network generalisation.",
            "Attack type remains Unclassified unless a separate trained classifier supplies predicted_attack_type.",
            "Temporal graph edges denote observed correlation/order, not causal proof.",
        ],
    }
    (output / "pipeline_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run benign-only anomaly detection and label-independent attack graph construction."
    )
    parser.add_argument("data_dir", help="Folder containing metadata-rich CICIDS2017 CSV files")
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument(
        "--nrows", type=int, default=0,
        help="Default 0 reads every row. Positive value is a per-file prefix cap for smoke tests only."
    )
    parser.add_argument("--benign-sample-n", type=int, default=500_000)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--calibration-quantile", type=float, default=0.05)
    parser.add_argument("--time-window-seconds", type=int, default=60)
    parser.add_argument("--max-sequence-gap-seconds", type=int, default=300)
    args = parser.parse_args()
    run(
        args.data_dir,
        args.output_dir,
        args.nrows,
        args.benign_sample_n,
        args.n_estimators,
        args.calibration_quantile,
        args.time_window_seconds,
        args.max_sequence_gap_seconds,
    )
