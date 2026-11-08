from __future__ import annotations

import argparse
import json
import time
import joblib
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from .event_builder import EventConfig, build_attack_events, normalize_columns
from .graph_builder import add_sequence_edges, build_attack_graph, write_attack_graph_gexf
from .incident_builder import build_potential_incidents


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


def clean_labels(df: pd.DataFrame, *, require_label: bool = False) -> pd.DataFrame:
    """Normalize metadata while allowing genuinely unlabeled inference traffic."""
    out = normalize_columns(df)
    if "label" not in out.columns:
        if require_label:
            raise ValueError("Benchmark training/evaluation requires a Label column.")
        return out
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
    # Preserve the declared numeric feature schema before partitioning.
    # Do not remove columns because they happen to be all-missing or constant
    # across the complete file: that would inspect held-out evaluation data.
    # SimpleImputer(keep_empty_features=True) handles columns that are empty
    # in the benign training partition without consulting calibration/test rows.
    x = x.replace([np.inf, -np.inf], np.nan)

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


def _benign_three_way_split(
    benign_positions: np.ndarray,
    hashes: np.ndarray,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Split benign duplicate groups into disjoint fit/calibration/test pools."""
    benign_groups = hashes[benign_positions]
    first = GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=seed)
    train_local, holdout_local = next(
        first.split(np.zeros(len(benign_positions)), groups=benign_groups)
    )
    train_positions = benign_positions[train_local]
    holdout_positions = benign_positions[holdout_local]

    second = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed + 1)
    calibration_local, test_local = next(
        second.split(
            np.zeros(len(holdout_positions)),
            groups=hashes[holdout_positions],
        )
    )
    calibration_positions = holdout_positions[calibration_local]
    test_positions = holdout_positions[test_local]

    sets = [
        set(hashes[positions].tolist())
        for positions in (train_positions, calibration_positions, test_positions)
    ]
    if (sets[0] & sets[1]) or (sets[0] & sets[2]) or (sets[1] & sets[2]):
        raise RuntimeError("Exact duplicate feature groups crossed a benign data split.")
    return train_positions, calibration_positions, test_positions


def _one_row_per_hash(positions: np.ndarray, hashes: np.ndarray) -> np.ndarray:
    if len(positions) == 0:
        return positions
    group_hashes = hashes[positions]
    _, first_indices = np.unique(group_hashes, return_index=True)
    return positions[np.sort(first_indices)]


def run(
    data_dir: str,
    output_dir: str,
    nrows: int = 0,
    benign_sample_n: int = 500_000,
    n_estimators: int = 200,
    calibration_quantile: float = 0.05,
    time_window_seconds: int = 60,
    max_sequence_gap_seconds: int = 300,
    calibration_rows: int = 5_000,
    evaluation_rows: int = 160_000,
) -> None:
    """Run held-out CICIDS2017 detection and graph construction.

    Data roles are disjoint:
      * model fitting: benign-only training groups;
      * threshold calibration: benign-only calibration groups;
      * evaluation/graph: held-out benign groups plus attack rows whose exact
        numeric feature hash does not occur in the fit/calibration partitions.

    Ground-truth labels are used for benign-pool construction and final
    evaluation only. They are never model features, anomaly predictions,
    event-group keys, graph attack-type predictions, or risk weights.
    """
    if benign_sample_n <= 0 or calibration_rows <= 0 or evaluation_rows <= 0:
        raise ValueError("Training, calibration and evaluation sample sizes must be positive.")
    if n_estimators <= 0:
        raise ValueError("n_estimators must be positive.")
    if not 0.0 < calibration_quantile < 0.5:
        raise ValueError("calibration_quantile must be between 0 and 0.5.")

    start_time = time.perf_counter()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    df = load_metadata_sample(Path(data_dir), nrows=nrows)
    work, x_raw, feature_columns = prepare_features(df)
    if "label" not in work.columns:
        raise ValueError(
            "Benchmark mode requires ground-truth Label for benign-only partitioning "
            "and held-out evaluation. Use --mode infer with a trained model artifact "
            "for unlabeled network traffic."
        )
    labels = work["label"].astype(str).str.strip()
    binary = labels.str.casefold().ne("benign").to_numpy(dtype=np.int8)
    benign_mask = binary == 0
    benign_positions = np.flatnonzero(benign_mask)
    if len(benign_positions) < 10:
        raise ValueError(
            f"Only {len(benign_positions)} benign flows found; "
            "at least 10 are required for a train/calibration/test split."
        )

    # Hash every numeric model vector without labels. Exact duplicate vectors
    # are assigned to one benign partition before model fitting or evaluation.
    hashes = pd.util.hash_pandas_object(x_raw, index=False).to_numpy(dtype=np.uint64)
    train_pool_positions, calibration_pool_positions, benign_test_positions = (
        _benign_three_way_split(benign_positions, hashes, seed=42)
    )

    # Train/calibration samples are deduplicated to avoid repeatedly weighting
    # identical flow vectors. The held-out evaluation keeps observed row counts.
    unique_train_pool = _one_row_per_hash(train_pool_positions, hashes)
    unique_calibration_pool = _one_row_per_hash(calibration_pool_positions, hashes)
    if len(unique_train_pool) < 2 or len(unique_calibration_pool) < 2:
        raise ValueError(
            "The benign duplicate-group split produced too few distinct rows "
            "for both model fitting and threshold calibration."
        )

    rng = np.random.default_rng(42)
    train_n = min(benign_sample_n, len(unique_train_pool))
    chosen_train_positions = np.sort(
        rng.choice(unique_train_pool, size=train_n, replace=False)
    )
    calibration_n = min(calibration_rows, len(unique_calibration_pool))
    chosen_calibration_positions = np.sort(
        rng.choice(unique_calibration_pool, size=calibration_n, replace=False)
    )

    fit_calibration_hashes = np.unique(np.concatenate([
        hashes[train_pool_positions],
        hashes[calibration_pool_positions],
    ]))
    attack_positions = np.flatnonzero(binary == 1)
    attack_hashes = hashes[attack_positions]

    overlaps_fit_or_calibration = np.isin(attack_hashes, fit_calibration_hashes)
    nonoverlap_attack_positions = attack_positions[~overlaps_fit_or_calibration]
    excluded_attack_duplicates = int(overlaps_fit_or_calibration.sum())

    # Do not put identical numeric feature vectors with contradictory benign
    # and attack labels into the same test sample. This is an ambiguous-label
    # data-quality case, not a detector error.
    benign_test_hashes = np.unique(hashes[benign_test_positions])
    overlaps_benign_test = np.isin(
        hashes[nonoverlap_attack_positions], benign_test_hashes
    )
    conflicting_test_attack_rows = int(overlaps_benign_test.sum())
    nonoverlap_attack_positions = nonoverlap_attack_positions[~overlaps_benign_test]

    evaluation_candidates = np.sort(np.concatenate([
        benign_test_positions,
        nonoverlap_attack_positions,
    ]))
    if len(evaluation_candidates) == 0:
        raise ValueError("No held-out evaluation rows remain after duplicate-group filtering.")
    if len(np.unique(binary[evaluation_candidates])) < 2:
        raise ValueError(
            "Held-out evaluation data must contain both benign and attack rows. "
            "Supply a larger or more representative metadata dataset."
        )

    evaluation_n = min(evaluation_rows, len(evaluation_candidates))
    if evaluation_n < len(evaluation_candidates):
        _, evaluation_local = train_test_split(
            evaluation_candidates,
            test_size=evaluation_n,
            random_state=42,
            stratify=binary[evaluation_candidates],
        )
        evaluation_positions = np.sort(evaluation_local)
    else:
        evaluation_positions = evaluation_candidates

    # Final explicit assertion: no exact feature vector crosses fit/calibration/evaluation.
    hash_sets = [
        set(hashes[chosen_train_positions].tolist()),
        set(hashes[chosen_calibration_positions].tolist()),
        set(hashes[evaluation_positions].tolist()),
    ]
    duplicate_overlap = sum(
        len(hash_sets[i] & hash_sets[j])
        for i in range(3) for j in range(i + 1, 3)
    )
    if duplicate_overlap:
        raise RuntimeError(
            f"Exact duplicate feature hashes cross fit/calibration/evaluation: {duplicate_overlap}"
        )

    # Imputation and the detector are fitted on the same benign training sample.
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    x_train = imputer.fit_transform(x_raw.iloc[chosen_train_positions])
    x_calibration = imputer.transform(x_raw.iloc[chosen_calibration_positions])
    x_evaluation = imputer.transform(x_raw.iloc[evaluation_positions])

    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=min(1024, len(chosen_train_positions)),
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
    calibration_score_quantiles = {
        str(q): float(np.quantile(calibration_scores, q))
        for q in (0.0, 0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99, 1.0)
    }

    model_artifact_path = output / "isolation_forest_model.joblib"
    joblib.dump({
        "artifact_version": 1,
        "model_name": "IsolationForest",
        "model": model,
        "imputer": imputer,
        "feature_columns": feature_columns,
        "threshold": threshold,
        "score_direction": "lower score is more anomalous",
        "calibration_score_quantiles": calibration_score_quantiles,
        "training_rows": int(len(chosen_train_positions)),
        "n_estimators": int(n_estimators),
        "max_samples": int(min(1024, len(chosen_train_positions))),
        "calibration_quantile": float(calibration_quantile),
        "threshold_source": "held_out_benign_only_calibration",
    }, model_artifact_path)

    score_started = time.perf_counter()
    evaluation_scores = model.score_samples(x_evaluation)
    scoring_seconds = time.perf_counter() - score_started
    evaluation_frame = work.iloc[evaluation_positions].copy()
    evaluation_frame["anomaly_score"] = evaluation_scores
    evaluation_frame["predicted_anomaly"] = evaluation_scores < threshold
    y_evaluation = binary[evaluation_positions]
    y_prediction = evaluation_frame["predicted_anomaly"].to_numpy(dtype=np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_evaluation, y_prediction, labels=[0, 1]
    ).ravel()
    detection_metrics = {
        "evaluation_rows": int(len(evaluation_positions)),
        "benign_evaluation_rows": int((y_evaluation == 0).sum()),
        "attack_evaluation_rows": int((y_evaluation == 1).sum()),
        "accuracy": float((tn + tp) / max(1, tn + fp + fn + tp)),
        "precision": float(precision_score(y_evaluation, y_prediction, zero_division=0)),
        "recall": float(recall_score(y_evaluation, y_prediction, zero_division=0)),
        "f1": float(f1_score(y_evaluation, y_prediction, zero_division=0)),
        "false_positive_rate": float(fp / max(1, tn + fp)),
        "false_negative_rate": float(fn / max(1, fn + tp)),
        "roc_auc": float(roc_auc_score(y_evaluation, -evaluation_scores)),
        "pr_auc_average_precision": float(average_precision_score(y_evaluation, -evaluation_scores)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "nominal_calibration_fpr": float(calibration_quantile),
        "measured_calibration_fpr": measured_calibration_fpr,
    }
    (output / "detection_metrics.json").write_text(
        json.dumps(detection_metrics, indent=2), encoding="utf-8"
    )

    # Per-attack recall is evaluation-only descriptive output, not a model input.
    per_attack = []
    evaluation_labels = labels.iloc[evaluation_positions].to_numpy()
    for attack_name in pd.unique(evaluation_labels):
        if str(attack_name).casefold() == "benign":
            continue
        mask = evaluation_labels == attack_name
        per_attack.append({
            "attack_type_ground_truth": str(attack_name),
            "test_support": int(mask.sum()),
            "detected": int(y_prediction[mask].sum()),
            "detection_recall": float(y_prediction[mask].mean()),
        })
    pd.DataFrame(per_attack).to_csv(
        output / "per_attack_detection_evaluation.csv", index=False
    )

    suspicious = evaluation_frame.loc[evaluation_frame["predicted_anomaly"]].copy()
    suspicious.to_csv(output / "suspicious_flows_with_metadata.csv", index=False)

    events = build_attack_events(
        suspicious,
        anomalous_only=True,
        config=EventConfig(time_window_seconds=time_window_seconds),
    )
    correlation_graph = build_attack_graph(events)
    correlation_graph = add_sequence_edges(
        correlation_graph, events, max_gap_seconds=max_sequence_gap_seconds
    )
    events, incidents = build_potential_incidents(events, correlation_graph)
    events.to_csv(output / "attack_events.csv", index=False)
    incidents.to_csv(output / "incident_groups.csv", index=False)

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
                selected = np.random.default_rng(42).choice(
                    list(graph.nodes()), max_png_nodes, replace=False
                )
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
    train_hashes = set(hashes[chosen_train_positions].tolist())
    calibration_hashes = set(hashes[chosen_calibration_positions].tolist())
    test_hashes = set(hashes[evaluation_positions].tolist())
    summary = {
        "pipeline_version": "2.1",
        "dataset_rows": int(len(df)),
        "feature_count": int(len(feature_columns)),
        "feature_columns": feature_columns,
        "label_distribution_for_evaluation_only": {
            str(k): int(v) for k, v in labels.value_counts().items()
        },
        "benign_train_pool_unique_rows": int(len(unique_train_pool)),
        "benign_training_rows_used": int(len(chosen_train_positions)),
        "benign_calibration_pool_unique_rows": int(len(unique_calibration_pool)),
        "benign_calibration_rows_used": int(len(chosen_calibration_positions)),
        "held_out_benign_test_pool_rows": int(len(benign_test_positions)),
        "attack_evaluation_rows_after_duplicate_purge": int(len(nonoverlap_attack_positions)),
        "attack_rows_excluded_for_fit_or_calibration_duplicate_hash": excluded_attack_duplicates,
        "attack_rows_excluded_for_conflicting_benign_test_hash": conflicting_test_attack_rows,
        "evaluation_rows": int(len(evaluation_positions)),
        "evaluation_metrics": detection_metrics,
        "exact_duplicate_overlap_fit_calibration_evaluation": int(duplicate_overlap),
        "threshold_source": "held_out_benign_only_calibration",
        "threshold_rule": f"lower {calibration_quantile:.1%} quantile of benign Isolation Forest score_samples",
        "isolation_forest_threshold": threshold,
        "model_artifact": str(model_artifact_path),
        "calibration_quantile": calibration_quantile,
        "calibration_score_quantiles": calibration_score_quantiles,
        "measured_calibration_fpr": measured_calibration_fpr,
        "score_direction": "lower score is more anomalous",
        "n_estimators": n_estimators,
        "max_samples": min(1024, len(chosen_train_positions)),
        "imputer": "median; fitted on selected benign training sample only",
        "fit_seconds": fit_seconds,
        "held_out_evaluation_scoring_seconds": scoring_seconds,
        "sampled_prefix_per_file": nrows if nrows > 0 else None,
        "suspicious_flows": int(len(suspicious)),
        "attack_events": int(len(events)),
        "potential_incidents": int(len(incidents)),
        "standalone_events": int(events["incident_id"].isna().sum()) if "incident_id" in events.columns else int(len(events)),
        "incident_confirmation_status": "potential_correlation_requires_analyst_validation",
        "graph_nodes": int(graph.number_of_nodes()),
        "graph_edges": int(graph.number_of_edges()),
        "sequence_edge_semantics": "strict non-overlapping shared-host temporal correlation; not causation",
        "time_window_seconds": time_window_seconds,
        "max_sequence_gap_seconds": max_sequence_gap_seconds,
        "gexf_written": bool(gexf_written),
        "png_status": png_status,
        "elapsed_seconds": round(elapsed, 2),
        "limitations": [
            "Labels are used to select benign fit/calibration pools and for final evaluation only. They are never numeric model features, predictions, event-group keys, graph classifications, or risk weights.",
            "The held-out evaluation set excludes attack rows whose exact numeric feature hash occurs in benign fit/calibration partitions and excludes same-test conflicting attack rows matching a benign test hash.",
            "Exact duplicate feature vectors are separated across fit/calibration/evaluation. This run does not establish cross-day or external-network generalisation.",
            "The cleaned and metadata-rich files may omit connection identifiers or timestamps depending on the source; this pipeline requires timestamp and source/destination metadata for event/graph stages.",
            "Attack type remains Unclassified unless a separate trained classifier supplies predicted_attack_type.",
            "Potential incidents are graph-connected candidate groups, not confirmed incidents. Temporal edges denote correlation/order, not causation.",
        ],
    }
    (output / "pipeline_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    print(json.dumps(summary, indent=2, default=str))


def run_inference(
    data_dir: str,
    model_artifact_path: str,
    output_dir: str,
    nrows: int = 0,
    time_window_seconds: int = 60,
    max_sequence_gap_seconds: int = 300,
) -> None:
    """Score unlabeled network-flow CSVs with a previously calibrated artifact.

    This path does not require or access ground-truth Label. The persisted
    imputer, feature order, detector and benign-calibrated threshold come from
    benchmark training. Only predicted anomaly flags drive event construction.
    Load joblib artifacts only from a trusted project environment.
    """
    start_time = time.perf_counter()
    artifact_path = Path(model_artifact_path)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Trained model artifact not found: {artifact_path}")

    artifact = joblib.load(artifact_path)
    required_artifact = {
        "artifact_version", "model_name", "model", "imputer",
        "feature_columns", "threshold", "calibration_score_quantiles",
    }
    if not isinstance(artifact, dict) or not required_artifact.issubset(artifact):
        raise ValueError("Model artifact is incomplete or has an unsupported format.")
    if artifact["artifact_version"] != 1 or artifact["model_name"] != "IsolationForest":
        raise ValueError("Unsupported model artifact version or detector.")

    df = load_metadata_sample(Path(data_dir), nrows=nrows)
    work, x_raw, _ = prepare_features(
        df, feature_columns=list(artifact["feature_columns"])
    )
    if "label" in work.columns:
        # Ground-truth labels are deliberately excluded from inference outputs.
        work = work.drop(columns=["label"])
    x_transformed = artifact["imputer"].transform(x_raw)
    model = artifact["model"]
    score_started = time.perf_counter()
    scores = model.score_samples(x_transformed)
    scoring_seconds = time.perf_counter() - score_started
    threshold = float(artifact["threshold"])
    work["anomaly_score"] = scores
    work["predicted_anomaly"] = scores < threshold

    suspicious = work.loc[work["predicted_anomaly"]].copy()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    suspicious.to_csv(output / "suspicious_flows_with_metadata.csv", index=False)

    events = build_attack_events(
        suspicious,
        anomalous_only=True,
        config=EventConfig(time_window_seconds=time_window_seconds),
    )
    correlation_graph = build_attack_graph(events)
    correlation_graph = add_sequence_edges(
        correlation_graph, events, max_gap_seconds=max_sequence_gap_seconds
    )
    events, incidents = build_potential_incidents(events, correlation_graph)
    events.to_csv(output / "attack_events.csv", index=False)
    incidents.to_csv(output / "incident_groups.csv", index=False)

    graph = build_attack_graph(events)
    graph = add_sequence_edges(graph, events, max_gap_seconds=max_sequence_gap_seconds)
    write_attack_graph_gexf(graph, str(output / "attack_graph.gexf"))

    summary = {
        "pipeline_version": "2.2-inference",
        "mode": "unlabeled_inference",
        "dataset_rows": int(len(work)),
        "feature_count": int(len(artifact["feature_columns"])),
        "feature_columns": list(artifact["feature_columns"]),
        "ground_truth_labels_required": False,
        "ground_truth_labels_used": False,
        "model_name": artifact["model_name"],
        "model_artifact": str(artifact_path),
        "threshold_source": artifact.get("threshold_source", "benign_calibration_in_model_artifact"),
        "isolation_forest_threshold": threshold,
        "calibration_score_quantiles": artifact["calibration_score_quantiles"],
        "score_direction": artifact.get("score_direction", "lower score is more anomalous"),
        "suspicious_flows": int(len(suspicious)),
        "attack_events": int(len(events)),
        "potential_incidents": int(len(incidents)),
        "standalone_events": int(events["incident_id"].isna().sum()) if "incident_id" in events.columns else int(len(events)),
        "graph_nodes": int(graph.number_of_nodes()),
        "graph_edges": int(graph.number_of_edges()),
        "sequence_edge_semantics": "shared-host temporal correlation; not causation",
        "time_window_seconds": time_window_seconds,
        "max_sequence_gap_seconds": max_sequence_gap_seconds,
        "scoring_seconds": scoring_seconds,
        "elapsed_seconds": round(time.perf_counter() - start_time, 2),
        "limitations": [
            "No ground-truth labels were required or used for flow scoring, suspicious-flow selection, event grouping or graph construction.",
            "Attack type remains Unclassified unless a separately trained classifier supplies predicted_attack_type.",
            "Potential incidents are graph-based candidate correlations requiring analyst validation, not confirmed campaigns or causal chains.",
            "The feature schema and threshold must match the environment/data source for which the model artifact was validated.",
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
    parser.add_argument("data_dir", help="Folder containing metadata-rich flow CSV files")
    parser.add_argument("--mode", choices=["benchmark", "infer"], default="benchmark")
    parser.add_argument("--model-artifact", default="outputs/isolation_forest_model.joblib",
                        help="Trusted Isolation Forest artifact required for --mode infer")
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
    parser.add_argument("--calibration-rows", type=int, default=5_000)
    parser.add_argument("--evaluation-rows", type=int, default=160_000)
    args = parser.parse_args()
    if args.mode == "benchmark":
        run(
            args.data_dir,
            args.output_dir,
            args.nrows,
            args.benign_sample_n,
            args.n_estimators,
            args.calibration_quantile,
            args.time_window_seconds,
            args.max_sequence_gap_seconds,
            args.calibration_rows,
            args.evaluation_rows,
        )
    else:
        run_inference(
            args.data_dir,
            args.model_artifact,
            args.output_dir,
            args.nrows,
            args.time_window_seconds,
            args.max_sequence_gap_seconds,
        )
