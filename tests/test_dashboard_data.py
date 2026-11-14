from pathlib import Path

import pandas as pd

from utils.dashboard_data import (
    build_attack_distribution,
    build_reference_traffic_counts,
    build_traffic_counts,
    load_reference_attack_distribution,
    load_reference_traffic_summary,
)


def test_build_attack_distribution_excludes_benign_and_missing_labels():
    frame = pd.DataFrame(
        {
            "Label": [
                "BENIGN",
                "DoS Hulk",
                "Bot",
                " benign ",
                None,
                "",
                "   ",
                "DoS Hulk",
            ]
        }
    )

    result = build_attack_distribution(frame)

    assert result.set_index("Attack Type")["Flows"].to_dict() == {
        "DoS Hulk": 2,
        "Bot": 1,
    }


def test_build_attack_distribution_returns_empty_for_missing_label_column():
    result = build_attack_distribution(pd.DataFrame({"Flow ID": ["a", "b"]}))

    assert list(result.columns) == ["Attack Type", "Flows"]
    assert result.empty


def test_build_attack_distribution_returns_empty_when_dataset_has_no_attacks():
    result = build_attack_distribution(pd.DataFrame({"Label": ["BENIGN", " benign "]}))

    assert list(result.columns) == ["Attack Type", "Flows"]
    assert result.empty


def test_reference_attack_distribution_contains_all_verified_cicids_classes():
    path = (
        Path(__file__).resolve().parents[1]
        / "research"
        / "cicids2017_attack_distribution.csv"
    )

    result = load_reference_attack_distribution(path)

    assert len(result) == 14
    assert int(result["Flows"].sum()) == 336_299
    assert result.iloc[0]["Attack Type"] == "DoS Hulk"
    assert int(result.iloc[0]["Flows"]) == 172_688


def test_reference_attack_distribution_excludes_invalid_rows(tmp_path):
    path = tmp_path / "distribution.csv"
    pd.DataFrame(
        {
            "Attack Type": ["BENIGN", "DoS", " ", "Bot", "XSS"],
            "Flows": [100, 12, 4, "bad", -1],
        }
    ).to_csv(path, index=False)

    result = load_reference_attack_distribution(path)

    assert result.to_dict("records") == [{"Attack Type": "DoS", "Flows": 12}]



def test_build_traffic_counts_from_local_ground_truth_labels():
    frame = pd.DataFrame(
        {"Label": ["BENIGN", "DoS Hulk", "Bot", " benign ", None, "", "  "]}
    )

    assert build_traffic_counts(frame) == {
        "total_flows": 4,
        "benign_flows": 2,
        "attack_flows": 2,
    }


def test_build_traffic_counts_returns_none_without_valid_labels():
    assert build_traffic_counts(None) is None
    assert build_traffic_counts(pd.DataFrame({"Flow ID": ["a"]})) is None
    assert build_traffic_counts(pd.DataFrame({"Label": [None, "", " "]})) is None


def test_build_reference_traffic_counts_derives_benign_rows():
    attacks = pd.DataFrame(
        {"Attack Type": ["DoS Hulk", "Bot"], "Flows": [12, 3]}
    )

    assert build_reference_traffic_counts(attacks, 20) == {
        "total_flows": 20,
        "benign_flows": 5,
        "attack_flows": 15,
    }


def test_build_reference_traffic_counts_rejects_invalid_or_inconsistent_inputs():
    attacks = pd.DataFrame(
        {"Attack Type": ["DoS Hulk", "Bot"], "Flows": [12, 3]}
    )
    assert build_reference_traffic_counts(attacks, 10) is None
    assert build_reference_traffic_counts(attacks, 0) is None
    assert build_reference_traffic_counts(
        pd.DataFrame({"Attack Type": ["DoS Hulk"], "Flows": ["bad"]}), 20
    ) is None
    assert build_reference_traffic_counts(pd.DataFrame(), 20) is None



def test_checked_in_traffic_summary_matches_all_attack_family_counts():
    root = Path(__file__).resolve().parents[1]
    summary = load_reference_traffic_summary(
        root / "research" / "cicids2017_traffic_summary.csv"
    )
    attacks = load_reference_attack_distribution(
        root / "research" / "cicids2017_attack_distribution.csv"
    )

    assert summary == {
        "Total Flows": 2_228_970,
        "Benign Flows": 1_892_671,
        "Attack Flows": 336_299,
    }
    assert int(attacks["Flows"].sum()) == summary["Attack Flows"]
    assert summary["Total Flows"] == (
        summary["Benign Flows"] + summary["Attack Flows"]
    )
