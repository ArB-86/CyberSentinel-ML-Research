from pathlib import Path

import pandas as pd

from utils.dashboard_data import (
    build_attack_distribution,
    load_reference_attack_distribution,
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
