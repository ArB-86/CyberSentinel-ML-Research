import pandas as pd

from utils.dashboard_data import build_attack_distribution


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
