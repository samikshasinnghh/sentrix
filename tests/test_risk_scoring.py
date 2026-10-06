import pandas as pd
import pytest

from src.detection.risk_scoring import (
    normalize_anomaly_score,
    add_consequence_weight,
    compute_risk_score,
    add_severity_band,
)


# ---------- normalize_anomaly_score ----------

def test_normalize_maps_min_to_zero_and_max_to_one():
    df = pd.DataFrame({"anomaly_score": [1.0, 2.0, 3.0]})
    out = normalize_anomaly_score(df)
    assert out["anomaly_score_normalized"].tolist() == pytest.approx([0.0, 0.5, 1.0])


def test_normalize_does_not_modify_input():
    df = pd.DataFrame({"anomaly_score": [1.0, 2.0, 3.0]})
    normalize_anomaly_score(df)
    assert "anomaly_score_normalized" not in df.columns


def test_normalize_identical_scores_does_not_produce_nan():
    # Happens when a batch has a single event, or all events score the same.
    df = pd.DataFrame({"anomaly_score": [0.7, 0.7, 0.7]})
    out = normalize_anomaly_score(df)
    assert not out["anomaly_score_normalized"].isna().any()


# ---------- add_consequence_weight ----------

def _weight_input(privileged=False, new_country=False, rules=0):
    return pd.DataFrame({
        "is_privileged_action": [privileged],
        "is_new_country": [new_country],
        "rules_triggered": [rules],
    })


@pytest.mark.parametrize("privileged, new_country, expected", [
    (False, False, 1.0),
    (True, False, 1.3),
    (False, True, 1.4),
    (True, True, 1.7),
])
def test_consequence_weight(privileged, new_country, expected):
    out = add_consequence_weight(_weight_input(privileged, new_country))
    assert out["consequence_weight"].iloc[0] == pytest.approx(expected)


@pytest.mark.parametrize("rules, expected", [
    (0, 0.0),
    (2, 0.10),
    (5, 0.25),
    (10, 0.25),  # capped
])
def test_rules_boost_scales_and_is_capped(rules, expected):
    out = add_consequence_weight(_weight_input(rules=rules))
    assert out["rules_boost"].iloc[0] == pytest.approx(expected)


# ---------- compute_risk_score ----------

def _score_input(normalized, weight=1.0, boost=0.0):
    return pd.DataFrame({
        "anomaly_score_normalized": [normalized],
        "consequence_weight": [weight],
        "rules_boost": [boost],
    })


def test_risk_score_formula():
    # (0.5 * 1.2 + 0.1) * 100 = 70
    out = compute_risk_score(_score_input(0.5, weight=1.2, boost=0.1))
    assert out["risk_score"].iloc[0] == pytest.approx(70.0)


def test_risk_score_is_clipped_to_100():
    out = compute_risk_score(_score_input(1.0, weight=1.7, boost=0.25))
    assert out["risk_score"].iloc[0] == 100.0


def test_risk_score_is_rounded_to_one_decimal():
    out = compute_risk_score(_score_input(0.3333))
    assert out["risk_score"].iloc[0] == pytest.approx(33.3)


def test_privileged_action_raises_the_score():
    df = pd.DataFrame({
        "anomaly_score_normalized": [0.5, 0.5],
        "is_privileged_action": [False, True],
        "is_new_country": [False, False],
        "rules_triggered": [0, 0],
    })
    out = compute_risk_score(add_consequence_weight(df))
    assert out["risk_score"].iloc[1] > out["risk_score"].iloc[0]


# ---------- add_severity_band ----------

@pytest.mark.parametrize("score, expected", [
    (0, "LOW"),
    (30.9, "LOW"),
    (31, "MEDIUM"),
    (60.9, "MEDIUM"),
    (61, "HIGH"),
    (80.9, "HIGH"),
    (81, "CRITICAL"),
    (100, "CRITICAL"),
])
def test_severity_band_boundaries(score, expected):
    out = add_severity_band(pd.DataFrame({"risk_score": [score]}))
    assert out["severity"].iloc[0] == expected


# ---------- whole scoring chain ----------

def test_full_pipeline_keeps_scores_in_range_with_valid_severities():
    df = pd.DataFrame({
        "anomaly_score": [-0.9, -0.5, -0.1, 0.0, 0.3, 0.8],
        "is_privileged_action": [False, True, False, True, False, True],
        "is_new_country": [False, False, True, True, False, True],
        "rules_triggered": [0, 1, 2, 5, 3, 8],
    })
    out = normalize_anomaly_score(df)
    out = add_consequence_weight(out)
    out = compute_risk_score(out)
    out = add_severity_band(out)

    assert out["risk_score"].between(0, 100).all()
    assert set(out["severity"]) <= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}