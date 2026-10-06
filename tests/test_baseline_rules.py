import pandas as pd
import pytest

from src.detection.baseline_rules import apply_activity_rules, apply_rba_rules


def _activity_row(**overrides):
    row = {
        "failed_logins_10min": 0,
        "actions_10min": 1,
        "is_unusual_hour": False,
        "is_new_country": False,
        "is_privileged_action": False,
    }
    row.update(overrides)
    return pd.DataFrame([row])


def _rba_row(**overrides):
    row = {
        "failed_logins_10min": 0,
        "is_unusual_hour": False,
        "is_new_country": False,
    }
    row.update(overrides)
    return pd.DataFrame([row])


# ---------- activity rules ----------

def test_clean_activity_row_triggers_no_rules():
    out = apply_activity_rules(_activity_row())
    assert out["rules_triggered"].iloc[0] == 0
    assert not out["baseline_flagged"].iloc[0]


@pytest.mark.parametrize("failed, expected", [(5, False), (6, True)])
def test_failed_login_threshold(failed, expected):
    out = apply_activity_rules(_activity_row(failed_logins_10min=failed))
    assert bool(out["rule_excessive_failed_logins"].iloc[0]) is expected


@pytest.mark.parametrize("actions, expected", [(10, False), (11, True)])
def test_volume_threshold(actions, expected):
    out = apply_activity_rules(_activity_row(actions_10min=actions))
    assert bool(out["rule_excessive_volume"].iloc[0]) is expected


@pytest.mark.parametrize("input_col, rule_col", [
    ("is_unusual_hour", "rule_unusual_hour"),
    ("is_new_country", "rule_new_country"),
    ("is_privileged_action", "rule_privileged_action"),
])
def test_single_flag_triggers_its_rule_and_flags_the_event(input_col, rule_col):
    out = apply_activity_rules(_activity_row(**{input_col: True}))
    assert bool(out[rule_col].iloc[0]) is True
    assert out["rules_triggered"].iloc[0] == 1
    assert bool(out["baseline_flagged"].iloc[0]) is True


def test_rules_triggered_counts_every_rule():
    out = apply_activity_rules(_activity_row(
        failed_logins_10min=6,
        actions_10min=11,
        is_unusual_hour=True,
        is_new_country=True,
        is_privileged_action=True,
    ))
    assert out["rules_triggered"].iloc[0] == 5


def test_activity_rules_do_not_modify_input():
    df = _activity_row()
    apply_activity_rules(df)
    assert "rules_triggered" not in df.columns


# ---------- RBA rules ----------

def test_clean_rba_row_triggers_no_rules():
    out = apply_rba_rules(_rba_row())
    assert out["rules_triggered"].iloc[0] == 0
    assert not out["baseline_flagged"].iloc[0]


def test_rba_rules_count_all_three_rules():
    out = apply_rba_rules(_rba_row(
        failed_logins_10min=6, is_unusual_hour=True, is_new_country=True,
    ))
    assert out["rules_triggered"].iloc[0] == 3
    assert bool(out["baseline_flagged"].iloc[0]) is True


def test_rba_has_no_volume_or_privileged_rule():
    out = apply_rba_rules(_rba_row())
    assert "rule_excessive_volume" not in out.columns
    assert "rule_privileged_action" not in out.columns