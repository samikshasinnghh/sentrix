import pandas as pd


def apply_activity_rules(df):
    df = df.copy()

    df["rule_excessive_failed_logins"] = df["failed_logins_10min"] > 5
    df["rule_excessive_volume"] = df["actions_10min"] > 10
    df["rule_unusual_hour"] = df["is_unusual_hour"] == True
    df["rule_new_country"] = df["is_new_country"] == True
    df["rule_privileged_action"] = df["is_privileged_action"] == True

    rule_columns = [
        "rule_excessive_failed_logins",
        "rule_excessive_volume",
        "rule_unusual_hour",
        "rule_new_country",
        "rule_privileged_action",
    ]

    df["baseline_flagged"] = df[rule_columns].any(axis=1)
    df["rules_triggered"] = df[rule_columns].sum(axis=1)

    return df


def apply_rba_rules(df):
    df = df.copy()

    df["rule_excessive_failed_logins"] = df["failed_logins_10min"] > 5
    df["rule_unusual_hour"] = df["is_unusual_hour"] == True
    df["rule_new_country"] = df["is_new_country"] == True

    rule_columns = [
        "rule_excessive_failed_logins",
        "rule_unusual_hour",
        "rule_new_country",
    ]

    df["baseline_flagged"] = df[rule_columns].any(axis=1)
    df["rules_triggered"] = df[rule_columns].sum(axis=1)

    return df


def print_metrics(tp, fn, fp, tn, name):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(name)
    print("  Precision:", round(precision, 4), f"({round(precision*100, 2)}%)")
    print("  Recall:   ", round(recall, 4), f"({round(recall*100, 2)}%)")
    print("  F1 score: ", round(f1, 4))
    print("  False positive rate:", round(fpr, 4), f"({round(fpr*100, 2)}%)")
    print()


if __name__ == "__main__":
    activity_df = pd.read_csv("data/processed/activity_features.csv")
    rba_df = pd.read_csv("data/processed/rba_features.csv")

    activity_flagged = apply_activity_rules(activity_df)
    rba_flagged = apply_rba_rules(rba_df)

    print("ACTIVITY PIPELINE")
    print("baseline_flagged breakdown:")
    print(activity_flagged["baseline_flagged"].value_counts())
    print()
    print("Flagged vs real attacks:")
    activity_ct = pd.crosstab(activity_flagged["baseline_flagged"], activity_flagged["is_attack"])
    print(activity_ct)

    print()
    print("==================================================")
    print()

    print("RBA PIPELINE")
    print("baseline_flagged breakdown:")
    print(rba_flagged["baseline_flagged"].value_counts())
    print()
    print("Flagged vs Is Account Takeover:")
    rba_ct = pd.crosstab(rba_flagged["baseline_flagged"], rba_flagged["Is Account Takeover"])
    print(rba_ct)

    print()
    print("==================================================")
    print("METRICS")
    print("==================================================")
    print()

    activity_tn = activity_ct.loc[False, False]
    activity_fn = activity_ct.loc[False, True]
    activity_fp = activity_ct.loc[True, False]
    activity_tp = activity_ct.loc[True, True]
    print_metrics(tp=activity_tp, fn=activity_fn, fp=activity_fp, tn=activity_tn, name="Activity baseline")

    rba_tn = rba_ct.loc[False, False]
    rba_fn = rba_ct.loc[False, True]
    rba_fp = rba_ct.loc[True, False]
    rba_tp = rba_ct.loc[True, True]
    print_metrics(tp=rba_tp, fn=rba_fn, fp=rba_fp, tn=rba_tn, name="RBA baseline")

    activity_flagged.to_csv("data/processed/activity_baseline.csv", index=False)
    rba_flagged.to_csv("data/processed/rba_baseline.csv", index=False)
    print("Saved both baseline output files")