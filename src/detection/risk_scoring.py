import pandas as pd


def normalize_anomaly_score(df):
    df = df.copy()

    min_score = df["anomaly_score"].min()
    max_score = df["anomaly_score"].max()

    df["anomaly_score_normalized"] = (df["anomaly_score"] - min_score) / (max_score - min_score)

    return df


def add_consequence_weight(df):
    df = df.copy()

    # Base weight of 1.0, boosted for privileged actions — a boost of
    # 0.3 was chosen deliberately conservative: this should raise a
    # privileged event's score meaningfully, but not let it override
    # the anomaly signal entirely (a routine privileged action by an
    # actual admin shouldn't automatically become CRITICAL).
    df["consequence_weight"] = 1.0
    df.loc[df["is_privileged_action"] == True, "consequence_weight"] += 0.3

    # A new-country login is a strong indicator of potential account
    # takeover specifically — one of the highest-consequence attack
    # types in our detection scope, even when it doesn't also trigger
    # volume-based signals. Boosted separately from privileged actions.
    df.loc[df["is_new_country"] == True, "consequence_weight"] += 0.4

    # Small additional boost per rule triggered, capped so a large
    # rules_triggered count doesn't dominate the formula entirely.
    df["rules_boost"] = (df["rules_triggered"] * 0.05).clip(upper=0.25)

    return df


def compute_risk_score(df):
    df = df.copy()

    # Combine: normalized anomaly score (0-1) × consequence weight,
    # plus the rules boost, then scale to 0-100 and clip to that range
    # in case the weighting pushes slightly over 1.0.
    raw_score = (df["anomaly_score_normalized"] * df["consequence_weight"]) + df["rules_boost"]
    df["risk_score"] = (raw_score * 100).clip(0, 100).round(1)

    return df


def add_severity_band(df):
    df = df.copy()

    def band(score):
        if score >= 81:
            return "CRITICAL"
        elif score >= 61:
            return "HIGH"
        elif score >= 31:
            return "MEDIUM"
        else:
            return "LOW"

    df["severity"] = df["risk_score"].apply(band)

    return df


if __name__ == "__main__":
    df = pd.read_csv("data/processed/activity_ml_results.csv")

    df = normalize_anomaly_score(df)
    df = add_consequence_weight(df)
    df = compute_risk_score(df)
    df = add_severity_band(df)

    print("Normalized score distribution:")
    print(df["anomaly_score_normalized"].describe())
    print()
    print("risk_score distribution:")
    print(df["risk_score"].describe())
    print()
    print("Average risk_score by is_attack:")
    print(df.groupby("is_attack")["risk_score"].mean())
    print()
    print("Average risk_score by attack_type:")
    print(df.groupby("attack_type")["risk_score"].mean().sort_values(ascending=False))
    print()
    print("severity breakdown:")
    print(df["severity"].value_counts())
    print()
    print("severity vs is_attack:")
    print(pd.crosstab(df["severity"], df["is_attack"]))
    print()
    print("severity vs attack_type:")
    print(pd.crosstab(df["severity"], df["attack_type"]))

    output_columns = [
        "event_id", "timestamp", "user_id", "role", "source_ip", "country",
        "action", "status", "is_privileged_action",
        "anomaly_score", "anomaly_score_normalized", "risk_score", "severity",
        "rules_triggered", "is_attack", "attack_type",
    ]
    final_df = df[output_columns]

    final_df.to_csv("data/processed/activity_scored.csv", index=False)
    print("\nSaved data/processed/activity_scored.csv")