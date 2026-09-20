import pandas as pd
from sklearn.ensemble import IsolationForest

# Columns the model is allowed to see — purely behavioral/engineered
# signals, nothing that identifies the event or leaks the answer.
ACTIVITY_FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "is_weekend",
    "user_avg_hour",
    "user_hour_std",
    "hour_deviation",
    "is_unusual_hour",
    "actions_10min",
    "failed_logins_10min",
    "is_new_country",
    "is_new_ip",
    "is_privileged_action",
]

CONTAMINATION = 0.02  # rough prior guess at what fraction of events are anomalous


def prepare_features(df):
    X = df[ACTIVITY_FEATURE_COLUMNS].copy()

    # Isolation Forest needs numeric input — convert booleans to 0/1 explicitly
    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(int)

    return X


def train_isolation_forest(X):
    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return model


if __name__ == "__main__":
    df = pd.read_csv("data/processed/activity_baseline.csv")

    X = prepare_features(df)

    print("Feature matrix shape:", X.shape)
    print()

    print("Training Isolation Forest...")
    model = train_isolation_forest(X)

    # decision_function: higher = more normal, lower = more anomalous
    # (sklearn's convention). We flip the sign so HIGHER = more
    # anomalous, matching how a "risk score" should read intuitively —
    # this also sets up Phase 7's risk scoring consistently.
    df["anomaly_score"] = -model.decision_function(X)

    # predict: -1 = anomaly, 1 = normal, based on the contamination threshold
    df["ml_flagged"] = model.predict(X) == -1

    print("Done.")
    print()
    print("anomaly_score distribution:")
    print(df["anomaly_score"].describe())
    print()
    print("ml_flagged breakdown:")
    print(df["ml_flagged"].value_counts())
    print()
    print("ML flagged vs real attacks:")
    print(pd.crosstab(df["ml_flagged"], df["is_attack"]))

    df.to_csv("data/processed/activity_ml_results.csv", index=False)
    print("\nSaved data/processed/activity_ml_results.csv")
    tn = ((~df["ml_flagged"]) & (~df["is_attack"])).sum()
    fn = ((~df["ml_flagged"]) & (df["is_attack"])).sum()
    fp = ((df["ml_flagged"]) & (~df["is_attack"])).sum()
    tp = ((df["ml_flagged"]) & (df["is_attack"])).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print()
    print("="*50)
    print("METRICS — Isolation Forest (Activity)")
    print("="*50)
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 score:  {f1:.4f}")
    print(f"False positive rate: {fpr:.4f} ({fpr*100:.2f}%)")