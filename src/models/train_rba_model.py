import pandas as pd
from sklearn.ensemble import IsolationForest

RBA_FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "is_weekend",
    "user_avg_hour",
    "user_hour_std",
    "hour_deviation",
    "is_unusual_hour",
    "failed_logins_10min",
    "is_new_country",
    "is_new_ip",
    "insufficient_history",
    "user_sample_count",
]

CONTAMINATION = 0.02


def prepare_features(df):
    X = df[RBA_FEATURE_COLUMNS].copy()

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
    df = pd.read_csv("data/processed/rba_baseline.csv")

    X = prepare_features(df)

    print("Feature matrix shape:", X.shape)
    print()

    print("Training Isolation Forest...")
    model = train_isolation_forest(X)

    df["anomaly_score"] = -model.decision_function(X)
    df["ml_flagged"] = model.predict(X) == -1

    print("Done.")
    print()
    print("ml_flagged breakdown:")
    print(df["ml_flagged"].value_counts())
    print()
    print("ML flagged vs Is Account Takeover:")
    print(pd.crosstab(df["ml_flagged"], df["Is Account Takeover"]))

    tn = ((~df["ml_flagged"]) & (~df["Is Account Takeover"])).sum()
    fn = ((~df["ml_flagged"]) & (df["Is Account Takeover"])).sum()
    fp = ((df["ml_flagged"]) & (~df["Is Account Takeover"])).sum()
    tp = ((df["ml_flagged"]) & (df["Is Account Takeover"])).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print()
    print("="*50)
    print("METRICS — Isolation Forest (RBA)")
    print("="*50)
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 score:  {f1:.4f}")
    print(f"False positive rate: {fpr:.4f} ({fpr*100:.2f}%)")

    df.to_csv("data/processed/rba_ml_results.csv", index=False)
    print("\nSaved data/processed/rba_ml_results.csv")