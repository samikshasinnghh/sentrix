import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

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


def prepare_features(df):
    X = df[RBA_FEATURE_COLUMNS].copy()
    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(int)
    return X


if __name__ == "__main__":
    df = pd.read_csv("data/processed/rba_baseline.csv")

    X = prepare_features(df)
    y = df["Is Account Takeover"]

    print("Total positives:", y.sum(), "out of", len(y))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        stratify=y,
        random_state=42,
    )

    print("Train set:", X_train.shape, "positives:", y_train.sum())
    print("Test set: ", X_test.shape, "positives:", y_test.sum())

    # class_weight="balanced" tells the model to weight the rare
    # positive class more heavily during training, since 141 positives
    # among 312K rows would otherwise be nearly ignored — the model
    # could get 99.95% "accuracy" by predicting "normal" every time.
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    tp = ((y_pred == True) & (y_test == True)).sum()
    fn = ((y_pred == False) & (y_test == True)).sum()
    fp = ((y_pred == True) & (y_test == False)).sum()
    tn = ((y_pred == False) & (y_test == False)).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print()
    print("="*50)
    print("METRICS — Random Forest (RBA, supervised, held-out test set)")
    print("="*50)
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 score:  {f1:.4f}")
    print(f"False positive rate: {fpr:.4f} ({fpr*100:.2f}%)")

    # Feature importance — which signals actually drove the model's
    # decisions? Worth inspecting, not just trusting blindly.
    importances = pd.Series(model.feature_importances_, index=RBA_FEATURE_COLUMNS)
    print()
    print("Feature importances:")
    print(importances.sort_values(ascending=False))