import pandas as pd

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


def prepare_features(df):
    X = df[ACTIVITY_FEATURE_COLUMNS].copy()

    # Isolation Forest needs numeric input — convert booleans to 0/1 explicitly
    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(int)

    return X


if __name__ == "__main__":
    df = pd.read_csv("data/processed/activity_baseline.csv")

    X = prepare_features(df)

    print("Feature matrix shape:", X.shape)
    print()
    print("Column dtypes:")
    print(X.dtypes)
    print()
    print("Any nulls?", X.isnull().sum().sum())
    print()
    print(X.head())