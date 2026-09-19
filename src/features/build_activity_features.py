import pandas as pd


def add_time_features(df):
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek  # 0=Monday, 6=Sunday
    df["is_weekend"] = df["day_of_week"].isin([5, 6])
    return df


def add_user_baseline_features(df):
    df = df.copy()

    # Per-user typical hour range, learned from their own history —
    # not hardcoded, computed from the data itself.
    user_hour_stats = df.groupby("user_id")["hour"].agg(["mean", "std"]).reset_index()
    user_hour_stats.columns = ["user_id", "user_avg_hour", "user_hour_std"]

    df = df.merge(user_hour_stats, on="user_id", how="left")

    # An event is "off-hours for this user" if it falls more than
    # 2 standard deviations from their typical hour. Users with almost
    # no variation (std near 0) get a safe fallback, so we don't divide
    # by a near-zero number and flag everything as anomalous.
    df["user_hour_std"] = df["user_hour_std"].fillna(1).replace(0, 1)
    df["hour_deviation"] = (df["hour"] - df["user_avg_hour"]).abs() / df["user_hour_std"]
    df["is_unusual_hour"] = df["hour_deviation"] > 2

    return df


def add_windowed_counts(df):
    df = df.copy()
    df = df.sort_values(["user_id", "timestamp"]).reset_index(drop=True)

    failed_counts = []
    action_counts = []

    for user_id, group in df.groupby("user_id"):
        timestamps = group["timestamp"].values
        statuses = group["status"].values

        for i in range(len(group)):
            window_start = timestamps[i] - pd.Timedelta(minutes=10)
            in_window = (timestamps >= window_start) & (timestamps <= timestamps[i])

            action_counts.append(in_window.sum())
            failed_counts.append(((statuses == "FAILURE") & in_window).sum())

    df["actions_10min"] = action_counts
    df["failed_logins_10min"] = failed_counts

    return df


def add_novelty_features(df):
    df = df.copy()
    df = df.sort_values(["user_id", "timestamp"]).reset_index(drop=True)

    # duplicated() marks every row as True except the FIRST time each
    # (user_id, country) pair appears, computed as one vectorized pass —
    # no per-row Python loop, so this runs in well under a second
    # regardless of row count. Requires data pre-sorted by timestamp,
    # since "first occurrence" only means "first chronologically" then.
    df["is_new_country"] = ~df.duplicated(subset=["user_id", "country"], keep="first")
    df["is_new_ip"] = ~df.duplicated(subset=["user_id", "source_ip"], keep="first")

    return df


if __name__ == "__main__":
    df = pd.read_csv("data/processed/activity_clean.csv", parse_dates=["timestamp"])

    df = add_time_features(df)
    df = add_user_baseline_features(df)
    df = add_windowed_counts(df)
    df = add_novelty_features(df)

    print(df.shape)
    print()
    print("is_new_country breakdown:")
    print(df["is_new_country"].value_counts())
    print()
    print("New country vs real attacks:")
    print(pd.crosstab(df["is_new_country"], df["is_attack"]))

    df.to_csv("data/processed/activity_features.csv", index=False)
    print("\nSaved data/processed/activity_features.csv")