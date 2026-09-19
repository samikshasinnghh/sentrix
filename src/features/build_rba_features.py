import pandas as pd

MIN_HISTORY_FOR_NOVELTY = 5


def add_time_features(df):
    df = df.copy()
    df["hour"] = df["Login Timestamp"].dt.hour
    df["day_of_week"] = df["Login Timestamp"].dt.dayofweek
    df["is_weekend"] = df["day_of_week"].isin([5, 6])
    return df


def add_windowed_failed_logins(df):
    df = df.copy()
    df = df.sort_values(["User ID", "Login Timestamp"]).reset_index(drop=True)

    df["failed_logins_10min"] = 0

    for user_id, group in df.groupby("User ID"):
        idx = group.index
        timestamps = group["Login Timestamp"].values
        is_failure = (~group["Login Successful"]).values

        counts = []
        for i in range(len(group)):
            window_start = timestamps[i] - pd.Timedelta(minutes=10)
            in_window = (timestamps >= window_start) & (timestamps <= timestamps[i])
            counts.append((is_failure & in_window).sum())

        df.loc[idx, "failed_logins_10min"] = counts

    return df


def add_novelty_features(df):
    df = df.copy()
    df = df.sort_values(["User ID", "Login Timestamp"]).reset_index(drop=True)

    user_counts = df.groupby("User ID").size().rename("user_sample_count")
    df = df.merge(user_counts, on="User ID", how="left")

    df["insufficient_history"] = df["user_sample_count"] < MIN_HISTORY_FOR_NOVELTY

    # Keep the raw novelty signal intact — don't discard it. Sparse
    # history is itself informative (a rarely-seen user acting is
    # already somewhat unusual), so we expose both signals separately
    # and let Phase 5's rules / Phase 6's model learn how to combine
    # them, rather than us guessing the right threshold here.
    df["is_new_country"] = ~df.duplicated(subset=["User ID", "Country"], keep="first")
    df["is_new_ip"] = ~df.duplicated(subset=["User ID", "IP Address"], keep="first")

    return df


if __name__ == "__main__":
    df = pd.read_csv("data/processed/rba_clean.csv", parse_dates=["Login Timestamp"])

    df = add_time_features(df)
    df = add_windowed_failed_logins(df)
    df = add_novelty_features(df)

    print(df.shape)
    print()
    print("insufficient_history breakdown:")
    print(df["insufficient_history"].value_counts())
    print()
    print("New country vs Is Account Takeover (raw signal, unfiltered):")
    print(pd.crosstab(df["is_new_country"], df["Is Account Takeover"]))
    print()
    print("Of the True Account Takeovers, how many also have insufficient_history:")
    print(df[df["Is Account Takeover"]]["insufficient_history"].value_counts())
    print()
    print("High failed_logins_10min (>5) vs Is Attack IP:")
    print(pd.crosstab(df["failed_logins_10min"] > 5, df["Is Attack IP"]))

    df.to_csv("data/processed/rba_features.csv", index=False)
    print("\nSaved data/processed/rba_features.csv")