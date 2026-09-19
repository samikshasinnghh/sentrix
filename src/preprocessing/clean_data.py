import pandas as pd


def clean_rba_data(df):
    df = df.copy()

    # Round-Trip Time is missing in ~96% of rows — imputing that much
    # would fabricate data, not clean it. Dropping the column is the
    # honest choice.
    df = df.drop(columns=["Round-Trip Time [ms]"])

    # Small, plausible real-world gaps (unresolved geo-IP data,
    # unrecognized user agents). Fill rather than drop rows, since
    # dropping risks losing one of the 141 real account-takeover rows.
    df["Region"] = df["Region"].fillna("Unknown")
    df["City"] = df["City"].fillna("Unknown")
    df["Device Type"] = df["Device Type"].fillna("Unknown")

    return df


def clean_activity_data(df):
    df = df.copy()

    # attack_type is NaN by design for every normal event — not a data
    # quality issue. Replacing with an explicit label for consistency.
    df["attack_type"] = df["attack_type"].fillna("none")

    return df


def check_duplicates(df, name):
    dupe_count = df.duplicated().sum()
    print(f"{name}: {dupe_count} duplicate rows")
    return dupe_count


def parse_rba_timestamps(df):
    df = df.copy()
    df["Login Timestamp"] = pd.to_datetime(df["Login Timestamp"])
    return df


def parse_activity_timestamps(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


if __name__ == "__main__":
    rba_df = pd.read_csv("data/raw/rba_sample.csv")
    activity_df = pd.read_csv("data/raw/synthetic_activity.csv")

    rba_clean = clean_rba_data(rba_df)
    activity_clean = clean_activity_data(activity_df)

    rba_clean = parse_rba_timestamps(rba_clean)
    activity_clean = parse_activity_timestamps(activity_clean)

    print("RBA timestamp dtype:", rba_clean["Login Timestamp"].dtype)
    print("RBA timestamp range:", rba_clean["Login Timestamp"].min(), "to", rba_clean["Login Timestamp"].max())
    print()
    print("Activity timestamp dtype:", activity_clean["timestamp"].dtype)
    print("Activity timestamp range:", activity_clean["timestamp"].min(), "to", activity_clean["timestamp"].max())

    print()
    check_duplicates(rba_clean, "RBA")
    check_duplicates(activity_clean, "Activity")

    print()
    print("RBA shape:", rba_clean.shape)
    print("Activity shape:", activity_clean.shape)

    rba_clean.to_csv("data/processed/rba_clean.csv", index=False)
    activity_clean.to_csv("data/processed/activity_clean.csv", index=False)

    print()
    print("Saved data/processed/rba_clean.csv")
    print("Saved data/processed/activity_clean.csv")