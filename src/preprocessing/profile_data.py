import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 150)


def profile(path, name):
    print(f"\n{'='*60}")
    print(f"PROFILING: {name}")
    print(f"{'='*60}")

    df = pd.read_csv(path)

    print(f"\nShape: {df.shape}")
    print(f"\nColumns and types:\n{df.dtypes}")
    print(f"\nMissing values per column:\n{df.isnull().sum()}")
    print(f"\nDuplicate rows: {df.duplicated().sum()}")
    print(f"\nFirst 3 rows:\n{df.head(3)}")

    return df


if __name__ == "__main__":
    rba_df = profile("data/raw/rba_sample.csv", "RBA Login Data")
    activity_df = profile("data/raw/synthetic_activity.csv", "Synthetic Activity Data")