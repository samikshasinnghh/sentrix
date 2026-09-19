import pandas as pd

SOURCE = r"C:\Users\samik\Downloads\rba-dataset-raw\rba-dataset.csv"
OUTPUT = "data/raw/rba_sample.csv"

CHUNK_SIZE = 500_000
SAMPLE_RATE = 0.01  # keep ~1% of non-takeover rows

takeover_rows = []
sampled_rows = []

reader = pd.read_csv(SOURCE, chunksize=CHUNK_SIZE)

for i, chunk in enumerate(reader):
    # Always keep every real account-takeover row
    takeovers = chunk[chunk["Is Account Takeover"] == True]
    takeover_rows.append(takeovers)

    # Randomly sample the rest
    non_takeovers = chunk[chunk["Is Account Takeover"] == False]
    sample = non_takeovers.sample(frac=SAMPLE_RATE, random_state=42)
    sampled_rows.append(sample)

    print(f"Processed chunk {i+1}, running total takeovers kept: "
          f"{sum(len(t) for t in takeover_rows)}")

result = pd.concat(takeover_rows + sampled_rows, ignore_index=True)
result = result.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

result.to_csv(OUTPUT, index=False)
print(f"\nFinal sample size: {len(result)} rows")
print(f"Account takeovers in sample: {(result['Is Account Takeover'] == True).sum()}")