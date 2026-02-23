import pandas as pd


# Merge
df1 = pd.read_csv("./output/hayabusa_evtx-attack-samples.csv")
df2 = pd.read_csv("./output/hayabusa_extx-to-mitre-attack.csv")
df3 = pd.read_csv("./output/hayabusa_yamatosecurity.csv")

df = pd.concat([df1, df2, df3], ignore_index=True)
df = df.sort_values("Timestamp").reset_index(drop=True)

# Sanity check
print(f"Total rows: {len(df)}")
print(f"Columns: {df.columns.tolist()}")
print(f"\nLevel distribution:")
print(df["Level"].value_counts())
print(f"\nMissing values:")
print(df.isnull().sum())

# Save
df.to_csv("./output/final_dataset.csv", index=False)
print("\nSaved to ./output/final_dataset.csv")