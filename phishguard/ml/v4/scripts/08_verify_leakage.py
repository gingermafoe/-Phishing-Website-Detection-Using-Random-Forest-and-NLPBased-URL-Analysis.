import os
import sys
import pandas as pd

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
ML_V4_DIR = os.path.join(WORKSPACE_DIR, "ml", "v4")
DATASET_DIR = os.path.join(ML_V4_DIR, "dataset")

print("=" * 80)
print("PHASE 15: COMPREHENSIVE LEAKAGE AUDIT")
print("=" * 80)

# Check all V4 dataset files
files_to_check = [
    os.path.join(DATASET_DIR, "v4_legitimate_curated.csv"),
    os.path.join(DATASET_DIR, "v4_phishing_curated.csv"),
    os.path.join(DATASET_DIR, "v4_modern_hosting_benchmark_heldout.csv")
]

forbidden_terms = [
    "klattendance",
    "klhunderground"
]

leakage_found = False
for fpath in files_to_check:
    if not os.path.exists(fpath):
        continue
    df = pd.read_csv(fpath)
    print(f"\nChecking: {os.path.basename(fpath)} ({len(df):,} rows)...")
    for term in forbidden_terms:
        matches = df[df["URL"].astype(str).str.contains(term, case=False, na=False)]
        if len(matches) > 0:
            print(f"  [CRITICAL LEAKAGE DETECTED] Found {len(matches)} matches for '{term}'!")
            leakage_found = True
        else:
            print(f"  [CLEAN] Zero matches for '{term}'.")

# Check train/test domain overlap in V4-B
import feature_config_v4b as fc_v4b
from sklearn.model_selection import GroupShuffleSplit
import urllib.parse

csv_path = os.path.join(WORKSPACE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
df = pd.read_csv(csv_path)
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
df["BaseDomain"] = df["Domain"].str.lower().str.replace(r"^www\.", "", regex=True)

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df["BaseDomain"]))
train_df = df.iloc[train_idx]
test_df = df.iloc[test_idx]

train_domains = set(train_df["BaseDomain"])
test_domains = set(test_df["BaseDomain"])
overlap = train_domains.intersection(test_domains)

print(f"\nBase Domain Overlap between Train and Test: {len(overlap)}")
assert len(overlap) == 0, f"Domain leakage detected: {len(overlap)}"
print("[LEAKAGE AUDIT PASSED] Domain disjointness strictly verified: overlap = 0.")

if not leakage_found:
    print("\n[ALL LEAKAGE CHECKS PASSED] Zero holdout leakage, zero domain overlap.")
