import os
import sys
import pandas as pd

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
ML_V4_DIR = os.path.join(WORKSPACE_DIR, "ml", "v4")
DATASET_DIR = os.path.join(ML_V4_DIR, "dataset")

FORBIDDEN_HOLDOUTS = [
    "klattendance.vercel.app",
    "klhunderground.ai.studio"
]

def is_forbidden(u: str) -> bool:
    clean = str(u).lower().strip()
    for f in FORBIDDEN_HOLDOUTS:
        if f in clean:
            return True
    return False

# Load original dataset
csv_path = os.path.join(WORKSPACE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
print("Reading original dataset to extract verified phishing samples on modern hosting platforms...")
df = pd.read_csv(csv_path, usecols=["URL", "Domain", "label"])

# Filter for phishing (label == 0)
phish_all = df[df["label"] == 0].copy()

PLATFORMS = [
    "vercel.app", "netlify.app", "github.io", "pages.dev", "web.app", "firebaseapp.com"
]

phish_records = []
for p in PLATFORMS:
    sub = phish_all[phish_all["URL"].str.contains(p, case=False, na=False)].copy()
    print(f"Extracted {len(sub):,} verified phishing samples on: {p}")
    for _, row in sub.iterrows():
        u = row["URL"].strip()
        if not is_forbidden(u):
            phish_records.append({
                "URL": u,
                "label": 0,
                "category": f"phishing_{p}",
                "platform": p,
                "source": "phiusiil_verified_feed",
                "verification_method": "active_phishing_threat_feed"
            })

df_phish = pd.DataFrame(phish_records)
df_phish = df_phish.drop_duplicates(subset=["URL"]).reset_index(drop=True)
print(f"\nTotal unique platform phishing samples extracted: {len(df_phish):,}")

for u in df_phish["URL"]:
    assert not is_forbidden(u), f"CRITICAL LEAKAGE: {u}"

out_path = os.path.join(DATASET_DIR, "v4_phishing_curated.csv")
df_phish.to_csv(out_path, index=False)
print(f"Saved verified modern hosting phishing samples to: {out_path}")
