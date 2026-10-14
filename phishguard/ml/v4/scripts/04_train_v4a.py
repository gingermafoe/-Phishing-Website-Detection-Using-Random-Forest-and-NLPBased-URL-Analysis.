import os
import sys
import json
import time
import random
import urllib.parse
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
ML_V3_DIR = os.path.join(WORKSPACE_DIR, "ml", "v3")
ML_V4_DIR = os.path.join(WORKSPACE_DIR, "ml", "v4")
MODELS_DIR = os.path.join(ML_V4_DIR, "models")
DATASET_DIR = os.path.join(ML_V4_DIR, "dataset")
REPORTS_DIR = os.path.join(ML_V4_DIR, "reports")

sys.path.insert(0, MODELS_DIR)
sys.path.insert(0, ML_V3_DIR)
import feature_config_v4a as fc_v4a
import feature_config_v3 as fc_v3

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

print("=" * 80)
print("PHISHGUARD V4-A TRAINING & EVALUATION PIPELINE")
print("=" * 80)

# 1. Load original PhiUSIIL dataset
csv_path = os.path.join(WORKSPACE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
print("Loading base PhiUSIIL dataset...")
df = pd.read_csv(csv_path)
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
df["BaseDomain"] = df["Domain"].str.lower().str.replace(r"^www\.", "", regex=True)

# 2. Domain-Aware Group Split (80% train, 20% test on BaseDomain)
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df["BaseDomain"]))
train_df = df.iloc[train_idx].copy().reset_index(drop=True)
test_df = df.iloc[test_idx].copy().reset_index(drop=True)

# 3. Add Curated Legitimate Modern Hosting Samples
legit_curated_path = os.path.join(DATASET_DIR, "v4_legitimate_curated.csv")
print("Loading curated legitimate modern hosting samples...")
df_legit_curated = pd.read_csv(legit_curated_path)

# Verify no forbidden holdout
for u in df_legit_curated["URL"]:
    assert not is_forbidden(u), f"CRITICAL: Forbidden URL in curated set: {u}"

df_legit_curated["BaseDomain"] = df_legit_curated["URL"].apply(
    lambda u: urllib.parse.urlparse(u).netloc.lower().replace("www.", "")
)

# Split curated modern hosting by BaseDomain (80% train, 20% test)
gss_curated = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
c_tr_idx, c_te_idx = next(gss_curated.split(df_legit_curated, groups=df_legit_curated["BaseDomain"]))

curated_train = df_legit_curated.iloc[c_tr_idx].copy().reset_index(drop=True)
curated_test = df_legit_curated.iloc[c_te_idx].copy().reset_index(drop=True)

# Ensure no domain overlap between curated train and test
c_tr_doms = set(curated_train["BaseDomain"])
c_te_doms = set(curated_test["BaseDomain"])
assert len(c_tr_doms.intersection(c_te_doms)) == 0, "Curated domain leakage!"

# Save curated test set for Phase 9 benchmark
curated_test.to_csv(os.path.join(DATASET_DIR, "v4_modern_hosting_benchmark_heldout.csv"), index=False)

# 4. Integrate into Training Pool
legit_train = train_df[train_df["label"] == 1].copy().reset_index(drop=True)
phish_train = train_df[train_df["label"] == 0].copy().reset_index(drop=True)

# Build training URLs list with V3-style structural expansion + modern hosting additions
train_urls = []
train_labels = []

# Base root legitimate: 50% apex / 50% www
for idx, row in legit_train.iterrows():
    base = row["BaseDomain"]
    u = f"https://{base}" if idx % 2 == 0 else f"https://www.{base}"
    if not is_forbidden(u):
        train_urls.append(u)
        train_labels.append(1)

# Add V3 structural augmentation
PATHS_SINGLE = ["about", "contact", "privacy", "terms", "faq", "blog", "services", "products", "login", "careers", "security", "overview"]
PATHS_MULTI = [("docs", "getting-started"), ("api", "v1"), ("help", "center"), ("wiki", "Computer_science"), ("3", "library", "unittest.html"), ("torvalds", "linux")]
QUERIES = [("q", "cybersecurity"), ("q", "machine+learning"), ("q", "python"), ("q", "random+forest"), ("lang", "en")]

random.seed(42)
sample_domains = random.sample(list(legit_train["BaseDomain"]), 45000)
for i, base in enumerate(sample_domains):
    mod = i % 5
    prefix = "www." if random.random() < 0.5 else ""
    if mod == 0:
        u = f"https://{prefix}{base}/{random.choice(PATHS_SINGLE)}"
    elif mod == 1:
        p = "/".join(random.choice(PATHS_MULTI))
        u = f"https://{prefix}{base}/{p}"
    elif mod == 2:
        k, v = random.choice(QUERIES)
        u = f"https://{prefix}{base}/search?{k}={v}"
    elif mod == 3:
        u = f"https://{prefix}{base}/explore?q=python&sort=relevance"
    else:
        u = f"https://{prefix}{base}/docs#installation"
    if not is_forbidden(u):
        train_urls.append(u)
        train_labels.append(1)

# Add curated legitimate modern hosting samples (train split only)
for _, row in curated_train.iterrows():
    u = row["URL"].strip()
    if not is_forbidden(u):
        train_urls.append(u)
        train_labels.append(1)

# Add phishing training samples
for _, row in phish_train.iterrows():
    u = row["URL"].strip()
    if not is_forbidden(u):
        train_urls.append(u)
        train_labels.append(0)

df_v4_train = pd.DataFrame({
    "URL": train_urls,
    "label": train_labels
})

# 5. Deduplication
initial_count = len(df_v4_train)
df_v4_train = df_v4_train.drop_duplicates(subset=["URL"]).reset_index(drop=True)
final_count = len(df_v4_train)
dups_removed = initial_count - final_count

print(f"\nDeduplication complete: {initial_count:,} -> {final_count:,} ({dups_removed:,} duplicates removed).")
print(f"Training distribution: Legit={(df_v4_train['label']==1).sum():,}, Phish={(df_v4_train['label']==0).sum():,}")

# Strict Holdout Verification on Training Data
for u in df_v4_train["URL"]:
    assert not is_forbidden(u), f"CRITICAL LEAKAGE DETECTED IN TRAINING: {u}"
print("Holdout exclusion PASSED: Neither klattendance nor klhunderground is in training data.")

# 6. Recalculate Empirical TLD Legitimate Probability Table from V4-A Training Data
print("\nRecalculating empirical TLD probability table from V4-A training data...")
legit_train_urls = df_v4_train[df_v4_train["label"] == 1]["URL"]

tld_counts = {}
total_legit = len(legit_train_urls)
for u in legit_train_urls:
    parsed = urllib.parse.urlparse(u if "://" in u else "http://" + u)
    netloc = parsed.netloc.lower().split(":")[0].replace("www.", "")
    parts = netloc.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld:
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

# Empirical P(TLD | Legit)
tld_prob_map = {tld: round(count / total_legit, 7) for tld, count in tld_counts.items()}

# Ensure common TLDs have non-zero empirical baseline
print(f"Recomputed {len(tld_prob_map)} TLD probabilities from V4-A training data.")
print(f"Sample TLD probs: com={tld_prob_map.get('com')}, org={tld_prob_map.get('org')}, app={tld_prob_map.get('app')}, dev={tld_prob_map.get('dev')}, studio={tld_prob_map.get('studio')}, io={tld_prob_map.get('io')}")

# Load character n-gram distribution from ml/lookup_tables.json
old_lookup = json.load(open(os.path.join(WORKSPACE_DIR, "ml", "lookup_tables.json"), "r"))
char_prob_map = old_lookup.get("char_prob_map", {})

lookup_v4a = {
    "tld_prob_map": tld_prob_map,
    "char_prob_map": char_prob_map
}

lookup_file_path = os.path.join(MODELS_DIR, "lookup_tables_v4a.json")
with open(lookup_file_path, "w", encoding="utf-8") as f:
    json.dump(lookup_v4a, f, indent=2)
print(f"Saved V4-A lookup table to: {lookup_file_path}")

# 7. Feature Extraction for Training and Test Set
print("\nExtracting 21 lexical features for training set...")
start_time = time.time()

# Extract training features
train_features = []
for u in df_v4_train["URL"]:
    train_features.append(fc_v4a.extract_v4a_lexical_features(u, tld_lookup=tld_prob_map))

X_train = pd.DataFrame(train_features)[fc_v4a.PRIMARY_FEATURES]
y_train = df_v4_train["label"].values

print(f"Training features extracted in {time.time() - start_time:.1f}s. Shape: {X_train.shape}")

# Extract test features (using V4-A lookup table learned from training data only)
print("Extracting 21 lexical features for held-out test set...")
test_features = []
for u in test_df["URL"]:
    test_features.append(fc_v4a.extract_v4a_lexical_features(u, tld_lookup=tld_prob_map))

X_test = pd.DataFrame(test_features)[fc_v4a.PRIMARY_FEATURES]
y_test = test_df["label"].values

# 8. Train Random Forest V4-A Classifier
print("\nTraining Random Forest V4-A (100 Trees, class_weight='balanced', random_state=42)...")
rf_v4a = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

rf_v4a.fit(X_train, y_train)

# 9. Save Model
model_save_path = os.path.join(MODELS_DIR, "random_forest_v4a.pkl")
joblib.dump(rf_v4a, model_save_path, compress=3)
print(f"Model saved to: {model_save_path}")

# 10. Evaluation on Held-Out Test Set
y_pred = rf_v4a.predict(X_test)
y_prob = rf_v4a.predict_proba(X_test)

cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
tp_phish = int(cm[0, 0])
fn_phish = int(cm[0, 1])
fp_phish = int(cm[1, 0])
tn_phish = int(cm[1, 1])

acc = accuracy_score(y_test, y_pred)
prec_phish = tp_phish / max(1, (tp_phish + fp_phish))
rec_phish = tp_phish / max(1, (tp_phish + fn_phish))
f1_phish = 2 * (prec_phish * rec_phish) / max(1e-9, (prec_phish + rec_phish))
fpr_phish = fp_phish / max(1, (fp_phish + tn_phish))
fnr_phish = fn_phish / max(1, (tp_phish + fn_phish))

print("\n" + "=" * 80)
print("V4-A HELD-OUT TEST EVALUATION METRICS")
print("=" * 80)
print(f"Accuracy:             {acc * 100:.4f}%")
print(f"Precision (Phishing): {prec_phish * 100:.4f}%")
print(f"Recall (Phishing):    {rec_phish * 100:.4f}%")
print(f"F1 (Phishing):        {f1_phish * 100:.4f}%")
print(f"FPR (Legit Flagged):  {fpr_phish * 100:.4f}% ({fp_phish} / {fp_phish + tn_phish})")
print(f"FNR (Phish Missed):   {fnr_phish * 100:.4f}% ({fn_phish} / {tp_phish + fn_phish})")

v4a_metrics = {
    "model_name": "Random Forest V4-A",
    "training_samples": len(df_v4_train),
    "test_samples": len(test_df),
    "accuracy": float(acc),
    "precision_phishing": float(prec_phish),
    "recall_phishing": float(rec_phish),
    "f1_phishing": float(f1_phish),
    "fpr_on_legitimate": float(fpr_phish),
    "fnr_on_phishing": float(fnr_phish),
    "confusion_matrix": {
        "true_phishing_detected": tp_phish,
        "phishing_missed": fn_phish,
        "legitimate_false_alarms": fp_phish,
        "true_legitimate_passed": tn_phish
    }
}

metrics_path = os.path.join(REPORTS_DIR, "v4a_metrics.json")
with open(metrics_path, "w", encoding="utf-8") as f:
    json.dump(v4a_metrics, f, indent=2)

print(f"Saved V4-A metrics to: {metrics_path}")
