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
import feature_config_v4b as fc_v4b

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
print("PHISHGUARD V4-B TRAINING & EVALUATION PIPELINE (LAPLACE SMOOTHING & SUBDOMAIN BALANCE)")
print("=" * 80)

# 1. Base PhiUSIIL dataset
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

# 3. Load Curated Legitimate Modern Hosting Samples
legit_curated_path = os.path.join(DATASET_DIR, "v4_legitimate_curated.csv")
df_legit_curated = pd.read_csv(legit_curated_path)

for u in df_legit_curated["URL"]:
    assert not is_forbidden(u), f"CRITICAL: Forbidden URL in curated set: {u}"

df_legit_curated["BaseDomain"] = df_legit_curated["URL"].apply(
    lambda u: urllib.parse.urlparse(u).netloc.lower().replace("www.", "")
)

gss_curated = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
c_tr_idx, c_te_idx = next(gss_curated.split(df_legit_curated, groups=df_legit_curated["BaseDomain"]))
curated_train = df_legit_curated.iloc[c_tr_idx].copy().reset_index(drop=True)

# Verify no domain overlap
c_tr_doms = set(curated_train["BaseDomain"])
c_te_doms = set(df_legit_curated.iloc[c_te_idx]["BaseDomain"])
assert len(c_tr_doms.intersection(c_te_doms)) == 0, "Curated domain leakage!"

# 4. Integrate into Training Pool with Full Subdomain and Structural Diversity
legit_train = train_df[train_df["label"] == 1].copy().reset_index(drop=True)
phish_train = train_df[train_df["label"] == 0].copy().reset_index(drop=True)

train_urls = []
train_labels = []

# Base root legitimate: 50% apex / 50% www
for idx, row in legit_train.iterrows():
    base = row["BaseDomain"]
    u = f"https://{base}" if idx % 2 == 0 else f"https://www.{base}"
    if not is_forbidden(u):
        train_urls.append(u)
        train_labels.append(1)

# Full structural & subdomain augmentation (restoring V3 balanced subdomains)
SUBDOMAINS = ["docs", "support", "en", "developer", "api", "blog", "community", "help", "dev", "app", "wiki"]
PATHS_SINGLE = ["about", "contact", "privacy", "terms", "faq", "blog", "services", "products", "login", "careers", "security", "overview"]
PATHS_MULTI = [
    ("docs", "getting-started"), ("api", "v1"), ("help", "center"),
    ("wiki", "Computer_science"), ("3", "library", "unittest.html"), ("torvalds", "linux")
]
QUERIES = [("q", "cybersecurity"), ("q", "machine+learning"), ("q", "python"), ("q", "random+forest"), ("lang", "en")]

random.seed(42)
sample_domains = random.sample(list(legit_train["BaseDomain"]), 45000)
for i, base in enumerate(sample_domains):
    mod = i % 10
    if mod == 0:
        u = f"https://{base}/{random.choice(PATHS_SINGLE)}"
    elif mod == 1:
        p = "/".join(random.choice(PATHS_MULTI))
        u = f"https://{base}/{p}"
    elif mod == 2:
        k, v = random.choice(QUERIES)
        u = f"https://{base}/search?{k}={v}"
    elif mod == 3:
        # Legitimate Subdomain + path (vital for Wikipedia / docs generalization)
        sub = random.choice(SUBDOMAINS)
        p = random.choice(PATHS_SINGLE)
        u = f"https://{sub}.{base}/{p}"
    elif mod == 4:
        # Legitimate Subdomain + deep path
        sub = random.choice(SUBDOMAINS)
        p = "/".join(random.choice(PATHS_MULTI))
        u = f"https://{sub}.{base}/{p}"
    elif mod == 5:
        # Legitimate Subdomain + query
        sub = random.choice(SUBDOMAINS)
        k, v = random.choice(QUERIES)
        u = f"https://{sub}.{base}/search?{k}={v}"
    elif mod == 6:
        # Bare Subdomain root
        sub = random.choice(SUBDOMAINS)
        u = f"https://{sub}.{base}/"
    elif mod == 7:
        u = f"https://www.{base}/docs#installation"
    elif mod == 8:
        u = f"https://{base}/explore?q=python&sort=relevance"
    else:
        p = "/".join(random.choice(PATHS_MULTI))
        u = f"https://www.{base}/{p}"
        
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

df_v4b_train = pd.DataFrame({
    "URL": train_urls,
    "label": train_labels
}).drop_duplicates(subset=["URL"]).reset_index(drop=True)

print(f"\nV4-B Training pool: {len(df_v4b_train):,} (Legit={(df_v4b_train['label']==1).sum():,}, Phish={(df_v4b_train['label']==0).sum():,})")

# Strict Holdout Verification
for u in df_v4b_train["URL"]:
    assert not is_forbidden(u), f"CRITICAL LEAKAGE IN V4-B TRAINING: {u}"

# 5. Laplace-Smoothed TLD Probability Computation
print("\nComputing Laplace-smoothed TLD probabilities from V4-B training distribution...")
legit_train_urls = df_v4b_train[df_v4b_train["label"] == 1]["URL"]

tld_counts = {}
total_legit = len(legit_train_urls)
for u in legit_train_urls:
    parsed = urllib.parse.urlparse(u if "://" in u else "http://" + u)
    netloc = parsed.netloc.lower().split(":")[0].replace("www.", "")
    parts = netloc.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld:
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

# Laplace smoothing parameter: alpha = 10.0
alpha = 10.0
V = len(tld_counts)
tld_prob_map_smoothed = {}
for tld, count in tld_counts.items():
    smoothed_prob = (count + alpha) / (total_legit + alpha * V)
    tld_prob_map_smoothed[tld] = round(smoothed_prob, 7)

# Default smoothed probability for unseen TLDs
default_smoothed = alpha / (total_legit + alpha * V)
tld_prob_map_smoothed["__default__"] = round(default_smoothed, 7)

print(f"Sample smoothed TLD probs (alpha={alpha}):")
print(f"  .com:    {tld_prob_map_smoothed.get('com')}")
print(f"  .org:    {tld_prob_map_smoothed.get('org')}")
print(f"  .net:    {tld_prob_map_smoothed.get('net')}")
print(f"  .app:    {tld_prob_map_smoothed.get('app')}")
print(f"  .dev:    {tld_prob_map_smoothed.get('dev')}")
print(f"  .studio: {tld_prob_map_smoothed.get('studio')}")
print(f"  .tech:   {tld_prob_map_smoothed.get('tech')}")
print(f"  .io:     {tld_prob_map_smoothed.get('io')}")

old_lookup = json.load(open(os.path.join(WORKSPACE_DIR, "ml", "lookup_tables.json"), "r"))
char_prob_map = old_lookup.get("char_prob_map", {})

lookup_v4b = {
    "tld_prob_map": tld_prob_map_smoothed,
    "char_prob_map": char_prob_map,
    "alpha": alpha,
    "total_legit_train": total_legit
}

lookup_file_path = os.path.join(MODELS_DIR, "lookup_tables_v4b.json")
with open(lookup_file_path, "w", encoding="utf-8") as f:
    json.dump(lookup_v4b, f, indent=2)
print(f"Saved V4-B lookup table to: {lookup_file_path}")

# 6. Extract Features & Train V4-B
print("\nExtracting features for V4-B training...")
train_features = [
    fc_v4b.extract_v4b_lexical_features(u, tld_lookup=tld_prob_map_smoothed)
    for u in df_v4b_train["URL"]
]
X_train = pd.DataFrame(train_features)[fc_v4b.PRIMARY_FEATURES]
y_train = df_v4b_train["label"].values

print("Extracting features for V4-B test set...")
test_features = [
    fc_v4b.extract_v4b_lexical_features(u, tld_lookup=tld_prob_map_smoothed)
    for u in test_df["URL"]
]
X_test = pd.DataFrame(test_features)[fc_v4b.PRIMARY_FEATURES]
y_test = test_df["label"].values

print("\nTraining Random Forest V4-B (100 Trees, class_weight='balanced', random_state=42)...")
rf_v4b = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf_v4b.fit(X_train, y_train)

model_save_path = os.path.join(MODELS_DIR, "random_forest_v4b.pkl")
joblib.dump(rf_v4b, model_save_path, compress=3)
print(f"Model saved to: {model_save_path}")

# 7. Evaluate Held-Out Test Set
y_pred = rf_v4b.predict(X_test)
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
print("V4-B HELD-OUT TEST EVALUATION METRICS")
print("=" * 80)
print(f"Accuracy:             {acc * 100:.4f}%")
print(f"Precision (Phishing): {prec_phish * 100:.4f}%")
print(f"Recall (Phishing):    {rec_phish * 100:.4f}%")
print(f"F1 (Phishing):        {f1_phish * 100:.4f}%")
print(f"FPR (Legit Flagged):  {fpr_phish * 100:.4f}% ({fp_phish} / {fp_phish + tn_phish})")
print(f"FNR (Phish Missed):   {fnr_phish * 100:.4f}% ({fn_phish} / {tp_phish + fn_phish})")

v4b_metrics = {
    "model_name": "Random Forest V4-B",
    "training_samples": len(df_v4b_train),
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

metrics_path = os.path.join(REPORTS_DIR, "v4b_metrics.json")
with open(metrics_path, "w", encoding="utf-8") as f:
    json.dump(v4b_metrics, f, indent=2)

print(f"Saved V4-B metrics to: {metrics_path}")
