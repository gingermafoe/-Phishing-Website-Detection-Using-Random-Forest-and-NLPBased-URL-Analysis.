import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
ML_V3_DIR = os.path.join(WORKSPACE_DIR, "ml", "v3")
ML_V4_DIR = os.path.join(WORKSPACE_DIR, "ml", "v4")

sys.path.insert(0, ML_V3_DIR)
import feature_config_v3 as fc_v3

# 1. Load V3 Model
v3_model_path = os.path.join(ML_V3_DIR, "random_forest_v3.pkl")
rf_v3 = joblib.load(v3_model_path)

# 2. Re-create V3 Test Set (identical to train_and_serialize_v3.py)
csv_path = os.path.join(WORKSPACE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
print("Loading dataset for V3 baseline reproduction...")
df = pd.read_csv(csv_path)
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
df["BaseDomain"] = df["Domain"].str.lower().str.replace(r"^www\.", "", regex=True)

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df["BaseDomain"]))
test_df = df.iloc[test_idx].copy().reset_index(drop=True)

print(f"Test samples: {len(test_df):,} | Legit: {(test_df['label']==1).sum():,} | Phish: {(test_df['label']==0).sum():,}")

# Features for test set
X_test = test_df[fc_v3.PRIMARY_FEATURES]
y_test = test_df["label"].values

classes = list(rf_v3.classes_)
phish_idx = classes.index(0)
legit_idx = classes.index(1)

y_pred = rf_v3.predict(X_test)
y_prob = rf_v3.predict_proba(X_test)

# Confusion matrix: tn=0,0 (phishing detected), fp=0,1 (phishing predicted as legit), fn=1,0 (legit predicted as phish), tp=1,1 (legit as legit)
# Let's standardize on Phishing Detection metrics (label 0 = Phishing, label 1 = Legitimate)
# Phishing detected as phishing = True Phish
# Legitimate detected as legitimate = True Legit
cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
# cm[0,0] = Phishing correctly classified as Phishing
# cm[0,1] = Phishing incorrectly classified as Legitimate (Missed Phishing / FN for detector)
# cm[1,0] = Legitimate incorrectly classified as Phishing (False Alarm / FP for detector)
# cm[1,1] = Legitimate correctly classified as Legitimate
tp_phish = int(cm[0, 0])
fn_phish = int(cm[0, 1])
fp_phish = int(cm[1, 0])
tn_phish = int(cm[1, 1])

acc = accuracy_score(y_test, y_pred)
# For phishing detection (pos_label=0):
prec_phish = tp_phish / max(1, (tp_phish + fp_phish))
rec_phish = tp_phish / max(1, (tp_phish + fn_phish))
f1_phish = 2 * (prec_phish * rec_phish) / max(1e-9, (prec_phish + rec_phish))
fpr_phish = fp_phish / max(1, (fp_phish + tn_phish)) # False positive rate on legitimate URLs
fnr_phish = fn_phish / max(1, (tp_phish + fn_phish)) # Miss rate on phishing URLs

baseline_metrics = {
    "model_name": "Random Forest V3 (Production Baseline)",
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

print("\n--- V3 HELD-OUT BASELINE METRICS ---")
print(f"Accuracy:             {acc * 100:.4f}%")
print(f"Precision (Phishing): {prec_phish * 100:.4f}%")
print(f"Recall (Phishing):    {rec_phish * 100:.4f}%")
print(f"F1 (Phishing):        {f1_phish * 100:.4f}%")
print(f"FPR (Legit Flagged):  {fpr_phish * 100:.4f}% ({fp_phish} / {fp_phish + tn_phish})")
print(f"FNR (Phish Missed):   {fnr_phish * 100:.4f}% ({fn_phish} / {tp_phish + fn_phish})")

out_file = os.path.join(ML_V4_DIR, "reports", "v3_baseline_reproduction.json")
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(baseline_metrics, f, indent=2)

print(f"\nSaved baseline metrics to: {out_file}")
