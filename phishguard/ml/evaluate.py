"""
PhishGuard - Machine Learning Evaluation Pipeline
Project Title: Phishing Website Detection Using Random Forest
Phase 1: Dataset Analysis and Random Forest Training

This script:
1. Loads the serialized model(s) and test split.
2. Evaluates the model independently on unseen, held-out test data.
3. Computes:
   - Accuracy
   - Precision
   - Recall
   - F1-score
   - Confusion Matrix
   - Classification Report
4. Displays sample counts and feature importance rankings.
5. Saves an evaluation report to 'evaluation_report.txt'.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Ensure proper utf-8 console output on Windows
sys.stdout.reconfigure(encoding='utf-8')

from feature_config import (
    TARGET_COLUMN,
    LABEL_MAPPING,
    PRIMARY_FEATURES,
    ALL_CLEAN_FEATURES
)


def evaluate_model():
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(ml_dir, "random_forest.pkl")
    full_model_path = os.path.join(ml_dir, "random_forest_full.pkl")
    test_csv_path = os.path.join(ml_dir, "test_sample.csv")
    metadata_path = os.path.join(ml_dir, "model_metadata.json")
    report_path = os.path.join(ml_dir, "evaluation_report.txt")

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}. Run train.py first.")
    if not os.path.exists(test_csv_path):
        raise FileNotFoundError(f"Test split not found at {test_csv_path}. Run train.py first.")

    print("=" * 80)
    print("PHISHGUARD: INDEPENDENT MODEL EVALUATION REPORT")
    print("=" * 80)

    # Load metadata if present
    metadata = {}
    if os.path.exists(metadata_path):
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    # Load test data
    print(f"Loading held-out test data from: {test_csv_path} ...")
    test_df = pd.read_csv(test_csv_path)
    n_test = len(test_df)
    y_test = test_df[TARGET_COLUMN]

    train_samples = metadata.get("dataset_summary", {}).get("train_samples", "N/A")
    print(f"Total Dataset Test Samples:  {n_test:,}")
    print(f"Total Dataset Train Samples: {train_samples:,}" if isinstance(train_samples, int) else f"Train Samples: {train_samples}")
    print(f"Class Breakdown in Test Set: {dict(y_test.value_counts())} (0: Phishing, 1: Legitimate)")

    # --------------------------------------------------------------------------
    # 1. EVALUATE PRIMARY MODEL (URL-ONLY 21 FEATURES)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EVALUATING MODEL 1: PRODUCTION URL-ONLY MODEL (21 Features)")
    print("=" * 80)

    rf_url = joblib.load(model_path)
    X_test_url = test_df[PRIMARY_FEATURES]
    y_pred_url = rf_url.predict(X_test_url)

    acc_url = accuracy_score(y_test, y_pred_url)
    prec_url = precision_score(y_test, y_pred_url)
    rec_url = recall_score(y_test, y_pred_url)
    f1_url = f1_score(y_test, y_pred_url)
    cm_url = confusion_matrix(y_test, y_pred_url)
    cr_url = classification_report(y_test, y_pred_url, digits=4, target_names=["Phishing (0)", "Legitimate (1)"])

    print(f"\n[Primary Model Performance Metrics]")
    print(f"Accuracy:  {acc_url * 100:.4f}% ({acc_url:.6f})")
    print(f"Precision: {prec_url * 100:.4f}% ({prec_url:.6f})")
    print(f"Recall:    {rec_url * 100:.4f}% ({rec_url:.6f})")
    print(f"F1-Score:  {f1_url * 100:.4f}% ({f1_url:.6f})")

    print("\nConfusion Matrix:")
    print(f"                     Predicted Phishing (0)   Predicted Legitimate (1)")
    print(f"Actual Phishing (0)         {cm_url[0][0]:6d}                     {cm_url[0][1]:6d}")
    print(f"Actual Legitimate (1)       {cm_url[1][0]:6d}                     {cm_url[1][1]:6d}")

    # Rates
    tn, fp, fn, tp = cm_url.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    print(f"\nFalse Positive Rate (FPR): {fpr*100:.4f}% ({fp} legitimate URLs falsely flagged as phishing)")
    print(f"False Negative Rate (FNR): {fnr*100:.4f}% ({fn} phishing URLs falsely flagged as legitimate)")

    print("\nDetailed Classification Report:")
    print(cr_url)

    # Top 15 Feature Importances
    imp_url = pd.Series(rf_url.feature_importances_, index=PRIMARY_FEATURES).sort_values(ascending=False)
    print("\nTop 15 Most Important Features (URL-Only Model):")
    print(f"{'Rank':<5} {'Feature Name':<28} {'Importance':<12} {'Cum. Importance'}")
    print("-" * 65)
    cum_sum = 0.0
    top15_lines = []
    for rank, (feat, val) in enumerate(imp_url.head(15).items(), 1):
        cum_sum += val
        line = f"{rank:<5} {feat:<28} {val:.6f}     {cum_sum*100:.2f}%"
        top15_lines.append(line)
        print(line)

    # --------------------------------------------------------------------------
    # 2. EVALUATE BENCHMARK MODEL (ALL-CLEAN 49 FEATURES)
    # --------------------------------------------------------------------------
    full_report_text = ""
    if os.path.exists(full_model_path):
        print("\n" + "=" * 80)
        print("EVALUATING MODEL 2: ALL-CLEAN BENCHMARK MODEL (49 Features: URL + HTML)")
        print("=" * 80)

        rf_all = joblib.load(full_model_path)
        X_test_all = test_df[ALL_CLEAN_FEATURES]
        y_pred_all = rf_all.predict(X_test_all)

        acc_all = accuracy_score(y_test, y_pred_all)
        prec_all = precision_score(y_test, y_pred_all)
        rec_all = recall_score(y_test, y_pred_all)
        f1_all = f1_score(y_test, y_pred_all)
        cm_all = confusion_matrix(y_test, y_pred_all)
        cr_all = classification_report(y_test, y_pred_all, digits=4, target_names=["Phishing (0)", "Legitimate (1)"])

        print(f"\n[Benchmark Model Performance Metrics]")
        print(f"Accuracy:  {acc_all * 100:.4f}% ({acc_all:.6f})")
        print(f"Precision: {prec_all * 100:.4f}% ({prec_all:.6f})")
        print(f"Recall:    {rec_all * 100:.4f}% ({rec_all:.6f})")
        print(f"F1-Score:  {f1_all * 100:.4f}% ({f1_all:.6f})")

        print("\nConfusion Matrix:")
        print(f"                     Predicted Phishing (0)   Predicted Legitimate (1)")
        print(f"Actual Phishing (0)         {cm_all[0][0]:6d}                     {cm_all[0][1]:6d}")
        print(f"Actual Legitimate (1)       {cm_all[1][0]:6d}                     {cm_all[1][1]:6d}")

        imp_all = pd.Series(rf_all.feature_importances_, index=ALL_CLEAN_FEATURES).sort_values(ascending=False)
        print("\nTop 15 Most Important Features (All-Clean Benchmark Model):")
        print(f"{'Rank':<5} {'Feature Name':<28} {'Importance':<12} {'Cum. Importance'}")
        print("-" * 65)
        cum_sum_all = 0.0
        top15_all_lines = []
        for rank, (feat, val) in enumerate(imp_all.head(15).items(), 1):
            cum_sum_all += val
            line = f"{rank:<5} {feat:<28} {val:.6f}     {cum_sum_all*100:.2f}%"
            top15_all_lines.append(line)
            print(line)

    # --------------------------------------------------------------------------
    # WRITE REPORT TO FILE
    # --------------------------------------------------------------------------
    report_content = f"""================================================================================
PHISHGUARD: EVALUATION REPORT
Project Title: Phishing Website Detection Using Random Forest
Phase 1: Dataset Analysis and Random Forest Training
================================================================================

1. DATASET SAMPLE COUNTS
--------------------------------------------------------------------------------
- Training Samples: {train_samples:,}
- Testing Samples:  {n_test:,} (20% Stratified Split, random_state=42)
- Total Clean URLs: {n_test + (train_samples if isinstance(train_samples, int) else 0):,}

2. PRIMARY MODEL: PRODUCTION URL-ONLY MODEL (21 Features)
--------------------------------------------------------------------------------
- Accuracy:  {acc_url * 100:.4f}% ({acc_url:.6f})
- Precision: {prec_url * 100:.4f}% ({prec_url:.6f})
- Recall:    {rec_url * 100:.4f}% ({rec_url:.6f})
- F1-Score:  {f1_url * 100:.4f}% ({f1_url:.6f})

Confusion Matrix:
                     Predicted Phishing (0)   Predicted Legitimate (1)
Actual Phishing (0)         {cm_url[0][0]:6d}                     {cm_url[0][1]:6d}
Actual Legitimate (1)       {cm_url[1][0]:6d}                     {cm_url[1][1]:6d}

Rates:
- False Positive Rate: {fpr*100:.4f}%
- False Negative Rate: {fnr*100:.4f}%

Classification Report:
{cr_url}

Top 15 Most Important Features (URL-Only Model):
{chr(10).join(top15_lines)}

3. BENCHMARK MODEL: ALL-CLEAN MODEL (49 Features: URL + HTML)
--------------------------------------------------------------------------------
- Accuracy:  {acc_all * 100:.4f}% ({acc_all:.6f})
- Precision: {prec_all * 100:.4f}% ({prec_all:.6f})
- Recall:    {rec_all * 100:.4f}% ({rec_all:.6f})
- F1-Score:  {f1_all * 100:.4f}% ({f1_all:.6f})

Confusion Matrix:
                     Predicted Phishing (0)   Predicted Legitimate (1)
Actual Phishing (0)         {cm_all[0][0]:6d}                     {cm_all[0][1]:6d}
Actual Legitimate (1)       {cm_all[1][0]:6d}                     {cm_all[1][1]:6d}

Top 15 Most Important Features (All-Clean Benchmark Model):
{chr(10).join(top15_all_lines if 'top15_all_lines' in locals() else [])}
================================================================================
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"\nFull evaluation report saved to: {report_path}")


if __name__ == "__main__":
    evaluate_model()
