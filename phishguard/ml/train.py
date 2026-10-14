"""
PhishGuard - Machine Learning Training Pipeline
Project Title: Phishing Website Detection Using Random Forest
Phase 1: Dataset Analysis and Random Forest Training

This script:
1. Safely loads the PhiUSIIL Phishing URL Dataset.
2. Performs full dataset inspection (schema, missing values, duplicates, class distribution).
3. Analyzes and mitigates data leakage:
   - Drops duplicate URLs to avoid train-test contamination.
   - Excludes high-cardinality string identifiers (URL, Domain, TLD, Title).
   - Excludes target leakage column (URLSimilarityIndex).
4. Configures and trains a Random Forest Classifier using stratified splitting.
5. Evaluates model performance using standard cybersecurity classification metrics.
6. Analyzes and saves top feature importances.
7. Serializes the trained model and metadata for Phase 2 FastAPI integration.
"""

import os
import sys
import json
import time
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
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

# Import feature definitions
from feature_config import (
    TARGET_COLUMN,
    LABEL_MAPPING,
    RAW_IDENTIFIERS,
    LEAKAGE_FEATURES,
    URL_LEXICAL_FEATURES,
    HTML_CONTENT_FEATURES,
    ALL_CLEAN_FEATURES,
    PRIMARY_FEATURES
)


def load_and_inspect_dataset(csv_path: str):
    """
    Task 1: Safely loads the dataset and prints comprehensive schema diagnostics.
    """
    print("=" * 80)
    print("TASK 1: DATASET INSPECTION & SCHEMA VERIFICATION")
    print("=" * 80)
    
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")
        
    print(f"Loading CSV from: {csv_path} ...")
    start_t = time.time()
    df = pd.read_csv(csv_path)
    load_duration = time.time() - start_t
    print(f"Dataset successfully loaded in {load_duration:.2f} seconds.")
    
    num_rows, num_cols = df.shape
    print(f"\n1. Dataset Dimensions:")
    print(f"   - Total Rows:    {num_rows:,}")
    print(f"   - Total Columns: {num_cols}")
    
    print(f"\n2. Columns & Data Types:")
    for idx, col in enumerate(df.columns):
        dtype_str = str(df[col].dtype)
        missing_count = int(df[col].isnull().sum())
        nunique_count = int(df[col].nunique())
        print(f"   [{idx+1:02d}] {col:<28} | Type: {dtype_str:<8} | Missing: {missing_count} | Unique: {nunique_count:,}")
        
    print(f"\n3. Missing Value Analysis:")
    total_missing = df.isnull().sum().sum()
    print(f"   - Total Missing Cells across entire dataset: {total_missing}")
    if total_missing == 0:
        print("   - Assessment: Complete dataset with zero null values across all 55 columns.")
        
    print(f"\n4. Duplicate Row Analysis:")
    exact_duplicates = df.duplicated().sum()
    print(f"   - Identical full-row duplicates: {exact_duplicates}")
    if "URL" in df.columns:
        url_duplicates = df.duplicated(subset=["URL"]).sum()
        print(f"   - Duplicate URL occurrences: {url_duplicates}")
        
    print(f"\n5. Target Column & Class Distribution:")
    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Expected target column '{TARGET_COLUMN}' not found in dataset!")
        
    counts = df[TARGET_COLUMN].value_counts()
    percents = df[TARGET_COLUMN].value_counts(normalize=True) * 100
    for val, count in counts.items():
        label_name = LABEL_MAPPING.get(val, f"Class {val}")
        pct = percents[val]
        print(f"   - {label_name} ({TARGET_COLUMN} = {val}): {count:,} samples ({pct:.2f}%)")
        
    return df


def audit_data_leakage_and_clean(df: pd.DataFrame):
    """
    Task 2: Detailed investigation of target leakage, duplicate URLs,
    and operational availability of features.
    """
    print("\n" + "=" * 80)
    print("TASK 2: DATA LEAKAGE AUDIT & PREPROCESSING")
    print("=" * 80)
    
    # 1. Target Leakage in URLSimilarityIndex
    print("\n[Audit Item A] Target Leakage in 'URLSimilarityIndex':")
    if "URLSimilarityIndex" in df.columns:
        legit_sim = df[df[TARGET_COLUMN] == 1]["URLSimilarityIndex"]
        phish_sim = df[df[TARGET_COLUMN] == 0]["URLSimilarityIndex"]
        print(f"   - Legitimate (label=1) URLSimilarityIndex: Min={legit_sim.min()}, Max={legit_sim.max()}, Mean={legit_sim.mean():.4f}, Std={legit_sim.std():.4f}")
        print(f"   - Phishing   (label=0) URLSimilarityIndex: Min={phish_sim.min():.4f}, Max={phish_sim.max()}, Mean={phish_sim.mean():.4f}, Std={phish_sim.std():.4f}")
        pct_legit_100 = (legit_sim == 100.0).mean() * 100
        print(f"   - Observation: Exactly {pct_legit_100:.2f}% of legitimate URLs have URLSimilarityIndex == 100.0.")
        print(f"   - Rationale: The dataset creators computed similarity against a legitimate benchmark list containing these exact URLs.")
        print(f"   - Decision: EXCLUDE 'URLSimilarityIndex' to eliminate artificial target leakage.")
        
    # 2. Duplicate URLs and Train-Test Contamination
    print("\n[Audit Item B] Duplicate URLs:")
    dup_url_count = df.duplicated(subset=["URL"]).sum()
    print(f"   - Detected {dup_url_count} duplicate URL entries ({dup_url_count * 2} rows involved).")
    print(f"   - Rationale: If identical URLs appear in both training and test sets, the model memorizes exact URLs instead of learning general patterns.")
    print(f"   - Decision: Remove duplicate URLs, retaining the first instance.")
    df_clean = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
    print(f"   - Clean dataset size: {len(df_clean):,} unique URL records.")

    # 3. Raw Identifiers vs Features
    print("\n[Audit Item C] Unstructured Text / High-Cardinality Identifiers:")
    print(f"   - Identified columns: {RAW_IDENTIFIERS}")
    print(f"   - Rationale: 'URL' ({df['URL'].nunique():,} unique), 'Domain' ({df['Domain'].nunique():,} unique), 'Title' ({df['Title'].nunique():,} unique) are raw strings.")
    print(f"     Directly feeding these into a tree classifier causes catastrophic overfitting or requires NLP (which is prohibited).")
    print(f"   - Decision: EXCLUDE all raw text identifiers.")

    # 4. Operational Availability (URL Lexical vs HTML Content)
    print("\n[Audit Item D] Operational Availability at Inference Time:")
    print(f"   - URL Lexical Features ({len(URL_LEXICAL_FEATURES)} features): Instantly extractable from URL string (<1ms, no network I/O, safe).")
    print(f"   - HTML Content Features ({len(HTML_CONTENT_FEATURES)} features): Require live HTTP GET, DOM parsing, and JavaScript execution.")
    print(f"     Cybersecurity Limitation: Over 60% of phishing sites are taken down within 24 hours. A model requiring HTML content")
    print(f"     fails whenever a URL is offline, times out, or delivers a malicious exploit.")
    print(f"   - Decision: Train the production model primarily on the 21 URL lexical features to guarantee reliable, real-time FastAPI inference,")
    print(f"     while simultaneously training a 49-feature benchmark model for complete dataset comparison.")

    return df_clean, dup_url_count


def train_random_forest(df_clean: pd.DataFrame, dup_url_count: int = 425):
    """
    Task 3 & 4: Trains the Random Forest models and evaluates on a stratified test set.
    """
    print("\n" + "=" * 80)
    print("TASK 3 & 4: MODEL TRAINING & RIGOROUS EVALUATION")
    print("=" * 80)

    # Stratified Train/Test Split (80% Train, 20% Test)
    test_size = 0.20
    random_state = 42
    print(f"\nSplitting data: {100*(1-test_size):.0f}% Train / {100*test_size:.0f}% Test (Stratified, random_state={random_state})...")
    
    train_df, test_df = train_test_split(
        df_clean,
        test_size=test_size,
        random_state=random_state,
        stratify=df_clean[TARGET_COLUMN]
    )

    n_train = len(train_df)
    n_test = len(test_df)
    train_dist = train_df[TARGET_COLUMN].value_counts().to_dict()
    test_dist = test_df[TARGET_COLUMN].value_counts().to_dict()

    print(f"Training Samples: {n_train:,} (Legitimate: {train_dist.get(1, 0):,}, Phishing: {train_dist.get(0, 0):,})")
    print(f"Testing  Samples: {n_test:,} (Legitimate: {test_dist.get(1, 0):,}, Phishing: {test_dist.get(0, 0):,})")

    # Hyperparameters
    rf_params = {
        "n_estimators": 100,
        "max_depth": None,
        "min_samples_split": 2,
        "min_samples_leaf": 1,
        "class_weight": "balanced",
        "random_state": random_state,
        "n_jobs": -1
    }

    print("\nRandom Forest Hyperparameters:")
    for k, v in rf_params.items():
        print(f"   - {k}: {v}")

    # --------------------------------------------------------------------------
    # MODEL 1: PRODUCTION URL-ONLY MODEL (21 Features)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TRAINING MODEL 1: Production URL-Only Lexical Model (21 Features)")
    print("-" * 70)
    
    X_train_url = train_df[PRIMARY_FEATURES]
    y_train = train_df[TARGET_COLUMN]
    X_test_url = test_df[PRIMARY_FEATURES]
    y_test = test_df[TARGET_COLUMN]

    t0 = time.time()
    rf_url = RandomForestClassifier(**rf_params)
    rf_url.fit(X_train_url, y_train)
    t_train_url = time.time() - t0
    print(f"Training completed in {t_train_url:.2f} seconds.")

    y_pred_url = rf_url.predict(X_test_url)
    
    acc_url = accuracy_score(y_test, y_pred_url)
    prec_url = precision_score(y_test, y_pred_url)
    rec_url = recall_score(y_test, y_pred_url)
    f1_url = f1_score(y_test, y_pred_url)
    cm_url = confusion_matrix(y_test, y_pred_url)
    cr_url = classification_report(y_test, y_pred_url, digits=4, target_names=["Phishing (0)", "Legitimate (1)"])

    print("\n[Evaluation Metrics - URL-Only Model]")
    print(f"Accuracy:  {acc_url * 100:.4f}% ({acc_url:.6f})")
    print(f"Precision: {prec_url * 100:.4f}% ({prec_url:.6f})")
    print(f"Recall:    {rec_url * 100:.4f}% ({rec_url:.6f})")
    print(f"F1-Score:  {f1_url * 100:.4f}% ({f1_url:.6f})")

    print("\nConfusion Matrix (Rows: Actual, Columns: Predicted):")
    print(f"                 Pred Phish (0)  Pred Legit (1)")
    print(f"Actual Phish (0)     {cm_url[0][0]:6d}          {cm_url[0][1]:6d}")
    print(f"Actual Legit (1)     {cm_url[1][0]:6d}          {cm_url[1][1]:6d}")

    print("\nDetailed Classification Report:")
    print(cr_url)

    # --------------------------------------------------------------------------
    # MODEL 2: ALL-CLEAN BENCHMARK MODEL (49 Features)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TRAINING MODEL 2: Full Dataset Clean Benchmark (49 Features: URL + HTML)")
    print("-" * 70)
    
    X_train_all = train_df[ALL_CLEAN_FEATURES]
    X_test_all = test_df[ALL_CLEAN_FEATURES]

    t0 = time.time()
    rf_all = RandomForestClassifier(**rf_params)
    rf_all.fit(X_train_all, y_train)
    t_train_all = time.time() - t0
    print(f"Training completed in {t_train_all:.2f} seconds.")

    y_pred_all = rf_all.predict(X_test_all)
    
    acc_all = accuracy_score(y_test, y_pred_all)
    prec_all = precision_score(y_test, y_pred_all)
    rec_all = recall_score(y_test, y_pred_all)
    f1_all = f1_score(y_test, y_pred_all)
    cm_all = confusion_matrix(y_test, y_pred_all)
    cr_all = classification_report(y_test, y_pred_all, digits=4, target_names=["Phishing (0)", "Legitimate (1)"])

    print("\n[Evaluation Metrics - All-Clean Benchmark Model]")
    print(f"Accuracy:  {acc_all * 100:.4f}% ({acc_all:.6f})")
    print(f"Precision: {prec_all * 100:.4f}% ({prec_all:.6f})")
    print(f"Recall:    {rec_all * 100:.4f}% ({rec_all:.6f})")
    print(f"F1-Score:  {f1_all * 100:.4f}% ({f1_all:.6f})")

    # --------------------------------------------------------------------------
    # TASK 5: FEATURE IMPORTANCES
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TASK 5: FEATURE IMPORTANCE ANALYSIS (TOP 15)")
    print("=" * 80)
    
    imp_url = pd.Series(rf_url.feature_importances_, index=PRIMARY_FEATURES).sort_values(ascending=False)
    print("\nTop 15 Most Important Features (Production URL-Only Model):")
    print(f"{'Rank':<5} {'Feature Name':<28} {'Importance':<12} {'Cum. Importance'}")
    print("-" * 65)
    cum_sum = 0.0
    top15_url = []
    for rank, (feat, val) in enumerate(imp_url.head(15).items(), 1):
        cum_sum += val
        top15_url.append({"rank": rank, "feature": feat, "importance": float(val), "cumulative": float(cum_sum)})
        print(f"{rank:<5} {feat:<28} {val:.6f}     {cum_sum*100:.2f}%")

    imp_all = pd.Series(rf_all.feature_importances_, index=ALL_CLEAN_FEATURES).sort_values(ascending=False)
    print("\nTop 15 Most Important Features (All-Clean Benchmark Model):")
    print(f"{'Rank':<5} {'Feature Name':<28} {'Importance':<12} {'Cum. Importance'}")
    print("-" * 65)
    cum_sum_all = 0.0
    top15_all = []
    for rank, (feat, val) in enumerate(imp_all.head(15).items(), 1):
        cum_sum_all += val
        top15_all.append({"rank": rank, "feature": feat, "importance": float(val), "cumulative": float(cum_sum_all)})
        print(f"{rank:<5} {feat:<28} {val:.6f}     {cum_sum_all*100:.2f}%")

    # --------------------------------------------------------------------------
    # TASK 6: SAVE ARTIFACTS
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TASK 6: SAVING MODEL & SERIALIZING METADATA")
    print("=" * 80)
    
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(ml_dir, "random_forest.pkl")
    benchmark_model_path = os.path.join(ml_dir, "random_forest_full.pkl")
    metadata_path = os.path.join(ml_dir, "model_metadata.json")

    print(f"Saving primary production model to: {model_path} ...")
    joblib.dump(rf_url, model_path, compress=3)
    print(f"Saving full clean benchmark model to: {benchmark_model_path} ...")
    joblib.dump(rf_all, benchmark_model_path, compress=3)

    # Save test dataset indices or sample for independent evaluation in evaluate.py
    test_csv_path = os.path.join(ml_dir, "test_sample.csv")
    test_df.to_csv(test_csv_path, index=False)
    print(f"Saved held-out test split ({len(test_df):,} rows) to: {test_csv_path}")

    metadata = {
        "project_title": "Phishing Website Detection Using Random Forest",
        "phase": "PHASE 1 - Dataset Analysis and Random Forest Training",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_summary": {
            "source": "PhiUSIIL Phishing URL Dataset",
            "total_raw_rows": int(len(df_clean) + dup_url_count),
            "duplicate_urls_removed": int(dup_url_count),
            "clean_rows": int(len(df_clean)),
            "total_columns": int(df_clean.shape[1]),
            "train_samples": int(n_train),
            "test_samples": int(n_test),
            "train_distribution": {str(k): int(v) for k, v in train_dist.items()},
            "test_distribution": {str(k): int(v) for k, v in test_dist.items()}
        },
        "feature_selection": {
            "excluded_identifiers": RAW_IDENTIFIERS,
            "excluded_leakage": LEAKAGE_FEATURES,
            "primary_url_features_count": len(PRIMARY_FEATURES),
            "primary_url_features": PRIMARY_FEATURES,
            "html_content_features_count": len(HTML_CONTENT_FEATURES),
            "html_content_features": HTML_CONTENT_FEATURES,
            "all_clean_features_count": len(ALL_CLEAN_FEATURES)
        },
        "hyperparameters": rf_params,
        "production_model_metrics": {
            "feature_set": "URL_LEXICAL_FEATURES (21 features)",
            "training_time_seconds": round(t_train_url, 2),
            "accuracy": float(acc_url),
            "precision": float(prec_url),
            "recall": float(rec_url),
            "f1_score": float(f1_url),
            "confusion_matrix": {
                "true_negative_phishing": int(cm_url[0][0]),
                "false_positive_legit": int(cm_url[0][1]),
                "false_negative_phish": int(cm_url[1][0]),
                "true_positive_legit": int(cm_url[1][1])
            },
            "top_15_features": top15_url
        },
        "benchmark_full_model_metrics": {
            "feature_set": "ALL_CLEAN_FEATURES (49 features)",
            "training_time_seconds": round(t_train_all, 2),
            "accuracy": float(acc_all),
            "precision": float(prec_all),
            "recall": float(rec_all),
            "f1_score": float(f1_all),
            "confusion_matrix": {
                "true_negative_phishing": int(cm_all[0][0]),
                "false_positive_legit": int(cm_all[0][1]),
                "false_negative_phish": int(cm_all[1][0]),
                "true_positive_legit": int(cm_all[1][1])
            },
            "top_15_features": top15_all
        }
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata and configuration saved to: {metadata_path}")
    print("\nTraining and Phase 1 Pipeline Completed Successfully!")


if __name__ == "__main__":
    # Base paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    csv_file = os.path.join(project_root, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")

    raw_df = load_and_inspect_dataset(csv_file)
    cleaned_df, dup_url_count = audit_data_leakage_and_clean(raw_df)
    train_random_forest(cleaned_df, dup_url_count)
