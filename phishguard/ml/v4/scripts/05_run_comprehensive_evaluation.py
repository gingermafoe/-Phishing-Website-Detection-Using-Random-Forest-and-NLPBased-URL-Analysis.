import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
ML_V3_DIR = os.path.join(WORKSPACE_DIR, "ml", "v3")
ML_V4_DIR = os.path.join(WORKSPACE_DIR, "ml", "v4")
MODELS_DIR = os.path.join(ML_V4_DIR, "models")
REPORTS_DIR = os.path.join(ML_V4_DIR, "reports")

sys.path.insert(0, ML_V3_DIR)
sys.path.insert(0, MODELS_DIR)

import feature_config_v3 as fc_v3
import feature_config_v4a as fc_v4a

# Load V3 and V4-A Models
rf_v3 = joblib.load(os.path.join(ML_V3_DIR, "random_forest_v3.pkl"))
rf_v4a = joblib.load(os.path.join(MODELS_DIR, "random_forest_v4a.pkl"))

classes_v3 = list(rf_v3.classes_)
phish_idx_v3 = classes_v3.index(0)

classes_v4a = list(rf_v4a.classes_)
phish_idx_v4a = classes_v4a.index(0)

def predict_v3(url: str):
    f = fc_v3.extract_v3_lexical_features(url)
    df_u = pd.DataFrame([f])[fc_v3.PRIMARY_FEATURES]
    p_phish = float(rf_v3.predict_proba(df_u)[0][phish_idx_v3])
    risk = int(round(p_phish * 100))
    pred = "legitimate" if risk < 50 else "phishing"
    return pred, risk, p_phish, f

def predict_v4a(url: str):
    f = fc_v4a.extract_v4a_lexical_features(url)
    df_u = pd.DataFrame([f])[fc_v4a.PRIMARY_FEATURES]
    p_phish = float(rf_v4a.predict_proba(df_u)[0][phish_idx_v4a])
    risk = int(round(p_phish * 100))
    pred = "legitimate" if risk < 50 else "phishing"
    return pred, risk, p_phish, f

print("=" * 80)
print("1. KLHOLDOUT INDEPENDENT VALIDATION TEST")
print("=" * 80)

HOLDOUTS = [
    "https://klattendance.vercel.app/",
    "https://klhunderground.ai.studio"
]

holdout_results = []
for u in HOLDOUTS:
    p3, r3, prob3, f3 = predict_v3(u)
    p4, r4, prob4, f4 = predict_v4a(u)
    print(f"\nTarget: {u}")
    print(f"  V3 Prediction:  {p3:<10} | Risk: {r3:<3} | P(Phish): {prob3:.4f} | TLDLegProb: {f3['TLDLegitimateProb']:.6f}")
    print(f"  V4-A Prediction:{p4:<10} | Risk: {r4:<3} | P(Phish): {prob4:.4f} | TLDLegProb: {f4['TLDLegitimateProb']:.6f}")
    holdout_results.append({
        "url": u,
        "v3_prediction": p3, "v3_risk": r3, "v3_prob": prob3, "v3_tld_prob": f3['TLDLegitimateProb'],
        "v4a_prediction": p4, "v4a_risk": r4, "v4a_prob": prob4, "v4a_tld_prob": f4['TLDLegitimateProb']
    })

print("\n" + "=" * 80)
print("2. EXISTING V3 REGRESSION FIXTURES (MUST PRESERVE)")
print("=" * 80)

REGRESSION_FIXTURES = [
    "https://google.com",
    "https://www.google.com",
    "https://chatgpt.com",
    "https://github.com/about",
    "https://github.com/search?q=random+forest",
    "https://en.wikipedia.org/wiki/Computer_science",
    "https://docs.python.org/3/library/unittest.html"
]

reg_results = []
print(f"{'URL':<50} | {'V3 Pred':<10} | {'V3 Risk':<7} | {'V4-A Pred':<10} | {'V4-A Risk':<7} | {'Status':<8}")
print("-" * 105)
for u in REGRESSION_FIXTURES:
    p3, r3, prob3, _ = predict_v3(u)
    p4, r4, prob4, _ = predict_v4a(u)
    status = "INTACT" if p4 == "legitimate" and r4 <= 30 else "REGRESSED"
    print(f"{u:<50} | {p3:<10} | {r3:<7} | {p4:<10} | {r4:<7} | {status:<8}")
    reg_results.append({
        "url": u, "v3_pred": p3, "v3_risk": r3, "v4a_pred": p4, "v4a_risk": r4, "status": status
    })

print("\n" + "=" * 80)
print("3. MODERN HOSTING INDEPENDENT BENCHMARK SUITE")
print("=" * 80)

BENCHMARK_HOSTING = [
    # Vercel
    ("https://my-portfolio.vercel.app", "Vercel", "legitimate"),
    ("https://react-dashboard.vercel.app/login", "Vercel", "legitimate"),
    ("https://docs.vercel.app/getting-started", "Vercel", "legitimate"),
    ("https://shop.vercel.app/products?category=shoes", "Vercel", "legitimate"),
    
    # Netlify
    ("https://react-app.netlify.app", "Netlify", "legitimate"),
    ("https://react-app.netlify.app/", "Netlify", "legitimate"),
    ("https://vitejs.netlify.app/docs/intro", "Netlify", "legitimate"),
    ("https://my-site.netlify.app/search?q=react", "Netlify", "legitimate"),
    
    # Cloudflare Pages
    ("https://my-blog.pages.dev", "Cloudflare Pages", "legitimate"),
    ("https://dashboard.pages.dev/analytics", "Cloudflare Pages", "legitimate"),
    ("https://web-app.pages.dev/api/v1/status", "Cloudflare Pages", "legitimate"),
    
    # Firebase
    ("https://my-project.web.app", "Firebase", "legitimate"),
    ("https://my-project.firebaseapp.com", "Firebase", "legitimate"),
    ("https://my-project.firebaseapp.com/dashboard/home", "Firebase", "legitimate"),
    
    # Modern TLDs
    ("https://subdomain.example.app", ".app", "legitimate"),
    ("https://subdomain.example.dev", ".dev", "legitimate"),
    ("https://subdomain.example.ai", ".ai", "legitimate"),
    ("https://subdomain.example.studio", ".studio", "legitimate"),
    ("https://subdomain.example.tech", ".tech", "legitimate"),
    ("https://subdomain.example.io", ".io", "legitimate"),
    ("https://subdomain.example.org", ".org", "legitimate")
]

bench_results = []
print(f"{'URL':<50} | {'Platform':<16} | {'V3 Pred':<10} | {'V3 Risk':<7} | {'V4-A Pred':<10} | {'V4-A Risk':<7}")
print("-" * 115)
for u, plat, expected in BENCHMARK_HOSTING:
    p3, r3, _, _ = predict_v3(u)
    p4, r4, _, _ = predict_v4a(u)
    print(f"{u:<50} | {plat:<16} | {p3:<10} | {r3:<7} | {p4:<10} | {r4:<7}")
    bench_results.append({
        "url": u, "platform": plat, "expected": expected,
        "v3_pred": p3, "v3_risk": r3, "v4a_pred": p4, "v4a_risk": r4
    })

print("\n" + "=" * 80)
print("4. ADVERSARIAL SAME-PLATFORM PHISHING DETECTION TEST")
print("=" * 80)

PAIRED_TESTS = [
    # Vercel
    ("https://zustand.vercel.app", "Vercel Clean (Legit)", "legitimate"),
    ("https://metamask-security-auth.vercel.app/login", "Vercel Phish Lure", "phishing"),
    ("https://chase-bank-verify.vercel.app/account", "Vercel Phish Lure", "phishing"),
    
    # Netlify
    ("https://alpinejs.netlify.app", "Netlify Clean (Legit)", "legitimate"),
    ("https://paypal-update-center.netlify.app/signin", "Netlify Phish Lure", "phishing"),
    ("https://apple-id-verify.netlify.app/recovery", "Netlify Phish Lure", "phishing"),
    
    # Cloudflare Pages
    ("https://cloudflare-docs.pages.dev", "Cloudflare Clean (Legit)", "legitimate"),
    ("https://netflix-billing-update.pages.dev/payment", "Cloudflare Phish Lure", "phishing"),
    
    # Firebase
    ("https://dart-pad.web.app", "Firebase Clean (Legit)", "legitimate"),
    ("https://coinbase-auth-verify.web.app/login", "Firebase Phish Lure", "phishing"),
    ("https://wells-fargo-alert.firebaseapp.com/secure", "Firebase Phish Lure", "phishing"),
    
    # Standard Phishing Fixtures
    ("http://198.98.58.123/", "Raw IP Phishing", "phishing"),
    ("http://www.shprakserf.gq", "HTTP Obscure Phishing", "phishing")
]

pair_results = []
print(f"{'URL':<50} | {'Category':<26} | {'Expected':<10} | {'V3 Pred':<10} | {'V3 Risk':<7} | {'V4-A Pred':<10} | {'V4-A Risk':<7}")
print("-" * 135)
for u, cat, exp in PAIRED_TESTS:
    p3, r3, _, _ = predict_v3(u)
    p4, r4, _, _ = predict_v4a(u)
    print(f"{u:<50} | {cat:<26} | {exp:<10} | {p3:<10} | {r3:<7} | {p4:<10} | {r4:<7}")
    pair_results.append({
        "url": u, "category": cat, "expected": exp,
        "v3_pred": p3, "v3_risk": r3, "v4a_pred": p4, "v4a_risk": r4
    })

eval_summary = {
    "holdout_results": holdout_results,
    "regression_results": reg_results,
    "modern_hosting_benchmark": bench_results,
    "adversarial_paired_tests": pair_results
}

eval_path = os.path.join(REPORTS_DIR, "v4a_evaluation_summary.json")
with open(eval_path, "w", encoding="utf-8") as f:
    json.dump(eval_summary, f, indent=2)
print(f"\nSaved comprehensive evaluation summary to: {eval_path}")
