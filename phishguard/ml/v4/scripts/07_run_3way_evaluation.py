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
import feature_config_v4b as fc_v4b

# Load V3, V4-A, and V4-B models
rf_v3 = joblib.load(os.path.join(ML_V3_DIR, "random_forest_v3.pkl"))
rf_v4a = joblib.load(os.path.join(MODELS_DIR, "random_forest_v4a.pkl"))
rf_v4b = joblib.load(os.path.join(MODELS_DIR, "random_forest_v4b.pkl"))

def predict(model, fc_module, url: str):
    f = fc_module.extract_v3_lexical_features(url) if hasattr(fc_module, "extract_v3_lexical_features") else \
        (fc_module.extract_v4a_lexical_features(url) if hasattr(fc_module, "extract_v4a_lexical_features") else \
         fc_module.extract_v4b_lexical_features(url))
    df_u = pd.DataFrame([f])[fc_module.PRIMARY_FEATURES]
    p_phish = float(model.predict_proba(df_u)[0][list(model.classes_).index(0)])
    risk = int(round(p_phish * 100))
    pred = "legitimate" if risk < 50 else "phishing"
    return pred, risk, p_phish, f

print("=" * 95)
print("3-WAY COMPARATIVE BENCHMARK: V3 (Production) vs V4-A (Data) vs V4-B (Smoothed + Balanced)")
print("=" * 95)

# 1. Holdouts
print("\n--- 1. INDEPENDENT HOLDOUTS ---")
HOLDOUTS = [
    "https://klattendance.vercel.app/",
    "https://klhunderground.ai.studio"
]
for u in HOLDOUTS:
    p3, r3, prob3, f3 = predict(rf_v3, fc_v3, u)
    p4a, r4a, prob4a, f4a = predict(rf_v4a, fc_v4a, u)
    p4b, r4b, prob4b, f4b = predict(rf_v4b, fc_v4b, u)
    print(f"\nTarget: {u}")
    print(f"  V3:   Pred={p3:<10} | Risk={r3:<3} | P(Phish)={prob3:.4f} | TLDProb={f3['TLDLegitimateProb']:.6f}")
    print(f"  V4-A: Pred={p4a:<10} | Risk={r4a:<3} | P(Phish)={prob4a:.4f} | TLDProb={f4a['TLDLegitimateProb']:.6f}")
    print(f"  V4-B: Pred={p4b:<10} | Risk={r4b:<3} | P(Phish)={prob4b:.4f} | TLDProb={f4b['TLDLegitimateProb']:.6f}")

# 2. Existing Regression Fixtures
print("\n--- 2. EXISTING REGRESSION FIXTURES ---")
REGRESSION_FIXTURES = [
    "https://google.com",
    "https://www.google.com",
    "https://chatgpt.com",
    "https://github.com/about",
    "https://github.com/search?q=random+forest",
    "https://en.wikipedia.org/wiki/Computer_science",
    "https://docs.python.org/3/library/unittest.html"
]

print(f"{'URL':<48} | {'V3 Risk':<8} | {'V4-A Risk':<10} | {'V4-B Risk':<10} | {'V4-B Status':<12}")
print("-" * 95)
for u in REGRESSION_FIXTURES:
    _, r3, _, _ = predict(rf_v3, fc_v3, u)
    _, r4a, _, _ = predict(rf_v4a, fc_v4a, u)
    p4b, r4b, _, _ = predict(rf_v4b, fc_v4b, u)
    status = "INTACT" if p4b == "legitimate" and r4b <= 20 else "REGRESSED"
    print(f"{u:<48} | {r3:<8} | {r4a:<10} | {r4b:<10} | {status:<12}")

# 3. Modern Hosting Benchmark
print("\n--- 3. MODERN HOSTING BENCHMARK ---")
BENCHMARK_HOSTING = [
    ("https://my-portfolio.vercel.app", "Vercel Subdomain"),
    ("https://react-dashboard.vercel.app/login", "Vercel Subdomain + Path"),
    ("https://docs.vercel.app/getting-started", "Vercel Deep Path"),
    ("https://shop.vercel.app/products?category=shoes", "Vercel Multi-Query"),
    ("https://react-app.netlify.app", "Netlify Subdomain"),
    ("https://vitejs.netlify.app/docs/intro", "Netlify Deep Path"),
    ("https://my-site.netlify.app/search?q=react", "Netlify Query"),
    ("https://my-blog.pages.dev", "Cloudflare Pages Subdomain"),
    ("https://dashboard.pages.dev/analytics", "Cloudflare Pages Path"),
    ("https://web-app.pages.dev/api/v1/status", "Cloudflare Pages Deep"),
    ("https://my-project.web.app", "Firebase Subdomain"),
    ("https://my-project.firebaseapp.com", "Firebase firebaseapp.com"),
    ("https://my-project.firebaseapp.com/dashboard/home", "Firebase Deep Path"),
    ("https://subdomain.example.app", ".app Subdomain"),
    ("https://subdomain.example.dev", ".dev Subdomain"),
    ("https://subdomain.example.ai", ".ai Subdomain"),
    ("https://subdomain.example.studio", ".studio Subdomain"),
    ("https://subdomain.example.tech", ".tech Subdomain"),
    ("https://subdomain.example.io", ".io Subdomain"),
    ("https://subdomain.example.org", ".org Subdomain")
]

print(f"{'URL':<50} | {'Platform':<24} | {'V3':<6} | {'V4-A':<6} | {'V4-B':<6}")
print("-" * 100)
for u, plat in BENCHMARK_HOSTING:
    _, r3, _, _ = predict(rf_v3, fc_v3, u)
    _, r4a, _, _ = predict(rf_v4a, fc_v4a, u)
    _, r4b, _, _ = predict(rf_v4b, fc_v4b, u)
    print(f"{u:<50} | {plat:<24} | {r3:<6} | {r4a:<6} | {r4b:<6}")

# 4. Adversarial Platform Phishing Detection
print("\n--- 4. ADVERSARIAL PLATFORM PHISHING DETECTION ---")
PAIRED_TESTS = [
    ("https://zustand.vercel.app", "Vercel Clean (Legit)", "legitimate"),
    ("https://metamask-security-auth.vercel.app/login", "Vercel Phish Lure", "phishing"),
    ("https://chase-bank-verify.vercel.app/account", "Vercel Phish Lure", "phishing"),
    ("https://alpinejs.netlify.app", "Netlify Clean (Legit)", "legitimate"),
    ("https://paypal-update-center.netlify.app/signin", "Netlify Phish Lure", "phishing"),
    ("https://apple-id-verify.netlify.app/recovery", "Netlify Phish Lure", "phishing"),
    ("https://cloudflare-docs.pages.dev", "Cloudflare Clean (Legit)", "legitimate"),
    ("https://netflix-billing-update.pages.dev/payment", "Cloudflare Phish Lure", "phishing"),
    ("https://dart-pad.web.app", "Firebase Clean (Legit)", "legitimate"),
    ("https://coinbase-auth-verify.web.app/login", "Firebase Phish Lure", "phishing"),
    ("http://198.98.58.123/", "Raw IP Phishing", "phishing"),
    ("http://www.shprakserf.gq", "HTTP Obscure Phishing", "phishing")
]

print(f"{'URL':<50} | {'Category':<26} | {'Expected':<10} | {'V3':<6} | {'V4-A':<6} | {'V4-B':<6}")
print("-" * 115)
for u, cat, exp in PAIRED_TESTS:
    _, r3, _, _ = predict(rf_v3, fc_v3, u)
    _, r4a, _, _ = predict(rf_v4a, fc_v4a, u)
    p4b, r4b, _, _ = predict(rf_v4b, fc_v4b, u)
    print(f"{u:<50} | {cat:<26} | {exp:<10} | {r3:<6} | {r4a:<6} | {r4b:<6}")
