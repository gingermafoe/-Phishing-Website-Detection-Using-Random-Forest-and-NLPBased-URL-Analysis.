import os
import sys
import joblib
import pandas as pd
import numpy as np

WORKSPACE_DIR = r"d:\B-Tech Projects No One Drive\ML 2-1\phishguard"
sys.path.insert(0, os.path.join(WORKSPACE_DIR, "ml", "v3"))
sys.path.insert(0, os.path.join(WORKSPACE_DIR, "ml", "v4", "models"))

import feature_config_v3 as fcv3
import feature_config_v4a as fcv4a
import feature_config_v4b as fcv4b

rf3 = joblib.load(os.path.join(WORKSPACE_DIR, "ml", "v3", "random_forest_v3.pkl"))
rf4a = joblib.load(os.path.join(WORKSPACE_DIR, "ml", "v4", "models", "random_forest_v4a.pkl"))
rf4b = joblib.load(os.path.join(WORKSPACE_DIR, "ml", "v4", "models", "random_forest_v4b.pkl"))

def get_attribution(rf, fc, feat_fn, url):
    classes = list(rf.classes_)
    phish_idx = classes.index(0)
    feat = feat_fn(url)
    df_u = pd.DataFrame([feat])[fc.PRIMARY_FEATURES]
    p_phish = float(rf.predict_proba(df_u)[0][phish_idx])
    
    contribs = np.zeros(len(fc.PRIMARY_FEATURES))
    root_probs = []
    X_val = df_u.values
    for est in rf.estimators_:
        tree = est.tree_
        node_indicator = est.decision_path(X_val)
        indices = node_indicator.indices
        root_val = tree.value[0][0]
        root_probs.append(root_val[phish_idx] / root_val.sum())
        for i in range(len(indices) - 1):
            curr_n = indices[i]
            next_n = indices[i+1]
            split_feat = tree.feature[curr_n]
            v_curr = tree.value[curr_n][0]
            v_next = tree.value[next_n][0]
            p_curr = v_curr[phish_idx] / v_curr.sum()
            p_next = v_next[phish_idx] / v_next.sum()
            contribs[split_feat] += (p_next - p_curr)
    contribs /= len(rf.estimators_)
    base = np.mean(root_probs)
    return feat, p_phish, base, contribs

targets = ["https://klattendance.vercel.app/", "https://klhunderground.ai.studio"]
for u in targets:
    print("=" * 80)
    print("TARGET URL:", u)
    print("=" * 80)
    for name, rf, fc, fn in [("V3", rf3, fcv3, fcv3.extract_v3_lexical_features), 
                             ("V4-A", rf4a, fcv4a, fcv4a.extract_v4a_lexical_features), 
                             ("V4-B", rf4b, fcv4b, fcv4b.extract_v4b_lexical_features)]:
        f, p_phish, base, c = get_attribution(rf, fc, fn, u)
        print(f"\n--- {name} (Risk: {int(round(p_phish*100))}, P(Phish): {p_phish:.4f}, Base: {base:.4f}) ---")
        df_c = pd.DataFrame({"Feature": fc.PRIMARY_FEATURES, "Value": [f[k] for k in fc.PRIMARY_FEATURES], "Contrib": c})
        print(f"{'Feature':<28} | {'Value':<12} | {'Contribution':<15}")
        print("-" * 60)
        for _, row in df_c.sort_values(by="Contrib", ascending=False).iterrows():
            if abs(row["Contrib"]) > 0.01:
                print(f"{row['Feature']:<28} | {str(row['Value']):<12} | {row['Contrib']:<+15.4f}")
