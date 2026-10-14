# PhishGuard: Phishing Website Detection Using Random Forest

**Academic Project**: University Machine Learning + Cybersecurity  
**Phase**: Phase 1 — Dataset Analysis and Random Forest Training  
**Status**: Completed and Verified

---

## 1. Project Overview & Requirements

PhishGuard is an applied machine learning and cybersecurity system designed to identify fraudulent (phishing) URLs and websites. The primary machine learning classifier is **Random Forest**, selected for its high interpretability, robustness to tabular feature interactions, resistance to overfitting, and low computational overhead.

### Architectural Constraints
- **Primary Algorithm**: Random Forest (`RandomForestClassifier` from `scikit-learn`). No replacement with XGBoost, neural networks, or transformers.
- **Natural Language Processing (NLP)**: Prohibited. No TF-IDF, bag-of-words, BERT, or word embeddings. Classification relies strictly on engineered lexical, statistical, and structural features.
- **Large Language Models (LLMs)**: Prohibited for classification.
- **External APIs**: None utilized in this phase; training and evaluation are completely self-contained.
- **Dataset**: PhiUSIIL Phishing URL Dataset (`PhiUSIIL_Phishing_URL_Dataset.csv`).

---

## 2. Dataset Inspection & Summary (Task 1)

The PhiUSIIL dataset was inspected directly from source rather than assuming schema properties:

| Metric | Inspection Finding |
| :--- | :--- |
| **Total Rows** | 235,795 |
| **Total Columns** | 55 |
| **Data Types** | 4 string / object columns (`URL`, `Domain`, `TLD`, `Title`), 51 numerical columns (`int64`, `float64`) |
| **Missing Values** | **0** across all 55 columns (complete dataset) |
| **Identical Full Rows** | 0 |
| **Duplicate URLs** | **425 duplicate URLs** (850 total rows involved) |
| **Target Column** | `label` (`int64`) |
| **Class 1 (Legitimate)** | **134,850 samples (57.19%)** |
| **Class 0 (Phishing)** | **100,945 samples (42.81%)** |

---

## 3. Data Leakage Investigation (Task 2)

Prior to model training, a rigorous cybersecurity and statistical audit was conducted to identify potential sources of leakage and operational failure:

### A. Target Leakage in `URLSimilarityIndex`
- **Finding**: For Class 1 (Legitimate), `URLSimilarityIndex` is **100.0 for 100.00% of samples** (mean = 100.0, standard deviation = 0.0). For Class 0 (Phishing), the mean drops to 49.62.
- **Cause**: During dataset compilation, the dataset authors evaluated each URL against a reference database of legitimate websites. Because the legitimate URLs were themselves part of this reference list, they evaluated to 100% similarity with themselves.
- **Risk**: Training on this feature allows any decision tree to classify a website with ~99.7% accuracy using a single trivial rule: `if URLSimilarityIndex == 100.0 then Legitimate else Phishing`. This model would fail catastrophically on any unseen URL in deployment.
- **Decision**: **Explicitly excluded** from all training pipelines.

### B. Train-Test Contamination via Duplicate URLs
- **Finding**: 425 URLs appeared multiple times across the 235,795 rows.
- **Risk**: Random splitting without deduplication allows identical URLs to appear simultaneously in both training and testing folds, rewarding memorization rather than generalization.
- **Decision**: All duplicate URL records were pruned prior to splitting, resulting in **235,370 clean, unique URL records**.

### C. Unstructured High-Cardinality String Identifiers
- **Finding**: `URL` (235,370 unique), `Domain` (220,086 unique), and `Title` (197,874 unique) are high-cardinality raw text strings.
- **Risk**: Feeding categorical string hashes or raw text directly into decision trees causes severe leaf fragmentation and overfitting. Using text embeddings violates the "no NLP" requirement.
- **Decision**: **Explicitly excluded** from the feature vector.

### D. Operational Availability Leakage (HTML Features vs. URL Features)
- **Finding**: 28 columns represent HTML/DOM features (`LineOfCode`, `NoOfImage`, `NoOfJS`, `HasSocialNet`, `NoOfExternalRef`, etc.).
- **Cybersecurity Realities**:
  1. Over 60% of real-world phishing websites are suspended or taken down within 24–48 hours. When an analyst or user submits a suspicious link to verify whether it was malicious, an offline page yields connection timeouts or HTTP errors, causing an HTML-dependent model to fail.
  2. Visiting an active malicious URL from a backend crawler poses significant security hazards (drive-by downloads, SSRF attacks, IP blocklisting).
  3. Live crawling adds 3–10 seconds of latency, while extracting lexical features from the URL string takes **<1 millisecond**.
- **Decision**: We engineered a **dual-model architecture**:
  1. **Primary Production Model (21 URL Lexical Features)**: 100% extractable from the URL string in real-time without network access.
  2. **Benchmark Model (49 Clean Features)**: Evaluates the theoretical upper bound when a live webpage DOM can be fully rendered.

---

## 4. Feature Selection & Exclusion Matrix

Every single column in the dataset was deliberately accounted for:

| Column Group | Count | Columns Included / Excluded | Decision Rationale |
| :--- | :---: | :--- | :--- |
| **Target** | 1 | `label` | Binary ground truth (1: Legitimate, 0: Phishing). |
| **Raw Identifiers** | 4 | `URL`, `Domain`, `TLD`, `Title` | **Excluded**. High-cardinality strings; prone to memorization; NLP is forbidden. `TLD` is captured numerically by `TLDLength` and `TLDLegitimateProb`. |
| **Target Leakage** | 1 | `URLSimilarityIndex` | **Excluded**. Benchmark self-comparison artifact (100% constant in legitimate class). |
| **URL Lexical Features** | 21 | `URLLength`, `DomainLength`, `IsDomainIP`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb` | **Selected (Primary Model)**. Extracted directly from URL string in <1ms without network dependencies. Zero security risk; robust on offline links. |
| **HTML Content Features** | 28 | `LineOfCode`, `LargestLineLength`, `HasTitle`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef` | **Evaluated in Benchmark Model**. Require live web crawling and DOM inspection. Prone to timeouts and downtime. |

---

## 5. Random Forest Model Configuration (Task 3)

The models were trained using `scikit-learn`'s `RandomForestClassifier`:

```python
RandomForestClassifier(
    n_estimators=100,          # 100 decision trees
    max_depth=None,            # Fully grown trees until purity/leaf limits
    min_samples_split=2,       # Minimum samples required to split an internal node
    min_samples_leaf=1,        # Minimum samples required at a leaf node
    class_weight='balanced',   # Adjust weights inversely proportional to class frequencies
    random_state=42,           # Ensures deterministic, reproducible results
    n_jobs=-1                  # Parallel multi-core execution
)
```

- **Split Ratio**: 80% Training (188,296 samples), 20% Testing (47,074 samples).
- **Stratification**: Enabled (`stratify=y`), preserving exact 57.19% / 42.81% class balance across splits.

---

## 6. Real Evaluation Metrics (Task 4)

All metrics were calculated on the held-out test split of **47,074 unseen samples**:

### A. Primary Production Model (21 URL-Only Features)
*Designed for real-time FastAPI inference without network crawling.*

- **Accuracy**: **99.6644%**
- **Precision (Legitimate)**: **99.5931%**
- **Recall (Legitimate)**: **99.8220%**
- **F1-Score (Macro)**: **99.66%** | **F1-Score (Legitimate)**: **99.7074%**
- **False Positive Rate (FPR)**: **0.5472%** (110 legitimate sites flagged as phishing)
- **False Negative Rate (FNR)**: **0.1780%** (48 phishing sites flagged as legitimate)

#### Confusion Matrix (URL-Only Model)
```
                          Predicted Phishing (0)   Predicted Legitimate (1)
Actual Phishing (0)              19,994                     110
Actual Legitimate (1)                48                  26,922
```

#### Classification Report (URL-Only Model)
```
                precision    recall  f1-score   support
  Phishing (0)     0.9976    0.9945    0.9961     20,104
Legitimate (1)     0.9959    0.9982    0.9971     26,970

      accuracy                         0.9966     47,074
     macro avg     0.9968    0.9964    0.9966     47,074
  weighted avg     0.9966    0.9966    0.9966     47,074
```

---

### B. Benchmark Model (All 49 Clean Features: URL + HTML)
*Evaluates upper-bound performance when full HTML DOM is parsed.*

- **Accuracy**: **99.9894%**
- **Precision**: **99.9889%**
- **Recall**: **99.9926%**
- **F1-Score**: **99.9907%**

#### Confusion Matrix (All-Clean Benchmark)
```
                          Predicted Phishing (0)   Predicted Legitimate (1)
Actual Phishing (0)              20,101                       3
Actual Legitimate (1)                 2                  26,968
```

---

## 7. Top 15 Feature Importances (Task 5)

Feature importances extracted directly from the trained Random Forest trees (`feature_importances_`):

### Top 15 Features for Primary URL-Only Model
| Rank | Feature Name | Importance | Cumulative | Cybersecurity Rationale |
| :---: | :--- | :---: | :---: | :--- |
| **1** | `IsHTTPS` | **0.365943** | 36.59% | While many phishing sites now use SSL, HTTP-only URLs in this dataset correlate heavily with malicious pages. |
| **2** | `NoOfOtherSpecialCharsInURL` | **0.124096** | 49.00% | Phishing links use unusual separators (`-`, `_`, `@`, `/`, `.`) to disguise spoofed domains. |
| **3** | `LetterRatioInURL` | **0.071348** | 56.14% | Fraudulent URLs have lower letter ratios due to encoded tokens, query parameters, and IP hex bytes. |
| **4** | `DegitRatioInURL` | **0.066960** | 62.83% | Phishing paths often feature long random numeric strings or IP addresses. |
| **5** | `NoOfDegitsInURL` | **0.066143** | 69.45% | Total digit count in path, hostname, and parameters. |
| **6** | `SpacialCharRatioInURL` | **0.060603** | 75.51% | High proportion of punctuation marks relative to total URL length. |
| **7** | `URLLength` | **0.059391** | 81.45% | Phishing URLs are substantially longer on average (mean: 45.7 vs 26.2 characters) to obfuscate target destinations. |
| **8** | `NoOfLettersInURL` | **0.048271** | 86.28% | Absolute alphabetical length in the domain and path. |
| **9** | `NoOfSubDomain` | **0.036776** | 89.95% | Phishers often create multi-level subdomains (e.g., `paypal.com.account-update.xyz`). |
| **10** | `TLDLegitimateProb` | **0.025957** | 92.55% | Free or abuse-prone TLDs (`.gq`, `.tk`, `.ru`) carry lower legitimate probability than `.gov`, `.edu`, `.com`. |
| **11** | `URLCharProb` | **0.023847** | 94.93% | Unnatural character transitions deviate from typical English/brand character distributions. |
| **12** | `CharContinuationRate` | **0.022999** | 97.23% | Measures consecutive repetition of character types (letters/digits). |
| **13** | `DomainLength` | **0.017361** | 98.97% | Length of the domain name (longer domains often indicate typosquatting). |
| **14** | `TLDLength` | **0.009088** | 99.88% | Length of the top-level domain extension. |
| **15** | `NoOfQMarkInURL` | **0.000862** | 99.96% | Presence of query string indicators. |

*The top 15 features account for **99.96%** of all decision tree splits.*

---

## 8. Project Structure & Artifacts (Task 6)

```
phishguard/
├── dataset/
│   └── PhiUSIIL_Phishing_URL_Dataset.csv   # Primary benchmark training dataset (54.2 MB)
├── ml/
│   ├── feature_config.py                   # Column groups, selection logic, and URL feature extractor
│   ├── train.py                            # Standalone training pipeline
│   ├── evaluate.py                         # Standalone evaluation & reporting pipeline
│   ├── random_forest.pkl                   # Trained production Random Forest model (21 features)
│   ├── random_forest_full.pkl              # Trained benchmark Random Forest model (49 features)
│   ├── model_metadata.json                 # Serialized metadata, schema, and metrics
│   ├── lookup_tables.json                  # Precomputed TLD probability and char frequency maps
│   ├── test_sample.csv                     # Held-out 20% test split (47,074 rows)
├── backend/                                # Phase 2: FastAPI backend service
│   ├── main.py                             # API routes, lifespan loader, CORS, schemas
│   ├── requirements.txt                    # Backend dependencies
│   ├── test_api.py                         # Automated endpoint test suite
│   └── README.md                           # Backend documentation
├── frontend/                               # Phase 3: React + TypeScript + Vite + Tailwind UI
│   ├── src/
│   │   ├── components/                     # Navbar, Hero, UrlScanner, ResultCard, RiskScore, etc.
│   │   ├── services/api.ts                 # Centralized FastAPI API client
│   │   ├── types/api.ts                    # TypeScript schemas
│   │   ├── App.tsx                         # State and layout coordinator
│   │   └── index.css                       # Dark cybersecurity theme & glassmorphism
│   ├── package.json                        # Frontend dependencies
│   └── README.md                           # Frontend documentation
└── README.md                               # Project documentation
```

### Reproducing Training, Backend, and Frontend

#### 1. ML Pipeline (Phase 1)
```bash
cd phishguard/ml
python train.py
python evaluate.py
```

#### 2. FastAPI Backend (Phase 2)
```bash
cd phishguard/backend
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

#### 3. React Frontend Dashboard (Phase 3)
```bash
cd phishguard/frontend
npm install
npm run dev
```

---

---

## 10. Phase 4: Live Threat Intelligence & Groq Security Scrutiny

PhishGuard integrates an optional, independent live threat-intelligence layer alongside supplementary AI security scrutiny.

### Core Architectural Guarantees:
1. **Random Forest V3 is Authoritative**:
   - The Random Forest classifier remains the primary, authoritative engine.
   - External reputation checks or Groq explanations **never modify** the model's prediction, probability, or risk score.
   - When external intelligence disagrees with Random Forest, the disagreement is displayed prominently.
2. **Supported Threat Intelligence Providers**:
   - **Google Safe Browsing API v4**: Detects active phishing, malware, and social engineering listings.
   - **VirusTotal URL API v3**: Multi-engine antivirus and security vendor reputation.
   - **PhishTank API**: Community and verified phishing report repository.
3. **Groq Security Scrutiny**:
   - Uses Groq (`qwen/qwen3.8-27b`) to synthesize an evidence-based explanation strictly from actual backend telemetry (21 URL lexical features, RF risk score, provider responses).
   - Never invents WHOIS, DNS, or webpage content evidence. Never claims to visit destination URLs.
4. **Zero-Crawl Safety**:
   - The backend performs zero network fetching or rendering of destination websites, mitigating SSRF and drive-by download risks.

### Running Automated Test Suite:
```bash
cd backend
python test_api.py
```
Runs 15 automated test cases covering model integrity, provider status mapping, timeout fallbacks, and schema invariants.

---

**Phase 1, Phase 2, Phase 3, and Phase 4 Completed and Verified.**
