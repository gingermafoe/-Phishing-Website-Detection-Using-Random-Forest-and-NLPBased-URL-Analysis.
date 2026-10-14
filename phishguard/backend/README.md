# PhishGuard — Backend API Service

FastAPI backend service for **PhishGuard: Phishing Website Detection Using Random Forest & Threat Intelligence**.

The backend accepts any input URL, performs real-time syntactic feature extraction (21 canonical lexical features), invokes the pre-trained Random Forest V3 classifier, queries optional independent live threat-intelligence providers (Google Safe Browsing, VirusTotal, PhishTank), and produces supplementary Groq security scrutiny explanations.

---

## 1. Architectural Architecture & Flow

```
[User Input URL]
       │
       ▼
[1. URL Syntax Validation] ──── (Rejects >2048 chars, malformed hostnames, non-HTTP/S)
       │
       ▼
[2. Lexical Feature Extraction] ── (Extracts 21 zero-crawl lexical/structural features)
       │
       ▼
[3. Authoritative Random Forest V3] ── (Inference: Class 1=Legit, 0=Phish, P(Phishing), Risk Score 0-100)
       │
       ├────────────────────────────────────────┐
       ▼                                        ▼
[4. Live Threat Intelligence (Async)]     [5. Authoritative Metrics Preserved]
   - Google Safe Browsing API                - Random Forest prediction is NEVER overridden
   - VirusTotal URL API v3                   - Disagreements are reported transparently
   - PhishTank Reputation API
       │
       ▼
[6. Groq Security Scrutiny] ── (Structured explanation based strictly on supplied telemetry)
       │
       ▼
[7. Comprehensive JSON Response]
```

---

## 2. Prerequisites & Installation

### Python Environment
- Python 3.10+ recommended
- Virtual environment or local installation

### Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

Core dependencies:
- `fastapi` & `uvicorn` (high-performance ASGI web framework and server)
- `pydantic` (strict payload validation)
- `scikit-learn` & `joblib` (model deserialization and inference)
- `pandas` & `numpy` (tabular feature vector formatting)
- `httpx` (async HTTP client for threat intelligence)
- `groq` (Groq SDK for supplementary security explanation)
- `python-dotenv` (environment configuration)

---

## 3. Configuration (.env)

Copy `.env.example` to `.env` in the `backend/` folder:

```bash
cp .env.example .env
```

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `GROQ_API_KEY` | Groq Cloud API Key for AI explanation | `gsk_...` (optional) |
| `GROQ_MODEL` | Groq LLM model name | `qwen/qwen3.8-27b` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API v4 Key | `AIza...` (optional) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 Key | `64-char hex` (optional) |
| `PHISHTANK_API_KEY` | PhishTank Application Key | `hex key` (optional) |
| `TI_REQUEST_TIMEOUT_SECONDS` | Timeout for external threat intelligence calls | `4.0` |

*Security Guarantee: All provider API keys remain exclusively on the backend. When an API key is not configured, the system marks that provider as "Not Configured" and proceeds without error.*

---

## 4. Starting the Backend Server

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

- **Base URL**: `http://127.0.0.1:8000`
- **Swagger Documentation**: `http://127.0.0.1:8000/docs`
- **ReDoc UI**: `http://127.0.0.1:8000/redoc`

---

## 5. API Endpoints

### A. Health Check (`GET /api/health`)
Verifies service availability and Random Forest V3 model loading status.

```bash
curl -X GET "http://127.0.0.1:8000/api/health"
```

Response:
```json
{
  "status": "ok",
  "model": "Random Forest V3",
  "model_loaded": true
}
```

---

### B. URL Threat Analysis (`POST /api/analyze`)

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.google.com"}'
```

Response:
```json
{
  "url": "https://www.google.com",
  "prediction": "legitimate",
  "label": 1,
  "probability": 1.0,
  "risk_score": 0,
  "model_version": "V3",
  "model_type": "Random Forest",
  "feature_count": 21,
  "phishing_probability": 0.0,
  "analyzed_at": "2026-10-14T06:00:00Z",
  "features": {
    "URLLength": 22,
    "DomainLength": 10,
    "IsDomainIP": 0,
    "TLDLength": 3,
    "NoOfSubDomain": 0,
    "HasObfuscation": 0,
    "NoOfObfuscatedChar": 0,
    "ObfuscationRatio": 0.0,
    "NoOfLettersInURL": 16,
    "LetterRatioInURL": 0.727,
    "NoOfDegitsInURL": 0,
    "DegitRatioInURL": 0.0,
    "NoOfEqualsInURL": 0,
    "NoOfQMarkInURL": 0,
    "NoOfAmpersandInURL": 0,
    "NoOfOtherSpecialCharsInURL": 2,
    "SpacialCharRatioInURL": 0.091,
    "IsHTTPS": 1,
    "CharContinuationRate": 0.4545,
    "TLDLegitimateProb": 0.522907,
    "URLCharProb": 0.08137524
  },
  "threat_intel_providers": [
    {
      "provider": "Google Safe Browsing",
      "status": "no_match_found",
      "status_label": "No Match Found",
      "evidence": "No threat matches returned in Google Safe Browsing database.",
      "checked_at": "2026-10-14T06:00:00Z",
      "explanation": "The URL is not currently listed in Google Safe Browsing threat databases. Absence of listing does not indicate or prove safety, as novel phishing campaigns may not yet be indexed."
    },
    {
      "provider": "VirusTotal",
      "status": "not_configured",
      "status_label": "Not Configured",
      "evidence": "API key not configured in backend environment variables.",
      "checked_at": "2026-10-14T06:00:00Z",
      "explanation": "VirusTotal check was skipped because no API key is configured. This does not indicate safety."
    },
    {
      "provider": "PhishTank",
      "status": "not_configured",
      "status_label": "Not Configured",
      "evidence": "API key not configured in backend environment variables.",
      "checked_at": "2026-10-14T06:00:00Z",
      "explanation": "PhishTank check was skipped because no API key is configured. This does not indicate safety."
    }
  ],
  "threat_intel_summary": {
    "status": "clean_matches",
    "summary": "No threat records found across 1 reporting provider(s). Note: Zero threat matches does NOT prove a website is safe.",
    "configured_providers_count": 1,
    "total_providers_count": 3,
    "malicious_count": 0
  },
  "ai_explanation": "...",
  "ai_explanation_available": true
}
```

---

## 6. Threat Intelligence Statuses

1. `malicious_match`: The provider actively reported a confirmed phishing or malicious match.
2. `no_match_found`: The provider checked its database and found no active threat listing. *(Note: Absence of detection does NOT prove safety).*
3. `unknown`: The provider has no record or conclusive rating for this URL (e.g. VirusTotal HTTP 404).
4. `unavailable`: The provider service timed out or returned HTTP 5xx.
5. `error`: The provider returned client error (4xx), quota exceeded (429), or network error.
6. `not_configured`: The provider API key is not configured in `.env`.

---

## 7. Running Automated Tests

```bash
cd backend
python test_api.py
```

Runs the 15-test automated verification suite covering:
- Schema and 21-feature vector integrity
- Legitimate and phishing classification
- Invariant Random Forest predictions when external providers or Groq disagree
- Mocked provider responses (malicious, clean, timeout, 500 error, unconfigured)
- Mocked Groq fallback scenarios
- Malformed and oversized URL rejection (422)
- Structured telemetry separation
