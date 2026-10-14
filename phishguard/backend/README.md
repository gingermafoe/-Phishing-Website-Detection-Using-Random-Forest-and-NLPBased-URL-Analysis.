# PhishGuard — Backend API Service

FastAPI backend service for **PhishGuard: Phishing Website Detection Using Random Forest**.

The backend accepts any input URL, performs real-time syntactic feature extraction (21 lexical features), and invokes the pre-trained Random Forest model (`ml/random_forest.pkl`) to predict whether the URL is **legitimate** or **phishing**, accompanied by confidence probabilities and a calibrated cybersecurity risk index.

---

## 1. Prerequisites & Installation

### Python Environment
- Python 3.10+ recommended
- Ensure virtual environment or local environment is active

### Install Dependencies
```bash
# Navigate to the backend directory
cd phishguard/backend

# Install required dependencies
pip install -r requirements.txt
```

The service relies only on essential libraries:
- `fastapi` & `uvicorn` (high-performance ASGI web framework and server)
- `pydantic` (strict payload validation)
- `scikit-learn` & `joblib` (model deserialization and inference)
- `pandas` & `numpy` (tabular feature vector formatting)
- `httpx` (automated endpoint integration testing)

---

## 2. Starting the Backend Server

```bash
# From within the backend directory
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The server initializes at:
- **Base URL**: `http://127.0.0.1:8000`
- **Interactive OpenAPI Docs (Swagger)**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc UI**: `http://127.0.0.1:8000/redoc`

The machine learning model (`ml/random_forest.pkl`) is loaded once during application startup.

---

## 3. API Endpoints

### A. Health Check
- **Endpoint**: `GET /api/health`
- **Description**: Verifies service availability and model loading status.

#### Example Request
```bash
curl -X GET "http://127.0.0.1:8000/api/health"
```

#### Example Response (`200 OK`)
```json
{
  "status": "ok",
  "model": "Random Forest",
  "model_loaded": true
}
```

---

### B. URL Threat Analysis
- **Endpoint**: `POST /api/analyze`
- **Description**: Evaluates an input URL and returns classification and risk score.

#### Example Request: Legitimate URL
```bash
curl -X POST "http://127.0.0.1:8000/api/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.google.com"}'
```

#### Example Response (`200 OK`)
```json
{
  "url": "https://www.google.com",
  "prediction": "legitimate",
  "label": 1,
  "probability": 0.95,
  "risk_score": 5
}
```

#### Example Request: Phishing URL
```bash
curl -X POST "http://127.0.0.1:8000/api/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-security-update.account-verify.com/login.php?user=123&token=abc"}'
```

#### Example Response (`200 OK`)
```json
{
  "url": "http://paypal-security-update.account-verify.com/login.php?user=123&token=abc",
  "prediction": "phishing",
  "label": 0,
  "probability": 1.0,
  "risk_score": 100
}
```

---

## 4. Risk Score Calculation

The `risk_score` is a standardized cybersecurity risk index ranging from **0 (Completely Safe)** to **100 (Critical Malicious Threat)**.

$$\text{risk\_score} = \text{round}(P(\text{Phishing}) \times 100)$$

- **Class Mapping**:
  - `label = 1`: **Legitimate**
  - `label = 0`: **Phishing**
- **Calculated Probability**:
  - $P(\text{Phishing})$ is the predicted probability for class 0 from `model.predict_proba()`.
- **Interpretative Thresholds**:
  - `0 - 25`: **Low Risk (Safe)** — High confidence legitimate website.
  - `26 - 69`: **Moderate Risk (Suspicious)** — URL exhibits unusual punctuation, length, or subdomain properties.
  - `70 - 100`: **High / Critical Risk (Phishing)** — URL exhibits prominent phishing indicators (IP address in hostname, credential query tokens, suspicious TLD, no SSL).

---

## 5. Security & Operational Guarantees

1. **Zero Web Crawling**: The backend performs zero network I/O to the destination URL. It does not issue HTTP requests or render DOM content, protecting the server against drive-by downloads, SSRF attacks, and IP blocking.
2. **Deterministic Feature Ordering**: The feature extractor guarantees the exact 21 features in the exact column sequence expected by the Random Forest classifier.
3. **CORS Enabled**: Out-of-the-box support for frontend origins (React, Vite) during development and production.
4. **Input Sanitization**: Rejects unsupported protocols (e.g. `ftp://`, `javascript:`), empty strings, and malformed domain structures with HTTP `422 Unprocessable Entity`.

---

## 6. Running Automated Tests

```bash
cd phishguard/backend
python test_api.py
```
