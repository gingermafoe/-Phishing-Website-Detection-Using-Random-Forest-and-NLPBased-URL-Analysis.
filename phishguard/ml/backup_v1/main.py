"""
PhishGuard - FastAPI Backend Service
Project: Phishing Website Detection Using Random Forest
Phase 2: FastAPI Backend

This service:
1. Loads the pre-trained Random Forest model (ml/random_forest.pkl) at startup.
2. Exposes GET /api/health for system status and model readiness.
3. Exposes POST /api/analyze to classify URLs as legitimate or phishing.
4. Performs strict URL syntax validation without crawling or visiting the destination.
5. Extracts exactly the 21 URL lexical features used during training.
6. Returns prediction, binary label, classification confidence, and a 0-100 risk score.
7. Configures CORS for seamless communication with the upcoming React frontend.
"""

import os
import sys
import re
import urllib.parse
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# ------------------------------------------------------------------------------
# 1. PATH RESOLUTION & ML IMPORT
# ------------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
ML_DIR = os.path.join(PROJECT_ROOT, "ml")

# Ensure ml package is accessible
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

import feature_config as fc

MODEL_PATH = os.path.join(ML_DIR, "random_forest.pkl")

# ------------------------------------------------------------------------------
# 2. LIFESPAN MANAGEMENT (Load Model Once on Startup)
# ------------------------------------------------------------------------------
ml_resources: Dict[str, Any] = {
    "model": None,
    "model_loaded": False,
    "feature_names": fc.PRIMARY_FEATURES
}


def get_model():
    """Returns the loaded model, lazily loading it once if not already initialized."""
    if ml_resources["model"] is None:
        if os.path.exists(MODEL_PATH):
            try:
                print(f"[LAZY-LOAD] Loading Random Forest model from: {MODEL_PATH} ...")
                ml_resources["model"] = joblib.load(MODEL_PATH)
                ml_resources["model_loaded"] = True
            except Exception as e:
                print(f"[ERROR] Failed to load model: {str(e)}")
                ml_resources["model"] = None
                ml_resources["model_loaded"] = False
    return ml_resources["model"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler. Loads the trained Random Forest model once
    upon application startup to guarantee zero per-request loading overhead.
    """
    print("=" * 70)
    print("PHISHGUARD BACKEND STARTUP")
    print("=" * 70)
    get_model()
    if ml_resources["model_loaded"]:
        print("Random Forest model successfully loaded into memory.")
        print(f"Configured feature vector: {len(ml_resources['feature_names'])} URL lexical features.")
    else:
        print(f"[ERROR] Model artifact missing or failed to load at: {MODEL_PATH}")

    yield

    print("Shutting down PhishGuard backend service...")
    ml_resources["model"] = None
    ml_resources["model_loaded"] = False


# ------------------------------------------------------------------------------
# 3. FASTAPI APPLICATION SETUP & CORS
# ------------------------------------------------------------------------------
app = FastAPI(
    title="PhishGuard API",
    description="High-performance machine learning backend for phishing URL detection using Random Forest.",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS so future React frontend (e.g. on localhost:3000, 5173) can communicate
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------------------
# 4. PYDANTIC SCHEMAS & URL VALIDATION
# ------------------------------------------------------------------------------
class URLAnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        description="The URL string to evaluate for phishing threats.",
        examples=["https://www.google.com", "http://paypal-verification.com/login"]
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL cannot be empty or whitespace.")
        
        cleaned = v.strip()

        # Reject URLs that are excessively long to prevent DoS
        if len(cleaned) > 2048:
            raise ValueError("URL exceeds maximum permissible length of 2048 characters.")

        # Scheme check: accept only http:// and https://
        parsed = urllib.parse.urlparse(cleaned)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme '{scheme}'. Only 'http://' and 'https://' are accepted.")

        # Hostname / netloc check: must have a valid non-empty domain or IP
        netloc = parsed.netloc.strip()
        if not netloc:
            raise ValueError("Invalid URL structure: Hostname or domain name is missing.")

        # Strip port if present
        host = netloc.split(":")[0]

        # Check for valid characters in domain / host
        # IPv4 pattern or domain pattern with at least one dot or localhost
        ipv4_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

        if not (re.match(ipv4_regex, host) or re.match(domain_regex, host) or host in ("localhost", "127.0.0.1")):
            raise ValueError(f"Invalid domain syntax in hostname '{host}'. Must be a valid domain or IP address.")

        return cleaned


class URLAnalyzeResponse(BaseModel):
    url: str = Field(..., description="The analyzed URL.")
    prediction: str = Field(..., description="Classification outcome: 'legitimate' or 'phishing'.")
    label: int = Field(..., description="Binary label: 1 for legitimate, 0 for phishing.")
    probability: float = Field(..., description="Model confidence score for the predicted class (0.0 to 1.0).")
    risk_score: int = Field(
        ...,
        description="Cybersecurity risk index from 0 (Safe) to 100 (Critical Risk), computed as round(P(Phishing) * 100)."
    )


class HealthResponse(BaseModel):
    status: str
    model: str
    model_loaded: bool


# ------------------------------------------------------------------------------
# 5. ENDPOINTS
# ------------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse, tags=["Diagnostics"])
def health_check():
    """
    Health check endpoint returning system status and model loading readiness.
    """
    model = get_model()
    is_ready = model is not None and ml_resources["model_loaded"]
    return {
        "status": "ok" if is_ready else "degraded",
        "model": "Random Forest",
        "model_loaded": is_ready
    }


@app.post("/api/analyze", response_model=URLAnalyzeResponse, tags=["Inference"])
def analyze_url(payload: URLAnalyzeRequest):
    """
    Analyzes an input URL using the pre-trained Random Forest model.
    
    Workflow:
    1. Validates syntactic structure (http:// or https:// with valid hostname).
    2. Extracts the 21 URL lexical features without crawling the target page.
    3. Runs inference through the Random Forest classifier.
    4. Computes probability and the 0-100 cybersecurity risk score.
    """
    model = get_model()
    if not model or not ml_resources["model_loaded"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning model is not loaded. Please verify ml/random_forest.pkl."
        )

    target_url = payload.url

    # Feature extraction (Task 5: exact 21 features in exact order)
    try:
        raw_features = fc.extract_lexical_features_from_url(target_url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Feature extraction failed for URL: {str(e)}"
        )

    # Ensure feature vector matches exact 21-feature schema and order used in training
    feature_order = fc.PRIMARY_FEATURES
    try:
        feature_df = pd.DataFrame([raw_features])[feature_order]
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feature schema mismatch: missing required feature {str(e)}"
        )

    # Run Random Forest prediction and probability estimation
    try:
        # Predict class (1 = Legitimate, 0 = Phishing)
        pred_label = int(model.predict(feature_df)[0])
        # Predict class probabilities [P(label=0), P(label=1)]
        prob_array = model.predict_proba(feature_df)[0]
        prob_phishing = float(prob_array[0])
        prob_legitimate = float(prob_array[1])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error during Random Forest prediction: {str(e)}"
        )

    # Human-readable prediction
    prediction_str = "legitimate" if pred_label == 1 else "phishing"

    # Confidence for predicted class
    confidence = prob_legitimate if pred_label == 1 else prob_phishing
    confidence_rounded = round(confidence, 4)

    # Cybersecurity Risk Score Calculation:
    # Scale: 0 (Extremely Safe) to 100 (Definite Phishing / Critical Risk)
    # Calculation: round(P(Phishing) * 100)
    # E.g., if P(Legitimate) = 0.97 -> P(Phishing) = 0.03 -> risk_score = 3
    # E.g., if P(Phishing) = 0.95 -> risk_score = 95
    risk_score = int(round(prob_phishing * 100))
    risk_score = max(0, min(100, risk_score))

    return {
        "url": target_url,
        "prediction": prediction_str,
        "label": pred_label,
        "probability": confidence_rounded,
        "risk_score": risk_score
    }


# ------------------------------------------------------------------------------
# 6. LOCAL ENTRYPOINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
