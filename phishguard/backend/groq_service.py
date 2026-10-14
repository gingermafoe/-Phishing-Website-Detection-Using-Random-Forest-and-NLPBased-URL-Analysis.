"""
PhishGuard - Groq AI Explanation Layer (Optional Service)
Project: Phishing Website Detection Using Random Forest V3

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. The Random Forest V3 classifier is the AUTHORITATIVE security classifier.
2. Groq is ONLY an optional, supplementary explanation layer.
3. Groq MUST NOT override, alter, or change the Random Forest prediction or risk score.
4. Groq MUST NOT whitelist/blacklist domains or introduce hardcoded domain rules.
5. If Groq is unavailable, times out, or GROQ_API_KEY is not configured:
   The backend returns normal Random Forest predictions with ai_explanation=None and ai_explanation_available=False.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
from dotenv import load_dotenv

# Configure module logger
logger = logging.getLogger("phishguard.groq")

# Load environment variables from backend/.env if present
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BACKEND_DIR, ".env")
if os.path.exists(ENV_PATH):
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

# Default Groq model: qwen/qwen3.8-27b (active production general-purpose chat model on Groq)
DEFAULT_GROQ_MODEL = "qwen/qwen3.8-27b"
REQUEST_TIMEOUT_SECONDS = 6.0

GROQ_SYSTEM_PROMPT = (
    "You are the explanation assistant for PhishGuard.\n\n"
    "PhishGuard uses a Random Forest V3 machine-learning classifier as its authoritative URL security classifier.\n\n"
    "Your job is ONLY to explain the classifier's supplied result in clear language.\n\n"
    "You must not override, reinterpret, or change the classifier's prediction or risk score.\n\n"
    "You must not invent evidence.\n\n"
    "You have NOT browsed or visited the destination website.\n\n"
    "You must not claim DNS, WHOIS, page-content, reputation, malware, registration, hosting, or threat-intelligence information unless explicitly supplied in the input.\n\n"
    "Explain the result using only the supplied URL features, probabilities, risk score, and model analysis.\n\n"
    "If the risk is elevated, explain which supplied characteristics contributed to the elevated risk.\n\n"
    "If the risk is low, explain which supplied characteristics support the lower risk.\n\n"
    "Clearly communicate that URL-only machine-learning analysis does not prove that a website is malicious or safe.\n\n"
    "Keep the explanation concise, technical but understandable, and suitable for a cybersecurity student project."
)


def is_groq_configured() -> bool:
    """Check if a non-empty GROQ_API_KEY is available in the environment."""
    key = os.getenv("GROQ_API_KEY", "").strip()
    return bool(key)


def get_groq_model() -> str:
    """Retrieve the configured Groq model or fallback to default."""
    model = os.getenv("GROQ_MODEL", "").strip()
    return model if model else DEFAULT_GROQ_MODEL


def generate_explanation(analysis_data: Dict[str, Any]) -> Tuple[Optional[str], bool]:
    """
    Generates a concise security explanation using Groq based strictly on
    the supplied Random Forest V3 classification outputs and lexical features.

    Parameters:
        analysis_data (dict): Dictionary containing:
            - url: Target URL string
            - prediction: 'legitimate' or 'phishing'
            - risk_score: 0-100 integer
            - phishing_probability: float (0.0 to 1.0)
            - legitimate_probability: float (0.0 to 1.0)
            - features: Dict of extracted 21 lexical features (optional but recommended)

    Returns:
        Tuple[Optional[str], bool]:
            - (explanation_text, True) on successful explanation generation.
            - (None, False) if API key missing, network error, timeout, or invalid response.
    """
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return None, False

    model_name = get_groq_model()

    try:
        from groq import Groq
        client = Groq(api_key=api_key, timeout=REQUEST_TIMEOUT_SECONDS, max_retries=0)
    except Exception as e:
        logger.warning(f"[PhishGuard Groq] Could not initialize Groq client: {e}")
        return None, False

    # Extract structured telemetry from analysis_data
    url = analysis_data.get("url", "unknown")
    prediction = analysis_data.get("prediction", "unknown")
    risk_score = analysis_data.get("risk_score", 0)
    p_phish = analysis_data.get("phishing_probability", 0.0)
    p_legit = analysis_data.get("legitimate_probability", 1.0 - p_phish)
    features = analysis_data.get("features", {})

    # Build concise telemetry summary
    telemetry_lines = [
        f"- Target URL: {url}",
        f"- Authoritative RF Prediction: {prediction.upper()}",
        f"- Cybersecurity Risk Score: {risk_score}/100",
        f"- Phishing Probability: {p_phish:.4f} ({round(p_phish * 100, 1)}%)",
        f"- Legitimate Probability: {p_legit:.4f} ({round(p_legit * 100, 1)}%)",
    ]

    if features:
        key_metrics = [
            f"IsHTTPS: {features.get('IsHTTPS', 'N/A')}",
            f"URLLength: {features.get('URLLength', 'N/A')}",
            f"DomainLength: {features.get('DomainLength', 'N/A')}",
            f"TLDLength: {features.get('TLDLength', 'N/A')}",
            f"NoOfSubDomain: {features.get('NoOfSubDomain', 'N/A')}",
            f"HasObfuscation: {features.get('HasObfuscation', 'N/A')}",
            f"NoOfDegitsInURL: {features.get('NoOfDegitsInURL', 'N/A')}",
            f"DegitRatioInURL: {features.get('DegitRatioInURL', 'N/A')}",
            f"SpacialCharRatioInURL: {features.get('SpacialCharRatioInURL', 'N/A')}",
            f"CharContinuationRate: {features.get('CharContinuationRate', 'N/A')}",
            f"TLDLegitimateProb: {features.get('TLDLegitimateProb', 'N/A')}",
            f"URLCharProb: {features.get('URLCharProb', 'N/A')}",
        ]
        telemetry_lines.append("- Key Lexical Features: " + ", ".join(key_metrics))

    user_prompt = (
        "Please provide a concise technical explanation for the following Random Forest V3 URL security analysis:\n\n"
        + "\n".join(telemetry_lines) + "\n\n"
        "Explain which supplied characteristics contributed to this risk score and prediction. "
        "Reiterate that this is URL-structure lexical analysis without visiting the destination website."
    )

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=500,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if not response.choices or not response.choices[0].message:
            return None, False

        content = response.choices[0].message.content
        if not content or not content.strip():
            return None, False

        return content.strip(), True

    except Exception as e:
        # Graceful failure: log error type without exposing API keys or crashing backend
        err_type = type(e).__name__
        logger.warning(f"[PhishGuard Groq] Explanation unavailable ({err_type}). Falling back to RF V3 output.")
        return None, False
