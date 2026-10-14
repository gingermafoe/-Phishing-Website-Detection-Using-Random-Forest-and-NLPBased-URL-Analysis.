"""
PhishGuard - Groq AI Security Scrutiny Layer (Supplementary Service)
Project: Phishing Website Detection Using Random Forest V3

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. The Random Forest V3 classifier is the AUTHORITATIVE security classifier.
2. Groq is strictly an optional, supplementary explanation layer.
3. Groq MUST NOT override, alter, or change the Random Forest prediction, probability, or risk score.
4. Groq MUST NOT invent DNS, WHOIS, SSL certificate, domain registration, hosting, malware, or webpage-content evidence.
5. Groq has NOT visited, crawled, or inspected the destination webpage.
6. Groq must NOT infer that HTTPS proves legitimacy, or that no reputation match proves safety.
7. If Groq is unavailable, times out, or GROQ_API_KEY is not configured:
   The backend returns normal Random Forest predictions with ai_explanation=None and ai_explanation_available=False.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple, List
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

# Default Groq model: qwen/qwen3.8-27b (or llama-3.3-70b-versatile)
DEFAULT_GROQ_MODEL = "qwen/qwen3.8-27b"
REQUEST_TIMEOUT_SECONDS = 6.0

GROQ_SYSTEM_PROMPT = (
    "You are the senior security explanation assistant for PhishGuard.\n\n"
    "PhishGuard uses an authoritative Random Forest V3 machine-learning classifier (21 URL lexical features) "
    "combined with independent external threat-intelligence reputation checks.\n\n"
    "MANDATORY ARCHITECTURAL RULES:\n"
    "1. Random Forest V3 is AUTHORITATIVE. You must NEVER override, alter, or contradict the classifier's prediction or risk score.\n"
    "2. Threat intelligence findings are independent external indicators. If external intelligence and Random Forest disagree, "
    "highlight this disagreement clearly without changing either result.\n"
    "3. You must NOT invent DNS, WHOIS, SSL certificate, domain registration, hosting, malware, or webpage-content evidence.\n"
    "4. You have NOT visited, crawled, or inspected the destination website. Never claim the webpage was loaded.\n"
    "5. Do NOT infer that HTTPS proves legitimacy. Phishing websites routinely use SSL/TLS encryption.\n"
    "6. Do NOT infer that lack of a threat-intelligence match proves safety. Newly created phishing domains frequently have clean reputation histories.\n"
    "7. Explain: (a) which extracted URL characteristics support or weaken the prediction, (b) whether threat intelligence reported matches or was unavailable, "
    "(c) what uncertainty remains (e.g. zero-crawl limitations), and (d) practical precautions for the user.\n"
    "8. Keep your response concise (under 250 words), structured, and professional for a cybersecurity audit."
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
    Generates a structured security explanation using Groq based strictly on
    the supplied Random Forest V3 classification outputs, lexical features, and threat intelligence.

    Parameters:
        analysis_data (dict): Dictionary containing:
            - url: Target URL string
            - prediction: 'legitimate' or 'phishing'
            - risk_score: 0-100 integer
            - phishing_probability: float (0.0 to 1.0)
            - legitimate_probability: float (0.0 to 1.0)
            - features: Dict of extracted 21 lexical features
            - threat_intel_providers: List of threat intel provider results
            - threat_intel_summary: Dict with overall threat intel status & summary

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
    ti_providers: List[Dict[str, Any]] = analysis_data.get("threat_intel_providers", [])
    ti_summary: Dict[str, Any] = analysis_data.get("threat_intel_summary", {})

    # Build concise telemetry summary
    telemetry_lines = [
        f"1. Target URL: {url}",
        f"2. Authoritative Random Forest V3 Prediction: {prediction.upper()} (Risk Score: {risk_score}/100, Phishing Probability: {p_phish:.4f}, Legitimate Probability: {p_legit:.4f})",
    ]

    if features:
        key_metrics = [
            f"IsHTTPS={features.get('IsHTTPS', 'N/A')}",
            f"URLLength={features.get('URLLength', 'N/A')}",
            f"DomainLength={features.get('DomainLength', 'N/A')}",
            f"NoOfSubDomain={features.get('NoOfSubDomain', 'N/A')}",
            f"HasObfuscation={features.get('HasObfuscation', 'N/A')}",
            f"NoOfObfuscatedChar={features.get('NoOfObfuscatedChar', 'N/A')}",
            f"NoOfDegitsInURL={features.get('NoOfDegitsInURL', 'N/A')}",
            f"DegitRatioInURL={features.get('DegitRatioInURL', 'N/A')}",
            f"SpacialCharRatioInURL={features.get('SpacialCharRatioInURL', 'N/A')}",
            f"CharContinuationRate={features.get('CharContinuationRate', 'N/A')}",
            f"TLDLegitimateProb={features.get('TLDLegitimateProb', 'N/A')}",
            f"URLCharProb={features.get('URLCharProb', 'N/A')}",
        ]
        telemetry_lines.append(f"3. Extracted Lexical Features: {', '.join(key_metrics)}")

    if ti_providers:
        ti_lines = []
        for p in ti_providers:
            ti_lines.append(f"{p.get('provider')}: status={p.get('status')} ({p.get('evidence')})")
        telemetry_lines.append(f"4. Threat Intelligence Evidence: {'; '.join(ti_lines)}")
        if ti_summary.get("summary"):
            telemetry_lines.append(f"5. Threat Intelligence Overall: {ti_summary.get('summary')}")

    user_prompt = (
        "Please provide a concise technical security scrutiny report based strictly on the following evidence:\n\n"
        + "\n".join(telemetry_lines) + "\n\n"
        "Explain which supplied characteristics contributed to this risk score, how threat intelligence relates to the classifier's verdict (including any agreement or disagreement), what uncertainty remains due to zero-crawl inspection, and practical precautions."
    )

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=600,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if not response.choices or not response.choices[0].message:
            return None, False

        content = response.choices[0].message.content
        if not content or not content.strip():
            return None, False

        return content.strip(), True

    except Exception as e:
        err_type = type(e).__name__
        logger.warning(f"[PhishGuard Groq] Explanation unavailable ({err_type}). Falling back to RF V3 output.")
        return None, False
