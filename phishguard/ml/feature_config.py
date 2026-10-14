"""
Feature Configuration and Feature Engineering for PhishGuard.

This module defines:
1. Feature groups and selection taxonomy:
   - RAW_IDENTIFIERS: Text/identifier columns excluded from direct modeling.
   - LEAKAGE_FEATURES: Columns exhibiting target leakage excluded from modeling.
   - URL_LEXICAL_FEATURES: 21 URL-based lexical and statistical features available in real-time.
   - HTML_CONTENT_FEATURES: 28 DOM/HTML features requiring webpage crawling.
   - ALL_CLEAN_FEATURES: The 49 non-leaking features across both categories.
2. Production-ready URL feature extraction logic for inference.
3. Feature metadata and cybersecurity domain explanations.
"""

import math
import re
import urllib.parse
from typing import Dict, List, Any

# ==============================================================================
# 1. COLUMN CLASSIFICATION & FEATURE SELECTION
# ==============================================================================

TARGET_COLUMN: str = "label"

# Label encoding definition:
# In the PhiUSIIL dataset:
#   1 = Legitimate website (Safe)
#   0 = Phishing website (Malicious)
LABEL_MAPPING = {
    0: "Phishing",
    1: "Legitimate"
}

# Raw text and identifier columns:
# Excluded because they are high-cardinality strings that cause overfitting /
# memorization, and NLP is explicitly prohibited for this project.
RAW_IDENTIFIERS: List[str] = [
    "URL",      # 235,370 unique string values (raw URL)
    "Domain",   # 220,086 unique string values (raw domain name)
    "TLD",      # 695 unique categorical strings (represented by numerical TLDLength & TLDLegitimateProb)
    "Title"     # 197,874 unique raw HTML title strings
]

# Target leakage columns:
# Excluded because they directly leak the ground-truth target label.
# In PhiUSIIL, legitimate URLs were compared against a legitimate reference list,
# making URLSimilarityIndex == 100.0 for 100% of legitimate sites (std = 0.0),
# creating artificial 100% self-similarity leakage.
LEAKAGE_FEATURES: List[str] = [
    "URLSimilarityIndex"
]

# Real-time URL Lexical & Statistical Features (21 features):
# Can be computed purely from the URL string itself in <1ms without network access.
# Realistic for deployment when a user inputs only a URL string.
URL_LEXICAL_FEATURES: List[str] = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb"
]

# HTML & Webpage Content Features (28 features):
# Require active network crawling, DOM rendering, and parsing.
# Prone to operational failure when a phishing site is already offline / blocked,
# introduces 3-10s latency, and exposes backend crawlers to malware payloads.
HTML_CONTENT_FEATURES: List[str] = [
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef"
]

# Combined clean dataset features (49 features):
ALL_CLEAN_FEATURES: List[str] = URL_LEXICAL_FEATURES + HTML_CONTENT_FEATURES

# Primary feature set used for the real-time production model (FastAPI backend):
PRIMARY_FEATURES: List[str] = URL_LEXICAL_FEATURES


# ==============================================================================
# 2. FEATURE EXTRACTION FOR LIVE INFERENCE (FastAPI READY)
# ==============================================================================

# Common TLD probabilities derived from PhiUSIIL legitimate distribution
# (Used as fallback lookup when dataset tables are loaded)
COMMON_TLD_PROB = {
    "com": 0.522907,
    "org": 0.079963,
    "de": 0.032650,
    "uk": 0.028555,
    "net": 0.023812,
    "edu": 0.021004,
    "ru": 0.018013,
    "ca": 0.015201,
    "au": 0.014102,
    "fr": 0.013500,
    "in": 0.005084
}

import json
import os

# Path to lookup tables
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOOKUP_FILE = os.path.join(_CURRENT_DIR, "lookup_tables.json")

_LOADED_TLD_MAP = None
_LOADED_CHAR_MAP = None

def _get_lookup_tables():
    global _LOADED_TLD_MAP, _LOADED_CHAR_MAP
    if _LOADED_TLD_MAP is None or _LOADED_CHAR_MAP is None:
        if os.path.exists(_LOOKUP_FILE):
            try:
                with open(_LOOKUP_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    _LOADED_TLD_MAP = data.get("tld_prob_map", COMMON_TLD_PROB)
                    _LOADED_CHAR_MAP = data.get("char_prob_map", {})
            except Exception:
                _LOADED_TLD_MAP = COMMON_TLD_PROB
                _LOADED_CHAR_MAP = {}
        else:
            _LOADED_TLD_MAP = COMMON_TLD_PROB
            _LOADED_CHAR_MAP = {}
    return _LOADED_TLD_MAP, _LOADED_CHAR_MAP


def extract_lexical_features_from_url(url: str, tld_lookup: Dict[str, float] = None) -> Dict[str, Any]:
    """
    Extracts the 21 URL lexical/statistical features from a raw URL string
    matching the exact PhiUSIIL dataset engineering schema.
    Designed for zero-dependency, microsecond inference in the FastAPI backend.
    """
    u = url.strip()
    if not u:
        raise ValueError("URL cannot be empty")

    is_https = 1 if u.lower().startswith("https://") else 0
    url_len = len(u) - 1 if not u.endswith('/') else len(u)
    url_len = max(1, url_len)

    # Parse domain and netloc
    parsed = urllib.parse.urlparse(u if "://" in u else "http://" + u)
    netloc = parsed.netloc.lower()
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    domain_len = len(netloc)

    # 1. IsDomainIP
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    is_domain_ip = 1 if re.match(ipv4_pattern, netloc) else 0

    # 2. TLD extraction and subdomain count
    domain_parts = netloc.split(".")
    if len(domain_parts) > 1:
        tld = domain_parts[-1]
        no_of_subdomain = max(0, len(domain_parts) - 2)
    else:
        tld = ""
        no_of_subdomain = 0
    tld_len = len(tld)

    # 3. Obfuscation detection (%-encoding)
    obf_chars = len(re.findall(r"%[0-9a-fA-F]{2}", u))
    has_obf = 1 if obf_chars > 0 else 0
    obf_ratio = round(obf_chars / url_len, 4)

    # 4. Content string (after stripping protocol and www. prefix)
    content = u
    if content.lower().startswith("https://"):
        content = content[8:]
    elif content.lower().startswith("http://"):
        content = content[7:]
    if content.lower().startswith("www."):
        content = content[4:]

    letters = sum(c.isalpha() for c in content) - 1
    letters = max(0, letters)
    letter_ratio = round(letters / url_len, 3)

    digits = sum(c.isdigit() for c in content)
    digit_ratio = round(digits / url_len, 3)

    no_of_equals = u.count("=")
    no_of_qmark = u.count("?")
    no_of_amp = u.count("&")

    standard_specials = set("=?!&")
    other_specials = sum(1 for c in content if not c.isalnum() and c not in standard_specials)
    spacial_ratio = round(other_specials / url_len, 3)

    # 5. Character Continuation Rate
    max_run = 1
    curr_run = 1
    for i in range(1, len(u)):
        c1, c2 = u[i-1], u[i]
        same = (c1.isalpha() and c2.isalpha()) or (c1.isdigit() and c2.isdigit()) or (not c1.isalnum() and not c2.isalnum())
        if same:
            curr_run += 1
            if curr_run > max_run:
                max_run = curr_run
        else:
            curr_run = 1
    continuation_rate = round(max_run / url_len, 4)

    # 6. Lookups for TLD probability & character probability
    tld_table, char_table = _get_lookup_tables()
    active_tld_map = tld_lookup or tld_table
    tld_prob = active_tld_map.get(tld, 0.0)

    if char_table:
        char_probs = [char_table.get(c.lower(), 0.001) for c in u]
        url_char_prob = round(sum(char_probs) / max(1, len(char_probs)), 8)
    else:
        url_char_prob = 0.055

    return {
        "URLLength": url_len,
        "DomainLength": domain_len,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_len,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obf,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": obf_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_amp,
        "NoOfOtherSpecialCharsInURL": other_specials,
        "SpacialCharRatioInURL": spacial_ratio,
        "IsHTTPS": is_https,
        "CharContinuationRate": continuation_rate,
        "TLDLegitimateProb": tld_prob,
        "URLCharProb": url_char_prob
    }
