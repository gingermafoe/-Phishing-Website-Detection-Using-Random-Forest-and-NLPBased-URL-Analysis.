"""
PhishGuard ML V4-A - Canonical Feature Engineering & Extraction
Project: Phishing Website Detection Using Random Forest (Phase 4 Experiment)

Properties:
1. Canonical Host Representation: Standardizes www. prefix.
2. Trailing Slash Invariance: Canonical length computation prevents trailing slash bias.
3. Structural Subdomain Accounting: NoOfSubDomain measures genuine subdomains.
4. Preserves 100% lexical zero-crawl architecture (<1ms, no network I/O).
5. Exact 21 URL lexical features matching the canonical schema.
6. Empirical TLD legitimate probability recalculated strictly from V4-A training data.
"""

import math
import re
import urllib.parse
import json
import os
from typing import Dict, List, Any

TARGET_COLUMN: str = "label"
LABEL_MAPPING = {
    0: "Phishing",
    1: "Legitimate"
}

PRIMARY_FEATURES: List[str] = [
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

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOOKUP_FILE = os.path.join(_CURRENT_DIR, "lookup_tables_v4a.json")

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


def extract_v4a_lexical_features(url: str, tld_lookup: Dict[str, float] = None) -> Dict[str, Any]:
    """
    Extracts the 21 URL lexical/statistical features using canonical domain representation
    and V4-A training lookup tables.
    """
    u = url.strip()
    if not u:
        raise ValueError("URL cannot be empty")

    is_https = 1 if u.lower().startswith("https://") else 0

    parsed = urllib.parse.urlparse(u if "://" in u else "http://" + u)
    raw_netloc = parsed.netloc.lower().split(":")[0]

    canonical_netloc = raw_netloc[4:] if raw_netloc.startswith("www.") else raw_netloc

    clean_u = u.rstrip("/")
    url_len = max(1, len(clean_u))
    domain_len = len(canonical_netloc)

    # 1. IsDomainIP
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    is_domain_ip = 1 if re.match(ipv4_pattern, canonical_netloc) else 0

    # 2. TLD extraction and canonical subdomain count
    domain_parts = canonical_netloc.split(".")
    if len(domain_parts) > 1:
        tld = domain_parts[-1]
        no_of_subdomain = max(0, len(domain_parts) - 2)
    else:
        tld = ""
        no_of_subdomain = 0
    tld_len = len(tld)

    # 3. Obfuscation detection
    obf_chars = len(re.findall(r"%[0-9a-fA-F]{2}", u))
    has_obf = 1 if obf_chars > 0 else 0
    obf_ratio = round(obf_chars / url_len, 4)

    # 4. Content string
    content = u
    if content.lower().startswith("https://"):
        content = content[8:]
    elif content.lower().startswith("http://"):
        content = content[7:]
    if content.lower().startswith("www."):
        content = content[4:]
    content_clean = content.rstrip("/")

    letters = sum(c.isalpha() for c in content_clean) - 1
    letters = max(0, letters)
    letter_ratio = round(letters / url_len, 3)

    digits = sum(c.isdigit() for c in content_clean)
    digit_ratio = round(digits / url_len, 3)

    no_of_equals = u.count("=")
    no_of_qmark = u.count("?")
    no_of_amp = u.count("&")

    standard_specials = set("=?!&")
    other_specials = sum(1 for c in content_clean if not c.isalnum() and c not in standard_specials)
    spacial_ratio = round(other_specials / url_len, 3)

    # 5. Character Continuation Rate
    max_run = 1
    curr_run = 1
    for i in range(1, len(clean_u)):
        c1, c2 = clean_u[i-1], clean_u[i]
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
        char_probs = [char_table.get(c.lower(), 0.001) for c in clean_u]
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
