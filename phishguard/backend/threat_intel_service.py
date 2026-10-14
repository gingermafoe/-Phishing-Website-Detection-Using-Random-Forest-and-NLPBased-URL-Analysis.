"""
PhishGuard - Threat Intelligence Service
Phase: Live Threat Intelligence Integration

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Random Forest V3 is the AUTHORITATIVE security classifier. Threat intelligence is supplementary external evidence.
2. Threat intelligence MUST NOT modify the Random Forest prediction, probability, or risk score.
3. Secrets and API keys MUST remain in backend environment variables. Never expose them to frontend or logs.
4. Distinguish statuses explicitly:
   - 'malicious_match' : Provider actively reported a confirmed phishing/threat detection.
   - 'no_match_found'  : Provider checked its database and found no active threat listing.
                         (NOTE: Absence of detection does NOT prove safety).
   - 'unknown'         : Provider has no record or conclusive rating for this URL.
   - 'unavailable'     : Provider service timed out or returned HTTP 5xx.
   - 'error'           : Provider returned client error (4xx), quota exceeded (429), or network error.
   - 'not_configured'  : API key is not configured in backend environment.
5. Never visit, crawl, render, or execute the submitted destination website.
6. Queries are issued only to explicitly configured, trusted provider APIs.
"""

import os
import base64
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
import httpx

logger = logging.getLogger("phishguard.threat_intel")

# Provider timeouts and settings
TI_REQUEST_TIMEOUT = float(os.getenv("TI_REQUEST_TIMEOUT_SECONDS", "4.0"))


def _utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


async def check_google_safe_browsing(
    url: str, client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Queries Google Safe Browsing API v4 lookup endpoint.
    Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
    """
    provider_name = "Google Safe Browsing"
    checked_at = _utc_now_iso()
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": provider_name,
            "status": "not_configured",
            "status_label": "Not Configured",
            "evidence": "API key not configured in backend environment variables.",
            "checked_at": checked_at,
            "explanation": "Google Safe Browsing check was skipped because no API key is configured. This does not indicate safety.",
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = await client.post(
            endpoint, json=payload, timeout=TI_REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list(
                    {m.get("threatType", "UNKNOWN") for m in matches}
                )
                evidence_str = f"Flagged as malicious threat: {', '.join(threat_types)}"
                return {
                    "provider": provider_name,
                    "status": "malicious_match",
                    "status_label": "Threat Match",
                    "evidence": evidence_str,
                    "checked_at": checked_at,
                    "explanation": "Google Safe Browsing actively classifies this URL as a known security threat.",
                }
            else:
                return {
                    "provider": provider_name,
                    "status": "no_match_found",
                    "status_label": "No Match Found",
                    "evidence": "No threat matches returned in Google Safe Browsing database.",
                    "checked_at": checked_at,
                    "explanation": "The URL is not currently listed in Google Safe Browsing threat databases. Absence of listing does not indicate or prove safety, as novel phishing campaigns may not yet be indexed.",
                }
        elif response.status_code == 429:
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Quota Exceeded",
                "evidence": "Google Safe Browsing API rate limit exceeded (HTTP 429).",
                "checked_at": checked_at,
                "explanation": "API request quota exceeded. Rate limit error.",
            }
        elif response.status_code in (400, 401, 403):
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Authentication/Client Error",
                "evidence": f"Google Safe Browsing API returned HTTP {response.status_code}.",
                "checked_at": checked_at,
                "explanation": "Query could not be authenticated or payload was rejected by Google Safe Browsing.",
            }
        else:
            return {
                "provider": provider_name,
                "status": "unavailable",
                "status_label": "Service Unavailable",
                "evidence": f"Google Safe Browsing returned HTTP {response.status_code}.",
                "checked_at": checked_at,
                "explanation": "Google Safe Browsing service is currently unavailable.",
            }

    except httpx.TimeoutException:
        return {
            "provider": provider_name,
            "status": "unavailable",
            "status_label": "Timed Out",
            "evidence": f"Query timed out after {TI_REQUEST_TIMEOUT}s.",
            "checked_at": checked_at,
            "explanation": "Google Safe Browsing did not respond within the timeout window.",
        }
    except Exception as e:
        logger.warning(f"Google Safe Browsing query error: {type(e).__name__}")
        return {
            "provider": provider_name,
            "status": "error",
            "status_label": "Error",
            "evidence": f"Network or execution error: {type(e).__name__}.",
            "checked_at": checked_at,
            "explanation": "An unexpected error occurred while querying Google Safe Browsing.",
        }


async def check_virustotal(
    url: str, client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Queries VirusTotal API v3 URL analysis endpoint.
    Endpoint: https://www.virustotal.com/api/v3/urls/{url_id}
    url_id is base64url encoded URL without padding.
    """
    provider_name = "VirusTotal"
    checked_at = _utc_now_iso()
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": provider_name,
            "status": "not_configured",
            "status_label": "Not Configured",
            "evidence": "API key not configured in backend environment variables.",
            "checked_at": checked_at,
            "explanation": "VirusTotal check was skipped because no API key is configured. This does not indicate safety.",
        }

    # Encode URL to base64url without padding
    url_id = (
        base64.urlsafe_b64encode(url.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        response = await client.get(
            endpoint, headers=headers, timeout=TI_REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious > 0 or suspicious >= 2:
                evidence_str = (
                    f"{malicious} security vendor(s) flagged this URL as malicious"
                )
                if suspicious > 0:
                    evidence_str += f" ({suspicious} suspicious)"
                evidence_str += f" out of {total} engines."

                return {
                    "provider": provider_name,
                    "status": "malicious_match",
                    "status_label": "Threat Match",
                    "evidence": evidence_str,
                    "checked_at": checked_at,
                    "explanation": "VirusTotal security engines detected malicious signatures or fraudulent hosting for this URL.",
                }
            else:
                evidence_str = f"0/{total} security engines flagged as malicious on VirusTotal."
                return {
                    "provider": provider_name,
                    "status": "no_match_found",
                    "status_label": "No Match Found",
                    "evidence": evidence_str,
                    "checked_at": checked_at,
                    "explanation": "No security vendors on VirusTotal currently classify this URL as malicious. Newly registered or unindexed domains may show 0 detections.",
                }
        elif response.status_code == 404:
            # Not in VirusTotal database yet
            return {
                "provider": provider_name,
                "status": "unknown",
                "status_label": "Unknown / Unseen",
                "evidence": "URL has no prior scan history in VirusTotal database (HTTP 404).",
                "checked_at": checked_at,
                "explanation": "VirusTotal has never analyzed this specific URL before. Fresh phishing sites typically have no prior records.",
            }
        elif response.status_code == 429:
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Quota Exceeded",
                "evidence": "VirusTotal API rate limit (e.g. 4 req/min) exceeded (HTTP 429).",
                "checked_at": checked_at,
                "explanation": "VirusTotal public or private quota limit reached.",
            }
        elif response.status_code in (401, 403):
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Authentication Error",
                "evidence": f"VirusTotal rejected API key (HTTP {response.status_code}).",
                "checked_at": checked_at,
                "explanation": "Invalid or unauthorized VirusTotal API key.",
            }
        else:
            return {
                "provider": provider_name,
                "status": "unavailable",
                "status_label": "Service Unavailable",
                "evidence": f"VirusTotal returned HTTP {response.status_code}.",
                "checked_at": checked_at,
                "explanation": "VirusTotal service is temporarily unavailable.",
            }

    except httpx.TimeoutException:
        return {
            "provider": provider_name,
            "status": "unavailable",
            "status_label": "Timed Out",
            "evidence": f"Query timed out after {TI_REQUEST_TIMEOUT}s.",
            "checked_at": checked_at,
            "explanation": "VirusTotal did not respond within the timeout window.",
        }
    except Exception as e:
        logger.warning(f"VirusTotal query error: {type(e).__name__}")
        return {
            "provider": provider_name,
            "status": "error",
            "status_label": "Error",
            "evidence": f"Network or execution error: {type(e).__name__}.",
            "checked_at": checked_at,
            "explanation": "An unexpected error occurred while querying VirusTotal.",
        }


async def check_phishtank(
    url: str, client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Queries PhishTank API endpoint.
    Endpoint: https://checkurl.phishtank.com/checkurl/
    Method: POST with form data 'url', 'format=json', and optional 'app_key'.
    """
    provider_name = "PhishTank"
    checked_at = _utc_now_iso()
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": provider_name,
            "status": "not_configured",
            "status_label": "Not Configured",
            "evidence": "API key not configured in backend environment variables.",
            "checked_at": checked_at,
            "explanation": "PhishTank check was skipped because no API key is configured. This does not indicate safety.",
        }

    endpoint = "https://checkurl.phishtank.com/checkurl/"
    headers = {
        "User-Agent": "phishguard/1.0 (phishtank-check)",
    }
    data = {
        "url": url,
        "format": "json",
        "app_key": api_key,
    }

    try:
        response = await client.post(
            endpoint, data=data, headers=headers, timeout=TI_REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            result_json = response.json()
            results = result_json.get("results", {})

            in_database = results.get("in_database", False)
            verified = results.get("verified", False)
            valid = results.get("valid", False)
            phish_id = results.get("phish_id", "N/A")

            if in_database and valid:
                status_str = "malicious_match"
                label = "Threat Match"
                evidence = f"Listed in PhishTank database as active verified phishing (ID: {phish_id})."
                explanation = "PhishTank community and automated verification confirm this URL as a live phishing site."
            elif in_database and not valid:
                status_str = "no_match_found"
                label = "Expired/Invalid Listing"
                evidence = f"URL was previously listed (ID: {phish_id}) but is marked invalid or expired."
                explanation = "The listing in PhishTank is no longer marked as an active phishing page."
            else:
                status_str = "no_match_found"
                label = "No Match Found"
                evidence = "URL is not listed in PhishTank verified phishing database."
                explanation = "URL was not found in PhishTank. PhishTank only contains reported and verified phishing submissions."

            return {
                "provider": provider_name,
                "status": status_str,
                "status_label": label,
                "evidence": evidence,
                "checked_at": checked_at,
                "explanation": explanation,
            }
        elif response.status_code in (401, 403):
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Authentication Error",
                "evidence": f"PhishTank rejected application key (HTTP {response.status_code}).",
                "checked_at": checked_at,
                "explanation": "PhishTank application key error.",
            }
        elif response.status_code == 429 or response.status_code == 509:
            return {
                "provider": provider_name,
                "status": "error",
                "status_label": "Rate Limit Exceeded",
                "evidence": f"PhishTank API rate limit reached (HTTP {response.status_code}).",
                "checked_at": checked_at,
                "explanation": "PhishTank API quota limit reached.",
            }
        else:
            return {
                "provider": provider_name,
                "status": "unavailable",
                "status_label": "Service Unavailable",
                "evidence": f"PhishTank returned HTTP {response.status_code}.",
                "checked_at": checked_at,
                "explanation": "PhishTank service is currently unavailable.",
            }

    except httpx.TimeoutException:
        return {
            "provider": provider_name,
            "status": "unavailable",
            "status_label": "Timed Out",
            "evidence": f"Query timed out after {TI_REQUEST_TIMEOUT}s.",
            "checked_at": checked_at,
            "explanation": "PhishTank did not respond within the timeout window.",
        }
    except Exception as e:
        logger.warning(f"PhishTank query error: {type(e).__name__}")
        return {
            "provider": provider_name,
            "status": "error",
            "status_label": "Error",
            "evidence": f"Network or execution error: {type(e).__name__}.",
            "checked_at": checked_at,
            "explanation": "An unexpected error occurred while querying PhishTank.",
        }


async def check_all_threat_intelligence(
    url: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Queries all three configured threat intelligence providers concurrently using httpx.
    Returns:
        (provider_results, summary_dict)
    """
    async with httpx.AsyncClient(
        follow_redirects=False, verify=True
    ) as client:
        # Run queries concurrently with bounded timeout
        results = await asyncio.gather(
            check_google_safe_browsing(url, client),
            check_virustotal(url, client),
            check_phishtank(url, client),
            return_exceptions=False,
        )

    provider_results: List[Dict[str, Any]] = list(results)

    # Compute overall threat intelligence summary
    total_providers = len(provider_results)
    configured_results = [
        p for p in provider_results if p["status"] != "not_configured"
    ]
    configured_count = len(configured_results)

    malicious_matches = [
        p for p in provider_results if p["status"] == "malicious_match"
    ]
    malicious_count = len(malicious_matches)

    no_matches = [p for p in provider_results if p["status"] == "no_match_found"]
    clean_count = len(no_matches)

    unavailable_count = len(
        [
            p
            for p in provider_results
            if p["status"] in ("unavailable", "error", "unknown")
        ]
    )

    if configured_count == 0:
        overall_status = "not_configured"
        summary_text = (
            "No external threat-intelligence providers are configured in the environment. "
            "Only local Random Forest machine-learning lexical analysis was performed."
        )
    elif malicious_count > 0:
        overall_status = "malicious_match"
        provider_names = ", ".join(p["provider"] for p in malicious_matches)
        summary_text = (
            f"THREAT DETECTED: {malicious_count} provider(s) ({provider_names}) reported an active malicious match. "
            f"External threat intelligence corroborates high risk."
        )
    elif clean_count > 0:
        overall_status = "clean_matches"
        if unavailable_count > 0:
            summary_text = (
                f"No threat records found across {clean_count} reporting provider(s). "
                f"({unavailable_count} provider check(s) were unavailable or returned no history). "
                f"Note: Zero threat matches does NOT prove a website is safe."
            )
        else:
            summary_text = (
                f"No threat records found across all {clean_count} active provider(s). "
                f"Note: Zero threat matches does NOT prove a website is safe, as zero-day attacks often evade reputation lists."
            )
    else:
        overall_status = "inconclusive"
        summary_text = (
            f"Threat-intelligence checks could not be completed for {configured_count} configured provider(s) "
            f"(services timed out, rate limited, or returned no data). Classification relies solely on Random Forest V3."
        )

    summary = {
        "status": overall_status,
        "summary": summary_text,
        "configured_providers_count": configured_count,
        "total_providers_count": total_providers,
        "malicious_count": malicious_count,
    }

    return provider_results, summary
