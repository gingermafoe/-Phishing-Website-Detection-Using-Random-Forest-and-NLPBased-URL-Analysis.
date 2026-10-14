"""
PhishGuard - Automated Backend Test Suite
Phase 4: Live Threat Intelligence & Groq Security Scrutiny Verification

This suite tests:
1. Schema & feature vector ordering integrity against V3 specification (21 features).
2. GET /api/health (System status, Random Forest V3 model loading).
3. Legitimate-style URL analysis (ChatGPT, Google).
4. Suspicious/phishing-style URL analysis (credential lure, IP-based).
5. Random Forest output remains UNCHANGED when threat-intelligence providers disagree.
6. Random Forest output remains UNCHANGED when Groq returns an alarming explanation.
7. Threat-intel provider reports a malicious match (mocked HTTP).
8. Threat-intel provider returns no match (mocked HTTP).
9. Threat-intel provider is not configured.
10. Threat-intel provider times out or returns an HTTP error.
11. Groq API key is missing (graceful fallback).
12. Groq times out or returns invalid output (graceful fallback).
13. Conflicting reputation results (one malicious, one clean).
14. Malformed and oversized URLs (rejected with HTTP 422).
15. Strict separation of model probabilities, risk score, provider evidence, and AI explanation.
"""

import os
import sys
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import httpx

# Ensure backend and ml directories are in path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
ML_DIR = os.path.join(PROJECT_ROOT, "ml")
ML_V3_DIR = os.path.join(ML_DIR, "v3")

for d in (BACKEND_DIR, ML_DIR, ML_V3_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from main import app
import feature_config_v3 as fc_v3
import threat_intel_service
import groq_service

EXPECTED_21_FEATURES = [
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
    "URLCharProb",
]


class TestPhishGuardBackendV4(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_feature_vector_schema_integrity(self):
        """Verify that the 21 production V3 features match the exact specification."""
        self.assertEqual(len(fc_v3.PRIMARY_FEATURES), 21, "Must contain exactly 21 features")
        self.assertEqual(fc_v3.PRIMARY_FEATURES, EXPECTED_21_FEATURES, "Feature names and order must match exactly")
        print("\n[TEST 1 PASSED] V3 21-feature vector schema and ordering verified.")

    def test_02_health_endpoint(self):
        """Verify GET /api/health returns status 200 and indicates V3 model is loaded."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["model"], "Random Forest V3")
        self.assertTrue(data["model_loaded"])
        print(f"[TEST 2 PASSED] Health check verified: {data}")

    def test_03_legitimate_url_analysis(self):
        """Verify POST /api/analyze classifies legitimate URL correctly (Risk <= 10)."""
        response = self.client.post("/api/analyze", json={"url": "https://www.google.com/search?q=cybersecurity"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 10)
        self.assertEqual(data["model_version"], "V3")
        self.assertIn("features", data)
        self.assertIn("threat_intel_providers", data)
        self.assertIn("threat_intel_summary", data)
        print(f"[TEST 3 PASSED] Legitimate URL verified: Risk {data['risk_score']}.")

    def test_04_suspicious_phishing_url_analysis(self):
        """Verify POST /api/analyze classifies credential lure URL as phishing (Risk >= 80)."""
        response = self.client.post(
            "/api/analyze",
            json={"url": "http://paypal-security-update.account-verify.com/login.php?user=123&token=abc"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertEqual(data["label"], 0)
        self.assertGreaterEqual(data["risk_score"], 80)
        print(f"[TEST 4 PASSED] Suspicious lure verified: Risk {data['risk_score']}.")

    def test_05_rf_unchanged_when_threat_intel_disagrees(self):
        """
        Verify that Random Forest output remains UNCHANGED even when threat intelligence
        reports a conflicting malicious match.
        """
        mock_ti_results = [
            {
                "provider": "Google Safe Browsing",
                "status": "malicious_match",
                "status_label": "Threat Match",
                "evidence": "Flagged as SOCIAL_ENGINEERING",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "Flagged by Google Safe Browsing.",
            },
            {
                "provider": "VirusTotal",
                "status": "malicious_match",
                "status_label": "Threat Match",
                "evidence": "12 vendors flagged as malicious",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "Flagged by VirusTotal.",
            },
            {
                "provider": "PhishTank",
                "status": "not_configured",
                "status_label": "Not Configured",
                "evidence": "Not configured",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "Not configured",
            },
        ]
        mock_ti_summary = {
            "status": "malicious_match",
            "summary": "2 provider(s) reported threat match.",
            "configured_providers_count": 2,
            "total_providers_count": 3,
            "malicious_count": 2,
        }

        with patch(
            "threat_intel_service.check_all_threat_intelligence",
            new_callable=AsyncMock,
            return_value=(mock_ti_results, mock_ti_summary),
        ):
            # ChatGPT is lexically legitimate (RF risk ~0)
            response = self.client.post("/api/analyze", json={"url": "https://chatgpt.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()

            # RF V3 MUST REMAIN AUTHORITATIVE: Legitimate, Risk <= 10
            self.assertEqual(data["prediction"], "legitimate")
            self.assertEqual(data["label"], 1)
            self.assertLessEqual(data["risk_score"], 10)

            # Threat intelligence reflects its own independent malicious finding
            self.assertEqual(data["threat_intel_summary"]["status"], "malicious_match")
            self.assertEqual(len(data["threat_intel_providers"]), 3)
            print("[TEST 5 PASSED] RF V3 output preserved despite conflicting malicious threat intel.")

    def test_06_rf_unchanged_when_groq_returns_alarming_explanation(self):
        """
        Verify that Random Forest output remains UNCHANGED when Groq returns
        an alarming or critical explanation.
        """
        alarming_explanation = (
            "CRITICAL WARNING: This URL exhibits severe anomalies and should be treated as high danger."
        )

        with patch("groq_service.generate_explanation", return_value=(alarming_explanation, True)):
            response = self.client.post("/api/analyze", json={"url": "https://www.google.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()

            # RF V3 is untouched: legitimate, label 1, risk <= 10
            self.assertEqual(data["prediction"], "legitimate")
            self.assertEqual(data["label"], 1)
            self.assertLessEqual(data["risk_score"], 10)
            self.assertEqual(data["ai_explanation"], alarming_explanation)
            self.assertTrue(data["ai_explanation_available"])
            print("[TEST 6 PASSED] RF V3 output preserved when Groq generates alarming explanation.")

    def test_07_provider_reports_malicious_match_mocked(self):
        """Verify handling when an external provider returns a confirmed threat match."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]
        }

        async def run_test():
            async with httpx.AsyncClient() as client:
                with patch.object(client, "post", new_callable=AsyncMock, return_value=mock_response):
                    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "fake_key_123"}):
                        res = await threat_intel_service.check_google_safe_browsing("http://phish.example.com", client)
                        self.assertEqual(res["status"], "malicious_match")
                        self.assertIn("SOCIAL_ENGINEERING", res["evidence"])
                        self.assertEqual(res["status_label"], "Threat Match")

        import asyncio
        asyncio.run(run_test())
        print("[TEST 7 PASSED] Provider malicious match handling verified.")

    def test_08_provider_returns_no_match_mocked(self):
        """Verify handling when external provider returns no match (clean)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # Empty matches

        async def run_test():
            async with httpx.AsyncClient() as client:
                with patch.object(client, "post", new_callable=AsyncMock, return_value=mock_response):
                    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "fake_key_123"}):
                        res = await threat_intel_service.check_google_safe_browsing("https://example.com", client)
                        self.assertEqual(res["status"], "no_match_found")
                        self.assertEqual(res["status_label"], "No Match Found")
                        self.assertIn("does not indicate or prove safety", res["explanation"])

        import asyncio
        asyncio.run(run_test())
        print("[TEST 8 PASSED] Provider no match found handling verified.")

    def test_09_provider_not_configured(self):
        """Verify handling when provider API key is not configured."""
        async def run_test():
            async with httpx.AsyncClient() as client:
                with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": ""}, clear=False):
                    res = await threat_intel_service.check_google_safe_browsing("https://example.com", client)
                    self.assertEqual(res["status"], "not_configured")
                    self.assertEqual(res["status_label"], "Not Configured")
                    self.assertIn("not configured", res["evidence"].lower())

        import asyncio
        asyncio.run(run_test())
        print("[TEST 9 PASSED] Provider not configured handling verified.")

    def test_10_provider_times_out_or_returns_error(self):
        """Verify that provider timeouts and errors are handled gracefully without failing the backend."""
        async def run_test():
            async with httpx.AsyncClient() as client:
                # Timeout
                with patch.object(client, "post", side_effect=httpx.TimeoutException("Timeout")):
                    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "fake_key"}):
                        res = await threat_intel_service.check_google_safe_browsing("https://example.com", client)
                        self.assertEqual(res["status"], "unavailable")
                        self.assertEqual(res["status_label"], "Timed Out")

                # HTTP 500
                err_resp = MagicMock()
                err_resp.status_code = 500
                with patch.object(client, "post", new_callable=AsyncMock, return_value=err_resp):
                    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "fake_key"}):
                        res = await threat_intel_service.check_google_safe_browsing("https://example.com", client)
                        self.assertEqual(res["status"], "unavailable")

        import asyncio
        asyncio.run(run_test())
        print("[TEST 10 PASSED] Provider timeout and HTTP 500 error handled gracefully.")

    def test_11_groq_missing_api_key(self):
        """Verify that when GROQ_API_KEY is missing, RF V3 predictions succeed with ai_explanation=None."""
        orig_key = os.environ.get("GROQ_API_KEY")
        try:
            os.environ["GROQ_API_KEY"] = ""
            response = self.client.post("/api/analyze", json={"url": "https://www.google.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["prediction"], "legitimate")
            self.assertFalse(data["ai_explanation_available"])
            self.assertIsNone(data["ai_explanation"])
        finally:
            if orig_key is not None:
                os.environ["GROQ_API_KEY"] = orig_key
        print("[TEST 11 PASSED] Missing Groq key handled cleanly.")

    def test_12_groq_times_out_or_invalid_output(self):
        """Verify that when Groq raises an exception or times out, backend falls back gracefully."""
        with patch("groq_service.generate_explanation", return_value=(None, False)):
            response = self.client.post("/api/analyze", json={"url": "https://www.google.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["prediction"], "legitimate")
            self.assertFalse(data["ai_explanation_available"])
            self.assertIsNone(data["ai_explanation"])
        print("[TEST 12 PASSED] Groq failure/timeout falls back gracefully.")

    def test_13_conflicting_reputation_results(self):
        """Verify handling of conflicting reputation results between providers."""
        mock_ti_results = [
            {
                "provider": "Google Safe Browsing",
                "status": "malicious_match",
                "status_label": "Threat Match",
                "evidence": "Flagged as MALWARE",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "Flagged as malware.",
            },
            {
                "provider": "VirusTotal",
                "status": "no_match_found",
                "status_label": "No Match Found",
                "evidence": "0/70 engines flagged",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "No engines flagged.",
            },
            {
                "provider": "PhishTank",
                "status": "unavailable",
                "status_label": "Timed Out",
                "evidence": "Timed out",
                "checked_at": "2026-10-14T11:00:00Z",
                "explanation": "Service timed out.",
            },
        ]
        mock_ti_summary = {
            "status": "malicious_match",
            "summary": "1 provider(s) reported threat match (Google Safe Browsing).",
            "configured_providers_count": 3,
            "total_providers_count": 3,
            "malicious_count": 1,
        }

        with patch(
            "threat_intel_service.check_all_threat_intelligence",
            new_callable=AsyncMock,
            return_value=(mock_ti_results, mock_ti_summary),
        ):
            response = self.client.post("/api/analyze", json={"url": "https://suspicious-test.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["threat_intel_summary"]["status"], "malicious_match")
            self.assertEqual(data["threat_intel_summary"]["malicious_count"], 1)
            # Ensure no invented combined probability
            self.assertNotIn("combined_probability", data)
            self.assertNotIn("combined_probability", data["threat_intel_summary"])
        print("[TEST 13 PASSED] Conflicting reputation results handled without invented probabilities.")

    def test_14_malformed_and_oversized_urls(self):
        """Verify rejection of malformed, unsupported protocol, or oversized URLs."""
        # 1. Unsupported protocol
        r1 = self.client.post("/api/analyze", json={"url": "ftp://files.example.com"})
        self.assertEqual(r1.status_code, 422)

        # 2. Empty string
        r2 = self.client.post("/api/analyze", json={"url": ""})
        self.assertEqual(r2.status_code, 422)

        # 3. Oversized URL (>2048 characters)
        huge_url = "https://example.com/" + "a" * 2050
        r3 = self.client.post("/api/analyze", json={"url": huge_url})
        self.assertEqual(r3.status_code, 422)

        # 4. Malformed domain syntax
        r4 = self.client.post("/api/analyze", json={"url": "https://not a valid domain/"})
        self.assertEqual(r4.status_code, 422)
        print("[TEST 14 PASSED] Malformed, invalid, and oversized URLs properly rejected (422).")

    def test_15_response_telemetry_separation(self):
        """Verify response contains all required fields with strict separation."""
        response = self.client.post("/api/analyze", json={"url": "https://en.wikipedia.org/wiki/Computer_science"})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Core fields
        self.assertIn("url", data)
        self.assertIn("prediction", data)
        self.assertIn("label", data)
        self.assertIn("probability", data)
        self.assertIn("risk_score", data)
        self.assertIn("phishing_probability", data)
        self.assertIn("analyzed_at", data)

        # Extracted 21 features
        self.assertIn("features", data)
        features = data["features"]
        self.assertEqual(len(features), 21)
        for f in EXPECTED_21_FEATURES:
            self.assertIn(f, features)

        # Threat intel
        self.assertIn("threat_intel_providers", data)
        self.assertIsInstance(data["threat_intel_providers"], list)
        self.assertEqual(len(data["threat_intel_providers"]), 3)
        self.assertIn("threat_intel_summary", data)

        # AI explanation
        self.assertIn("ai_explanation", data)
        self.assertIn("ai_explanation_available", data)
        print("[TEST 15 PASSED] Complete response telemetry separation verified.")


if __name__ == "__main__":
    unittest.main()
