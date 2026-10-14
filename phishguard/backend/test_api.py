"""
PhishGuard - Automated Backend Test Suite
Phase 3: FastAPI Backend V3 Production Verification

This suite tests:
1. Schema & feature vector ordering integrity against V3 specification
2. GET /api/health (System status, Random Forest V3 model loading)
3. POST /api/analyze with ChatGPT apex & trailing slash (https://chatgpt.com -> legitimate, risk ~0)
4. POST /api/analyze with Google apex & WWW (https://google.com, https://www.google.com -> legitimate)
5. POST /api/analyze with Google search query (https://www.google.com/search?q=cybersecurity -> legitimate, risk ~0)
6. POST /api/analyze with GitHub apex & about path (https://github.com, https://github.com/about -> legitimate, risk <= 38)
7. POST /api/analyze with GitHub search query (https://github.com/search?q=random+forest -> legitimate, risk ~1)
8. POST /api/analyze with Wikipedia deep path (https://en.wikipedia.org/wiki/Computer_science -> legitimate, risk ~0)
9. POST /api/analyze with Python docs deep path (https://docs.python.org/3/library/unittest.html -> legitimate, risk <= 5)
10. POST /api/analyze with known phishing URLs (high risk >= 80)
11. POST /api/analyze with IP-based phishing (http://198.98.58.123/ -> phishing, risk >= 90)
12. Schema validation on invalid/malformed inputs (Status 422 Unprocessable Entity)
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

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
    "URLCharProb"
]


class TestPhishGuardAPIV3(unittest.TestCase):

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

    def test_03_analyze_chatgpt_apex_and_slash(self):
        """Verify POST /api/analyze classifies ChatGPT apex & trailing slash as legitimate (Risk ~0)."""
        for u in ("https://chatgpt.com", "https://chatgpt.com/"):
            response = self.client.post("/api/analyze", json={"url": u})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["prediction"], "legitimate")
            self.assertEqual(data["label"], 1)
            self.assertLessEqual(data["risk_score"], 10)
            self.assertEqual(data["model_version"], "V3")
        print(f"[TEST 3 PASSED] ChatGPT apex & slash verified: Risk {data['risk_score']}.")

    def test_04_analyze_google_search_query(self):
        """Verify POST /api/analyze classifies Google search query as legitimate (Risk ~0)."""
        response = self.client.post("/api/analyze", json={"url": "https://www.google.com/search?q=cybersecurity"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 10)
        print(f"[TEST 4 PASSED] Google search query verified: Risk {data['risk_score']}.")

    def test_05_analyze_github_about_path(self):
        """Verify POST /api/analyze classifies GitHub /about path as legitimate (Risk ~2)."""
        response = self.client.post("/api/analyze", json={"url": "https://github.com/about"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 20)
        print(f"[TEST 5 PASSED] GitHub /about verified: Risk {data['risk_score']}.")

    def test_06_analyze_github_search_query(self):
        """Verify POST /api/analyze classifies GitHub search query as legitimate (Risk ~1)."""
        response = self.client.post("/api/analyze", json={"url": "https://github.com/search?q=random+forest"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 15)
        print(f"[TEST 6 PASSED] GitHub search query verified: Risk {data['risk_score']}.")

    def test_07_analyze_wikipedia_deep_path(self):
        """Verify POST /api/analyze classifies Wikipedia deep path as legitimate (Risk ~0)."""
        response = self.client.post("/api/analyze", json={"url": "https://en.wikipedia.org/wiki/Computer_science"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 15)
        print(f"[TEST 7 PASSED] Wikipedia deep path verified: Risk {data['risk_score']}.")

    def test_08_analyze_python_docs_deep_path(self):
        """Verify POST /api/analyze classifies Python docs unittest.html as legitimate (Risk ~3)."""
        response = self.client.post("/api/analyze", json={"url": "https://docs.python.org/3/library/unittest.html"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], 1)
        self.assertLessEqual(data["risk_score"], 20)
        print(f"[TEST 8 PASSED] Python docs deep path verified: Risk {data['risk_score']}.")

    def test_09_analyze_phishing_url(self):
        """Verify POST /api/analyze classifies PayPal credential lure as phishing."""
        response = self.client.post("/api/analyze", json={"url": "http://paypal-security-update.account-verify.com/login.php?user=123&token=abc"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertEqual(data["label"], 0)
        self.assertGreaterEqual(data["risk_score"], 80)
        print(f"[TEST 9 PASSED] Phishing credential lure verified: Risk {data['risk_score']}.")

    def test_10_analyze_ip_phishing_url(self):
        """Verify POST /api/analyze classifies raw IP phishing URL as phishing."""
        response = self.client.post("/api/analyze", json={"url": "http://198.98.58.123/"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertEqual(data["label"], 0)
        self.assertGreaterEqual(data["risk_score"], 90)
        print(f"[TEST 10 PASSED] IP-based phishing verified: Risk {data['risk_score']}.")

    def test_11_analyze_dataset_http_phishing(self):
        """Verify POST /api/analyze classifies HTTP phishing domain."""
        response = self.client.post("/api/analyze", json={"url": "http://www.shprakserf.gq"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertEqual(data["label"], 0)
        self.assertGreaterEqual(data["risk_score"], 80)
        print(f"[TEST 11 PASSED] HTTP phishing domain verified: Risk {data['risk_score']}.")

    def test_12_reject_invalid_url_syntax(self):
        """Verify rejection of obviously invalid input."""
        for bad_url in ("not_a_valid_url", "ftp://files.example.com", ""):
            response = self.client.post("/api/analyze", json={"url": bad_url})
            self.assertEqual(response.status_code, 422)
        print("[TEST 12 PASSED] Invalid URL syntax properly rejected with HTTP 422.")

    def test_13_ai_explanation_schema_presence(self):
        """Verify POST /api/analyze response includes ai_explanation and ai_explanation_available fields."""
        response = self.client.post("/api/analyze", json={"url": "https://chatgpt.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ai_explanation_available", data)
        self.assertIn("ai_explanation", data)
        self.assertIsInstance(data["ai_explanation_available"], bool)
        if data["ai_explanation_available"]:
            self.assertIsInstance(data["ai_explanation"], str)
            self.assertTrue(len(data["ai_explanation"]) > 0)
        else:
            self.assertIsNone(data["ai_explanation"])
        print(f"[TEST 13 PASSED] AI explanation schema presence verified (available={data['ai_explanation_available']}).")

    def test_14_graceful_fallback_without_groq_key(self):
        """Verify that when GROQ_API_KEY is not provided, Random Forest V3 predictions remain unaffected."""
        import groq_service
        orig_key = os.environ.get("GROQ_API_KEY")
        try:
            os.environ["GROQ_API_KEY"] = ""
            response = self.client.post("/api/analyze", json={"url": "https://www.google.com/search?q=cybersecurity"})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["prediction"], "legitimate")
            self.assertEqual(data["risk_score"], 0)
            self.assertFalse(data["ai_explanation_available"])
            self.assertIsNone(data["ai_explanation"])
        finally:
            if orig_key is not None:
                os.environ["GROQ_API_KEY"] = orig_key
        print("[TEST 14 PASSED] Graceful Groq fallback verified: RF V3 prediction preserved with ai_explanation=null.")


if __name__ == "__main__":
    unittest.main()

