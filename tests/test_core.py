"""
Tests for core components of the Phishing Triage system.
"""

import os
import sys
import json
import pytest

# Add project root and src to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, PROJECT_ROOT)

from email_parser import parse_eml
from ioc_extractor import extract_iocs, extract_urls
from auth_analyzer import analyze_authentication
from url_features import extract_features, get_feature_names, features_to_vector
from risk_engine import assess_risk, get_recommended_actions


SAMPLES_DIR = os.path.join(PROJECT_ROOT, "samples")


# --- Email Parser Tests ---

class TestEmailParser:
    def _load_sample(self, filename):
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "rb") as f:
            return parse_eml(f.read())

    def test_parse_suspicious_email(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert parsed["subject"] == "Urgent: Your Account Has Been Suspended"
        assert "suspicious-domain.tk" in parsed["from"]
        assert parsed["to"] is not None
        assert parsed["body_text"] != ""
        assert parsed["body_html"] != ""

    def test_parse_legitimate_email(self):
        parsed = self._load_sample("legitimate_email.eml")
        assert "Weekly Product Updates" in parsed["subject"]
        assert "legitimate-company.com" in parsed["from"]

    def test_parse_attachments(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert len(parsed["attachments"]) >= 1
        att = parsed["attachments"][0]
        assert att["filename"] == "account_notice.pdf"
        assert att["mime_type"] == "application/pdf"
        assert att["size"] > 0
        assert len(att["sha256"]) == 64

    def test_parse_auth_results_raw(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert len(parsed["auth_results_raw"]) > 0

    def test_parse_received_headers(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert len(parsed["received"]) > 0

    def test_parse_reply_to(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert parsed["reply_to"] is not None
        assert "another-domain.ml" in parsed["reply_to"]

    def test_parse_return_path(self):
        parsed = self._load_sample("suspicious_email.eml")
        assert parsed["return_path"] is not None

    def test_parse_empty_bytes(self):
        """Parser should handle empty/malformed input gracefully."""
        parsed = parse_eml(b"")
        assert parsed["subject"] is None
        assert parsed["body_text"] == "" or parsed["body_text"] is None

    def test_parse_minimal_email(self):
        raw = b"From: test@test.com\r\nSubject: Hi\r\n\r\nHello"
        parsed = parse_eml(raw)
        assert parsed["from_address"] == "test@test.com"
        assert parsed["subject"] == "Hi"


# --- IOC Extractor Tests ---

class TestIOCExtractor:
    def _get_iocs_from_sample(self, filename):
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "rb") as f:
            parsed = parse_eml(f.read())
        return extract_iocs(parsed)

    def test_extract_urls(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        urls = [i for i in iocs if i["type"] == "url"]
        assert len(urls) >= 1
        url_values = [u["value"] for u in urls]
        assert any("suspicious-site.tk" in u for u in url_values)

    def test_extract_domains(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        assert len(domains) >= 1

    def test_extract_ips(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        assert any("192.168.1.100" in ip for ip in ips)

    def test_extract_emails(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        emails = [i["value"] for i in iocs if i["type"] == "email"]
        assert len(emails) >= 1

    def test_extract_attachment_names(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        att_names = [i["value"] for i in iocs if i["type"] == "attachment_name"]
        assert "account_notice.pdf" in att_names

    def test_extract_sha256(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        hashes = [i for i in iocs if i["type"] == "sha256"]
        assert len(hashes) >= 1
        assert len(hashes[0]["value"]) == 64

    def test_no_duplicates(self):
        iocs = self._get_iocs_from_sample("suspicious_email.eml")
        seen = set()
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            assert key not in seen, f"Duplicate IOC: {key}"
            seen.add(key)


# --- Authentication Analyzer Tests ---

class TestAuthAnalyzer:
    def _analyze_sample(self, filename):
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "rb") as f:
            parsed = parse_eml(f.read())
        return analyze_authentication(parsed)

    def test_suspicious_email_auth(self):
        auth = self._analyze_sample("suspicious_email.eml")
        assert auth["spf"]["result"] == "FAIL"
        assert auth["dkim"]["result"] == "FAIL"
        assert auth["dmarc"]["result"] == "FAIL"

    def test_legitimate_email_auth(self):
        auth = self._analyze_sample("legitimate_email.eml")
        assert auth["spf"]["result"] == "PASS"
        assert auth["dkim"]["result"] == "PASS"
        assert auth["dmarc"]["result"] == "PASS"

    def test_alignment_check(self):
        auth = self._analyze_sample("suspicious_email.eml")
        assert auth["alignment"]["aligned"] is False
        assert len(auth["alignment"]["issues"]) > 0

    def test_legitimate_alignment(self):
        auth = self._analyze_sample("legitimate_email.eml")
        # Return-Path matches From domain
        assert auth["alignment"]["aligned"] is True

    def test_no_auth_headers(self):
        raw = b"From: test@test.com\r\nSubject: Test\r\n\r\nHello"
        parsed = parse_eml(raw)
        auth = analyze_authentication(parsed)
        assert auth["spf"]["result"] == "UNKNOWN"
        assert auth["dkim"]["result"] == "UNKNOWN"
        assert auth["dmarc"]["result"] == "UNKNOWN"

    def test_risk_factors_generated(self):
        auth = self._analyze_sample("suspicious_email.eml")
        assert len(auth["risk_factors"]) > 0

    def test_summary_generated(self):
        auth = self._analyze_sample("suspicious_email.eml")
        assert auth["summary"] != ""


# --- URL Feature Extraction Tests ---

class TestURLFeatures:
    def test_basic_features(self):
        features = extract_features("https://www.google.com")
        assert features["has_https"] == 1
        assert features["url_length"] > 0
        assert features["domain_length"] > 0

    def test_ip_hostname(self):
        features = extract_features("http://192.168.1.1/login.php")
        assert features["has_ip_address"] == 1

    def test_suspicious_url(self):
        features = extract_features("http://paypal-login.evil.tk/verify?id=123")
        assert features["has_suspicious_tld"] == 1
        assert features["has_login_keyword"] == 1
        assert features["num_hyphens"] >= 1

    def test_shortened_url(self):
        features = extract_features("http://bit.ly/abc123")
        assert features["is_shortened"] == 1

    def test_at_symbol(self):
        features = extract_features("http://google.com@evil.tk")
        assert features["has_at_symbol"] == 1

    def test_feature_names_consistent(self):
        names = get_feature_names()
        features = extract_features("https://example.com")
        assert set(names) == set(features.keys())

    def test_feature_vector_length(self):
        features = extract_features("https://example.com")
        vector = features_to_vector(features)
        assert len(vector) == len(get_feature_names())


# --- Risk Engine Tests ---

class TestRiskEngine:
    def test_high_risk_assessment(self):
        result = assess_risk(
            ml_results=[{"prediction": "phishing", "probability": 0.95, "model": "rf", "url": "http://evil.tk"}],
            auth_results={"spf": {"result": "FAIL"}, "dkim": {"result": "FAIL"}, "dmarc": {"result": "FAIL"},
                          "alignment": {"aligned": False, "issues": ["Mismatch"]}, "risk_factors": ["SPF fail"]},
            ti_results={"url:http://evil.tk": [{"provider": "urlhaus", "status": "success", "malicious": True,
                                                 "data": {"threat": "phishing"}, "score": 1.0}]},
        )
        assert result["severity"] in ("HIGH", "CRITICAL")
        assert result["risk_score"] > 50

    def test_low_risk_assessment(self):
        result = assess_risk(
            ml_results=[{"prediction": "legitimate", "probability": 0.1, "model": "rf", "url": "https://google.com"}],
            auth_results={"spf": {"result": "PASS"}, "dkim": {"result": "PASS"}, "dmarc": {"result": "PASS"},
                          "alignment": {"aligned": True, "issues": []}, "risk_factors": []},
            ti_results={},
        )
        assert result["severity"] == "LOW"
        assert result["risk_score"] < 25

    def test_evidence_present(self):
        result = assess_risk(
            ml_results=[{"prediction": "phishing", "probability": 0.8, "model": "rf", "url": "http://test.tk"}],
        )
        assert len(result["evidence"]) > 0
        assert "score_breakdown" in result

    def test_ml_not_sole_authority(self):
        """ML alone at 0.6 prob should not cause CRITICAL."""
        result = assess_risk(
            ml_results=[{"prediction": "phishing", "probability": 0.6, "model": "rf", "url": "http://test.com"}],
            auth_results={"spf": {"result": "PASS"}, "dkim": {"result": "PASS"}, "dmarc": {"result": "PASS"},
                          "alignment": {"aligned": True, "issues": []}, "risk_factors": []},
        )
        assert result["severity"] != "CRITICAL"

    def test_no_evidence(self):
        result = assess_risk()
        assert result["severity"] == "LOW"
        assert result["risk_score"] == 0.0

    def test_recommended_actions(self):
        evidence = [{"source": "ml", "finding": "phishing", "impact": "negative"}]
        actions = get_recommended_actions("HIGH", evidence)
        assert len(actions) > 0

    def test_sandbox_disabled(self):
        result = assess_risk(
            sandbox_results={"status": "disabled", "message": "Sandbox analysis unavailable / disabled"}
        )
        sb_evidence = [e for e in result["evidence"] if e["source"] == "sandbox"]
        assert any("unavailable" in e["finding"].lower() or "disabled" in e["finding"].lower() for e in sb_evidence)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
