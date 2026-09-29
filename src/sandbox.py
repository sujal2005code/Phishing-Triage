"""
Sandbox Analysis — provider abstraction for optional dynamic analysis.

Providers:
- MockSandboxProvider: local development/testing
- URLScanProvider: real URL scanning through urlscan.io
- AnyRunProvider: legacy placeholder kept for compatibility

Safety:
- Suspicious files are never executed directly on the host.
- urlscan.io is used for URL analysis.
"""

import os
import time
import requests
from abc import ABC, abstractmethod
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ============================================================
# Base Provider
# ============================================================

class SandboxProvider(ABC):
    """Base class for sandbox analysis providers."""

    def __init__(self):
        self.name = "base"
        self.enabled = True

    @abstractmethod
    def analyze_url(self, url: str) -> dict:
        """Submit a URL for sandbox analysis."""
        pass

    @abstractmethod
    def analyze_file(self, file_hash: str, filename: str) -> dict:
        """Submit a file hash for sandbox analysis."""
        pass

    def is_available(self) -> bool:
        return self.enabled

    def _unavailable_result(
        self,
        reason: str = "Sandbox not configured"
    ) -> dict:
        return {
            "provider": self.name,
            "status": "unavailable",
            "reason": reason,
            "data": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _error_result(self, reason: str) -> dict:
        return {
            "provider": self.name,
            "status": "error",
            "reason": reason,
            "data": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _result(
        self,
        target: str,
        target_type: str,
        verdict: str,
        score: float,
        details: dict,
    ) -> dict:
        return {
            "provider": self.name,
            "status": "completed",
            "target": target,
            "target_type": target_type,
            "verdict": verdict,
            "score": score,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        }


# ============================================================
# Mock Sandbox
# ============================================================

class MockSandboxProvider(SandboxProvider):
    """
    Mock sandbox for development/testing.

    Used when:
        SANDBOX_PROVIDER=mock
    """

    def __init__(self):
        super().__init__()

        self.name = "mock_sandbox"

        sandbox_enabled = os.getenv(
            "SANDBOX_ENABLED", "false"
        ).lower() in ("true", "1", "yes")

        sandbox_provider = os.getenv(
            "SANDBOX_PROVIDER", "mock"
        ).lower()

        self.enabled = (
            sandbox_enabled
            and sandbox_provider == "mock"
        )

    def analyze_url(self, url: str) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "Sandbox analysis disabled"
            )

        return self._result(
            target=url,
            target_type="url",
            verdict="mock_analysis",
            score=0.0,
            details={
                "note": (
                    "This is MOCK sandbox data for "
                    "development purposes only."
                ),
                "mock": True,
                "simulated_behaviors": [
                    "HTTP request to target URL",
                    "Page rendered in isolated browser",
                    "No malicious behavior detected (simulated)",
                ],
                "network_connections": 1,
                "processes_created": 0,
                "files_dropped": 0,
            },
        )

    def analyze_file(
        self,
        file_hash: str,
        filename: str
    ) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "Sandbox analysis disabled"
            )

        return self._result(
            target=file_hash,
            target_type="file",
            verdict="mock_analysis",
            score=0.0,
            details={
                "note": (
                    "This is MOCK sandbox data for "
                    "development purposes only."
                ),
                "mock": True,
                "filename": filename,
                "simulated_behaviors": [
                    "File opened in isolated environment",
                    "No malicious behavior detected (simulated)",
                ],
            },
        )


# ============================================================
# URLScan.io Provider
# ============================================================

class URLScanProvider(SandboxProvider):
    """
    Real URL analysis using urlscan.io.

    Flow:
        1. Submit URL
        2. Receive scan UUID
        3. Wait for scan
        4. Poll result endpoint
        5. Normalize verdict/evidence

    Required environment variables:
        URLSCAN_ENABLED=true
        URLSCAN_API_KEY=<your key>
    """

    def __init__(self):
        super().__init__()

        self.name = "urlscan"

        self.api_url = "https://urlscan.io/api/v1"

        self.api_key = os.getenv(
            "URLSCAN_API_KEY", ""
        ).strip()

        urlscan_enabled = os.getenv(
            "URLSCAN_ENABLED", "false"
        ).lower() in ("true", "1", "yes")

        sandbox_enabled = os.getenv(
            "SANDBOX_ENABLED", "false"
        ).lower() in ("true", "1", "yes")

        sandbox_provider = os.getenv(
            "SANDBOX_PROVIDER", ""
        ).lower()

        self.enabled = (
            sandbox_enabled
            and sandbox_provider == "urlscan"
            and urlscan_enabled
            and bool(self.api_key)
        )

        self.submit_timeout = int(
            os.getenv("URLSCAN_SUBMIT_TIMEOUT", "30")
        )

        self.initial_wait = int(
            os.getenv("URLSCAN_INITIAL_WAIT", "10")
        )

        self.poll_interval = int(
            os.getenv("URLSCAN_POLL_INTERVAL", "2")
        )

        self.max_wait = int(
            os.getenv("URLSCAN_MAX_WAIT", "90")
        )

    def _headers(self) -> dict:
        return {
            "api-key": self.api_key,
            "Content-Type": "application/json",
        }

    def _extract_verdict(self, data: dict) -> tuple:
        """
        Extract a normalized verdict from urlscan's result.

        Returns:
            (verdict, score)
        """

        verdicts = data.get("verdicts", {}) or {}

        urlscan_verdict = verdicts.get(
            "urlscan", {}
        ) or {}

        engines_verdict = verdicts.get(
            "engines", {}
        ) or {}

        community_verdict = verdicts.get(
            "community", {}
        ) or {}

        malicious = bool(
            urlscan_verdict.get("malicious")
            or engines_verdict.get("malicious")
            or community_verdict.get("malicious")
        )

        # Collect any available verdict information
        brands = (
            urlscan_verdict.get("brands", [])
            or []
        )

        engines = (
            engines_verdict.get("engines", [])
            or []
        )

        if malicious:
            return "malicious", 1.0

        # Some scans may have suspicious indicators
        score_value = (
            urlscan_verdict.get("score")
            or engines_verdict.get("score")
            or 0
        )

        try:
            score_value = float(score_value)
        except (TypeError, ValueError):
            score_value = 0.0

        if score_value > 0:
            return "suspicious", min(
                score_value / 100.0,
                1.0
            )

        return "clean", 0.0

    def _build_details(
        self,
        data: dict,
        result_url: str
    ) -> dict:
        """
        Extract useful evidence from the urlscan result.
        """

        page = data.get("page", {}) or {}
        stats = data.get("stats", {}) or {}
        lists = data.get("lists", {}) or {}
        verdicts = data.get("verdicts", {}) or {}

        return {
            "result_url": result_url,

            "page": {
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "server": page.get("server"),
                "mime_type": page.get("mimeType"),
                "status": page.get("status"),
                "title": page.get("title"),
            },

            "stats": {
                "requests": stats.get("requests"),
                "uniq_requests": stats.get(
                    "uniqRequests"
                ),
                "protocols": stats.get("protocols"),
                "ips": stats.get("ips"),
                "domains": stats.get("domains"),
                "tls": stats.get("tls"),
            },

            "lists": {
                "domains": lists.get("domains", []),
                "ips": lists.get("ips", []),
                "urls": lists.get("urls", []),
            },

            "verdicts": verdicts,
        }

    def analyze_url(self, url: str) -> dict:
        if not self.enabled:
            if not self.api_key:
                return self._unavailable_result(
                    "URLScan API key not configured"
                )

            return self._unavailable_result(
                "URLScan sandbox disabled"
            )

        # ----------------------------------------------------
        # Step 1: Submit URL
        # ----------------------------------------------------

        payload = {
            "url": url,
            "visibility": "unlisted",
        }

        try:
            response = requests.post(
                f"{self.api_url}/scan",
                headers=self._headers(),
                json=payload,
                timeout=self.submit_timeout,
            )
        except requests.RequestException as exc:
            return self._error_result(
                f"URLScan submission failed: {exc}"
            )

        if response.status_code != 200:
            return self._error_result(
                f"URLScan submission HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )

        try:
            submission = response.json()
        except ValueError:
            return self._error_result(
                "URLScan returned invalid JSON during submission"
            )

        scan_id = submission.get("uuid")

        if not scan_id:
            return self._error_result(
                "URLScan submission succeeded but no scan UUID was returned"
            )

        result_url = submission.get(
            "result",
            f"https://urlscan.io/result/{scan_id}/"
        )

        # ----------------------------------------------------
        # Step 2: Wait before polling
        # ----------------------------------------------------

        time.sleep(self.initial_wait)

        # ----------------------------------------------------
        # Step 3: Poll for result
        # ----------------------------------------------------

        result_endpoint = (
            f"{self.api_url}/result/{scan_id}/"
        )

        elapsed = self.initial_wait

        while elapsed <= self.max_wait:

            try:
                response = requests.get(
                    result_endpoint,
                    headers={
                        "api-key": self.api_key
                    },
                    timeout=30,
                )
            except requests.RequestException as exc:
                return self._error_result(
                    f"URLScan result request failed: {exc}"
                )

            # Scan still processing
            if response.status_code == 404:
                time.sleep(self.poll_interval)
                elapsed += self.poll_interval
                continue

            # Scan deleted/unavailable
            if response.status_code == 410:
                return self._error_result(
                    "URLScan result was deleted or is no longer available"
                )

            # Other HTTP errors
            if response.status_code != 200:
                return self._error_result(
                    f"URLScan result HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )

            try:
                data = response.json()
            except ValueError:
                return self._error_result(
                    "URLScan returned invalid JSON for scan result"
                )

            # ------------------------------------------------
            # Step 4: Normalize verdict
            # ------------------------------------------------

            verdict, score = self._extract_verdict(
                data
            )

            details = self._build_details(
                data,
                result_url
            )

            details["scan_id"] = scan_id
            details["visibility"] = submission.get(
                "visibility"
            )

            return self._result(
                target=url,
                target_type="url",
                verdict=verdict,
                score=score,
                details=details,
            )

        # ----------------------------------------------------
        # Timeout waiting for result
        # ----------------------------------------------------

        return self._error_result(
            f"URLScan analysis timed out after {self.max_wait} seconds. "
            f"Scan ID: {scan_id}"
        )

    def analyze_file(
        self,
        file_hash: str,
        filename: str
    ) -> dict:
        """
        urlscan.io is being used here as the URL-analysis
        provider. It does not replace a file malware sandbox
        in this implementation.
        """

        if not self.enabled:
            return self._unavailable_result(
                "URLScan sandbox disabled"
            )

        return self._unavailable_result(
            "URLScan provider currently supports URL analysis only; "
            f"file '{filename}' was not submitted"
        )


# ============================================================
# ANY.RUN Legacy Provider
# ============================================================

class AnyRunProvider(SandboxProvider):
    """
    Legacy ANY.RUN provider placeholder.

    Kept for compatibility with older configuration.
    Not used when SANDBOX_PROVIDER=urlscan.
    """

    def __init__(self):
        super().__init__()

        self.name = "anyrun"

        self.api_key = os.getenv(
            "ANYRUN_API_KEY", ""
        ).strip()

        sandbox_enabled = os.getenv(
            "SANDBOX_ENABLED", "false"
        ).lower() in ("true", "1", "yes")

        sandbox_provider = os.getenv(
            "SANDBOX_PROVIDER", ""
        ).lower()

        self.enabled = (
            sandbox_enabled
            and sandbox_provider == "anyrun"
            and bool(self.api_key)
        )

    def analyze_url(self, url: str) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "ANY.RUN not configured"
            )

        return self._unavailable_result(
            "ANY.RUN integration not implemented in V1"
        )

    def analyze_file(
        self,
        file_hash: str,
        filename: str
    ) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "ANY.RUN not configured"
            )

        return self._unavailable_result(
            "ANY.RUN integration not implemented in V1"
        )


# ============================================================
# Provider Registry
# ============================================================

def get_sandbox_provider() -> SandboxProvider:
    """Get the configured sandbox provider."""

    provider_name = os.getenv(
        "SANDBOX_PROVIDER", "mock"
    ).lower()

    if provider_name == "urlscan":
        return URLScanProvider()

    if provider_name == "anyrun":
        return AnyRunProvider()

    return MockSandboxProvider()


# ============================================================
# Run Sandbox Analysis
# ============================================================

def run_sandbox_analysis(
    urls: list = None,
    attachments: list = None
) -> dict:
    """
    Run sandbox analysis on URLs and/or attachment hashes.

    Args:
        urls:
            List of URLs to analyze.

        attachments:
            List of dicts with 'sha256' and 'filename'.

    Returns:
        Dict with 'url_results' and 'file_results'.
    """

    provider = get_sandbox_provider()

    results = {
        "provider": provider.name,
        "enabled": provider.is_available(),
        "url_results": [],
        "file_results": [],
    }

    if not provider.is_available():
        results["status"] = "disabled"
        results["message"] = (
            "Sandbox analysis unavailable / disabled"
        )
        return results

    if urls:
        for url in urls:
            result = provider.analyze_url(url)
            results["url_results"].append(result)

    if attachments:
        for att in attachments:
            result = provider.analyze_file(
                att.get("sha256", ""),
                att.get("filename", "unknown"),
            )

            results["file_results"].append(result)

    results["status"] = "completed"

    return results


# ============================================================
# Sandbox Status
# ============================================================

def get_sandbox_status() -> dict:
    """Get the current sandbox configuration status."""

    provider = get_sandbox_provider()

    return {
        "enabled": provider.is_available(),
        "provider": provider.name,
        "sandbox_enabled_env": os.getenv(
            "SANDBOX_ENABLED",
            "false",
        ),
        "sandbox_provider_env": os.getenv(
            "SANDBOX_PROVIDER",
            "mock",
        ),
        "urlscan_enabled_env": os.getenv(
            "URLSCAN_ENABLED",
            "false",
        ),
        "urlscan_key_configured": bool(
            os.getenv("URLSCAN_API_KEY", "").strip()
        ),
    }


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":
    print("Sandbox Status:")

    status = get_sandbox_status()

    for key, value in status.items():
        print(f"  {key}: {value}")