"""
Threat Intelligence Providers — abstraction layer for VirusTotal, URLhaus, and OpenPhish.

API keys come from environment variables. Handles:
- Missing API keys → reports unavailable
- Timeouts → reports timeout
- Rate limits → reports rate-limited
- API errors → reports error with details
- No results → reports clean/no data

One provider failure never crashes the entire investigation.
"""

import os
import json
import time
import hashlib
from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Default timeout for API requests
DEFAULT_TIMEOUT = 15


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""

    def __init__(self):
        self.name = "base"
        self.enabled = True
        self.last_error = None

    @abstractmethod
    def lookup_url(self, url: str) -> dict:
        """Look up a URL's reputation."""
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> dict:
        """Look up a domain's reputation."""
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> dict:
        """Look up a file hash."""
        pass

    @abstractmethod
    def lookup_ip(self, ip: str) -> dict:
        """Look up an IP address."""
        pass

    def is_available(self) -> bool:
        """Check if this provider is configured and available."""
        return self.enabled

    def _unavailable_result(self, reason: str = "Provider not configured") -> dict:
        return {
            "provider": self.name,
            "status": "unavailable",
            "reason": reason,
            "data": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _error_result(self, error: str) -> dict:
        return {
            "provider": self.name,
            "status": "error",
            "reason": str(error),
            "data": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _result(self, data: dict, malicious: bool = False, score: float = 0.0) -> dict:
        return {
            "provider": self.name,
            "status": "success",
            "malicious": malicious,
            "score": score,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _no_data_result(self) -> dict:
        return {
            "provider": self.name,
            "status": "no_data",
            "reason": "No results found for this indicator",
            "data": None,
            "timestamp": datetime.utcnow().isoformat(),
        }


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal threat intelligence provider."""

    def __init__(self):
        super().__init__()
        self.name = "virustotal"
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.enabled = bool(self.api_key)

    def _get_headers(self):
        return {"x-apikey": self.api_key}

    def lookup_url(self, url: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("VIRUSTOTAL_API_KEY not configured")
        try:
            import requests
            import base64

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self._get_headers(),
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 429:
                return self._error_result("Rate limited by VirusTotal API")
            if resp.status_code == 404:
                return self._no_data_result()
            if resp.status_code != 200:
                return self._error_result(f"HTTP {resp.status_code}: {resp.text[:200]}")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            score = malicious_count / total if total > 0 else 0

            return self._result(
                data={
                    "malicious_count": malicious_count,
                    "total_engines": total,
                    "stats": stats,
                    "reputation": data.get("reputation"),
                    "categories": data.get("categories", {}),
                },
                malicious=malicious_count > 0,
                score=score,
            )
        except ImportError:
            return self._error_result("requests library not available")
        except Exception as e:
            return self._error_result(str(e))

    def lookup_domain(self, domain: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("VIRUSTOTAL_API_KEY not configured")
        try:
            import requests

            resp = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=self._get_headers(),
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 429:
                return self._error_result("Rate limited by VirusTotal API")
            if resp.status_code == 404:
                return self._no_data_result()
            if resp.status_code != 200:
                return self._error_result(f"HTTP {resp.status_code}")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return self._result(
                data={
                    "malicious_count": malicious_count,
                    "total_engines": total,
                    "stats": stats,
                    "reputation": data.get("reputation"),
                    "registrar": data.get("registrar"),
                    "creation_date": data.get("creation_date"),
                },
                malicious=malicious_count > 0,
                score=malicious_count / total if total > 0 else 0,
            )
        except Exception as e:
            return self._error_result(str(e))

    def lookup_hash(self, file_hash: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("VIRUSTOTAL_API_KEY not configured")
        try:
            import requests

            resp = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self._get_headers(),
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 429:
                return self._error_result("Rate limited")
            if resp.status_code == 404:
                return self._no_data_result()
            if resp.status_code != 200:
                return self._error_result(f"HTTP {resp.status_code}")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return self._result(
                data={
                    "malicious_count": malicious_count,
                    "total_engines": total,
                    "stats": stats,
                    "type_description": data.get("type_description"),
                    "meaningful_name": data.get("meaningful_name"),
                },
                malicious=malicious_count > 0,
                score=malicious_count / total if total > 0 else 0,
            )
        except Exception as e:
            return self._error_result(str(e))

    def lookup_ip(self, ip: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("VIRUSTOTAL_API_KEY not configured")
        try:
            import requests

            resp = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=self._get_headers(),
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 429:
                return self._error_result("Rate limited")
            if resp.status_code == 404:
                return self._no_data_result()
            if resp.status_code != 200:
                return self._error_result(f"HTTP {resp.status_code}")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return self._result(
                data={
                    "malicious_count": malicious_count,
                    "total_engines": total,
                    "stats": stats,
                    "as_owner": data.get("as_owner"),
                    "country": data.get("country"),
                },
                malicious=malicious_count > 0,
                score=malicious_count / total if total > 0 else 0,
            )
        except Exception as e:
            return self._error_result(str(e))


class URLhausProvider(ThreatIntelProvider):
    """URLhaus threat intelligence provider (abuse.ch)."""

    def __init__(self):
        super().__init__()
        self.name = "urlhaus"
        self.enabled = os.getenv(
            "URLHAUS_ENABLED", "true"
        ).lower() in ("true", "1", "yes")

        self.api_url = "https://urlhaus-api.abuse.ch/v1"
        self.auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()

    def lookup_url(self, url: str) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "URLhaus disabled in configuration"
            )

        if not self.auth_key:
            return self._unavailable_result(
                "URLhaus Auth-Key not configured"
            )

        try:
            import requests

            resp = requests.post(
                f"{self.api_url}/url/",
                data={"url": url},
                headers={"Auth-Key": self.auth_key},
                timeout=DEFAULT_TIMEOUT,
            )

            if resp.status_code != 200:
                return self._error_result(
                    f"HTTP {resp.status_code}"
                )

            data = resp.json()
            query_status = data.get("query_status", "")

            if query_status == "no_results":
                return self._no_data_result()

            threat = data.get("threat", "")
            tags = data.get("tags", [])
            url_status = data.get("url_status", "")

            return self._result(
                data={
                    "threat": threat,
                    "tags": tags if tags else [],
                    "url_status": url_status,
                    "date_added": data.get("date_added"),
                    "reporter": data.get("reporter"),
                },
                malicious=(
                    query_status == "ok"
                    and url_status != "offline"
                ),
                score=1.0 if query_status == "ok" else 0.0,
            )

        except Exception as e:
            return self._error_result(str(e))

    def lookup_domain(self, domain: str) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "URLhaus disabled"
            )

        if not self.auth_key:
            return self._unavailable_result(
                "URLhaus Auth-Key not configured"
            )

        try:
            import requests

            resp = requests.post(
                f"{self.api_url}/host/",
                data={"host": domain},
                headers={"Auth-Key": self.auth_key},
                timeout=DEFAULT_TIMEOUT,
            )

            if resp.status_code != 200:
                return self._error_result(
                    f"HTTP {resp.status_code}"
                )

            data = resp.json()

            if data.get("query_status") == "no_results":
                return self._no_data_result()

            url_count = data.get("url_count", 0)
            urls_online = data.get("urls_online", 0)

            return self._result(
                data={
                    "url_count": url_count,
                    "urls_online": urls_online,
                    "blacklists": data.get(
                        "blacklists", {}
                    ),
                },
                malicious=url_count > 0,
                score=min(url_count / 10, 1.0),
            )

        except Exception as e:
            return self._error_result(str(e))

    def lookup_hash(self, file_hash: str) -> dict:
        if not self.enabled:
            return self._unavailable_result(
                "URLhaus disabled"
            )

        if not self.auth_key:
            return self._unavailable_result(
                "URLhaus Auth-Key not configured"
            )

        try:
            import requests

            hash_type = (
                "sha256_hash"
                if len(file_hash) == 64
                else "md5_hash"
            )

            resp = requests.post(
                f"{self.api_url}/payload/",
                data={hash_type: file_hash},
                headers={"Auth-Key": self.auth_key},
                timeout=DEFAULT_TIMEOUT,
            )

            if resp.status_code != 200:
                return self._error_result(
                    f"HTTP {resp.status_code}"
                )

            data = resp.json()

            if data.get("query_status") == "no_results":
                return self._no_data_result()

            return self._result(
                data={
                    "file_type": data.get("file_type"),
                    "signature": data.get("signature"),
                    "url_count": data.get("url_count", 0),
                },
                malicious=(
                    data.get("query_status") == "ok"
                ),
                score=(
                    1.0
                    if data.get("query_status") == "ok"
                    else 0.0
                ),
            )

        except Exception as e:
            return self._error_result(str(e))

    def lookup_ip(self, ip: str) -> dict:
        # URLhaus uses the host endpoint for IPs too
        return self.lookup_domain(ip)


class OpenPhishProvider(ThreatIntelProvider):
    """OpenPhish threat intelligence provider. Uses the free feed."""

    def __init__(self):
        super().__init__()
        self.name = "openphish"
        self.enabled = os.getenv("OPENPHISH_ENABLED", "true").lower() in ("true", "1", "yes")
        self.feed_url = "https://openphish.com/feed.txt"
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = 3600  # 1 hour

    def _load_feed(self) -> set:
        """Load and cache the OpenPhish feed."""
        now = time.time()
        if self._cache is not None and (now - self._cache_time) < self._cache_ttl:
            return self._cache

        try:
            import requests

            resp = requests.get(self.feed_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                self._cache = set(line.strip() for line in resp.text.strip().split("\n") if line.strip())
                self._cache_time = now
                return self._cache
            else:
                return set()
        except Exception:
            return self._cache or set()

    def lookup_url(self, url: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("OpenPhish disabled in configuration")
        try:
            feed = self._load_feed()
            if not feed:
                return self._error_result("Unable to load OpenPhish feed")

            # Check exact match and prefix match
            found = url in feed or any(url.startswith(entry) for entry in feed)

            if found:
                return self._result(
                    data={"matched": True, "feed_size": len(feed)},
                    malicious=True,
                    score=1.0,
                )
            else:
                return self._result(
                    data={"matched": False, "feed_size": len(feed)},
                    malicious=False,
                    score=0.0,
                )
        except Exception as e:
            return self._error_result(str(e))

    def lookup_domain(self, domain: str) -> dict:
        if not self.enabled:
            return self._unavailable_result("OpenPhish disabled")
        try:
            feed = self._load_feed()
            if not feed:
                return self._error_result("Unable to load OpenPhish feed")

            matched_urls = [u for u in feed if domain in u]

            return self._result(
                data={"matched_urls_count": len(matched_urls), "feed_size": len(feed)},
                malicious=len(matched_urls) > 0,
                score=min(len(matched_urls) / 5, 1.0),
            )
        except Exception as e:
            return self._error_result(str(e))

    def lookup_hash(self, file_hash: str) -> dict:
        # OpenPhish doesn't support hash lookups
        return self._unavailable_result("OpenPhish does not support hash lookups")

    def lookup_ip(self, ip: str) -> dict:
        # OpenPhish doesn't support IP lookups
        return self._unavailable_result("OpenPhish does not support IP lookups")


# Provider registry
def get_providers() -> list:
    """Get all configured threat intelligence providers."""
    return [
        VirusTotalProvider(),
        URLhausProvider(),
        OpenPhishProvider(),
    ]


def enrich_iocs(iocs: list, providers: list = None) -> dict:
    """
    Query all configured providers for each IOC.

    Args:
        iocs: List of dicts with 'type' and 'value'.
        providers: Optional list of provider instances.

    Returns:
        Dict mapping IOC values to lists of provider results.
    """
    if providers is None:
        providers = get_providers()

    results = {}

    for ioc in iocs:
        ioc_type = ioc["type"]
        ioc_value = ioc["value"]
        key = f"{ioc_type}:{ioc_value}"
        results[key] = []

        for provider in providers:
            if not provider.is_available():
                results[key].append(provider._unavailable_result())
                continue

            try:
                if ioc_type == "url":
                    result = provider.lookup_url(ioc_value)
                elif ioc_type == "domain":
                    result = provider.lookup_domain(ioc_value)
                elif ioc_type in ("sha256", "md5", "hash"):
                    result = provider.lookup_hash(ioc_value)
                elif ioc_type in ("ipv4", "ip"):
                    result = provider.lookup_ip(ioc_value)
                else:
                    result = provider._unavailable_result(
                        f"IOC type '{ioc_type}' not supported by {provider.name}"
                    )
                results[key].append(result)
            except Exception as e:
                results[key].append(provider._error_result(str(e)))

    return results


def get_provider_status() -> list:
    """Get the configuration status of all providers."""
    status = []
    for p in get_providers():
        status.append({
            "name": p.name,
            "enabled": p.enabled,
            "available": p.is_available(),
        })
    return status


if __name__ == "__main__":
    print("Threat Intelligence Provider Status:")
    for s in get_provider_status():
        icon = "✓" if s["available"] else "✗"
        print(f"  {icon} {s['name']}: {'available' if s['available'] else 'not configured'}")
