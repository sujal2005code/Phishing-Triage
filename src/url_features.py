"""
URL Feature Extractor — converts a URL into numeric features for ML classification.
Features are lexical/structural only (no DNS lookups) for fast offline analysis.
"""

import re
from urllib.parse import urlparse, unquote
import math

# Known URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
    "ow.ly", "short.link", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly",
    "shorturl.at", "bl.ink", "rebrand.ly", "clck.ru", "v.gd",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "buzz", "surf", "monster", "icu", "cam", "click", "link",
}


def extract_features(url: str) -> dict:
    """
    Extract ML features from a URL.

    Returns:
        Dict of feature_name -> numeric_value.
    """
    try:
        url = unquote(url).strip()
        parsed = urlparse(url)
    except Exception:
        return _empty_features()

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url

    features = {}

    # Length features
    features["url_length"] = len(full_url)
    features["domain_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # Count features
    features["num_dots"] = hostname.count(".")
    features["num_hyphens"] = hostname.count("-")
    features["num_underscores"] = full_url.count("_")
    features["num_slashes"] = full_url.count("/")
    features["num_question_marks"] = full_url.count("?")
    features["num_equals"] = full_url.count("=")
    features["num_ampersands"] = full_url.count("&")
    features["num_at_symbols"] = full_url.count("@")
    features["num_digits_in_domain"] = sum(c.isdigit() for c in hostname)
    features["num_special_chars"] = sum(
        not c.isalnum() and c not in "./-_:?" for c in full_url
    )

    # Subdomain features
    domain_parts = hostname.split(".")
    features["num_subdomains"] = max(0, len(domain_parts) - 2)
    features["subdomain_length"] = (
        len(".".join(domain_parts[:-2])) if len(domain_parts) > 2 else 0
    )

    # Boolean / binary features
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["has_ip_address"] = 1 if _is_ip_hostname(hostname) else 0
    features["has_at_symbol"] = 1 if "@" in full_url else 0
    features["has_double_slash_redirect"] = 1 if "//" in path else 0
    features["is_shortened"] = 1 if _is_shortened_url(hostname) else 0
    features["has_suspicious_tld"] = 1 if _has_suspicious_tld(hostname) else 0
    features["has_port"] = 1 if parsed.port and parsed.port not in (80, 443) else 0

    # Suspicious keyword features
    features["has_login_keyword"] = 1 if _has_keywords(full_url, ["login", "signin", "sign-in", "logon"]) else 0
    features["has_account_keyword"] = 1 if _has_keywords(full_url, ["account", "verify", "confirm", "secure"]) else 0
    features["has_update_keyword"] = 1 if _has_keywords(full_url, ["update", "upgrade", "suspend", "limit"]) else 0
    features["has_bank_keyword"] = 1 if _has_keywords(full_url, ["bank", "paypal", "payment", "wallet"]) else 0

    # Entropy — higher entropy can indicate encoded/obfuscated URLs
    features["url_entropy"] = _shannon_entropy(full_url)
    features["domain_entropy"] = _shannon_entropy(hostname)

    # Ratio features
    features["digit_ratio"] = (
        sum(c.isdigit() for c in full_url) / len(full_url) if full_url else 0
    )
    features["letter_ratio"] = (
        sum(c.isalpha() for c in full_url) / len(full_url) if full_url else 0
    )

    # Path depth
    features["path_depth"] = path.count("/") - 1 if path else 0

    # File extension in path
    features["has_executable_ext"] = 1 if _has_executable_extension(path) else 0

    return features


def get_feature_names() -> list:
    """Return ordered list of feature names used by the model."""
    # Generate from a dummy URL to get consistent ordering
    dummy = extract_features("https://example.com")
    return sorted(dummy.keys())


def features_to_vector(features: dict) -> list:
    """Convert features dict to a sorted vector for ML prediction."""
    names = get_feature_names()
    return [features.get(name, 0) for name in names]


def _empty_features() -> dict:
    """Return all-zero features for unparseable URLs."""
    names = get_feature_names() if hasattr(_empty_features, "_cached") else []
    if not names:
        # Bootstrap: create minimal feature set
        return {name: 0 for name in [
            "url_length", "domain_length", "path_length", "query_length",
            "num_dots", "num_hyphens", "num_underscores", "num_slashes",
            "num_question_marks", "num_equals", "num_ampersands",
            "num_at_symbols", "num_digits_in_domain", "num_special_chars",
            "num_subdomains", "subdomain_length", "has_https",
            "has_ip_address", "has_at_symbol", "has_double_slash_redirect",
            "is_shortened", "has_suspicious_tld", "has_port",
            "has_login_keyword", "has_account_keyword", "has_update_keyword",
            "has_bank_keyword", "url_entropy", "domain_entropy",
            "digit_ratio", "letter_ratio", "path_depth", "has_executable_ext",
        ]}
    return {name: 0 for name in names}


def _is_ip_hostname(hostname: str) -> bool:
    """Check if hostname is an IP address."""
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    return False


def _is_shortened_url(hostname: str) -> bool:
    """Check if hostname belongs to a known URL shortener."""
    return hostname.lower() in URL_SHORTENERS


def _has_suspicious_tld(hostname: str) -> bool:
    """Check if hostname uses a suspicious TLD."""
    parts = hostname.lower().split(".")
    if parts:
        return parts[-1] in SUSPICIOUS_TLDS
    return False


def _has_keywords(text: str, keywords: list) -> bool:
    """Check if text contains any of the given keywords (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _has_executable_extension(path: str) -> bool:
    """Check if path ends with an executable extension."""
    exts = {".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".msi",
            ".js", ".vbs", ".wsf", ".ps1", ".jar"}
    path_lower = path.lower()
    return any(path_lower.endswith(ext) for ext in exts)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


if __name__ == "__main__":
    import json

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "https://secure-login.paypal.com.evil-site.tk/verify?id=12345",
        "http://bit.ly/abc123",
    ]

    for url in test_urls:
        feats = extract_features(url)
        print(f"\n{url}")
        print(json.dumps(feats, indent=2))
