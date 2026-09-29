"""
IOC Extractor — extracts URLs, domains, IPs, email addresses, hashes,
and attachment names from parsed email data. Deduplicates and normalizes.
"""

import re
from urllib.parse import urlparse, unquote
from typing import Optional


# Regex patterns
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'`\)\]\}]+',
    re.IGNORECASE,
)

# Match domains (not IPs) — simple but effective
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b'
)

IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

SHA256_PATTERN = re.compile(
    r'\b[a-fA-F0-9]{64}\b'
)

# Common non-interesting domains to filter out
NOISE_DOMAINS = {
    "w3.org", "www.w3.org", "schemas.microsoft.com",
    "schemas.openxmlformats.org", "xml.org", "xmlns.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
}


def extract_iocs(parsed_email: dict) -> list:
    """
    Extract all IOCs from parsed email data.

    Args:
        parsed_email: Output from email_parser.parse_eml().

    Returns:
        List of dicts with keys: type, value, context.
        Deduplicated by (type, value).
    """
    iocs = []
    seen = set()

    # Combine text sources for extraction
    text_sources = []
    if parsed_email.get("body_text"):
        text_sources.append(("body_text", parsed_email["body_text"]))
    if parsed_email.get("body_html"):
        text_sources.append(("body_html", parsed_email["body_html"]))

    # Also extract from headers
    for hdr_key in ("from", "to", "reply_to", "return_path", "subject"):
        val = parsed_email.get(hdr_key)
        if val:
            text_sources.append((f"header:{hdr_key}", val))

    # Extract from received headers
    for i, recv in enumerate(parsed_email.get("received", [])):
        text_sources.append((f"received_header_{i}", recv))

    # Extract URLs
    for ctx, text in text_sources:
        for url in URL_PATTERN.findall(text):
            url_clean = _normalize_url(url)
            if url_clean and ("url", url_clean) not in seen:
                seen.add(("url", url_clean))
                iocs.append({"type": "url", "value": url_clean, "context": ctx})

    # Extract domains from URLs and text
    for ctx, text in text_sources:
        for domain in DOMAIN_PATTERN.findall(text):
            domain_lower = domain.lower()
            if domain_lower not in NOISE_DOMAINS and ("domain", domain_lower) not in seen:
                seen.add(("domain", domain_lower))
                iocs.append({"type": "domain", "value": domain_lower, "context": ctx})

    # Also extract domains from discovered URLs
    for ioc in [i for i in iocs if i["type"] == "url"]:
        try:
            parsed = urlparse(ioc["value"])
            domain = parsed.hostname
            if domain and ("domain", domain) not in seen and domain not in NOISE_DOMAINS:
                seen.add(("domain", domain))
                iocs.append({"type": "domain", "value": domain, "context": "extracted_from_url"})
        except Exception:
            pass

    # Extract IPv4 addresses
    for ctx, text in text_sources:
        for ip in IPV4_PATTERN.findall(text):
            if _is_valid_ip(ip) and ("ipv4", ip) not in seen:
                seen.add(("ipv4", ip))
                iocs.append({"type": "ipv4", "value": ip, "context": ctx})

    # Extract email addresses
    for ctx, text in text_sources:
        for addr in EMAIL_PATTERN.findall(text):
            addr_lower = addr.lower()
            if ("email", addr_lower) not in seen:
                seen.add(("email", addr_lower))
                iocs.append({"type": "email", "value": addr_lower, "context": ctx})

    # Add explicit sender/recipient addresses
    for field in ("from_address", "to_address", "reply_to_address"):
        addr = parsed_email.get(field)
        if addr and ("email", addr.lower()) not in seen:
            seen.add(("email", addr.lower()))
            iocs.append({"type": "email", "value": addr.lower(), "context": f"header:{field}"})

    # Extract SHA256 hashes from text
    for ctx, text in text_sources:
        for h in SHA256_PATTERN.findall(text):
            h_lower = h.lower()
            if ("sha256", h_lower) not in seen:
                seen.add(("sha256", h_lower))
                iocs.append({"type": "sha256", "value": h_lower, "context": ctx})

    # Add attachment IOCs
    for att in parsed_email.get("attachments", []):
        fname = att.get("filename", "")
        if fname and ("attachment_name", fname) not in seen:
            seen.add(("attachment_name", fname))
            iocs.append({"type": "attachment_name", "value": fname, "context": "attachment"})

        sha = att.get("sha256", "")
        if sha and ("sha256", sha) not in seen:
            seen.add(("sha256", sha))
            iocs.append({"type": "sha256", "value": sha, "context": f"attachment:{fname}"})

    return iocs


def extract_urls(parsed_email: dict) -> list:
    """Extract only URLs from the parsed email. Returns list of URL strings."""
    iocs = extract_iocs(parsed_email)
    return [ioc["value"] for ioc in iocs if ioc["type"] == "url"]


def _normalize_url(url: str) -> Optional[str]:
    """Normalize a URL — decode, strip trailing punctuation."""
    try:
        url = unquote(url).strip()
        # Strip trailing punctuation that's likely not part of the URL
        url = re.sub(r'[.,;:!?\)\]\}>]+$', '', url)
        # Basic validation
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return url
        return None
    except Exception:
        return None


def _is_valid_ip(ip: str) -> bool:
    """Check if an IP is a plausible public/routable IP (not 0.0.0.0 or broadcast)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
        # Filter out obviously uninteresting IPs
        if nums[0] == 0 or ip == "255.255.255.255":
            return False
        # Filter out common version-number patterns (e.g., 1.0.0.1 could be real)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    import sys
    import json
    from email_parser import parse_eml

    if len(sys.argv) < 2:
        print("Usage: python ioc_extractor.py <path_to_eml>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        parsed = parse_eml(f.read())

    iocs = extract_iocs(parsed)
    print(f"\nExtracted {len(iocs)} IOCs:\n")
    for ioc in iocs:
        print(f"  [{ioc['type']:>16}] {ioc['value']}")
