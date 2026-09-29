"""
Email Authentication Analyzer — extracts SPF, DKIM, and DMARC evidence
from email headers (primarily Authentication-Results).

Does NOT fabricate results. Uses UNKNOWN when evidence is unavailable.
"""

import re
from typing import Optional


# Result statuses
PASS = "PASS"
FAIL = "FAIL"
NONE = "NONE"
UNKNOWN = "UNKNOWN"

VALID_STATUSES = {PASS, FAIL, NONE, UNKNOWN}


def analyze_authentication(parsed_email: dict) -> dict:
    """
    Analyze email authentication evidence.

    Args:
        parsed_email: Output from email_parser.parse_eml().

    Returns:
        Dict with spf, dkim, dmarc results and supporting details.
    """
    auth_results_raw = parsed_email.get("auth_results_raw", [])
    headers = parsed_email.get("headers", {})

    # Parse Authentication-Results headers
    spf_result = UNKNOWN
    dkim_result = UNKNOWN
    dmarc_result = UNKNOWN
    spf_details = ""
    dkim_details = ""
    dmarc_details = ""

    for auth_header in auth_results_raw:
        if not auth_header:
            continue

        # SPF
        spf = _extract_auth_status(auth_header, "spf")
        if spf and spf_result == UNKNOWN:
            spf_result = spf["status"]
            spf_details = spf["detail"]

        # DKIM
        dkim = _extract_auth_status(auth_header, "dkim")
        if dkim and dkim_result == UNKNOWN:
            dkim_result = dkim["status"]
            dkim_details = dkim["detail"]

        # DMARC
        dmarc = _extract_auth_status(auth_header, "dmarc")
        if dmarc and dmarc_result == UNKNOWN:
            dmarc_result = dmarc["status"]
            dmarc_details = dmarc["detail"]

    # Fallback: check Received-SPF header
    received_spf = headers.get("Received-SPF") or headers.get("received-spf")
    if received_spf and spf_result == UNKNOWN:
        spf_from_header = _parse_received_spf(received_spf)
        if spf_from_header:
            spf_result = spf_from_header["status"]
            spf_details = spf_from_header["detail"]

    # Check for DKIM-Signature header presence (doesn't validate, just existence)
    dkim_sig = headers.get("DKIM-Signature") or headers.get("dkim-signature")
    has_dkim_signature = dkim_sig is not None

    # Analyze sender alignment
    alignment = _check_alignment(parsed_email)

    return {
        "spf": {
            "result": spf_result,
            "details": spf_details,
        },
        "dkim": {
            "result": dkim_result,
            "details": dkim_details,
            "signature_present": has_dkim_signature,
        },
        "dmarc": {
            "result": dmarc_result,
            "details": dmarc_details,
        },
        "alignment": alignment,
        "summary": _generate_summary(spf_result, dkim_result, dmarc_result),
        "risk_factors": _identify_risk_factors(
            spf_result, dkim_result, dmarc_result, alignment, has_dkim_signature
        ),
    }


def _extract_auth_status(auth_header: str, mechanism: str) -> Optional[dict]:
    """
    Extract authentication status for a mechanism (spf/dkim/dmarc)
    from an Authentication-Results header.
    """
    # Pattern: mechanism=result or mechanism = result
    pattern = rf'{mechanism}\s*=\s*(\w+)'
    match = re.search(pattern, auth_header, re.IGNORECASE)
    if not match:
        return None

    raw_status = match.group(1).lower()
    status = _normalize_status(raw_status)

    # Extract the rest of the clause for details
    # Find from the match position to the next semicolon or end
    start = match.start()
    rest = auth_header[start:]
    end_match = re.search(r';', rest)
    detail = rest[:end_match.start()].strip() if end_match else rest.strip()

    return {"status": status, "detail": detail}


def _normalize_status(raw: str) -> str:
    """Normalize a status string to PASS/FAIL/NONE/UNKNOWN."""
    raw = raw.lower().strip()
    if raw in ("pass", "passed"):
        return PASS
    elif raw in ("fail", "failed", "hardfail", "softfail"):
        return FAIL
    elif raw in ("none", "missing", "notfound"):
        return NONE
    elif raw in ("neutral", "temperror", "permerror", "policy"):
        return FAIL  # Conservative — treat errors as failures
    else:
        return UNKNOWN


def _parse_received_spf(header_value: str) -> Optional[dict]:
    """Parse Received-SPF header. Format: 'status (details) ...'"""
    if isinstance(header_value, list):
        header_value = header_value[0]

    match = re.match(r'(\w+)\s*(.*)', header_value, re.IGNORECASE)
    if not match:
        return None

    raw_status = match.group(1)
    detail = match.group(2).strip()

    return {
        "status": _normalize_status(raw_status),
        "detail": f"Received-SPF: {header_value[:200]}",
    }


def _check_alignment(parsed_email: dict) -> dict:
    """Check sender alignment between From, Return-Path, and Reply-To."""
    from_addr = parsed_email.get("from_address", "")
    return_path = parsed_email.get("return_path", "")
    reply_to = parsed_email.get("reply_to_address", "")

    from_domain = _get_domain(from_addr)
    return_domain = _get_domain(return_path) if return_path else None
    reply_domain = _get_domain(reply_to) if reply_to else None

    issues = []

    if return_domain and from_domain and return_domain != from_domain:
        issues.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})")

    if reply_domain and from_domain and reply_domain != from_domain:
        issues.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")

    return {
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "reply_to_domain": reply_domain,
        "aligned": len(issues) == 0,
        "issues": issues,
    }


def _get_domain(address: str) -> Optional[str]:
    """Extract domain from an email address."""
    if not address:
        return None
    if "@" in address:
        return address.split("@")[-1].lower().strip("<>")
    return None


def _generate_summary(spf: str, dkim: str, dmarc: str) -> str:
    """Generate a human-readable authentication summary."""
    parts = []
    results = {"SPF": spf, "DKIM": dkim, "DMARC": dmarc}

    failures = [k for k, v in results.items() if v == FAIL]
    passes = [k for k, v in results.items() if v == PASS]
    unknowns = [k for k, v in results.items() if v == UNKNOWN]

    if failures:
        parts.append(f"FAILED: {', '.join(failures)}")
    if passes:
        parts.append(f"PASSED: {', '.join(passes)}")
    if unknowns:
        parts.append(f"UNKNOWN: {', '.join(unknowns)}")

    if not parts:
        return "No authentication evidence available."

    return " | ".join(parts)


def _identify_risk_factors(spf: str, dkim: str, dmarc: str,
                           alignment: dict, has_dkim_sig: bool) -> list:
    """Identify authentication-related risk factors."""
    factors = []

    if spf == FAIL:
        factors.append("SPF check failed — sender may not be authorized to send from this domain")
    if dkim == FAIL:
        factors.append("DKIM check failed — email signature verification failed")
    if dmarc == FAIL:
        factors.append("DMARC check failed — domain's email authentication policy not satisfied")

    if not alignment.get("aligned", True):
        for issue in alignment.get("issues", []):
            factors.append(f"Sender alignment issue: {issue}")

    if spf == UNKNOWN and dkim == UNKNOWN and dmarc == UNKNOWN:
        factors.append("No authentication evidence found in email headers")

    if has_dkim_sig and dkim == FAIL:
        factors.append("DKIM signature present but verification failed")

    return factors


if __name__ == "__main__":
    import sys
    import json
    from email_parser import parse_eml

    if len(sys.argv) < 2:
        print("Usage: python auth_analyzer.py <path_to_eml>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        parsed = parse_eml(f.read())

    auth = analyze_authentication(parsed)
    print(json.dumps(auth, indent=2))
