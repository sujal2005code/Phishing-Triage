"""
Risk Engine — combines evidence from all analysis stages into a severity,
verdict, risk score, and list of contributing factors.

The ML model is ONE evidence source, not the sole decision-maker.

Evidence sources:
  1. ML phishing prediction
  2. SPF/DKIM/DMARC authentication
  3. Threat intelligence results
  4. IOC findings
  5. Attachment/hash findings
  6. Sandbox findings (when available)

Severity levels (project-defined, not universal standards):
  LOW, MEDIUM, HIGH, CRITICAL

The scoring thresholds below are engineering decisions for this project.
They are documented, transparent, and adjustable.
"""

from typing import Optional


# =============================================================================
# Scoring weights — engineering decisions, not universal standards.
# Each category contributes a weighted score to the overall risk.
# =============================================================================

WEIGHTS = {
    "ml_prediction": 25,         # max 25 points
    "authentication": 20,        # max 20 points
    "threat_intelligence": 30,   # max 30 points
    "attachment_risk": 15,       # max 15 points
    "sandbox": 10,               # max 10 points
}

# Severity thresholds (out of 100)
SEVERITY_THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH": 50,
    "MEDIUM": 25,
    "LOW": 0,
}


def assess_risk(
    ml_results: list = None,
    auth_results: dict = None,
    ti_results: dict = None,
    iocs: list = None,
    attachments: list = None,
    sandbox_results: dict = None,
) -> dict:
    """
    Combine all evidence sources into a risk assessment.

    Returns:
        Dict with risk_score, severity, verdict, evidence breakdown, and reasons.
    """
    evidence = []
    total_score = 0.0

    # --- 1. ML Evidence ---
    ml_score, ml_evidence = _assess_ml(ml_results)
    total_score += ml_score
    evidence.extend(ml_evidence)

    # --- 2. Authentication Evidence ---
    auth_score, auth_evidence = _assess_authentication(auth_results)
    total_score += auth_score
    evidence.extend(auth_evidence)

    # --- 3. Threat Intelligence Evidence ---
    ti_score, ti_evidence = _assess_threat_intel(ti_results)
    total_score += ti_score
    evidence.extend(ti_evidence)

    # --- 4. Attachment Risk ---
    att_score, att_evidence = _assess_attachments(attachments, iocs)
    total_score += att_score
    evidence.extend(att_evidence)

    # --- 5. Sandbox Evidence ---
    sb_score, sb_evidence = _assess_sandbox(sandbox_results)
    total_score += sb_score
    evidence.extend(sb_evidence)

    # Clamp score
    total_score = min(100, max(0, total_score))

    # Determine severity
    severity = _score_to_severity(total_score)

    # Generate verdict
    verdict = _generate_verdict(severity, evidence)

    return {
        "risk_score": round(total_score, 1),
        "severity": severity,
        "verdict": verdict,
        "evidence": evidence,
        "score_breakdown": {
            "ml_prediction": round(ml_score, 1),
            "authentication": round(auth_score, 1),
            "threat_intelligence": round(ti_score, 1),
            "attachment_risk": round(att_score, 1),
            "sandbox": round(sb_score, 1),
        },
        "max_possible_score": sum(WEIGHTS.values()),
        "scoring_note": (
            "Risk score is computed by combining weighted evidence from multiple sources. "
            "Thresholds are project-defined engineering decisions, not universal standards."
        ),
    }


def _assess_ml(ml_results: list) -> tuple:
    """Score ML predictions. Returns (score, evidence_list)."""
    if not ml_results:
        return 0.0, [{"source": "ml", "finding": "No ML analysis performed", "impact": "neutral"}]

    max_score = WEIGHTS["ml_prediction"]
    evidence = []
    highest_prob = 0.0

    for result in ml_results:
        if not isinstance(result, dict):
            continue
        prediction = result.get("prediction", "")
        probability = result.get("probability", 0.0)
        url = result.get("url", "unknown")

        if prediction == "phishing":
            highest_prob = max(highest_prob, probability)
            evidence.append({
                "source": "ml",
                "finding": f"URL classified as phishing (probability: {probability:.2%}) by {result.get('model', 'unknown')}",
                "url": url,
                "impact": "negative",
                "details": result.get("note", ""),
            })
        else:
            evidence.append({
                "source": "ml",
                "finding": f"URL classified as legitimate (probability: {1-probability:.2%})",
                "url": url,
                "impact": "positive",
            })

    score = highest_prob * max_score

    if not evidence:
        evidence.append({"source": "ml", "finding": "No URLs analyzed", "impact": "neutral"})

    return score, evidence


def _assess_authentication(auth_results: dict) -> tuple:
    """Score email authentication results."""
    if not auth_results:
        return 0.0, [{"source": "auth", "finding": "No authentication data available", "impact": "neutral"}]

    max_score = WEIGHTS["authentication"]
    evidence = []
    failures = 0
    checks = 0

    for mech in ("spf", "dkim", "dmarc"):
        result = auth_results.get(mech, {})
        status = result.get("result", "UNKNOWN")

        if status == "FAIL":
            failures += 1
            checks += 1
            evidence.append({
                "source": "auth",
                "finding": f"{mech.upper()} check FAILED",
                "impact": "negative",
                "details": result.get("details", ""),
            })
        elif status == "PASS":
            checks += 1
            evidence.append({
                "source": "auth",
                "finding": f"{mech.upper()} check PASSED",
                "impact": "positive",
            })
        else:
            evidence.append({
                "source": "auth",
                "finding": f"{mech.upper()} result: {status}",
                "impact": "neutral",
            })

    # Alignment issues
    alignment = auth_results.get("alignment", {})
    if not alignment.get("aligned", True):
        failures += 1
        for issue in alignment.get("issues", []):
            evidence.append({
                "source": "auth",
                "finding": f"Alignment issue: {issue}",
                "impact": "negative",
            })

    # Auth risk factors from analyzer
    for factor in auth_results.get("risk_factors", []):
        evidence.append({
            "source": "auth",
            "finding": factor,
            "impact": "negative",
        })

    # Score: more failures = higher risk
    # Score: more failures = higher risk.
    # Never allow this category to exceed its configured maximum.
    if checks > 0:
        score = min(
            (failures / max(checks, 1)) * max_score,
            max_score
        )
    elif failures > 0:
        score = max_score * 0.5
    else:
        score = 0.0

    return score, evidence

def _assess_threat_intel(ti_results: dict) -> tuple:
    """Score threat intelligence results."""
    if not ti_results:
        return 0.0, [{"source": "ti", "finding": "No threat intelligence queries performed", "impact": "neutral"}]

    max_score = WEIGHTS["threat_intelligence"]
    evidence = []
    malicious_count = 0
    total_queries = 0

    for ioc_key, provider_results in ti_results.items():
        for result in provider_results:
            provider = result.get("provider", "unknown")
            status = result.get("status", "unknown")

            if status == "unavailable":
                evidence.append({
                    "source": "ti",
                    "finding": f"{provider}: {result.get('reason', 'unavailable')}",
                    "ioc": ioc_key,
                    "impact": "neutral",
                })
                continue

            if status == "error":
                evidence.append({
                    "source": "ti",
                    "finding": f"{provider}: query error — {result.get('reason', 'unknown error')}",
                    "ioc": ioc_key,
                    "impact": "neutral",
                })
                continue

            if status == "no_data":
                evidence.append({
                    "source": "ti",
                    "finding": f"{provider}: no data found for {ioc_key}",
                    "ioc": ioc_key,
                    "impact": "neutral",
                })
                continue

            total_queries += 1
            is_malicious = result.get("malicious", False)
            data = result.get("data", {})

            if is_malicious:
                malicious_count += 1
                detail = _format_ti_detail(provider, data)
                evidence.append({
                    "source": "ti",
                    "finding": f"{provider}: MALICIOUS — {detail}",
                    "ioc": ioc_key,
                    "impact": "negative",
                    "score": result.get("score", 0),
                })
            else:
                evidence.append({
                    "source": "ti",
                    "finding": f"{provider}: clean/not flagged for {ioc_key}",
                    "ioc": ioc_key,
                    "impact": "positive",
                })

    if total_queries > 0:
        score = (malicious_count / total_queries) * max_score
    else:
        score = 0.0

    return score, evidence


def _format_ti_detail(provider: str, data: dict) -> str:
    """Format TI data into a readable detail string."""
    if provider == "virustotal":
        mc = data.get("malicious_count", 0)
        total = data.get("total_engines", 0)
        return f"{mc}/{total} detections"
    elif provider == "urlhaus":
        threat = data.get("threat", "unknown")
        return f"threat type: {threat}"
    elif provider == "openphish":
        return "found in OpenPhish feed"
    return str(data)[:100]


def _assess_attachments(attachments: list, iocs: list = None) -> tuple:
    """Score attachment risk based on metadata."""
    if not attachments:
        return 0.0, [{"source": "attachment", "finding": "No attachments found", "impact": "neutral"}]

    max_score = WEIGHTS["attachment_risk"]
    evidence = []
    risk_points = 0

    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".msi",
        ".js", ".vbs", ".wsf", ".ps1", ".jar", ".hta", ".cpl",
        ".reg", ".inf", ".lnk",
    }
    SUSPICIOUS_EXTENSIONS = {
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".zip", ".rar", ".7z", ".iso", ".img",
    }

    for att in attachments:
        filename = att.get("filename", "").lower()
        mime = att.get("mime_type", "")

        # Check for dangerous extensions
        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            risk_points += 3
            evidence.append({
                "source": "attachment",
                "finding": f"Dangerous executable attachment: {att.get('filename', '')}",
                "impact": "negative",
                "details": f"MIME: {mime}, Size: {att.get('size', 0)} bytes",
            })
        elif any(filename.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            risk_points += 1
            evidence.append({
                "source": "attachment",
                "finding": f"Suspicious attachment type: {att.get('filename', '')}",
                "impact": "negative",
                "details": f"MIME: {mime}, Size: {att.get('size', 0)} bytes",
            })
        else:
            evidence.append({
                "source": "attachment",
                "finding": f"Attachment: {att.get('filename', '')} ({mime})",
                "impact": "neutral",
            })

        # Report hash for analyst reference
        sha = att.get("sha256", "")
        if sha:
            evidence.append({
                "source": "attachment",
                "finding": f"SHA256: {sha}",
                "impact": "neutral",
            })

    score = min(risk_points / 3, 1.0) * max_score
    return score, evidence


def _assess_sandbox(sandbox_results: dict) -> tuple:
    """Score sandbox results."""
    if not sandbox_results:
        return 0.0, [{"source": "sandbox", "finding": "Sandbox analysis not performed", "impact": "neutral"}]

    if sandbox_results.get("status") == "disabled":
        return 0.0, [{
            "source": "sandbox",
            "finding": "Sandbox analysis unavailable / disabled",
            "impact": "neutral",
        }]

    max_score = WEIGHTS["sandbox"]
    evidence = []
    highest_risk = 0.0

    for results_key in ("url_results", "file_results"):
        for result in sandbox_results.get(results_key, []):
            if result.get("status") == "unavailable":
                evidence.append({
                    "source": "sandbox",
                    "finding": f"Sandbox: {result.get('reason', 'unavailable')}",
                    "impact": "neutral",
                })
                continue

            details = result.get("details", {})
            if details.get("mock", False):
                evidence.append({
                    "source": "sandbox",
                    "finding": f"Mock sandbox analysis for {result.get('target', 'unknown')} (development mode)",
                    "impact": "neutral",
                    "details": "Mock data — not a real analysis",
                })
                continue

            verdict = result.get("verdict", "")
            score = result.get("score", 0.0)
            highest_risk = max(highest_risk, score)

            if verdict in ("malicious", "suspicious"):
                evidence.append({
                    "source": "sandbox",
                    "finding": f"Sandbox verdict: {verdict} (score: {score})",
                    "target": result.get("target"),
                    "impact": "negative",
                })
            else:
                evidence.append({
                    "source": "sandbox",
                    "finding": f"Sandbox verdict: {verdict}",
                    "target": result.get("target"),
                    "impact": "neutral" if verdict else "neutral",
                })

    score = highest_risk * max_score

    if not evidence:
        evidence.append({"source": "sandbox", "finding": "No sandbox results", "impact": "neutral"})

    return score, evidence


def _score_to_severity(score: float) -> str:
    """Map a risk score to a severity level."""
    if score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_verdict(severity: str, evidence: list) -> str:
    """Generate a verdict statement based on evidence."""
    negative = [e for e in evidence if e.get("impact") == "negative"]
    positive = [e for e in evidence if e.get("impact") == "positive"]

    if severity == "CRITICAL":
        return "This email shows strong indicators of a phishing attack. Multiple evidence sources flagged malicious content."
    elif severity == "HIGH":
        return "This email shows significant phishing indicators. Analyst review is recommended."
    elif severity == "MEDIUM":
        return "This email has some suspicious characteristics. Further investigation may be warranted."
    elif severity == "LOW" and not negative:
        return "No significant phishing indicators detected. The email appears legitimate based on available evidence."
    else:
        return "Low-risk indicators detected. The email has minor suspicious elements but no strong evidence of phishing."


def get_recommended_actions(severity: str, evidence: list) -> list:
    """Generate recommended analyst actions based on assessment."""
    actions = []

    if severity in ("CRITICAL", "HIGH"):
        actions.append("Do NOT click any links or download attachments from this email")
        actions.append("Quarantine or block the sender address")
        actions.append("Alert affected users if the email was delivered to multiple recipients")
        actions.append("Search for similar emails in the mail gateway logs")
        actions.append("Report to security team for further investigation")

    if severity == "MEDIUM":
        actions.append("Exercise caution with links and attachments")
        actions.append("Verify the sender's identity through an alternative channel")
        actions.append("Review email details manually for additional context")

    # Specific actions based on evidence
    neg_evidence = [e for e in evidence if e.get("impact") == "negative"]

    for e in neg_evidence:
        if "SPF" in e.get("finding", "") and "FAIL" in e.get("finding", ""):
            actions.append("Investigate sender domain SPF configuration and delivery chain")
        if "attachment" in e.get("source", "").lower() and "dangerous" in e.get("finding", "").lower():
            actions.append("Submit attachment hashes to additional threat intelligence sources")
        if "virustotal" in e.get("finding", "").lower() and "MALICIOUS" in e.get("finding", "").upper():
            actions.append("Block identified malicious URLs/domains at the network perimeter")

    if severity == "LOW":
        actions.append("No immediate action required")
        actions.append("Continue monitoring for similar patterns")

    # Deduplicate
    return list(dict.fromkeys(actions))


if __name__ == "__main__":
    # Example usage
    result = assess_risk(
        ml_results=[{"prediction": "phishing", "probability": 0.91, "model": "random_forest", "url": "http://evil.tk/login"}],
        auth_results={"spf": {"result": "FAIL"}, "dkim": {"result": "PASS"}, "dmarc": {"result": "FAIL"},
                       "alignment": {"aligned": False, "issues": ["Domains differ"]}, "risk_factors": []},
    )
    import json
    print(json.dumps(result, indent=2))
