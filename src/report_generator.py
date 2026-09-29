"""
Report Generator — produces SOC-style incident reports in JSON and HTML/Markdown.
Reports contain evidence, findings, and recommended analyst actions.
"""

import os
import json
from datetime import datetime


REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


def generate_report(
    case_id: str,
    parsed_email: dict,
    iocs: list,
    auth_results: dict,
    ml_results: list,
    ti_results: dict,
    sandbox_results: dict,
    risk_assessment: dict,
    attachments: list = None,
) -> dict:
    """
    Generate a complete SOC-style incident report.

    Returns:
        Dict with json_report, html_report, and file paths.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    report_data = _build_report_data(
        case_id, parsed_email, iocs, auth_results,
        ml_results, ti_results, sandbox_results,
        risk_assessment, attachments,
    )

    # JSON report
    json_path = os.path.join(REPORTS_DIR, f"{case_id}_report.json")
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    # Markdown report
    md_content = _render_markdown(report_data)
    md_path = os.path.join(REPORTS_DIR, f"{case_id}_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # HTML report
    html_content = _render_html(report_data)
    html_path = os.path.join(REPORTS_DIR, f"{case_id}_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return {
        "report_data": report_data,
        "json_path": json_path,
        "markdown_path": md_path,
        "html_path": html_path,
        "markdown_content": md_content,
        "html_content": html_content,
    }


def _build_report_data(case_id, parsed_email, iocs, auth_results,
                        ml_results, ti_results, sandbox_results,
                        risk_assessment, attachments) -> dict:
    """Build the structured report data."""
    from risk_engine import get_recommended_actions

    severity = risk_assessment.get("severity", "UNKNOWN")
    evidence = risk_assessment.get("evidence", [])
    actions = get_recommended_actions(severity, evidence)

    return {
        "report_metadata": {
            "case_id": case_id,
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "Phishing Triage Investigation",
            "system": "Phishing Triage & Email Threat Analysis System",
        },
        "risk_assessment": {
            "risk_score": risk_assessment.get("risk_score"),
            "severity": severity,
            "verdict": risk_assessment.get("verdict"),
            "score_breakdown": risk_assessment.get("score_breakdown", {}),
            "scoring_note": risk_assessment.get("scoring_note", ""),
        },
        "email_summary": {
            "from": parsed_email.get("from"),
            "from_address": parsed_email.get("from_address"),
            "to": parsed_email.get("to"),
            "to_address": parsed_email.get("to_address"),
            "reply_to": parsed_email.get("reply_to"),
            "subject": parsed_email.get("subject"),
            "date": parsed_email.get("date"),
            "message_id": parsed_email.get("message_id"),
            "return_path": parsed_email.get("return_path"),
        },
        "authentication": {
            "spf": auth_results.get("spf", {}),
            "dkim": auth_results.get("dkim", {}),
            "dmarc": auth_results.get("dmarc", {}),
            "alignment": auth_results.get("alignment", {}),
            "summary": auth_results.get("summary", ""),
            "risk_factors": auth_results.get("risk_factors", []),
        },
        "iocs": {
            "total_count": len(iocs),
            "by_type": _group_iocs_by_type(iocs),
            "indicators": iocs,
        },
        "url_analysis": {
            "total_urls_analyzed": len(ml_results) if ml_results else 0,
            "predictions": _format_ml_results(ml_results),
        },
        "threat_intelligence": _format_ti_results(ti_results),
        "attachments": {
            "count": len(attachments) if attachments else 0,
            "details": attachments or [],
        },
        "sandbox_analysis": _format_sandbox_results(sandbox_results),
        "evidence_summary": {
            "negative_indicators": [e for e in evidence if e.get("impact") == "negative"],
            "positive_indicators": [e for e in evidence if e.get("impact") == "positive"],
            "neutral_indicators": [e for e in evidence if e.get("impact") == "neutral"],
        },
        "recommended_actions": actions,
    }


def _group_iocs_by_type(iocs: list) -> dict:
    groups = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        if t not in groups:
            groups[t] = []
        groups[t].append(ioc["value"])
    return groups


def _format_ml_results(ml_results: list) -> list:
    if not ml_results:
        return []
    return [{
        "url": r.get("url"),
        "prediction": r.get("prediction"),
        "probability": r.get("probability"),
        "model": r.get("model"),
        "note": r.get("note", ""),
    } for r in ml_results]


def _format_ti_results(ti_results: dict) -> dict:
    if not ti_results:
        return {"status": "not_queried", "results": {}}

    formatted = {"status": "queried", "results": {}}
    for ioc_key, results in ti_results.items():
        formatted["results"][ioc_key] = []
        for r in results:
            formatted["results"][ioc_key].append({
                "provider": r.get("provider"),
                "status": r.get("status"),
                "malicious": r.get("malicious", False),
                "detail": r.get("reason") or _format_ti_detail_short(r),
            })
    return formatted


def _format_ti_detail_short(result: dict) -> str:
    data = result.get("data", {})
    if not data:
        return ""
    provider = result.get("provider", "")
    if provider == "virustotal":
        return f"{data.get('malicious_count', 0)}/{data.get('total_engines', 0)} detections"
    elif provider == "urlhaus":
        return f"threat: {data.get('threat', 'unknown')}"
    elif provider == "openphish":
        return "in feed" if data.get("matched") else "not in feed"
    return ""


def _format_sandbox_results(sandbox_results: dict) -> dict:
    if not sandbox_results:
        return {"status": "not_performed"}
    return {
        "status": sandbox_results.get("status", "unknown"),
        "provider": sandbox_results.get("provider"),
        "enabled": sandbox_results.get("enabled", False),
        "message": sandbox_results.get("message", ""),
        "url_results": sandbox_results.get("url_results", []),
        "file_results": sandbox_results.get("file_results", []),
    }


def _render_markdown(data: dict) -> str:
    """Render report as Markdown."""
    meta = data["report_metadata"]
    risk = data["risk_assessment"]
    email = data["email_summary"]
    auth = data["authentication"]
    iocs_data = data["iocs"]
    urls = data["url_analysis"]
    ti = data["threat_intelligence"]
    att = data["attachments"]
    sandbox = data["sandbox_analysis"]
    evidence = data["evidence_summary"]
    actions = data["recommended_actions"]

    lines = []
    lines.append(f"# Phishing Triage Report: {meta['case_id']}")
    lines.append(f"**Generated:** {meta['generated_at']}")
    lines.append("")

    # Risk Assessment
    lines.append("## Risk Assessment")
    lines.append(f"- **Severity:** {risk['severity']}")
    lines.append(f"- **Risk Score:** {risk['risk_score']}/100")
    lines.append(f"- **Verdict:** {risk['verdict']}")
    lines.append("")
    if risk.get("score_breakdown"):
        lines.append("### Score Breakdown")
        for k, v in risk["score_breakdown"].items():
            lines.append(f"- {k.replace('_', ' ').title()}: {v}")
        lines.append("")

    # Email Summary
    lines.append("## Email Summary")
    lines.append(f"- **From:** {email.get('from', 'N/A')}")
    lines.append(f"- **To:** {email.get('to', 'N/A')}")
    lines.append(f"- **Subject:** {email.get('subject', 'N/A')}")
    lines.append(f"- **Date:** {email.get('date', 'N/A')}")
    lines.append(f"- **Message-ID:** {email.get('message_id', 'N/A')}")
    if email.get("reply_to"):
        lines.append(f"- **Reply-To:** {email['reply_to']}")
    if email.get("return_path"):
        lines.append(f"- **Return-Path:** {email['return_path']}")
    lines.append("")

    # Authentication
    lines.append("## Email Authentication")
    lines.append(f"- **SPF:** {auth.get('spf', {}).get('result', 'UNKNOWN')}")
    lines.append(f"- **DKIM:** {auth.get('dkim', {}).get('result', 'UNKNOWN')}")
    lines.append(f"- **DMARC:** {auth.get('dmarc', {}).get('result', 'UNKNOWN')}")
    if auth.get("risk_factors"):
        lines.append("\n**Risk Factors:**")
        for rf in auth["risk_factors"]:
            lines.append(f"- ⚠️ {rf}")
    lines.append("")

    # IOCs
    lines.append("## Extracted IOCs")
    lines.append(f"**Total:** {iocs_data['total_count']}")
    for ioc_type, values in iocs_data.get("by_type", {}).items():
        lines.append(f"\n### {ioc_type.upper()} ({len(values)})")
        for v in values[:20]:  # Limit display
            lines.append(f"- `{v}`")
        if len(values) > 20:
            lines.append(f"- _(and {len(values) - 20} more)_")
    lines.append("")

    # URL Analysis / ML
    lines.append("## URL Analysis (ML Classification)")
    if urls.get("predictions"):
        for pred in urls["predictions"]:
            icon = "🔴" if pred["prediction"] == "phishing" else "🟢"
            lines.append(f"- {icon} `{pred['url']}` — **{pred['prediction']}** (probability: {pred.get('probability', 'N/A')}, model: {pred.get('model', 'N/A')})")
        lines.append(f"\n_Note: {urls['predictions'][0].get('note', 'Probability is model output, not absolute certainty.')}_")
    else:
        lines.append("- No URLs analyzed")
    lines.append("")

    # Threat Intelligence
    lines.append("## Threat Intelligence")
    if ti.get("status") == "queried":
        for ioc_key, results in ti.get("results", {}).items():
            lines.append(f"\n### {ioc_key}")
            for r in results:
                status = r.get("status", "")
                icon = "🔴" if r.get("malicious") else ("⚪" if status in ("unavailable", "error", "no_data") else "🟢")
                detail = r.get("detail", "")
                lines.append(f"- {icon} **{r['provider']}**: {status} {f'— {detail}' if detail else ''}")
    else:
        lines.append("- No threat intelligence queries performed")
    lines.append("")

    # Attachments
    lines.append("## Attachments")
    if att["count"] > 0:
        for a in att["details"]:
            lines.append(f"- **{a.get('filename', 'N/A')}** — {a.get('mime_type', 'N/A')}, {a.get('size', 0)} bytes")
            lines.append(f"  - SHA256: `{a.get('sha256', 'N/A')}`")
    else:
        lines.append("- No attachments found")
    lines.append("")

    # Sandbox
    lines.append("## Sandbox Analysis")
    if sandbox.get("status") == "disabled":
        lines.append(f"- {sandbox.get('message', 'Sandbox analysis unavailable / disabled')}")
    elif sandbox.get("url_results") or sandbox.get("file_results"):
        for r in sandbox.get("url_results", []) + sandbox.get("file_results", []):
            details = r.get("details", {})
            if details.get("mock"):
                lines.append(f"- **{r.get('target', 'N/A')}**: Mock analysis (development mode)")
            else:
                lines.append(f"- **{r.get('target', 'N/A')}**: {r.get('verdict', 'N/A')}")
    else:
        lines.append("- Sandbox analysis not performed")
    lines.append("")

    # Evidence Summary
    lines.append("## Evidence Summary")
    neg = evidence.get("negative_indicators", [])
    pos = evidence.get("positive_indicators", [])
    if neg:
        lines.append("\n### Negative Indicators")
        for e in neg:
            lines.append(f"- ⚠️ [{e.get('source', '')}] {e['finding']}")
    if pos:
        lines.append("\n### Positive Indicators")
        for e in pos:
            lines.append(f"- ✅ [{e.get('source', '')}] {e['finding']}")
    lines.append("")

    # Recommended Actions
    lines.append("## Recommended Analyst Actions")
    for i, action in enumerate(actions, 1):
        lines.append(f"{i}. {action}")
    lines.append("")

    lines.append("---")
    lines.append(f"_Report generated by {meta['system']}_")

    return "\n".join(lines)


def _render_html(data: dict) -> str:
    """Render report as an HTML document."""
    md_content = _render_markdown(data)

    # Convert markdown to simple HTML
    try:
        import markdown
        body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: wrap in pre
        body = f"<pre>{md_content}</pre>"

    risk = data["risk_assessment"]
    severity = risk.get("severity", "UNKNOWN")
    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
    }
    color = severity_colors.get(severity, "#6c757d")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Triage Report - {data['report_metadata']['case_id']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background: #f8f9fa;
        }}
        .severity-banner {{
            background: {color};
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 1.2em;
        }}
        h1, h2, h3 {{
            color: #1a1a2e;
        }}
        h1 {{
            border-bottom: 3px solid {color};
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        pre {{
            background: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        ul, ol {{
            padding-left: 20px;
        }}
        li {{
            margin-bottom: 5px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="severity-banner">
        Severity: {severity} | Risk Score: {risk.get('risk_score', 'N/A')}/100
    </div>
    {body}
</body>
</html>"""

    return html


if __name__ == "__main__":
    # Quick test
    report = generate_report(
        case_id="TEST-001",
        parsed_email={"from": "test@example.com", "to": "user@company.com", "subject": "Test"},
        iocs=[{"type": "url", "value": "http://evil.tk", "context": "body"}],
        auth_results={"spf": {"result": "FAIL"}, "dkim": {"result": "UNKNOWN"}, "dmarc": {"result": "UNKNOWN"},
                       "summary": "SPF FAIL", "risk_factors": [], "alignment": {"aligned": True}},
        ml_results=[{"url": "http://evil.tk", "prediction": "phishing", "probability": 0.85, "model": "rf"}],
        ti_results={},
        sandbox_results={"status": "disabled", "message": "Sandbox disabled"},
        risk_assessment={"risk_score": 42, "severity": "MEDIUM", "verdict": "Suspicious",
                          "evidence": [], "score_breakdown": {}},
    )
    print(f"Reports generated:\n  {report['json_path']}\n  {report['markdown_path']}\n  {report['html_path']}")
