"""
Phishing Triage & Email Threat Analysis System
Streamlit Dashboard — main entry point.

A clean cybersecurity dashboard for automated phishing investigation.
"""

import os
import sys
import json
import tempfile
from datetime import datetime

import streamlit as st

# Add src to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

from email_parser import parse_eml
from ioc_extractor import extract_iocs, extract_urls
from auth_analyzer import analyze_authentication
from url_features import extract_features
from threat_intel import enrich_iocs, get_provider_status
from sandbox import run_sandbox_analysis, get_sandbox_status
from risk_engine import assess_risk, get_recommended_actions
from report_generator import generate_report
from database import init_db, create_case, save_email, save_iocs, save_attachment, \
    save_threat_intel, save_sandbox_result, save_report, update_case_verdict, list_cases

# Try to import ML predictor (requires trained model)
try:
    from ml_predictor import predict_url, predict_urls, get_available_models, get_evaluation_summary
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

from dotenv import load_dotenv
load_dotenv()


# --- Page Configuration ---
st.set_page_config(
    page_title="Phishing Triage System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown("""
<style>
    .severity-critical { background: #dc3545; color: white; padding: 10px 20px; border-radius: 8px; font-size: 1.3em; font-weight: bold; text-align: center; }
    .severity-high { background: #fd7e14; color: white; padding: 10px 20px; border-radius: 8px; font-size: 1.3em; font-weight: bold; text-align: center; }
    .severity-medium { background: #ffc107; color: #333; padding: 10px 20px; border-radius: 8px; font-size: 1.3em; font-weight: bold; text-align: center; }
    .severity-low { background: #28a745; color: white; padding: 10px 20px; border-radius: 8px; font-size: 1.3em; font-weight: bold; text-align: center; }
    .metric-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin: 5px 0; }
    .status-pass { color: #28a745; font-weight: bold; }
    .status-fail { color: #dc3545; font-weight: bold; }
    .status-unknown { color: #6c757d; font-weight: bold; }
    div[data-testid="stMetricValue"] { font-size: 1.1rem; }
</style>
""", unsafe_allow_html=True)


# --- Initialize ---
init_db()


def main():
    """Main application entry point."""

    # Sidebar
    with st.sidebar:
        st.title("🛡️ Phishing Triage")
        st.caption("Email Threat Analysis System")
        st.divider()

        page = st.radio(
            "Navigation",
            ["📧 New Investigation", "📊 Dashboard", "🔍 Past Cases", "⚙️ Settings"],
            index=0,
        )

        st.divider()

        # System status
        st.subheader("System Status")
        _show_system_status()

    if page == "📧 New Investigation":
        _page_new_investigation()
    elif page == "📊 Dashboard":
        _page_dashboard()
    elif page == "🔍 Past Cases":
        _page_past_cases()
    elif page == "⚙️ Settings":
        _page_settings()


def _show_system_status():
    """Show system component status in sidebar."""
    # ML status
    if ML_AVAILABLE:
        models = get_available_models()
        if models:
            st.success(f"ML: {len(models)} model(s) ready")
        else:
            st.warning("ML: No trained models")
    else:
        st.warning("ML: Models not loaded")

    # TI status
    ti_status = get_provider_status()
    for p in ti_status:
        if p["available"]:
            st.success(f"{p['name'].title()}: Available")
        else:
            st.info(f"{p['name'].title()}: Not configured")

    # Sandbox status
    sb = get_sandbox_status()
    if sb["enabled"]:
        st.success(f"Sandbox: {sb['provider']}")
    else:
        st.info("Sandbox: Disabled")


# =============================================================================
# NEW INVESTIGATION PAGE
# =============================================================================

def _page_new_investigation():
    st.title("📧 New Phishing Investigation")
    st.markdown("Upload a suspicious `.eml` file to begin automated analysis.")

    uploaded_file = st.file_uploader(
        "Upload .eml file",
        type=["eml"],
        help="Upload a suspicious email file in .eml format",
    )

    if uploaded_file is not None:
        if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
            _run_investigation(uploaded_file)


def _run_investigation(uploaded_file):
    """Run the complete investigation pipeline."""
    progress = st.progress(0, text="Starting investigation...")

    try:
        # Step 1: Create case
        progress.progress(5, text="Creating case...")
        case_id = create_case()
        st.session_state["current_case_id"] = case_id

        # Step 2: Parse email
        progress.progress(10, text="Parsing email...")
        eml_content = uploaded_file.read()
        parsed_email = parse_eml(eml_content)
        parsed_email["filename"] = uploaded_file.name
        save_email(case_id, parsed_email)

        # Step 3: Extract IOCs
        progress.progress(20, text="Extracting IOCs...")
        iocs = extract_iocs(parsed_email)
        save_iocs(case_id, iocs)

        # Step 4: Analyze authentication
        progress.progress(30, text="Analyzing email authentication...")
        auth_results = analyze_authentication(parsed_email)

        # Step 5: Save attachments
        progress.progress(35, text="Processing attachments...")
        attachments = parsed_email.get("attachments", [])
        for att in attachments:
            save_attachment(case_id, att)

        # Step 6: ML classification
        progress.progress(45, text="Running ML classification...")
        ml_results = []
        urls = extract_urls(parsed_email)
        if ML_AVAILABLE and urls:
            try:
                ml_results = predict_urls(urls[:20])  # Limit to 20 URLs
            except Exception as e:
                st.warning(f"ML prediction error: {e}")
        elif not ML_AVAILABLE:
            st.info("ML models not trained yet. Run `python src/train_model.py` to train.")

        # Step 7: Threat intelligence
        progress.progress(60, text="Querying threat intelligence...")
        # Only query URLs and domains to avoid excessive API calls
        ti_iocs = [i for i in iocs if i["type"] in ("url", "domain") and i.get("value")][:10]
        ti_results = enrich_iocs(ti_iocs) if ti_iocs else {}
        for ioc_key, results in ti_results.items():
            for r in results:
                if r.get("status") == "success":
                    ioc_parts = ioc_key.split(":", 1)
                    save_threat_intel(case_id, r["provider"], ioc_parts[1] if len(ioc_parts) > 1 else ioc_key,
                                     ioc_parts[0] if len(ioc_parts) > 1 else "unknown", r)

        # Step 8: Sandbox analysis
        progress.progress(75, text="Running sandbox analysis...")
        sandbox_results = run_sandbox_analysis(
            urls=urls[:5] if urls else None,
            attachments=attachments if attachments else None,
        )
        if sandbox_results.get("status") == "completed":
            for r in sandbox_results.get("url_results", []) + sandbox_results.get("file_results", []):
                save_sandbox_result(case_id, r)

        # Step 9: Risk assessment
        progress.progress(85, text="Computing risk assessment...")
        risk_assessment = assess_risk(
            ml_results=ml_results,
            auth_results=auth_results,
            ti_results=ti_results,
            iocs=iocs,
            attachments=attachments,
            sandbox_results=sandbox_results,
        )
        update_case_verdict(
            case_id, risk_assessment["severity"],
            risk_assessment["verdict"], risk_assessment["risk_score"]
        )

        # Step 10: Generate report
        progress.progress(95, text="Generating report...")
        report = generate_report(
            case_id=case_id,
            parsed_email=parsed_email,
            iocs=iocs,
            auth_results=auth_results,
            ml_results=ml_results,
            ti_results=ti_results,
            sandbox_results=sandbox_results,
            risk_assessment=risk_assessment,
            attachments=attachments,
        )
        save_report(case_id, "json", json.dumps(report["report_data"]), report["json_path"])
        save_report(case_id, "markdown", report["markdown_content"], report["markdown_path"])
        save_report(case_id, "html", report["html_content"], report["html_path"])

        progress.progress(100, text="Investigation complete!")

        # Store results in session state
        st.session_state["investigation"] = {
            "case_id": case_id,
            "parsed_email": parsed_email,
            "iocs": iocs,
            "auth_results": auth_results,
            "ml_results": ml_results,
            "ti_results": ti_results,
            "sandbox_results": sandbox_results,
            "risk_assessment": risk_assessment,
            "report": report,
            "attachments": attachments,
        }

        # Show results
        _show_investigation_results()

    except Exception as e:
        progress.empty()
        st.error(f"Investigation failed: {str(e)}")
        st.exception(e)


def _show_investigation_results():
    """Display investigation results dashboard."""
    inv = st.session_state.get("investigation")
    if not inv:
        st.info("No investigation results to display.")
        return

    case_id = inv["case_id"]
    risk = inv["risk_assessment"]
    parsed_email = inv["parsed_email"]
    auth = inv["auth_results"]
    iocs = inv["iocs"]
    ml_results = inv["ml_results"]
    ti_results = inv["ti_results"]
    sandbox_results = inv["sandbox_results"]
    attachments = inv["attachments"]
    report = inv["report"]

    st.divider()

    # --- Risk Assessment Banner ---
    severity = risk["severity"]
    severity_class = f"severity-{severity.lower()}"
    st.markdown(f'<div class="{severity_class}">⚠️ SEVERITY: {severity} | Risk Score: {risk["risk_score"]}/100</div>', unsafe_allow_html=True)
    st.markdown(f"**Verdict:** {risk['verdict']}")
    st.divider()

    # --- Tabs ---
    tabs = st.tabs([
        "📧 Email Overview", "🔐 Authentication", "🔎 IOCs",
        "🤖 ML Analysis", "🌐 Threat Intel", "📎 Attachments",
        "🧪 Sandbox", "📊 Risk Details", "📝 Report",
    ])

    # Tab 1: Email Overview
    with tabs[0]:
        _tab_email_overview(parsed_email)

    # Tab 2: Authentication
    with tabs[1]:
        _tab_authentication(auth)

    # Tab 3: IOCs
    with tabs[2]:
        _tab_iocs(iocs)

    # Tab 4: ML Analysis
    with tabs[3]:
        _tab_ml_analysis(ml_results)

    # Tab 5: Threat Intelligence
    with tabs[4]:
        _tab_threat_intel(ti_results)

    # Tab 6: Attachments
    with tabs[5]:
        _tab_attachments(attachments)

    # Tab 7: Sandbox
    with tabs[6]:
        _tab_sandbox(sandbox_results)

    # Tab 8: Risk Details
    with tabs[7]:
        _tab_risk_details(risk)

    # Tab 9: Report
    with tabs[8]:
        _tab_report(report, case_id)


# =============================================================================
# TAB RENDERERS
# =============================================================================

def _tab_email_overview(parsed_email):
    st.subheader("Email Overview")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**From:**")
        st.code(parsed_email.get("from", "N/A"))
        st.markdown("**To:**")
        st.code(parsed_email.get("to", "N/A"))
        st.markdown("**Subject:**")
        st.code(parsed_email.get("subject", "N/A"))
    with col2:
        st.markdown("**Date:**")
        st.code(parsed_email.get("date", "N/A"))
        st.markdown("**Message-ID:**")
        st.code(parsed_email.get("message_id", "N/A"))
        if parsed_email.get("reply_to"):
            st.markdown("**Reply-To:**")
            st.code(parsed_email["reply_to"])
        if parsed_email.get("return_path"):
            st.markdown("**Return-Path:**")
            st.code(parsed_email["return_path"])

    # Body preview
    with st.expander("📄 Email Body (Text)", expanded=False):
        st.text(parsed_email.get("body_text", "No text body") or "No text body")

    with st.expander("🌐 Email Body (HTML Source)", expanded=False):
        st.code(parsed_email.get("body_html", "No HTML body") or "No HTML body", language="html")

    # Received headers
    received = parsed_email.get("received", [])
    if received:
        with st.expander(f"📬 Received Headers ({len(received)})", expanded=False):
            for i, r in enumerate(received):
                st.text(f"[{i+1}] {r}")


def _tab_authentication(auth):
    st.subheader("Email Authentication Results")

    col1, col2, col3 = st.columns(3)

    for col, mech in zip([col1, col2, col3], ["spf", "dkim", "dmarc"]):
        with col:
            result = auth.get(mech, {}).get("result", "UNKNOWN")
            if result == "PASS":
                st.metric(mech.upper(), "✅ PASS")
            elif result == "FAIL":
                st.metric(mech.upper(), "❌ FAIL")
            elif result == "NONE":
                st.metric(mech.upper(), "⚪ NONE")
            else:
                st.metric(mech.upper(), "❓ UNKNOWN")

            details = auth.get(mech, {}).get("details", "")
            if details:
                st.caption(details[:100])

    st.divider()

    # Alignment
    alignment = auth.get("alignment", {})
    if alignment.get("aligned"):
        st.success("✅ Sender alignment: Domains are aligned")
    else:
        st.error("⚠️ Sender alignment issues detected")
        for issue in alignment.get("issues", []):
            st.warning(issue)

    # Summary
    st.markdown(f"**Summary:** {auth.get('summary', 'N/A')}")

    # Risk factors
    risk_factors = auth.get("risk_factors", [])
    if risk_factors:
        st.markdown("**Risk Factors:**")
        for rf in risk_factors:
            st.markdown(f"- ⚠️ {rf}")


def _tab_iocs(iocs):
    st.subheader(f"Extracted IOCs ({len(iocs)})")

    if not iocs:
        st.info("No IOCs extracted.")
        return

    # Group by type
    grouped = {}
    for ioc in iocs:
        t = ioc["type"]
        if t not in grouped:
            grouped[t] = []
        grouped[t].append(ioc)

    for ioc_type, items in grouped.items():
        with st.expander(f"**{ioc_type.upper()}** ({len(items)})", expanded=(ioc_type in ("url", "domain"))):
            for item in items:
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.code(item["value"])
                with col2:
                    st.caption(item.get("context", ""))


def _tab_ml_analysis(ml_results):
    st.subheader("URL ML Classification")

    if not ml_results:
        if not ML_AVAILABLE:
            st.warning("⚠️ ML models not available. Run `python src/train_model.py` to train models.")
        else:
            st.info("No URLs found to analyze.")
        return

    # Show model evaluation summary
    try:
        summary = get_evaluation_summary()
        if summary:
            with st.expander("📊 Model Evaluation Summary", expanded=False):
                st.json(summary.get("models", {}))
                st.caption(f"Best model: {summary.get('best_model', 'N/A')} | "
                           f"Dataset: {summary.get('dataset_size', 'N/A')} samples")
    except Exception:
        pass

    # Show predictions
    for result in ml_results:
        prediction = result.get("prediction", "unknown")
        probability = result.get("probability", 0)
        url = result.get("url", "N/A")

        if prediction == "phishing":
            st.error(f"🔴 **PHISHING** — {probability:.1%} probability")
        else:
            st.success(f"🟢 **LEGITIMATE** — {1-probability:.1%} confidence")

        st.code(url)
        st.caption(f"Model: {result.get('model', 'N/A')} | "
                   f"Note: {result.get('note', 'Probability is model output, not absolute certainty.')}")
        st.divider()


def _tab_threat_intel(ti_results):
    st.subheader("Threat Intelligence Results")

    if not ti_results:
        st.info("No threat intelligence queries were performed.")
        return

    for ioc_key, provider_results in ti_results.items():
        with st.expander(f"🔎 {ioc_key}", expanded=True):
            for result in provider_results:
                provider = result.get("provider", "unknown")
                status = result.get("status", "unknown")

                col1, col2, col3 = st.columns([1, 1, 2])
                with col1:
                    st.markdown(f"**{provider.title()}**")
                with col2:
                    if status == "success" and result.get("malicious"):
                        st.error("🔴 MALICIOUS")
                    elif status == "success":
                        st.success("🟢 Clean")
                    elif status == "unavailable":
                        st.info("⚪ Unavailable")
                    elif status == "error":
                        st.warning("⚠️ Error")
                    elif status == "no_data":
                        st.info("⚪ No data")
                with col3:
                    data = result.get("data", {})
                    if data and result.get("malicious"):
                        if provider == "virustotal":
                            st.markdown(f"**{data.get('malicious_count', 0)}/{data.get('total_engines', 0)}** detections")
                        elif provider == "urlhaus":
                            st.markdown(f"Threat: **{data.get('threat', 'N/A')}**")
                        elif provider == "openphish":
                            st.markdown("**Found in phishing feed**")
                    elif status == "unavailable":
                        st.caption(result.get("reason", ""))
                    elif status == "error":
                        st.caption(result.get("reason", ""))


def _tab_attachments(attachments):
    st.subheader("Attachment Analysis")

    if not attachments:
        st.info("No attachments found in this email.")
        return

    for att in attachments:
        with st.expander(f"📎 {att.get('filename', 'unnamed')}", expanded=True):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Filename", att.get("filename", "N/A"))
            with col2:
                st.metric("MIME Type", att.get("mime_type", "N/A"))
            with col3:
                size_kb = att.get("size", 0) / 1024
                st.metric("Size", f"{size_kb:.1f} KB")

            st.markdown("**SHA256:**")
            st.code(att.get("sha256", "N/A"))

            # Warn about dangerous types
            fname = att.get("filename", "").lower()
            dangerous = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".ps1", ".jar", ".hta"]
            if any(fname.endswith(ext) for ext in dangerous):
                st.error("⚠️ DANGEROUS: Executable attachment detected!")


def _tab_sandbox(sandbox_results):
    st.subheader("Sandbox Analysis")

    if not sandbox_results:
        st.info("Sandbox analysis was not performed.")
        return

    if sandbox_results.get("status") == "disabled":
        st.warning(f"🔒 {sandbox_results.get('message', 'Sandbox analysis unavailable / disabled')}")
        st.caption("Set `SANDBOX_ENABLED=true` in `.env` to enable sandbox analysis.")
        return

    st.success(f"Provider: {sandbox_results.get('provider', 'N/A')}")

    for results_key, label in [("url_results", "URL Analysis"), ("file_results", "File Analysis")]:
        results = sandbox_results.get(results_key, [])
        if results:
            st.markdown(f"### {label}")
            for r in results:
                details = r.get("details", {})
                if details.get("mock"):
                    st.info(f"🧪 **Mock analysis** for `{r.get('target', 'N/A')}` (development mode)")
                    st.caption("Mock data — not a real sandbox analysis")
                else:
                    verdict = r.get("verdict", "N/A")
                    st.markdown(f"**Target:** `{r.get('target', 'N/A')}` — Verdict: **{verdict}**")


def _tab_risk_details(risk):
    st.subheader("Risk Assessment Details")

    # Score breakdown
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Risk Score", f"{risk['risk_score']}/100")
        st.metric("Severity", risk["severity"])
    with col2:
        st.markdown("### Score Breakdown")
        breakdown = risk.get("score_breakdown", {})
        for category, score in breakdown.items():
            label = category.replace("_", " ").title()
            st.progress(min(score / 30, 1.0), text=f"{label}: {score}")

    st.divider()

    # Verdict
    st.markdown(f"**Verdict:** {risk['verdict']}")

    # Evidence
    st.markdown("### Evidence")
    negatives = [e for e in risk.get("evidence", []) if e.get("impact") == "negative"]
    positives = [e for e in risk.get("evidence", []) if e.get("impact") == "positive"]
    neutrals = [e for e in risk.get("evidence", []) if e.get("impact") == "neutral"]

    if negatives:
        st.markdown("**⚠️ Negative Indicators:**")
        for e in negatives:
            st.markdown(f"- 🔴 [{e.get('source', '')}] {e['finding']}")

    if positives:
        st.markdown("**✅ Positive Indicators:**")
        for e in positives:
            st.markdown(f"- 🟢 [{e.get('source', '')}] {e['finding']}")

    if neutrals:
        with st.expander(f"ℹ️ Neutral Indicators ({len(neutrals)})", expanded=False):
            for e in neutrals:
                st.markdown(f"- ⚪ [{e.get('source', '')}] {e['finding']}")

    st.divider()

    # Recommended actions
    actions = get_recommended_actions(risk["severity"], risk.get("evidence", []))
    st.markdown("### Recommended Actions")
    for i, action in enumerate(actions, 1):
        st.markdown(f"**{i}.** {action}")

    # Scoring note
    st.caption(risk.get("scoring_note", ""))


def _tab_report(report, case_id):
    st.subheader("Investigation Report")

    report_format = st.selectbox("Report Format", ["Markdown", "HTML", "JSON"])

    if report_format == "Markdown":
        st.markdown(report["markdown_content"])
        st.download_button(
            "📥 Download Markdown Report",
            data=report["markdown_content"],
            file_name=f"{case_id}_report.md",
            mime="text/markdown",
        )
    elif report_format == "HTML":
        st.components.v1.html(report["html_content"], height=800, scrolling=True)
        st.download_button(
            "📥 Download HTML Report",
            data=report["html_content"],
            file_name=f"{case_id}_report.html",
            mime="text/html",
        )
    elif report_format == "JSON":
        st.json(report["report_data"])
        st.download_button(
            "📥 Download JSON Report",
            data=json.dumps(report["report_data"], indent=2),
            file_name=f"{case_id}_report.json",
            mime="application/json",
        )


# =============================================================================
# DASHBOARD PAGE
# =============================================================================

def _page_dashboard():
    st.title("📊 Investigation Dashboard")

    # Show current investigation if available
    if "investigation" in st.session_state:
        _show_investigation_results()
    else:
        st.info("No active investigation. Upload an .eml file from 'New Investigation' to begin.")

        # Show quick stats
        cases = list_cases()
        if cases:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Cases", len(cases))
            with col2:
                critical_high = len([c for c in cases if c.get("severity") in ("CRITICAL", "HIGH")])
                st.metric("Critical/High", critical_high)
            with col3:
                latest = cases[0] if cases else None
                st.metric("Latest Case", latest["case_id"][:20] if latest else "N/A")


# =============================================================================
# PAST CASES PAGE
# =============================================================================

def _page_past_cases():
    st.title("🔍 Past Cases")
    cases = list_cases()

    if not cases:
        st.info("No past cases found.")
        return

    for case in cases:
        severity = case.get("severity", "UNKNOWN")
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(severity, "⚪")

        with st.expander(f"{icon} {case['case_id']} — {severity} (Score: {case.get('risk_score', 'N/A')})"):
            st.markdown(f"**Status:** {case.get('status', 'N/A')}")
            st.markdown(f"**Verdict:** {case.get('verdict', 'N/A')}")
            st.markdown(f"**Created:** {case.get('created_at', 'N/A')}")
            st.markdown(f"**Updated:** {case.get('updated_at', 'N/A')}")


# =============================================================================
# SETTINGS PAGE
# =============================================================================

def _page_settings():
    st.title("⚙️ Settings")

    st.markdown("### System Configuration")
    st.markdown("Configure the system via the `.env` file in the project root.")

    st.markdown("### Current Configuration")

    # ML
    st.markdown("#### Machine Learning")
    if ML_AVAILABLE:
        models = get_available_models()
        st.success(f"Available models: {', '.join(models) if models else 'None'}")
        summary = get_evaluation_summary()
        if summary:
            st.markdown(f"**Best model:** {summary.get('best_model', 'N/A')}")
            st.markdown(f"**Dataset size:** {summary.get('dataset_size', 'N/A')}")
            st.json(summary.get("models", {}))
    else:
        st.warning("ML models not trained. Run: `python src/train_model.py`")

    # Threat Intelligence
    st.markdown("#### Threat Intelligence Providers")
    for p in get_provider_status():
        if p["available"]:
            st.success(f"✅ {p['name'].title()}: Configured")
        else:
            st.info(f"⚪ {p['name'].title()}: Not configured")

    # Sandbox
    st.markdown("#### Sandbox")
    sb = get_sandbox_status()
    st.json(sb)

    # ENV example
    st.markdown("#### .env Template")
    try:
        env_example_path = os.path.join(PROJECT_ROOT, ".env.example")
        with open(env_example_path) as f:
            st.code(f.read(), language="bash")
    except Exception:
        st.info(".env.example not found")


if __name__ == "__main__":
    main()
