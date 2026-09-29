"""
Batch evaluation of the Phishing Triage pipeline.

Test set:
    Sample/phishing/    -> phishing
    Sample/legitimate/  -> legitimate

This uses the same core analysis functions as app.py.
"""

import os
import sys
import csv
import traceback

# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SAMPLE_ROOT = os.path.join(
    PROJECT_ROOT,
    "Sample"
)

PHISHING_DIR = os.path.join(SAMPLE_ROOT, "phishing")
LEGITIMATE_DIR = os.path.join(SAMPLE_ROOT, "legitimate")

OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports")
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "batch_test_results.csv"
)

# ---------------------------------------------------------
# Import project modules
# ---------------------------------------------------------

sys.path.insert(
    0,
    os.path.join(PROJECT_ROOT, "src")
)

from email_parser import parse_eml
from ioc_extractor import extract_iocs, extract_urls
from auth_analyzer import analyze_authentication
from ml_predictor import predict_urls
from risk_engine import assess_risk


def analyze_email(filepath):
    """
    Run the core phishing-triage analysis on one .eml file.
    """

    with open(filepath, "rb") as f:
        eml_content = f.read()

    # Same parser used by app.py
    parsed_email = parse_eml(eml_content)

    # IOC extraction
    iocs = extract_iocs(parsed_email)

    # Authentication analysis
    auth_results = analyze_authentication(parsed_email)

    # URL extraction
    urls = extract_urls(parsed_email)

    # ML classification
    ml_results = []

    if urls:
        ml_results = predict_urls(urls[:20])

    # For batch testing, don't make hundreds of external
    # threat-intelligence API requests.
    ti_results = {}

    # Sandbox disabled for this evaluation
    sandbox_results = {
        "status": "disabled",
        "provider": "none"
    }

    # Same risk engine used by the application
    risk_assessment = assess_risk(
        ml_results=ml_results,
        auth_results=auth_results,
        ti_results=ti_results,
        iocs=iocs,
        attachments=parsed_email.get("attachments", []),
        sandbox_results=sandbox_results,
    )

    return {
        "parsed_email": parsed_email,
        "iocs": iocs,
        "auth_results": auth_results,
        "urls": urls,
        "ml_results": ml_results,
        "risk": risk_assessment,
    }


def main():

    print("=" * 70)
    print("PHISHING TRIAGE — BATCH EMAIL EVALUATION")
    print("=" * 70)

    print(f"\nPhishing directory:")
    print(PHISHING_DIR)

    print(f"\nLegitimate directory:")
    print(LEGITIMATE_DIR)

    if not os.path.isdir(PHISHING_DIR):
        print("\nERROR: phishing directory not found.")
        return

    if not os.path.isdir(LEGITIMATE_DIR):
        print("\nERROR: legitimate directory not found.")
        return

    phishing_files = [
        os.path.join(PHISHING_DIR, f)
        for f in os.listdir(PHISHING_DIR)
        if f.lower().endswith(".eml")
    ]

    legitimate_files = [
    os.path.join(LEGITIMATE_DIR, f)
    for f in os.listdir(LEGITIMATE_DIR)
    if os.path.isfile(os.path.join(LEGITIMATE_DIR, f))
]

    phishing_files.sort()
    legitimate_files.sort()

    print(f"\nPhishing samples:   {len(phishing_files)}")
    print(f"Legitimate samples: {len(legitimate_files)}")

    if not phishing_files or not legitimate_files:
        print("\nERROR: One or both test directories are empty.")
        return

    results = []

    # ---------------------------------------------------------
    # Process both groups
    # ---------------------------------------------------------

    test_groups = [
        ("phishing", 1, phishing_files),
        ("legitimate", 0, legitimate_files),
    ]

    total = len(phishing_files) + len(legitimate_files)
    current = 0

    for actual_type, actual_label, files in test_groups:

        for filepath in files:

            current += 1

            filename = os.path.basename(filepath)

            print(
                f"\n[{current}/{total}] "
                f"{actual_type.upper()} — {filename}"
            )

            try:

                analysis = analyze_email(filepath)

                risk = analysis["risk"]
                ml_results = analysis["ml_results"]

                # -------------------------------------------------
                # Determine email-level prediction
                #
                # If ANY extracted URL is classified as phishing,
                # mark the email as phishing.
                #
                # Otherwise use the risk engine severity.
                # -------------------------------------------------

                phishing_urls = [
                    r for r in ml_results
                    if r.get("prediction") == "phishing"
                ]

                if phishing_urls:
                    predicted_label = 1
                    predicted_type = "phishing"
                else:
                    predicted_label = 0
                    predicted_type = "legitimate"

                # -------------------------------------------------
                # Authentication information
                # -------------------------------------------------

                auth = analysis["auth_results"]

                spf = auth.get("spf", {}).get(
                    "result", "UNKNOWN"
                )

                dkim = auth.get("dkim", {}).get(
                    "result", "UNKNOWN"
                )

                dmarc = auth.get("dmarc", {}).get(
                    "result", "UNKNOWN"
                )

                # -------------------------------------------------
                # ML information
                # -------------------------------------------------

                if ml_results:

                    max_ml_probability = max(
                        r.get("probability", 0)
                        for r in ml_results
                    )

                    model_name = ml_results[0].get(
                        "model",
                        "unknown"
                    )

                    ml_prediction_count = len(
                        phishing_urls
                    )

                else:

                    max_ml_probability = 0
                    model_name = "none"
                    ml_prediction_count = 0

                risk_score = risk.get(
                    "risk_score",
                    0
                )

                severity = risk.get(
                    "severity",
                    "UNKNOWN"
                )

                correct = predicted_label == actual_label

                results.append({
                    "filename": filename,
                    "actual": actual_type,
                    "predicted": predicted_type,
                    "correct": correct,
                    "risk_score": risk_score,
                    "severity": severity,
                    "url_count": len(analysis["urls"]),
                    "phishing_url_count": ml_prediction_count,
                    "max_ml_probability": max_ml_probability,
                    "model": model_name,
                    "spf": spf,
                    "dkim": dkim,
                    "dmarc": dmarc,
                })

                status = "✓" if correct else "✗"

                print(
                    f"  {status} "
                    f"Predicted: {predicted_type.upper()} | "
                    f"Risk: {risk_score}/100 | "
                    f"URLs: {len(analysis['urls'])}"
                )

            except Exception as e:

                print(
                    f"  ERROR: {str(e)}"
                )

                traceback.print_exc()

                results.append({
                    "filename": filename,
                    "actual": actual_type,
                    "predicted": "ERROR",
                    "correct": False,
                    "risk_score": "",
                    "severity": "ERROR",
                    "url_count": "",
                    "phishing_url_count": "",
                    "max_ml_probability": "",
                    "model": "",
                    "spf": "",
                    "dkim": "",
                    "dmarc": "",
                })

    # ---------------------------------------------------------
    # Calculate metrics
    # ---------------------------------------------------------

    tp = sum(
        r["actual"] == "phishing"
        and r["predicted"] == "phishing"
        for r in results
    )

    fn = sum(
        r["actual"] == "phishing"
        and r["predicted"] == "legitimate"
        for r in results
    )

    tn = sum(
        r["actual"] == "legitimate"
        and r["predicted"] == "legitimate"
        for r in results
    )

    fp = sum(
        r["actual"] == "legitimate"
        and r["predicted"] == "phishing"
        for r in results
    )

    total_valid = tp + fn + tn + fp

    accuracy = (
        (tp + tn) / total_valid
        if total_valid else 0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp) else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) else 0
    )

    f1 = (
        2 * precision * recall /
        (precision + recall)
        if (precision + recall) else 0
    )

    # ---------------------------------------------------------
    # Print summary
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("BATCH EVALUATION RESULTS")
    print("=" * 70)

    print(f"\nTrue Positives:  {tp}")
    print(f"False Negatives: {fn}")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")

    print("\nMetrics:")

    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")

    print("\nInterpretation:")

    print(
        f"Phishing detection: "
        f"{recall * 100:.1f}%"
    )

    print(
        f"Legitimate correctly accepted: "
        f"{tn / (tn + fp) * 100:.1f}%"
        if (tn + fp)
        else "N/A"
    )

    print(
        f"False-positive rate: "
        f"{fp / (tn + fp) * 100:.1f}%"
        if (tn + fp)
        else "N/A"
    )

    # ---------------------------------------------------------
    # Save CSV
    # ---------------------------------------------------------

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    fieldnames = list(results[0].keys())

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nDetailed results saved to:")

    print(OUTPUT_FILE)

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()