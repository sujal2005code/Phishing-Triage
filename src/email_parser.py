"""
Email Parser — extracts headers, body, and attachments from .eml files.
Treats all input as untrusted. Never executes attachment content.
"""

import email
import email.policy
import hashlib
import re
from email import message_from_bytes, message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional


def parse_eml(eml_content: bytes) -> dict:
    """
    Parse a raw .eml file into structured data.

    Args:
        eml_content: Raw bytes of the .eml file.

    Returns:
        Dict with keys: from, to, reply_to, subject, date, message_id,
        return_path, headers, received, auth_results_raw, body_text,
        body_html, attachments.
    """
    msg = message_from_bytes(eml_content, policy=email.policy.default)
    return _extract_message(msg)


def parse_eml_string(eml_string: str) -> dict:
    """Parse from a string representation."""
    msg = message_from_string(eml_string, policy=email.policy.default)
    return _extract_message(msg)


def _extract_message(msg) -> dict:
    """Extract structured data from an email.message.Message object."""
    result = {
        "from": _safe_header(msg, "From"),
        "from_address": _extract_email_address(msg, "From"),
        "to": _safe_header(msg, "To"),
        "to_address": _extract_email_address(msg, "To"),
        "reply_to": _safe_header(msg, "Reply-To"),
        "reply_to_address": _extract_email_address(msg, "Reply-To"),
        "subject": _safe_header(msg, "Subject"),
        "date": _safe_header(msg, "Date"),
        "message_id": _safe_header(msg, "Message-ID"),
        "return_path": _safe_header(msg, "Return-Path"),
        "headers": {},
        "received": [],
        "auth_results_raw": [],
        "body_text": "",
        "body_html": "",
        "attachments": [],
    }

    # Collect all headers
    for key in msg.keys():
        val = _safe_header(msg, key)
        if key.lower() == "received":
            result["received"].append(val)
        elif key.lower() == "authentication-results":
            result["auth_results_raw"].append(val)
        else:
            if key in result["headers"]:
                # Multiple values for same header
                if isinstance(result["headers"][key], list):
                    result["headers"][key].append(val)
                else:
                    result["headers"][key] = [result["headers"][key], val]
            else:
                result["headers"][key] = val

    # Parse date
    try:
        if result["date"]:
            result["date_parsed"] = parsedate_to_datetime(result["date"]).isoformat()
    except Exception:
        result["date_parsed"] = None

    # Extract body and attachments
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition.lower() or (
                content_type not in ("text/plain", "text/html", "multipart/mixed",
                                     "multipart/alternative", "multipart/related")
                and part.get_filename()
            ):
                # Attachment — extract metadata only, never execute
                _extract_attachment(part, result)
            elif content_type == "text/plain" and not result["body_text"]:
                try:
                    result["body_text"] = part.get_content()
                except Exception:
                    result["body_text"] = _safe_payload(part)
            elif content_type == "text/html" and not result["body_html"]:
                try:
                    result["body_html"] = part.get_content()
                except Exception:
                    result["body_html"] = _safe_payload(part)
    else:
        content_type = msg.get_content_type()
        try:
            body = msg.get_content()
        except Exception:
            body = _safe_payload(msg)

        if content_type == "text/html":
            result["body_html"] = body
        else:
            result["body_text"] = body

    return result


def _extract_attachment(part, result: dict):
    """Extract attachment metadata — filename, MIME type, size, SHA256. Never executes content."""
    filename = part.get_filename()
    if filename:
        # Sanitize filename — remove path separators
        filename = re.sub(r'[/\\]', '_', filename)

    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
    except Exception:
        payload = b""

    attachment = {
        "filename": filename or "unnamed_attachment",
        "mime_type": part.get_content_type(),
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    result["attachments"].append(attachment)


def _safe_header(msg, name: str) -> Optional[str]:
    """Safely extract a header value, returning None if absent or malformed."""
    try:
        val = msg.get(name)
        if val is None:
            return None
        return str(val).strip()
    except Exception:
        return None


def _extract_email_address(msg, header_name: str) -> Optional[str]:
    """Extract just the email address from a header like 'Name <addr@example.com>'."""
    raw = _safe_header(msg, header_name)
    if not raw:
        return None
    _, addr = parseaddr(raw)
    return addr if addr else None


def _safe_payload(part) -> str:
    """Safely extract text payload with fallback decoding."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        # Try UTF-8 first, fall back to latin-1
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.decode("latin-1", errors="replace")
    except Exception:
        return ""


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python email_parser.py <path_to_eml>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = parse_eml(f.read())

    # Print summary
    print(f"From: {data['from']}")
    print(f"To: {data['to']}")
    print(f"Subject: {data['subject']}")
    print(f"Date: {data['date']}")
    print(f"Attachments: {len(data['attachments'])}")
    for att in data["attachments"]:
        print(f"  - {att['filename']} ({att['mime_type']}, {att['size']} bytes, SHA256: {att['sha256']})")
