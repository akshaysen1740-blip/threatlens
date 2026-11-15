"""
Email phishing heuristics.

Header checks: SPF/DKIM/DMARC results, From vs Reply-To / Return-Path mismatch,
brand impersonation in the display name, urgency in the subject, and (optional)
whether the sender domain publishes SPF and DMARC records.

Body checks: links whose text shows a different domain than the real target,
suspicious links (scored with the URL analyzer) and risky attachments.
"""
import email
import html
import re
from email import policy
from email.utils import parseaddr

import dns.exception
import dns.resolver

from .models import Finding
from .scoring import score_findings
from .url_analyzer import POPULAR_BRANDS, analyze_url, registered_domain

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
ANCHOR_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

URGENCY_WORDS = (
    "urgent", "immediately", "suspended", "verify your", "action required", "final notice",
    "unusual activity", "account locked", "within 24 hours", "password expires", "confirm your",
)

RISKY_EXTENSIONS = (
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi", ".iso", ".img",
    ".html", ".htm", ".docm", ".xlsm", ".pptm", ".lnk", ".hta",
)

MAX_LINKS = 10


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">") if "@" in address else ""


def parse_auth_results(headers: list[str]) -> dict[str, str]:
    """Extracts spf/dkim/dmarc results. The first (topmost) header is from the most recent receiving server."""
    results: dict[str, str] = {}
    for header in headers:
        for mechanism in ("spf", "dkim", "dmarc"):
            if mechanism not in results:
                match = re.search(rf"\b{mechanism}=(\w+)", header, re.IGNORECASE)
                if match:
                    results[mechanism] = match.group(1).lower()
    return results


def _auth_findings(auth: dict[str, str], has_auth_header: bool) -> list[Finding]:
    if not has_auth_header:
        return [Finding("no_auth_results", "No authentication results", "low",
                        "The email has no Authentication-Results header, so SPF/DKIM/DMARC can't be confirmed.")]
    findings = []
    for mechanism in ("spf", "dkim", "dmarc"):
        result = auth.get(mechanism)
        name = mechanism.upper()
        if result in ("fail", "permerror"):
            findings.append(Finding(f"{mechanism}_fail", f"{name} check failed", "high",
                                    f"{name} result is '{result}': the sender is likely spoofed."))
        elif result in ("softfail", "none", "neutral", "temperror"):
            findings.append(Finding(f"{mechanism}_weak", f"{name} not passing", "medium",
                                    f"{name} result is '{result}'."))
    return findings


def _txt_records(resolver: dns.resolver.Resolver, name: str) -> list[str] | None:
    """Returns TXT records, [] if the name genuinely has none, or None if the lookup itself failed."""
    try:
        answers = resolver.resolve(name, "TXT", lifetime=5)
        return [b"".join(r.strings).decode(errors="ignore") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None  # timeout / resolver problem: not evidence either way


def _sender_dns_findings(domain: str) -> list[Finding]:
    findings = []
    resolver = dns.resolver.Resolver()

    spf = _txt_records(resolver, domain)
    if spf is not None and not any(r.lower().startswith("v=spf1") for r in spf):
        findings.append(Finding("sender_no_spf", "Sender domain has no SPF record", "low",
                                f"'{domain}' does not publish SPF, so anyone can send mail as it."))

    dmarc = _txt_records(resolver, f"_dmarc.{domain}")
    if dmarc is not None and not any(r.lower().startswith("v=dmarc1") for r in dmarc):
        findings.append(Finding("sender_no_dmarc", "Sender domain has no DMARC record", "low",
                                f"'{domain}' does not publish a DMARC policy."))
    return findings


def _body_parts(msg) -> tuple[str, str]:
    text, html_body = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, KeyError, ValueError):
            continue
        if not isinstance(content, str):
            continue
        if part.get_content_type() == "text/html":
            html_body.append(content)
        elif part.get_content_type() == "text/plain":
            text.append(content)
    return "\n".join(text), "\n".join(html_body)


def _link_mismatch_findings(html_body: str) -> list[Finding]:
    findings = []
    for href, inner in ANCHOR_RE.findall(html_body):
        if not href.lower().startswith("http"):
            continue
        visible = html.unescape(TAG_RE.sub("", inner)).strip()
        shown = DOMAIN_IN_TEXT_RE.search(visible)
        if not shown:
            continue
        real_host = re.sub(r"^https?://", "", href, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if registered_domain(shown.group(1).lower()) != registered_domain(real_host.lower()):
            findings.append(Finding("link_text_mismatch", "Link text hides the real destination", "high",
                                    f"Link shows '{shown.group(1)}' but actually goes to '{real_host}'."))
            break  # one is enough to flag
    return findings


def analyze_email(raw_email: str, network_checks: bool = True) -> dict:
    msg = email.message_from_string(raw_email, policy=policy.default)
    findings: list[Finding] = []

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    subject = str(msg.get("Subject", ""))

    from_domain = _domain_of(from_addr)
    from_root = registered_domain(from_domain) if from_domain else ""

    auth_headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    auth = parse_auth_results(auth_headers)
    findings.extend(_auth_findings(auth, bool(auth_headers)))

    if not from_domain:
        findings.append(Finding("missing_from", "Missing or invalid sender", "medium",
                                "The From header has no valid email address."))

    reply_domain = _domain_of(reply_to)
    if reply_domain and from_root and registered_domain(reply_domain) != from_root:
        findings.append(Finding("reply_to_mismatch", "Reply-To differs from sender", "medium",
                                f"Replies go to '{reply_domain}' instead of '{from_domain}'."))

    return_domain = _domain_of(return_path)
    if return_domain and from_root and registered_domain(return_domain) != from_root:
        findings.append(Finding("return_path_mismatch", "Return-Path differs from sender", "low",
                                f"Bounces go to '{return_domain}' while the sender is '{from_domain}'."))

    lowered_name = display_name.lower()
    for brand in POPULAR_BRANDS:
        if brand in lowered_name.replace(" ", "") and brand not in from_domain:
            findings.append(Finding("display_name_spoof", "Display name impersonates a brand", "high",
                                    f"Display name mentions '{brand}' but the email comes from '{from_domain or 'unknown'}'."))
            break

    urgent = [w for w in URGENCY_WORDS if w in subject.lower()]
    if urgent:
        findings.append(Finding("urgent_subject", "Urgent or threatening subject", "low",
                                f"Subject uses pressure words: {', '.join(urgent)}."))

    if network_checks and from_domain:
        findings.extend(_sender_dns_findings(from_root))

    text_body, html_body = _body_parts(msg)
    findings.extend(_link_mismatch_findings(html_body))

    # Analyze unique links offline (fast) and summarize the risky ones
    links = list(dict.fromkeys(URL_RE.findall(text_body + "\n" + html.unescape(html_body))))[:MAX_LINKS]
    link_results = []
    for link in links:
        result = analyze_url(link, network_checks=False)
        score, verdict = score_findings(result["findings"])
        link_results.append({"url": link, "riskScore": score, "verdict": verdict})
        if verdict != "safe":
            reasons = ", ".join(f.title for f in result["findings"][:3])
            findings.append(Finding(
                "suspicious_link",
                "Suspicious link in email",
                "high" if verdict == "malicious" else "medium",
                f"{link} ({reasons}).",
            ))

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or ""
        attachments.append(filename)
        if filename.lower().endswith(RISKY_EXTENSIONS):
            findings.append(Finding("risky_attachment", "Dangerous attachment type", "high",
                                    f"'{filename}' can run code or hide a phishing page."))

    return {
        "from": from_addr,
        "displayName": display_name,
        "subject": subject,
        "authentication": auth,
        "links": link_results,
        "attachments": attachments,
        "findings": findings,
    }
