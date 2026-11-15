"""
URL heuristics used by phishing detection.

Offline checks (always run): IP-based hosts, lookalike/typosquat domains, brand names
in unrelated domains, suspicious TLDs and keywords, punycode, URL length and entropy.

Network checks (optional): DNS resolution and the site's SSL certificate.
"""
import ipaddress
import math
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import tldextract

from .models import Finding

# suffix_list_urls=() uses the public suffix list bundled with tldextract (no download needed)
_extract = tldextract.TLDExtract(suffix_list_urls=())

POPULAR_BRANDS = (
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix",
    "linkedin", "github", "whatsapp", "outlook", "office365", "dropbox", "adobe", "binance",
    "coinbase", "hdfcbank", "icicibank", "flipkart", "paytm", "phonepe",
)

# Legitimate domains that contain a brand name but belong to that brand
BRAND_ALLOWLIST = {
    "amazonaws.com", "googleusercontent.com", "googleapis.com", "googlemail.com", "githubusercontent.com",
    "microsoftonline.com", "facebookmail.com", "paypal-community.com",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "country",
    "kim", "loan", "review", "rest", "support", "cam", "icu",
}

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "verification", "account", "update", "secure", "banking",
    "password", "confirm", "wallet", "suspended", "unlock", "billing",
)

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rb.gy", "cutt.ly"}

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    return raw if _SCHEME.match(raw) else f"http://{raw}"


def registered_domain(host: str) -> str:
    """'mail.paypal.co.uk' -> 'paypal.co.uk'."""
    ext = _extract(host)
    if not ext.suffix:
        return ext.domain
    return f"{ext.domain}.{ext.suffix}" if ext.domain else ext.suffix


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_findings(domain_label: str, subdomain: str, registered: str) -> list[Finding]:
    findings: list[Finding] = []
    if registered in BRAND_ALLOWLIST:
        return findings

    # Check the whole label and each hyphen/dot-separated part: "paypa1-secure-login" -> "paypa1", ...
    tokens = {domain_label, *domain_label.split("-"), *re.split(r"[.-]", subdomain)} - {""}
    normalized_label = domain_label.translate(HOMOGLYPHS)

    for brand in POPULAR_BRANDS:
        if domain_label == brand:
            continue  # the real brand domain (e.g. paypal.com)

        max_distance = 1 if len(brand) <= 6 else 2
        lookalike = any(
            token != brand and (token.translate(HOMOGLYPHS) == brand or 0 < levenshtein(token, brand) <= max_distance)
            for token in tokens
        )
        if lookalike:
            findings.append(Finding(
                f"typosquat_{brand}",
                "Lookalike of a well-known brand",
                "high",
                f"'{registered}' imitates {brand} with a slightly changed spelling, a common phishing trick.",
            ))
        elif brand in normalized_label or brand in tokens:
            findings.append(Finding(
                f"brand_misuse_{brand}",
                "Brand name used on an unrelated domain",
                "high",
                f"The URL mentions '{brand}' but the real domain is '{registered}'.",
            ))
    return findings


def _looks_random(label: str) -> bool:
    """Machine-generated names are long, high-entropy and have few vowels (e.g. 'x7kq9zv2lm4p')."""
    letters = label.replace("-", "")
    if len(letters) < 10:
        return False
    vowel_ratio = sum(ch in "aeiou" for ch in letters) / len(letters)
    return shannon_entropy(letters) > 3.0 and vowel_ratio < 0.25


def check_dns(host: str, timeout: float = 5.0) -> list[Finding]:
    resolver = dns.resolver.Resolver()
    try:
        resolver.resolve(host, "A", lifetime=timeout)
        return []
    except dns.resolver.NXDOMAIN:
        return [Finding("dns_nxdomain", "Domain does not exist", "medium",
                        f"'{host}' has no DNS record. It may be a taken-down or not-yet-active phishing domain.")]
    except dns.resolver.NoAnswer:
        try:
            resolver.resolve(host, "AAAA", lifetime=timeout)
            return []
        except dns.exception.DNSException:
            return [Finding("dns_no_address", "Domain has no address", "low",
                            f"'{host}' exists but does not point to any server.")]
    except dns.exception.DNSException:
        return []  # resolver problem, not evidence about the domain


def check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> list[Finding]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return [Finding("ssl_invalid", "Invalid SSL certificate", "high",
                        f"The certificate could not be verified: {exc.verify_message}.")]
    except ssl.SSLError as exc:
        return [Finding("ssl_error", "SSL handshake failed", "medium", f"TLS error: {exc.reason}.")]
    except OSError:
        return [Finding("https_unreachable", "HTTPS not reachable", "low",
                        "Could not connect to the site over HTTPS.")]

    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)

    if (not_after - now).days < 7:
        findings.append(Finding("ssl_expiring", "SSL certificate about to expire", "low",
                                f"Certificate expires on {not_after.date()}."))
    if (now - not_before).days < 7:
        findings.append(Finding("ssl_new", "Very new SSL certificate", "low",
                                f"Certificate was issued on {not_before.date()}. Phishing sites often use brand-new certificates."))
    return findings


def analyze_url(raw_url: str, network_checks: bool = True) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    findings: list[Finding] = []

    if not host:
        findings.append(Finding("invalid_url", "Invalid URL", "medium", "The URL has no valid host name."))
        return {"url": url, "host": host, "registeredDomain": None, "findings": findings}

    is_ip = _is_ip(host)
    ext = _extract(host)
    registered = host if is_ip else registered_domain(host)

    if is_ip:
        findings.append(Finding("ip_host", "Uses an IP address instead of a domain", "high",
                                "Legitimate sites almost always use a domain name."))
    else:
        findings.extend(_brand_findings(ext.domain, ext.subdomain, registered))

        if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
            findings.append(Finding("suspicious_tld", "Suspicious top-level domain", "medium",
                                    f"'.{ext.suffix}' domains are cheap and frequently abused for phishing."))
        if "xn--" in host:
            findings.append(Finding("punycode", "Internationalized (punycode) domain", "medium",
                                    "Punycode domains can imitate real domains with lookalike characters."))
        if host.count(".") >= 4:
            findings.append(Finding("many_subdomains", "Unusually many subdomains", "low",
                                    "Deep subdomains are often used to hide the real domain."))
        if ext.domain.count("-") >= 2:
            findings.append(Finding("hyphenated_domain", "Heavily hyphenated domain", "low",
                                    f"'{ext.domain}' contains several hyphens."))
        if _looks_random(ext.domain):
            findings.append(Finding("random_domain", "Random-looking domain name", "medium",
                                    "The domain looks machine-generated, which is common for throwaway phishing domains."))
        if registered in URL_SHORTENERS:
            findings.append(Finding("url_shortener", "URL shortener", "low",
                                    "Shortened links hide the real destination."))

    if "@" in parsed.netloc:
        findings.append(Finding("at_symbol", "'@' in URL", "high",
                                "Everything before '@' is ignored by the browser and can be used to disguise the real host."))
    if len(url) > 100:
        findings.append(Finding("long_url", "Very long URL", "low", f"The URL is {len(url)} characters long."))

    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    keywords = sorted({k for k in SUSPICIOUS_KEYWORDS if k in path_and_query or k in ext.subdomain})
    if keywords:
        findings.append(Finding("suspicious_keywords", "Credential-related keywords", "low",
                                f"Contains: {', '.join(keywords)}."))

    if parsed.scheme == "http":
        findings.append(Finding("no_https", "Not using HTTPS", "low",
                                "Data sent to this page is not encrypted."))

    if network_checks and not is_ip:
        dns_findings = check_dns(host)
        findings.extend(dns_findings)
        if parsed.scheme == "https" and not dns_findings:
            findings.extend(check_ssl(host, parsed.port or 443))

    return {"url": url, "host": host, "registeredDomain": registered, "findings": findings}
