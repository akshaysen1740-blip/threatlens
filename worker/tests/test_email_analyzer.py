from pathlib import Path

from app.analyzers.email_analyzer import analyze_email, parse_auth_results
from app.analyzers.scoring import score_findings

SAMPLES = Path(__file__).resolve().parents[2] / "samples"

PHISHING = """\
From: "PayPal Support" <service@paypa1-alerts.xyz>
Reply-To: help@totally-different.top
Return-Path: <bounce@mailer.cheap-sender.ru>
To: victim@example.com
Subject: URGENT: Your account has been suspended - verify your identity
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-alerts.xyz; dkim=none; dmarc=fail header.from=paypa1-alerts.xyz
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>We noticed unusual activity. Log in within 24 hours or your account will be closed.</p>
<a href="http://paypa1-secure-login.xyz/verify-account">https://www.paypal.com/signin</a>
</body></html>
"""

CLEAN = """\
From: "GitHub" <noreply@github.com>
To: dev@example.com
Subject: Your weekly digest
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi! Here is what happened in your repositories this week: https://github.com/notifications
"""


def ids(result):
    return {f.id for f in result["findings"]}


def test_parse_auth_results():
    header = "mx.example.com; spf=pass smtp.mailfrom=a.com; dkim=fail; dmarc=none"
    assert parse_auth_results([header]) == {"spf": "pass", "dkim": "fail", "dmarc": "none"}


def test_phishing_email_is_malicious():
    result = analyze_email(PHISHING, network_checks=False)
    score, verdict = score_findings(result["findings"])
    assert verdict == "malicious"
    assert score == 100
    assert {
        "spf_fail",
        "dmarc_fail",
        "reply_to_mismatch",
        "display_name_spoof",
        "link_text_mismatch",
        "urgent_subject",
    } <= ids(result)


def test_clean_email_is_safe():
    result = analyze_email(CLEAN, network_checks=False)
    _, verdict = score_findings(result["findings"])
    assert verdict == "safe"
    assert result["authentication"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_missing_auth_header_is_reported():
    raw = 'From: someone@example.com\nSubject: hello\n\nplain body'
    assert "no_auth_results" in ids(analyze_email(raw, network_checks=False))


def test_sample_files_match_expectations():
    phishing = analyze_email((SAMPLES / "phishing-email.eml").read_text(), network_checks=False)
    clean = analyze_email((SAMPLES / "clean-email.eml").read_text(), network_checks=False)
    assert score_findings(phishing["findings"])[1] == "malicious"
    assert score_findings(clean["findings"])[1] == "safe"
    assert "risky_attachment" in ids(phishing)


def test_dns_failure_is_not_treated_as_missing_records(monkeypatch):
    import dns.exception
    import dns.resolver

    def fail(*_args, **_kwargs):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fail)
    result = analyze_email(CLEAN, network_checks=True)
    assert not {"sender_no_spf", "sender_no_dmarc"} & ids(result)


def test_missing_dmarc_record_is_reported(monkeypatch):
    import dns.resolver

    class Answer:
        strings = [b"v=spf1 include:_spf.example.com ~all"]

    def fake_resolve(_self, name, _rtype, lifetime=None):
        if name.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        return [Answer()]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    found = ids(analyze_email(CLEAN, network_checks=True))
    assert "sender_no_dmarc" in found
    assert "sender_no_spf" not in found
