"""Runs one scan: analysis -> scoring -> explanation."""
from .ai.explainer import explain
from .analyzers.email_analyzer import analyze_email
from .analyzers.scoring import score_findings
from .analyzers.url_analyzer import analyze_url
from .config import Settings


class PermanentError(Exception):
    """An error that retrying will not fix (bad input), so the job goes straight to the DLQ."""


def run_scan(settings: Settings, scan_type: str, payload: dict) -> dict:
    if scan_type == "url":
        url = payload.get("url")
        if not url:
            raise PermanentError("Missing 'url' in payload")
        analysis = analyze_url(url, network_checks=settings.enable_network_checks)
        target = analysis["url"]
    elif scan_type == "email":
        raw = payload.get("rawEmail")
        if not raw:
            raise PermanentError("Missing 'rawEmail' in payload")
        analysis = analyze_email(raw, network_checks=settings.enable_network_checks)
        target = analysis["subject"] or analysis["from"] or "(email)"
    else:
        raise PermanentError(f"Unknown scan type: {scan_type}")

    findings = analysis.pop("findings")
    score, verdict = score_findings(findings)
    explanation, source = explain(settings, scan_type, target, score, verdict, findings)

    return {
        "riskScore": score,
        "verdict": verdict,
        "findings": [f.to_dict() for f in findings],
        "explanation": explanation,
        "explanationSource": source,
        "details": analysis,
    }
