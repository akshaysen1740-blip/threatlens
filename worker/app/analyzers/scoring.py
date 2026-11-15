"""Turns a list of findings into a 0-100 risk score and a verdict."""
from .models import SEVERITY_WEIGHTS, Finding

SUSPICIOUS_THRESHOLD = 25
MALICIOUS_THRESHOLD = 60


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))
    if score >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return score, verdict
