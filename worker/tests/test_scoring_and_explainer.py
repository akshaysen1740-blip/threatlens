from app.ai.explainer import build_prompt, explain, rule_based_explanation
from app.analyzers.models import Finding
from app.analyzers.scoring import score_findings
from app.config import Settings


def test_score_is_capped_at_100():
    findings = [Finding(str(i), "x", "critical", "") for i in range(5)]
    assert score_findings(findings) == (100, "malicious")


def test_score_thresholds():
    assert score_findings([]) == (0, "safe")
    assert score_findings([Finding("a", "a", "medium", "")]) == (20, "safe")
    assert score_findings([Finding("a", "a", "high", "")]) == (35, "suspicious")
    assert score_findings([Finding("a", "a", "high", ""), Finding("b", "b", "medium", "")]) == (55, "suspicious")
    assert score_findings([Finding("a", "a", "high", ""), Finding("b", "b", "high", "")]) == (70, "malicious")


def test_falls_back_to_rules_without_provider():
    settings = Settings(llm_provider="none", llm_api_key="")
    findings = [Finding("ip_host", "Uses an IP address instead of a domain", "high", "")]
    text, source = explain(settings, "url", "http://1.2.3.4", 35, "suspicious", findings)
    assert source == "rules"
    assert "suspicious" in text


def test_falls_back_to_rules_when_llm_fails(monkeypatch):
    import app.ai.explainer as explainer

    def boom(*_args, **_kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setitem(explainer.PROVIDERS, "openai", boom)
    settings = Settings(llm_provider="openai", llm_api_key="sk-test")
    _, source = explain(settings, "url", "http://x.com", 0, "safe", [])
    assert source == "rules"


def test_uses_ai_when_provider_succeeds(monkeypatch):
    import app.ai.explainer as explainer

    monkeypatch.setitem(explainer.PROVIDERS, "anthropic", lambda *_a, **_k: "  AI says it is safe.  ")
    settings = Settings(llm_provider="anthropic", llm_api_key="key")
    assert explain(settings, "url", "http://x.com", 0, "safe", []) == ("AI says it is safe.", "ai")


def test_prompt_contains_findings_but_is_bounded():
    prompt = build_prompt("url", "x" * 1000, 70, "malicious", [Finding("a", "Bad thing", "high", "detail")])
    assert "[high] Bad thing: detail" in prompt
    assert "x" * 301 not in prompt


def test_rule_based_lists_top_reasons():
    findings = [Finding("a", "Low thing", "low", ""), Finding("b", "Critical thing", "critical", "")]
    text = rule_based_explanation(60, "malicious", findings)
    assert text.index("critical thing") < text.index("low thing")
    assert "Do not click" in text
