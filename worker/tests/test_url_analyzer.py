from app.analyzers.scoring import score_findings
from app.analyzers.url_analyzer import analyze_url, levenshtein, normalize_url, registered_domain


def ids(result):
    return {f.id for f in result["findings"]}


def verdict(url):
    result = analyze_url(url, network_checks=False)
    return score_findings(result["findings"])[1], result


def test_normalize_adds_scheme():
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("https://example.com") == "https://example.com"


def test_registered_domain_handles_multi_part_suffix():
    assert registered_domain("mail.paypal.co.uk") == "paypal.co.uk"


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("google", "google") == 0


def test_legitimate_https_url_is_safe():
    result, analysis = verdict("https://www.google.com/search?q=python")
    assert result == "safe"
    assert not any(i.startswith(("typosquat", "brand_misuse")) for i in ids(analysis))


def test_typosquat_with_homoglyph_is_detected():
    _, analysis = verdict("https://paypa1.com")
    assert "typosquat_paypal" in ids(analysis)


def test_brand_in_subdomain_is_detected():
    _, analysis = verdict("https://paypal.com.account-verify.xyz/login")
    found = ids(analysis)
    assert "brand_misuse_paypal" in found
    assert "suspicious_tld" in found


def test_classic_phishing_url_is_malicious():
    result, analysis = verdict("http://paypa1-secure-login.xyz/verify-account")
    assert result == "malicious"
    assert {"suspicious_tld", "no_https", "suspicious_keywords"} <= ids(analysis)


def test_ip_address_host_is_flagged():
    _, analysis = verdict("http://192.168.10.5/login")
    assert "ip_host" in ids(analysis)


def test_at_symbol_trick_is_flagged():
    _, analysis = verdict("http://google.com@evil.example/login")
    assert "at_symbol" in ids(analysis)


def test_allowlisted_brand_domain_is_not_flagged():
    _, analysis = verdict("https://my-bucket.s3.amazonaws.com/file.txt")
    assert not any(i.startswith(("typosquat", "brand_misuse")) for i in ids(analysis))


def test_lookalike_inside_hyphenated_domain_is_detected():
    _, analysis = verdict("http://paypa1-secure-login.xyz/verify-account")
    assert "typosquat_paypal" in ids(analysis)
    assert "random_domain" not in ids(analysis)


def test_exact_brand_with_extra_words_is_brand_misuse():
    _, analysis = verdict("https://paypal-secure-help.com")
    assert "brand_misuse_paypal" in ids(analysis)


def test_random_machine_generated_domain_is_flagged():
    _, analysis = verdict("https://x7kq9zv2lm4pt.com")
    assert "random_domain" in ids(analysis)


def test_normal_domains_have_no_brand_or_random_findings():
    for url in ("https://stackoverflow.com", "https://login.microsoftonline.com", "https://www.wikipedia.org",
                "https://news.ycombinator.com", "https://docs.python.org/3/"):
        found = ids(analyze_url(url, network_checks=False))
        assert not any(i.startswith(("typosquat", "brand_misuse", "random")) for i in found), (url, found)
