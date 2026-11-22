"""
Unit tests for Phase 4A URL Intelligence Engine (PhishIntel).
Tests local, deterministic feature extraction, edge-case parsing, rule triggers,
and guarantees ZERO network access (socket isolation).
"""

import socket
import pytest
from app.schemas.url_intelligence import (
    HeuristicRiskCategory,
    HostClassification,
    HostType,
    ObservationSeverity,
    ParseStatus,
)
from app.services.url_intelligence import (
    analyze_url,
    analyze_urls,
    analyze_email_extracted_urls,
)
from app.schemas.email import ExtractedURL


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces zero network access by disabling socket connection and DNS resolution.
    Any attempt to open a socket or query DNS will fail the test immediately.
    """
    def fail_network(*args, **kwargs):
        raise RuntimeError("Network access attempted during URL analysis unit test!")

    monkeypatch.setattr(socket, "socket", fail_network)
    monkeypatch.setattr(socket, "gethostbyname", fail_network)
    monkeypatch.setattr(socket, "getaddrinfo", fail_network)


# 1. Normal HTTPS URL
def test_normal_https_url():
    url = "https://www.example.com/about/team"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.scheme == "https"
    assert res.features.is_https is True
    assert res.features.is_http is False
    assert res.features.normalized_host == "www.example.com"
    assert res.features.is_ip_literal is False
    assert res.features.is_non_default_port is False
    assert res.heuristic_risk_category == HeuristicRiskCategory.INFO
    assert any(o.rule_id == "RULE_HTTPS_STANDARD" for o in res.observations)


# 2. Normal HTTP URL
def test_normal_http_url():
    url = "http://example.org/index.html"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.scheme == "http"
    assert res.features.is_http is True
    assert res.features.is_https is False
    assert res.features.normalized_host == "example.org"
    assert any(o.rule_id == "RULE_HTTP_UNENCRYPTED" for o in res.observations)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.INFO, HeuristicRiskCategory.LOW)


# 3. Hostname containing multiple subdomains
def test_multiple_subdomains():
    url = "https://a.b.c.d.secure-banking.example.com/login"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.subdomain_count >= 3
    assert any(o.rule_id == "RULE_DEEP_SUBDOMAINS" for o in res.observations)


# 4. Hostname with hyphens
def test_hostname_with_hyphens():
    url = "https://secure-login-account-update.com/portal"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.hyphens_in_host == 3
    assert any(o.rule_id == "RULE_HYPHENATED_HOST" for o in res.observations)


# 5. IPv4-literal URL (Public and Private)
def test_ipv4_literal_public():
    url = "http://93.184.216.34/login"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.is_ip_literal is True
    assert res.features.ip_version == 4
    assert res.features.host_type == HostType.IPV4
    assert res.features.host_classification == HostClassification.PUBLIC
    assert any(o.rule_id == "RULE_PUBLIC_IP_HOST" for o in res.observations)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)


def test_ipv4_literal_private():
    url = "http://192.168.1.100/admin"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.is_ip_literal is True
    assert res.features.ip_version == 4
    assert res.features.host_classification == HostClassification.PRIVATE
    assert any(o.rule_id == "RULE_PRIVATE_IP_HOST" for o in res.observations)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.LOW, HeuristicRiskCategory.MEDIUM)
    assert res.heuristic_risk_category != HeuristicRiskCategory.HIGH


# 6. IPv6-literal URL
def test_ipv6_literal():
    url = "http://[2001:db8::1]:8080/path"
    res = analyze_url(url)

    assert res.parse_status == ParseStatus.PARSED
    assert res.features.is_ip_literal is True
    assert res.features.ip_version == 6
    assert res.features.host_type == HostType.IPV6
    assert res.features.port == 8080
    assert res.features.is_non_default_port is True


# 7. URL containing user-info (@ in authority)
def test_url_with_userinfo():
    url = "http://legit-bank.com@attacker-site.com/login"
    res = analyze_url(url)

    assert res.features.has_userinfo is True
    assert res.features.normalized_host == "attacker-site.com"
    assert any(o.rule_id == "RULE_USERINFO_AUTH" for o in res.observations)
    assert res.heuristic_risk_category == HeuristicRiskCategory.HIGH


# 8. Non-default port
def test_non_default_port():
    url = "https://example.com:8443/api"
    res = analyze_url(url)

    assert res.features.port == 8443
    assert res.features.is_non_default_port is True
    assert any(o.rule_id == "RULE_NON_DEFAULT_PORT" for o in res.observations)


def test_default_port_not_flagged():
    url = "https://example.com:443/api"
    res = analyze_url(url)

    assert res.features.port == 443
    assert res.features.is_non_default_port is False
    assert not any(o.rule_id == "RULE_NON_DEFAULT_PORT" for o in res.observations)


# 9. Punycode hostname
def test_punycode_hostname():
    url = "https://xn--pple-43d.com/store"
    res = analyze_url(url)

    assert res.features.is_punycode is True
    assert any(o.rule_id == "RULE_PUNYCODE_HOST" for o in res.observations)


# 10. Unicode hostname
def test_unicode_hostname():
    url = "https://münchen-stadt.de/rathaus"
    res = analyze_url(url)

    assert res.features.has_unicode is True
    assert any(o.rule_id == "RULE_UNICODE_HOST" for o in res.observations)


# 11. Percent-encoding (single and double encoding)
def test_percent_encoding():
    url = "https://example.com/path%20with%20spaces%2ftest"
    res = analyze_url(url)

    assert res.features.percent_encoding_count >= 3
    assert any(o.rule_id == "RULE_HEAVY_PERCENT_ENCODING" for o in res.observations)


def test_double_percent_encoding():
    url = "https://example.com/path%252e%252e/secret"
    res = analyze_url(url)

    assert any(o.rule_id == "RULE_DOUBLE_PERCENT_ENCODING" for o in res.observations)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)


# 12. Query and fragment components
def test_query_and_fragment():
    url = "https://example.com/search?q=test&redirect=https://other.com#top"
    res = analyze_url(url)

    assert res.features.has_query is True
    assert res.features.has_fragment is True
    assert res.features.query_param_count == 2
    assert any(o.rule_id == "RULE_OPEN_REDIRECT_PARAM" for o in res.observations)


def test_email_in_query():
    url = "https://phish-portal.com/login.php?email=target.user@corporate.com"
    res = analyze_url(url)

    assert any(o.rule_id == "RULE_EMAIL_IN_QUERY" for o in res.observations)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)


# 13. Malformed URL
def test_malformed_url():
    url = "   "
    res = analyze_url(url)
    assert res.parse_status == ParseStatus.MALFORMED
    assert any(o.rule_id == "RULE_EMPTY_URL" for o in res.observations)

    url_missing_host = "https:///path/only"
    res2 = analyze_url(url_missing_host)
    assert res2.parse_status == ParseStatus.MALFORMED
    assert any(o.rule_id == "RULE_MISSING_HOSTNAME" for o in res2.observations)


# 14. Unsupported scheme
def test_unsupported_scheme():
    url_js = "javascript:alert(1)"
    res_js = analyze_url(url_js)
    assert res_js.parse_status == ParseStatus.UNSUPPORTED_SCHEME
    assert res_js.features.is_unusual_scheme is True
    assert res_js.heuristic_risk_category == HeuristicRiskCategory.HIGH

    url_data = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    res_data = analyze_url(url_data)
    assert res_data.parse_status == ParseStatus.UNSUPPORTED_SCHEME


# 15. Trailing dot in hostname
def test_trailing_dot():
    url = "https://example.com./welcome"
    res = analyze_url(url)

    assert res.features.has_trailing_dot is True
    assert res.features.normalized_host == "example.com"
    assert any(o.rule_id == "RULE_TRAILING_DOT" for o in res.observations)


# 16. Duplicate URL handling and batch analysis
def test_batch_analysis_and_deduplication():
    urls = [
        "https://example.com/page1",
        "https://example.com/page1",  # exact duplicate
        "http://legit.com@phish-login.com/admin",  # userinfo credential trick (HIGH)
        "http://example.com:8080/",   # non-default port (MEDIUM)
    ]
    batch_res = analyze_urls(urls)

    assert batch_res.total_urls == 4
    assert batch_res.unique_urls == 3
    assert len(batch_res.url_results) == 4
    assert batch_res.highest_risk_category == HeuristicRiskCategory.HIGH
    assert batch_res.risk_breakdown["HIGH"] >= 1


# 18. Missing scheme / relative URL
def test_missing_scheme():
    url = "www.example.com/login"
    res = analyze_url(url)
    assert res.parse_status == ParseStatus.MISSING_SCHEME
    assert any(o.rule_id == "RULE_MISSING_SCHEME" for o in res.observations)


# 19. Localhost hostname
def test_localhost():
    url = "http://localhost:3000/dashboard"
    res = analyze_url(url)
    assert res.features.host_type == HostType.LOCALHOST
    assert res.features.host_classification == HostClassification.LOOPBACK
    assert any(o.rule_id == "RULE_LOCALHOST_HOST" for o in res.observations)


# 20. Email parser ExtractedURL bridge test
def test_email_extracted_urls_bridge():
    extracted = [
        ExtractedURL(url="https://secure.example.com/", scheme="https", domain="secure.example.com", source="both"),
        ExtractedURL(url="http://attacker.com@login.com/", scheme="http", domain="login.com", source="plain_text"),
    ]
    batch_res = analyze_email_extracted_urls(extracted)

    assert batch_res.total_urls == 2
    assert len(batch_res.url_results) == 2
    assert batch_res.url_results[0].features.scheme == "https"


