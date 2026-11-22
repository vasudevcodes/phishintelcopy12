"""
Targeted Regression Test Suite: URL Extraction Source Policy and Cleanup.
Validates RFC 5322 and HTML body URL harvesting against strict source policies:
- Genuine HTML anchor hyperlinks (<a href>) included.
- Genuine plain-text URLs included.
- Image src, tracking pixels, stylesheet, script, and XML namespace URLs excluded.
- Placeholder links (href="#", javascript:, mailto:, tel:) excluded.
- Deduplication and same-host multi-path preservation verified.
- Strict isolation across consecutive email analyses verified.
"""

from pathlib import Path
import pytest
from app.services.email_parser import extract_urls, parse_email_message

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_plain_text_urls_extracted():
    plain = "Please review the security bulletin at https://security.example.com/advisory/2026-01 for details."
    results = extract_urls(plain_text=plain, html_content=None)
    assert len(results) == 1
    assert results[0].url == "https://security.example.com/advisory/2026-01"
    assert results[0].domain == "security.example.com"
    assert results[0].source == "plain_text"


def test_html_anchor_links_with_anchor_text():
    html = """
    <html>
      <body>
        <p>Click <a href="https://portal.bank.example.com/auth/login">here to verify your account</a> immediately.</p>
      </body>
    </html>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://portal.bank.example.com/auth/login"
    assert results[0].domain == "portal.bank.example.com"
    assert results[0].source == "html_href"
    assert results[0].anchor_text == "here to verify your account"


def test_plain_and_html_combined_not_double_counted():
    plain = "Login at https://service.example.org/portal or contact support."
    html = """
    <div>
      <a href="https://service.example.org/portal">Access Portal</a>
    </div>
    """
    results = extract_urls(plain_text=plain, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://service.example.org/portal"
    assert results[0].source == "both"
    assert results[0].anchor_text == "Access Portal"


def test_duplicate_anchor_links_deduplicated():
    html = """
    <div>
      <a href="https://example.com/unsubscribe">Unsubscribe</a>
      <p>Some text</p>
      <a href="https://example.com/unsubscribe">Click here to unsubscribe</a>
    </div>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://example.com/unsubscribe"


def test_same_hostname_distinct_paths_preserved():
    html = """
    <div>
      <a href="https://corp.example.com/inbox">Inbox</a>
      <a href="https://corp.example.com/settings">Settings</a>
      <a href="https://corp.example.com/logout">Logout</a>
    </div>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 3
    urls = {u.url for u in results}
    assert "https://corp.example.com/inbox" in urls
    assert "https://corp.example.com/settings" in urls
    assert "https://corp.example.com/logout" in urls


def test_image_src_and_tracking_pixels_excluded():
    html = """
    <html>
      <head>
        <link rel="stylesheet" href="https://cdn.example.com/assets/styles.css" />
        <script src="https://cdn.example.com/tracker.js"></script>
      </head>
      <body>
        <img src="https://cdn.example.com/images/logo.png" alt="Logo" />
        <img src="https://mail-tracker.analytics.net/open.gif?user=123" width="1" height="1" />
        <p>Visit our genuine <a href="https://actual-link.com/home">Website</a></p>
      </body>
    </html>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://actual-link.com/home"


def test_xml_namespaces_and_dtds_excluded():
    html = """
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <body>
        <a href="https://news.example.com/article">Read News</a>
      </body>
    </html>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://news.example.com/article"


def test_html_entity_ampersand_normalized():
    html = '<a href="https://store.example.com/item?id=100&amp;cat=books&amp;ref=email">Buy Book</a>'
    plain = "https://store.example.com/item?id=100&cat=books&ref=email"
    results = extract_urls(plain_text=plain, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://store.example.com/item?id=100&cat=books&ref=email"
    assert results[0].source == "both"


def test_trailing_punctuation_stripped():
    plain = "Visit https://alpha.example.com/test. Also check https://beta.example.com/docs, and (https://gamma.example.com/info)."
    results = extract_urls(plain_text=plain, html_content=None)
    urls = {u.url for u in results}
    assert "https://alpha.example.com/test" in urls
    assert "https://beta.example.com/docs" in urls
    assert "https://gamma.example.com/info" in urls


def test_legitimate_tracking_redirects_preserved():
    html = """
    <div>
      <a href="https://click.marketing.net/r?dest=login&user=1">Login</a>
      <a href="https://click.marketing.net/r?dest=privacy&user=1">Privacy</a>
    </div>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 2
    urls = {u.url for u in results}
    assert "https://click.marketing.net/r?dest=login&user=1" in urls
    assert "https://click.marketing.net/r?dest=privacy&user=1" in urls


def test_placeholder_and_non_http_links_excluded():
    """
    Excludes href="#", javascript:, mailto:, tel:, and empty links.
    """
    html = """
    <div>
      <a href="#">Top of Page</a>
      <a href="#section2">Jump to Section</a>
      <a href="javascript:void(0)">Do Nothing</a>
      <a href="mailto:support@company.com">Email Us</a>
      <a href="tel:+18005550199">Call Support</a>
      <a href="">Empty Link</a>
      <a href="https://actual-destination.com/help">Help Center</a>
    </div>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 1
    assert results[0].url == "https://actual-destination.com/help"


# --- Validation Scenario Tests (Required Cases 1 - 8 + Newsletter) ---


def test_validation_case_1_one_hyperlink():
    """1. Email containing exactly one hyperlink."""
    plain = "Please check your statement: https://banking.example.com/statement"
    results = extract_urls(plain_text=plain, html_content=None)
    assert len(results) == 1
    assert results[0].url == "https://banking.example.com/statement"


def test_validation_case_2_several_hyperlinks():
    """2. Email containing several hyperlinks across different sections."""
    html = """
    <html>
      <body>
        <p><a href="https://service.com/dashboard">Dashboard</a></p>
        <p><a href="https://service.com/invoices">Invoices</a></p>
        <p><a href="https://service.com/profile">Profile</a></p>
        <p><a href="https://docs.service.com/api">API Reference</a></p>
      </body>
    </html>
    """
    results = extract_urls(plain_text=None, html_content=html)
    assert len(results) == 4
    urls = {u.url for u in results}
    assert "https://service.com/dashboard" in urls
    assert "https://service.com/invoices" in urls
    assert "https://service.com/profile" in urls
    assert "https://docs.service.com/api" in urls


def test_validation_case_3_no_hyperlinks():
    """3. Email containing no hyperlinks (clean plain text or body)."""
    with open(FIXTURES_DIR / "01_simple_plaintext.eml", "rb") as f:
        response = parse_email_message(f.read(), "01_simple_plaintext.eml")
    assert len(response.urls) == 0
    assert response.url_analysis is not None
    assert response.url_analysis.total_urls == 0
    assert response.url_analysis.unique_urls == 0
    assert len(response.url_analysis.url_results) == 0


def test_validation_case_4_images_and_tracking_pixels():
    """4. Email containing images and tracking pixels without clickable links."""
    html = """
    <html>
      <body>
        <img src="https://branding.cdn.net/logo.png" />
        <img src="https://tracker.email.com/pixel.gif?uid=998877" width="1" height="1" />
        <p>No links here, just plain text informing you of maintenance.</p>
      </body>
    </html>
    """
    results = extract_urls(plain_text="No links here, just plain text informing you of maintenance.", html_content=html)
    assert len(results) == 0


def test_validation_case_5_html_and_plaintext_same_links():
    """5. Email containing HTML and plain-text versions of the same links."""
    plain = "Visit https://app.example.com/welcome and https://app.example.com/terms"
    html = """
    <div>
      <a href="https://app.example.com/welcome">Welcome</a>
      <a href="https://app.example.com/terms">Terms of Service</a>
    </div>
    """
    results = extract_urls(plain_text=plain, html_content=html)
    assert len(results) == 2
    for u in results:
        assert u.source == "both"


def test_validation_case_6_consecutive_email_analyses_isolated():
    """6. Two different emails analyzed consecutively — verifies zero URL leakage."""
    with open(FIXTURES_DIR / "03_multipart_plain_html.eml", "rb") as f:
        res1 = parse_email_message(f.read(), "03_multipart_plain_html.eml")

    with open(FIXTURES_DIR / "sample-1.eml", "rb") as f:
        res2 = parse_email_message(f.read(), "sample-1.eml")

    with open(FIXTURES_DIR / "01_simple_plaintext.eml", "rb") as f:
        res3 = parse_email_message(f.read(), "01_simple_plaintext.eml")

    # Email 1 has 2 newsletter links
    assert len(res1.urls) == 2
    res1_urls = {u.url for u in res1.urls}
    assert "https://updates.tech/articles/ai-security" in res1_urls
    assert "https://updates.tech/unsubscribe?id=sub123" in res1_urls

    # Email 2 has exactly 1 phishing link
    assert len(res2.urls) == 1
    assert res2.urls[0].url == "https://blog1seguimentmydomaine2bra.me/"

    # Email 3 has zero links
    assert len(res3.urls) == 0

    # Ensure no cross-contamination between any of the runs
    assert not any("updates.tech" in u.url for u in res2.urls)
    assert not any("blog1seguimentmydomaine2bra.me" in u.url for u in res1.urls)


def test_validation_case_7_phishing_email_with_malicious_links():
    """7. A phishing email with malicious links (sample-1.eml and sample-10.eml)."""
    with open(FIXTURES_DIR / "sample-1.eml", "rb") as f:
        res = parse_email_message(f.read(), "sample-1.eml")
    assert len(res.urls) == 1
    assert "blog1seguimentmydomaine2bra.me" in res.urls[0].url
    assert res.urls[0].source == "html_href"


def test_validation_case_8_legitimate_email_with_legitimate_links():
    """8. A legitimate email with legitimate links (google_notification.eml)."""
    with open(FIXTURES_DIR / "google_notification.eml", "rb") as f:
        res = parse_email_message(f.read(), "google_notification.eml")
    assert len(res.urls) == 2
    urls = {u.url for u in res.urls}
    assert "https://support.google.com/youtube?p=advanced_features5" in urls
    assert "https://support.google.com/accounts?p=verification-data-deletion" in urls
    # Images (gstatic logo, user avatar) excluded
    assert not any("gstatic.com" in u.url for u in res.urls)
    assert not any("googleusercontent.com" in u.url for u in res.urls)


def test_supplied_newsletter_fixture_not_arbitrarily_limited():
    """
    Validates that the supplied Tech Digest newsletter fixture (03_multipart_plain_html.eml)
    extracts all its genuine hyperlinks without arbitrary limits or double-counting.
    """
    with open(FIXTURES_DIR / "03_multipart_plain_html.eml", "rb") as f:
        res = parse_email_message(f.read(), "03_multipart_plain_html.eml")

    assert len(res.urls) == 2
    urls = {u.url: u for u in res.urls}
    assert "https://updates.tech/articles/ai-security" in urls
    assert urls["https://updates.tech/articles/ai-security"].source == "both"
    assert urls["https://updates.tech/articles/ai-security"].anchor_text == "AI Security Review"

    assert "https://updates.tech/unsubscribe?id=sub123" in urls
    assert urls["https://updates.tech/unsubscribe?id=sub123"].source == "both"
    assert urls["https://updates.tech/unsubscribe?id=sub123"].anchor_text == "Click here to unsubscribe"
