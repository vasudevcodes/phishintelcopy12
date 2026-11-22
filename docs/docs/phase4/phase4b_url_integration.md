# Phase 4B — URL Intelligence Integration Technical Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 4B — URL Intelligence Integration  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Module Paths**:
- `backend/app/services/email_parser.py`
- `backend/app/services/url_intelligence.py`
- `backend/app/schemas/email.py`
- `backend/app/schemas/url_intelligence.py`
- `backend/app/api/endpoints/email.py`
**Test Paths**:
- `backend/tests/test_url_integration.py` (New: 10 tests)
- `backend/tests/test_url_intelligence.py` (Phase 4A: 23 tests)
- `backend/tests/test_email_parser.py` (Phase 1: 9 tests)
- `backend/tests/test_api.py` (Phase 1: 8 tests)
**Status Verdict**: **`PHASE_4B_INTEGRATION_COMPLETE`**

---

## 1. Executive Summary & Integration Objective

Phase 4B integrates the standalone **Phase 4A URL Intelligence Engine** directly into the active **Phase 1 backend email forensic analysis pipeline**.

Before this phase:
- The Phase 1 email parser extracted URLs from RFC 5322 plaintext and HTML bodies as simple `ExtractedURL` records (`url`, `source`, `occurrences`).
- The Phase 4A URL engine existed as an isolated service capable of deterministic, rule-based forensic analysis.
- The primary API endpoint (`POST /api/v1/email/analyze`) returned parsed email structure, headers, attachments, and raw URL strings, but no structural URL risk evidence.

After Phase 4B:
- An uploaded `.eml` file is parsed once by the RFC 5322 forensic parser.
- Deduplicated extracted URLs are passed directly into the URL Intelligence Engine.
- The origin source (`plain_text`, `html_href`, `both`) is preserved for each analyzed URL.
- The existing API response contract is extended in a strictly backward-compatible manner by appending a structured `url_analysis` section (`URLBatchAnalysisResult`).
- Zero machine learning retraining, zero evidence fusion, zero DNS queries, and zero outbound network traffic occur.

---

## 2. Execution Flow Architecture

```
                  Client Upload (.eml file)
                            │
                            ▼
           POST /api/v1/email/analyze
                            │
                 [Validate Extension & Size]
                 [Max 10MB, non-empty, .eml]
                            │
                            ▼
             email_parser.parse_email_message()
       ┌────────────────────┴────────────────────┐
       ▼                                         ▼
RFC 5322 Header & Body Extraction         Attachment & Hop IP Extraction
       │
       ▼
Extracted URLs Collection (Deduplicated)
(url, source: 'plain_text' | 'html_href' | 'both', occurrences)
       │
       ▼
url_intelligence.analyze_email_extracted_urls()  <--- [Wrapped in non-fatal try/except]
       ├── RFC 3986 Lexical & Syntactic Parsing
       ├── Authority & Hostname Normalization (IDN / Punycode / Userinfo / Dots)
       ├── IP-Literal Detection (Public vs Private vs Loopback)
       ├── Structural Feature Extraction (Lengths, Subdomains, Delimiters, Tokens)
       ├── Deterministic Rule Observation Engine (INFO / LOW / MEDIUM / HIGH)
       └── Transparent Heuristic Risk Scoring (0–100 integer score)
       │
       ▼
URLBatchAnalysisResult
       │
       ▼
EmailAnalysisResponse
├── Existing Phase 1 Fields (headers, body, urls, attachments, ip_candidates)
└── url_analysis (Phase 4B URLBatchAnalysisResult)
```

---

## 3. API Contract & Backward Compatibility

### 3.1 Endpoint Specification
- **Method**: `POST`
- **Route**: `/api/v1/email/analyze`
- **Content-Type**: `multipart/form-data`
- **Upload Constraints**:
  - Exactly one file field named `file`.
  - Extension must end in `.eml` (case-insensitive).
  - Maximum upload size: 10 MB (`10 * 1024 * 1024` bytes).
  - Empty files (0 bytes) rejected with HTTP 400.

### 3.2 Backward Compatibility Analysis
- **Zero Breaking Changes**: All existing top-level fields of `EmailAnalysisResponse` remain unchanged in name, type, and semantic structure:
  - `filename`: `str`
  - `file_size_bytes`: `int`
  - `file_hash_sha256`: `str`
  - `parsing_status`: `str` (`"success"`, `"partial_success"`, `"error"`)
  - `headers`: `EmailHeaders`
  - `body`: `EmailBody`
  - `urls`: `List[ExtractedURL]`
  - `attachments`: `List[EmailAttachment]`
  - `ip_candidates`: `List[ReceivedIPCandidate]`
  - `warnings`: `List[str]`
  - `errors`: `List[str]`
  - `parsed_at`: `str`
- **Extension**: A single optional field is appended:
  - `url_analysis`: `Optional[URLBatchAnalysisResult] = None`
- Existing clients consuming the Phase 1 schema ignore the new field or continue parsing without breakage.

### 3.3 Synthetic API Request & Response Example

#### Request:
```http
POST /api/v1/email/analyze HTTP/1.1
Host: localhost:8000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX7MA4YWxkTrZu0gW

------WebKitFormBoundaryX7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="synthetic_invoice_notice.eml"
Content-Type: message/rfc822

From: billing@synthetic-finance-notice.com
To: victim@example-corp.com
Subject: Urgent: Unpaid Invoice Notice
Date: Mon, 12 Oct 2026 10:00:00 +0000
Message-ID: <synthetic-001@synthetic-finance-notice.com>
Content-Type: text/html; charset="utf-8"

<p>Your invoice is overdue. Please review immediately:</p>
<p><a href="http://192.168.1.50:8080/portal/login?id=4981#auth">Access Account Portal</a></p>
<p>Alternative link: <a href="https://legit-brand.com@evil-phish-domain.com/secure">Confirm Credentials</a></p>
------WebKitFormBoundaryX7MA4YWxkTrZu0gW--
```

#### Response (HTTP 200 OK):
```json
{
  "filename": "synthetic_invoice_notice.eml",
  "file_size_bytes": 624,
  "file_hash_sha256": "4b68ef5c88e5e6e8e0407186178a9947d413340026a760fef77002b851dfd3eb",
  "parsing_status": "success",
  "headers": {
    "from_header": "billing@synthetic-finance-notice.com",
    "to_headers": ["victim@example-corp.com"],
    "cc_headers": [],
    "bcc_headers": [],
    "subject": "Urgent: Unpaid Invoice Notice",
    "date_header": "Mon, 12 Oct 2026 10:00:00 +0000",
    "message_id": "<synthetic-001@synthetic-finance-notice.com>",
    "reply_to": null,
    "return_path": null,
    "received_headers": [],
    "spf_headers": [],
    "dkim_signatures": [],
    "dmarc_headers": []
  },
  "body": {
    "has_plain_text": false,
    "has_html": true,
    "plain_text_content": null,
    "html_content": "<p>Your invoice is overdue. Please review immediately:</p>\n<p><a href=\"http://192.168.1.50:8080/portal/login?id=4981#auth\">Access Account Portal</a></p>\n<p>Alternative link: <a href=\"https://legit-brand.com@evil-phish-domain.com/secure\">Confirm Credentials</a></p>",
    "body_char_count": 274,
    "extracted_urls_count": 2
  },
  "urls": [
    {
      "url": "http://192.168.1.50:8080/portal/login?id=4981#auth",
      "source": "html_href",
      "occurrences": 1
    },
    {
      "url": "https://legit-brand.com@evil-phish-domain.com/secure",
      "source": "html_href",
      "occurrences": 1
    }
  ],
  "attachments": [],
  "ip_candidates": [],
  "url_analysis": {
    "total_urls": 2,
    "unique_urls": 2,
    "highest_risk_category": "HIGH",
    "risk_breakdown": {
      "INFO": 0,
      "LOW": 0,
      "MEDIUM": 0,
      "HIGH": 2
    },
    "url_results": [
      {
        "url_index": 0,
        "original_url": "http://192.168.1.50:8080/portal/login?id=4981#auth",
        "normalized_hostname": "192.168.1.50",
        "parse_status": "parsed",
        "source": "html_href",
        "features": {
          "scheme": "http",
          "is_https": false,
          "hostname": "192.168.1.50",
          "port": 8080,
          "has_non_standard_port": true,
          "is_ip_literal": true,
          "ip_version": 4,
          "ip_classification": "private",
          "is_punycode": false,
          "is_fqdn_valid": false,
          "has_userinfo": false,
          "subdomain_count": 0,
          "path_depth": 2,
          "query_param_count": 1,
          "has_fragment": true,
          "url_length": 50,
          "hostname_length": 12,
          "path_length": 13,
          "query_length": 7,
          "hex_encoded_char_count": 0,
          "hyphen_count_hostname": 0,
          "at_symbol_count": 0,
          "double_slash_in_path": false
        },
        "observations": [
          {
            "rule_id": "RULE_CLEAR_TEXT_HTTP",
            "severity": "LOW",
            "title": "Cleartext HTTP Scheme",
            "description": "URL transmits data without TLS encryption.",
            "score_impact": 10
          },
          {
            "rule_id": "RULE_NON_STANDARD_PORT",
            "severity": "MEDIUM",
            "title": "Non-Standard Port Explicitly Defined",
            "description": "Port 8080 specified instead of standard HTTP (80) or HTTPS (443).",
            "score_impact": 20
          },
          {
            "rule_id": "RULE_IP_LITERAL_HOST",
            "severity": "HIGH",
            "title": "IP Literal Used as Hostname",
            "description": "Destination address is direct private IPv4 literal (192.168.1.50) bypassing DNS hierarchy.",
            "score_impact": 35
          }
        ],
        "heuristic_risk_score": 65,
        "heuristic_risk_category": "HIGH",
        "risk_summary": "High heuristic risk: 3 observation(s) recorded."
      },
      {
        "url_index": 1,
        "original_url": "https://legit-brand.com@evil-phish-domain.com/secure",
        "normalized_hostname": "evil-phish-domain.com",
        "parse_status": "parsed",
        "source": "html_href",
        "features": {
          "scheme": "https",
          "is_https": true,
          "hostname": "evil-phish-domain.com",
          "port": null,
          "has_non_standard_port": false,
          "is_ip_literal": false,
          "ip_version": null,
          "ip_classification": null,
          "is_punycode": false,
          "is_fqdn_valid": true,
          "has_userinfo": true,
          "subdomain_count": 0,
          "path_depth": 1,
          "query_param_count": 0,
          "has_fragment": false,
          "url_length": 51,
          "hostname_length": 21,
          "path_length": 7,
          "query_length": 0,
          "hex_encoded_char_count": 0,
          "hyphen_count_hostname": 2,
          "at_symbol_count": 1,
          "double_slash_in_path": false
        },
        "observations": [
          {
            "rule_id": "RULE_USERINFO_AUTH_TRICK",
            "severity": "HIGH",
            "title": "Credentials / Deceptive Brand Embedded in Userinfo Authority",
            "description": "URL contains '@' userinfo authority component, disguising actual target destination.",
            "score_impact": 40
          }
        ],
        "heuristic_risk_score": 40,
        "heuristic_risk_category": "HIGH",
        "risk_summary": "High heuristic risk: 1 observation(s) recorded."
      }
    ]
  },
  "warnings": [],
  "errors": [],
  "parsed_at": "2026-10-12T10:00:01.123456"
}
```

---

## 4. Error Handling & Edge Case Resilience

The integration was designed defensively to guarantee that email analysis never fails due to URL parsing edge cases:

| Edge Case | Engine Behavior | Impact on Response |
| :--- | :--- | :--- |
| **Email with zero URLs** | `urls` is empty list `[]`. `analyze_email_extracted_urls` returns batch with `total_urls=0`, `url_results=[]`, `highest_risk_category="INFO"`. | Request returns HTTP 200 with clean empty analysis structure. Never raises null pointer or index error. |
| **Email with duplicate URLs** | Deduplicated at parser extraction stage. Single URL evaluated once, tracking cumulative source (`"both"` if in plain text and HTML). | Single analysis entry returned with combined metadata. |
| **Malformed URL (e.g. `https:///missing-host`)** | `analyze_url` marks `parse_status="malformed"`, attaches `RULE_MISSING_HOST` / `RULE_MALFORMED_URL` observation, score 30 (`MEDIUM`). | Analysis completes safely without crashing request. |
| **Dangerous / script schemes (`javascript:`, `data:`)** | Flagged as `RULE_DANGEROUS_SCHEME` (`HIGH` severity, +40 score). Host set to empty string. | Safely cataloged without code execution. |
| **Missing optional metadata** | Handled with Pydantic default fields (`None` or empty lists). | Serializes safely into schema. |
| **Unexpected URL Engine Exception** | Trapped by top-level `try...except Exception as url_err` in `email_parser.py`. Warning appended to `warnings`, `parsing_status` set to `"partial_success"`, `url_analysis` set to `None`. | Email parsing succeeds; valid headers, bodies, attachments, and IPs are returned intact to the caller. |

---

## 5. Network Safety Guarantees

Phase 4B enforces strict zero network execution. The integration is mathematically and functionally isolated from network I/O:

1. **No External DNS Resolutions**: Hostnames and domains are evaluated purely via syntax, character sets, and regular expressions. No `socket.getaddrinfo`, `socket.gethostbyname`, or DNS queries are invoked.
2. **No HTTP Requests or Page Fetching**: The engine never fetches target pages, follows HTTP redirects, or triggers tracking web beacons.
3. **No External Reputation Services**: No third-party APIs (VirusTotal, Google Safe Browsing, etc.) are queried.
4. **Programmatic Network Neutralization in Test Suite**:
   In `backend/tests/test_url_integration.py`, an autouse Pytest fixture intercepts `socket.socket.connect`, `socket.getaddrinfo`, and `socket.gethostbyname`. Any attempt to connect to external hosts or query external DNS immediately raises a `RuntimeError`, guaranteeing test failure if network calls are attempted.

---

## 6. Complete Test Execution & Results

### 6.1 Test Suite Breakdown
The complete backend test suite was executed via `D:\python\python.exe -m pytest backend/tests`:

```
backend/tests/test_api.py .............. [ 8 tests passed ]
backend/tests/test_email_parser.py ..... [ 9 tests passed ]
backend/tests/test_url_integration.py .. [ 10 tests passed ]
backend/tests/test_url_intelligence.py . [ 23 tests passed ]
------------------------------------------------------------
Total: 50 passed, 0 failed, 0 skipped in 0.91 seconds
```

### 6.2 Focused Integration Tests (`test_url_integration.py`)
1. `test_api_integration_multiple_urls`: Uploads multi-URL `.eml`, verifies all 4 distinct URLs are extracted, analyzed, and populated in `url_analysis`.
2. `test_api_integration_no_urls`: Uploads zero-URL plaintext `.eml`, verifies empty analysis collection without crash.
3. `test_api_integration_single_valid_url`: Uploads single-URL `.eml`, verifies correct extraction, hostname normalization, and heuristic score.
4. `test_api_integration_duplicate_urls_in_eml`: Uploads email with identical links in text and HTML, verifies deduplication.
5. `test_api_integration_malformed_url_in_eml`: Uploads email with malformed link (`https:///missing-host/path`), verifies `parse_status="malformed"` and graceful analysis.
6. `test_api_integration_unsupported_scheme_in_eml`: Uploads mixed deceptive userinfo link, verifies `RULE_USERINFO_AUTH_TRICK` triggering and `HIGH` severity.
7. `test_api_integration_multipart_html_and_plaintext`: Uploads multipart email, verifies both bodies and URL intelligence parse cleanly.
8. `test_api_integration_heuristic_score_serialization`: Verifies integer bounds `[0, 100]`, category enum strings, and absence of probability percentages.
9. `test_api_integration_upload_constraints_intact`: Verifies rejection of `.pdf` files (400), empty files (400), and oversized >10MB files (413).
10. `test_api_integration_graceful_url_engine_failure`: Monkeypatches URL engine failure, verifies parser returns HTTP 200 with `partial_success` and non-fatal warning without crashing.

---

## 7. Modified & Created Files

| File Path | Action | Description & Rationale |
| :--- | :--- | :--- |
| `backend/app/schemas/url_intelligence.py` | Modified | Added optional `source: Optional[str] = Field(None)` to `URLAnalysisResult` to track extraction origin (`plain_text`, `html_href`, `both`). |
| `backend/app/schemas/email.py` | Modified | Imported `URLBatchAnalysisResult` and added optional field `url_analysis: Optional[URLBatchAnalysisResult] = None` to `EmailAnalysisResponse`. |
| `backend/app/services/url_intelligence.py` | Modified | Updated `analyze_url()` and `analyze_email_extracted_urls()` to accept and preserve the `source` field. |
| `backend/app/services/email_parser.py` | Modified | Invoked `analyze_email_extracted_urls()` within `parse_email_message()` under non-fatal exception handling, populating `url_analysis`. |
| `backend/tests/test_url_integration.py` | Created | 10 end-to-end integration tests verifying endpoint upload, URL intelligence output, edge cases, and socket isolation. |
| `docs/phase4/phase4b_url_integration.md` | Created | Comprehensive Phase 4B integration technical report (this document). |

---

## 8. Protected Artifact Verification

To strictly guarantee non-interference with completed phases, SHA-256 cryptographic hashes of all protected datasets and saved model checkpoints were re-verified:

| Protected Artifact Path | Expected SHA-256 Hash | Verified Match |
| :--- | :--- | :---: |
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH (True)** |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH (True)** |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH (True)** |
| `data/processed/phishmmf/cleaned_email_dataset.csv` | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | **MATCH (True)** |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH (True)** |

---

## 9. Remaining Limitations & Boundary Declarations

1. **Standalone Heuristic Scope**: The URL heuristic scores (0–100) are explainable syntactic and lexical risk indicators, not posterior probabilities. They are not combined with DistilBERT NLP probabilities in this phase.
2. **No External Redirection Following**: In compliance with zero network execution and safety constraints, URL shorteners (e.g., `bit.ly`) are flagged for high risk but are not unshortened via live HTTP HEAD requests.
3. **Phases 5, 6, and 7 Deferred**: Cryptographic authentication (SPF/DKIM/DMARC in Phase 5), IP geolocation / ASN intelligence (Phase 6), and multi-modal evidence fusion (Phase 7) remain distinct and unexecuted.

---

## 10. Final Verification & Status

- [x] Existing API tests pass (`backend/tests/test_api.py`: 8/8 passed).
- [x] Phase 1 parser tests pass (`backend/tests/test_email_parser.py`: 9/9 passed).
- [x] Phase 4A URL tests pass (`backend/tests/test_url_intelligence.py`: 23/23 passed).
- [x] New integration tests pass (`backend/tests/test_url_integration.py`: 10/10 passed).
- [x] Total test suite passes: **50/50 tests passed (100%)**.
- [x] Protected dataset hashes remain bit-identical.
- [x] Saved DistilBERT model checkpoint remains bit-identical.
- [x] Zero network requests were made during URL analysis or testing.

**FINAL STATUS: `PHASE_4B_INTEGRATION_COMPLETE`**
