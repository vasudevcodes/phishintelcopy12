# Phase 4A — URL Intelligence Engine Technical Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 4A — URL Intelligence Engine  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Module Path**: `backend/app/services/url_intelligence.py`  
**Schema Path**: `backend/app/schemas/url_intelligence.py`  
**Test Path**: `backend/tests/test_url_intelligence.py`  
**Status Verdict**: **`PHASE_4A_URL_ENGINE_COMPLETE`**

---

## 1. Executive Summary & Objective

Phase 4A designs, implements, and certifies the **PhishIntel URL Intelligence Engine**. This module provides a deterministic, explainable, and local analysis pipeline for all URLs extracted by the Phase 1 email parser.

### Key Operational Guarantees
- **Zero Network Execution**: The module performs strictly local syntactic, structural, and lexical analysis using Python standard library modules (`urllib.parse`, `ipaddress`, `re`, `unicodedata`). **Zero HTTP requests, zero DNS resolutions, zero external reputation queries, and zero socket calls were made.** Network access is programmatically blocked and verified in tests.
- **Explainable Rule-Based Architecture**: Rather than outputting uncalibrated, black-box confidence scores (e.g., "97% phishing"), the engine produces transparent, rule-by-rule observations mapped to four standardized severity tiers: `INFO`, `LOW`, `MEDIUM`, and `HIGH`.
- **Full Backward Compatibility**: The existing Phase 1 RFC 5322 parser (`email_parser.py`) and API schemas remain 100% functional and unmodified. The URL engine seamlessly consumes `ExtractedURL` objects or raw URL strings via a non-breaking service bridge.
- **Comprehensive Test Coverage**: All 40 unit tests in the backend test suite passed with 100% success (including 23 dedicated URL intelligence tests covering 16+ edge cases under active socket neutralization).

---

## 2. Architecture & Design Principles

```
Email Text / HTML
       │
       ▼
Phase 1 Forensic Parser (email_parser.py)
       │
       ▼
ExtractedURL Objects (Deduplicated)
       │
       ▼
Phase 4A URL Intelligence Engine (url_intelligence.py)
   ├── 1. RFC 3986 Lexical & Syntactic Parsing (urllib.parse)
   ├── 2. Authority & Hostname Normalization (IDN / Punycode / Userinfo / FQDN dots)
   ├── 3. IP-Literal Detection & Classification (ipaddress: Public vs Private vs Loopback)
   ├── 4. Structural Feature Extraction (Lengths, Subdomains, Delimiters, Encodings)
   ├── 5. Deterministic Rule Observation Engine (INFO / LOW / MEDIUM / HIGH)
   └── 6. Explainable Heuristic Risk Scoring (0–100 Transparent Indicator)
       │
       ▼
URLAnalysisResult / URLBatchAnalysisResult (Pydantic Models)
```

### Safety & Privacy Boundaries
1. **No Network Probing**: URLs in phishing emails frequently contain unique tracking tokens or canary hashes. Attempting to resolve DNS or fetch HTTP content alerts the threat actor that the email was opened and risks triggering drive-by downloads. Phase 4A operates completely offline.
2. **Credential & Privacy Protection**: Sensitive query parameters and user-info components (e.g. `user:password@host` or `?token=XYZ`) are neutralized during hostname extraction and are never dumped to log files.
3. **No Allowlist Complacency**: The engine does not hardcode commercial domain allowlists (e.g. marking `microsoft.com` or `google.com` as unconditionally safe), preventing open-redirect and subdomain abuse evasion.

---

## 3. URL Features Implemented

The engine extracts 18 granular, deterministic features for each analyzed URL, structured in the `URLFeatures` Pydantic model:

| # | Feature Field | Data Type | Extraction Mechanism & Semantic Purpose |
| :- | :--- | :--- | :--- |
| 1 | `scheme` | `Optional[str]` | Protocol extracted via `urlsplit` (e.g., `http`, `https`, `data`, `javascript`). |
| 2 | `is_https` / `is_http` | `bool` | Protocol encryption status. |
| 3 | `is_unusual_scheme` | `bool` | Flags script-capable or non-standard schemes (`javascript:`, `data:`, `file:`). |
| 4 | `normalized_host` | `Optional[str]` | Lowercase hostname with trailing root dot stripped and userinfo isolated. |
| 5 | `host_type` | `HostType` | Classified as `domain`, `ipv4`, `ipv6`, `localhost`, or `invalid`. |
| 6 | `is_ip_literal` | `bool` | Whether the hostname is a direct IP address literal. |
| 7 | `ip_version` | `Optional[int]` | Identifies IP version (4 or 6) via `ipaddress.ip_address`. |
| 8 | `host_classification` | `HostClassification` | Evaluates IP scope: `public`, `private` (RFC 1918), `loopback`, `link_local`, or `reserved`. |
| 9 | `url_length` | `int` | Total character count of the full URL string. |
| 10 | `host_length` | `int` | Total character count of the normalized hostname. |
| 11 | `subdomain_count` | `int` | Number of subdomains preceding the registrable second-level domain. |
| 12 | `dots_in_host` / `dots_in_url` | `int` | Count of dot characters in hostname and entire URL. |
| 13 | `hyphens_in_host` / `hyphens_in_url` | `int` | Count of hyphen characters in hostname and entire URL. |
| 14 | `has_userinfo` | `bool` | Detects `@` inside authority, indicating userinfo browser-navigation spoofing. |
| 15 | `port` / `is_non_default_port` | `int`, `bool` | Extracts explicit port and validates against standard port mappings (e.g. 80, 443). |
| 16 | `percent_encoding_count` | `int` | Counts `%XX` hexadecimal escape sequences in URL. |
| 17 | `is_punycode` / `has_unicode` | `bool` | Identifies `xn--` Punycode labels and non-ASCII Unicode characters (IDN homoglyphs). |
| 18 | `has_path` / `has_query` / `has_fragment` | `bool` | Tracks structural presence of non-root path, query parameters, and fragments. |

---

## 4. Rule Definitions, Severity Tiers, and Heuristic Scoring

### 4.1 Explainable Rule Catalog

The rule engine evaluates extracted features against explicit security heuristics. Each rule yields an explainable `URLObservation`:

| Rule ID | Severity | Rule Name | Trigger Condition | Security Rationale |
| :--- | :---: | :--- | :--- | :--- |
| `RULE_HTTPS_STANDARD` | `INFO` | Standard HTTPS Protocol | `scheme == 'https'` | Confirms encrypted transport. |
| `RULE_NON_ROOT_PATH` | `INFO` | Non-Root Path Present | `path not in ('', '/')` | Indicates navigation to a specific sub-resource or script. |
| `RULE_QUERY_PARAMETERS` | `INFO` | Query Parameters Present | `query != ''` | Documents parameter passing. |
| `RULE_FRAGMENT_PRESENT` | `INFO` | Fragment Identifier Present | `fragment != ''` | Identifies client-side section navigation. |
| `RULE_TRAILING_DOT` | `INFO` | Trailing Root Dot | Hostname ends in `.` | Valid DNS FQDN syntax, unusual in conversational email links. |
| `RULE_HTTP_UNENCRYPTED` | `LOW` | Unencrypted HTTP | `scheme == 'http'` | Transport is unencrypted; vulnerable to eavesdropping and manipulation. |
| `RULE_MISSING_SCHEME` | `LOW` | Missing Protocol Scheme | `scheme is None` | Incomplete or relative URL string. |
| `RULE_LONG_URL` | `LOW` | Long URL Length | $120 < \text{len} \le 200$ | Extended length typical of tracking or redirection links. |
| `RULE_HYPHENATED_HOST` | `LOW` | Multiple Hyphens in Host | $\ge 2$ hyphens in host | Frequent in lookalike or brand-impersonation domain registrations. |
| `RULE_OPEN_REDIRECT_PARAM` | `LOW` | Potential Redirect Param | Query key in redirect set | Presence of `redirect=`, `url=`, `next=` suggesting potential open redirection. |
| `RULE_PUBLIC_IP_HOST` | `MEDIUM` | Public IP-Literal Host | Host is a public IP | Phishing sites frequently host credential lures directly on raw IPs to evade domain reputation. |
| `RULE_NON_DEFAULT_PORT` | `MEDIUM` | Non-Default Explicit Port | Port differs from scheme default | Non-standard port (e.g. `:8080`, `:8443`) often denotes disposable attack servers. |
| `RULE_PUNYCODE_HOST` | `MEDIUM` | Punycode / IDN Hostname | Label begins with `xn--` | Potential IDN homograph visual spoofing imitating legitimate brands. |
| `RULE_UNICODE_HOST` | `MEDIUM` | Non-ASCII Unicode in Host | Host contains non-ASCII | Visual character ambiguity and homoglyph vulnerability. |
| `RULE_DEEP_SUBDOMAINS` | `MEDIUM` | Deep Subdomain Hierarchy | $\ge 4$ subdomains | Complex sub-delegation frequently used in bulletproof hosting. |
| `RULE_EMAIL_IN_QUERY` | `MEDIUM` | Email Address in Query | Email regex in query | Pre-filled recipient addresses indicate targeted credential harvesting. |
| `RULE_DOUBLE_PERCENT_ENCODING` | `MEDIUM` | Double Percent-Encoding | Regex `%25[0-9a-fA-F]{2}` | Obfuscation technique designed to bypass naive security filters. |
| `RULE_EXCESSIVE_URL_LENGTH` | `MEDIUM` | Excessive URL Length | $\text{len} > 200$ characters | Exceptionally long URL strings used to hide payload structures. |
| `RULE_LOOPBACK_HOST` | `MEDIUM` | Loopback Destination | Host is loopback / localhost | Targets local interface (`127.0.0.1`, `localhost`). |
| `RULE_USERINFO_AUTH` | `HIGH` | Authority User-Info Deception | `@` present in authority | Major browser spoofing lure: everything before `@` is ignored; browser navigates to domain after `@`. |
| `RULE_PRIVATE_IP_HOST` | `HIGH` | Private / Intranet IP Host | Host in RFC 1918 range | Links targeting internal IP space (`192.168.x.x`, `10.x.x.x`) suggest intranet reconnaissance or SSRF. |
| `RULE_RESERVED_IP_HOST` | `HIGH` | Reserved IP Hostname | Host is reserved / multicast | Non-routable or special-purpose IP range. |
| `RULE_UNUSUAL_SCHEME` | `HIGH` | Dangerous Protocol Scheme | Scheme in `{javascript, data}` | Script-capable or inline data schemes execute client-side code directly. |
| `RULE_MALFORMED_URL` | `HIGH` | Malformed URL Structure | Missing host or corrupt syntax | Structural parsing failure. |

---

### 4.2 Heuristic Risk Scoring Methodology

To provide a transparent, explainable assessment without fabricating pseudo-probabilities, the engine computes a **Heuristic Risk Score (0–100)**:

$$\text{Category} = \max_{o \in \text{Observations}}(\text{Severity}(o))$$

$$\text{Base Score} = \begin{cases} 65 & \text{if Category} = \text{HIGH} \\ 35 & \text{if Category} = \text{MEDIUM} \\ 15 & \text{if Category} = \text{LOW} \\ 0 & \text{if Category} = \text{INFO} \end{cases}$$

$$\text{Heuristic Score} = \min\left(100, \text{Base Score} + \sum_{o \in \text{Obs}} \text{Weight}(\text{Severity}(o))\right)$$

Where additional observation increments are: $\text{HIGH} = +10$, $\text{MEDIUM} = +5$, $\text{LOW} = +2$.

> [!NOTE]
> **Heuristic Interpretation**:  
> This score represents an index of structural anomaly and evasion complexity. A high score signifies that a URL exhibits patterns disproportionately associated with phishing lures (e.g. `@` authority deception or private IP targeting). **It is NOT a calibrated probability and MUST NOT be combined directly with DistilBERT posterior probabilities in Phase 4A.** Evidence fusion is deferred to Phase 7.

---

## 5. Synthetic Demonstration Examples

### Example 1: Standard Legitimate Corporate URL
- **Input**: `https://www.example.com/about/team`
- **Parse Status**: `parsed`
- **Normalized Host**: `www.example.com`
- **Triggered Rules**:
  - `RULE_HTTPS_STANDARD` (`INFO`): Encrypted transport.
  - `RULE_NON_ROOT_PATH` (`INFO`): Path `/about/team` present.
- **Risk Category**: **`INFO`** (Score: `0 / 100`)
- **Summary**: Standard, well-formed HTTPS link with zero evasion indicators.

### Example 2: Authority User-Info Spoofing Lure
- **Input**: `http://legit-bank.com@attacker-site.com/login`
- **Parse Status**: `parsed`
- **Normalized Host**: `attacker-site.com` (Successfully isolated from fake userinfo)
- **Triggered Rules**:
  - `RULE_USERINFO_AUTH` (`HIGH`): Text before `@` (`legit-bank.com`) is ignored; browser navigates to `attacker-site.com`.
  - `RULE_HTTP_UNENCRYPTED` (`LOW`): Cleartext HTTP protocol.
  - `RULE_NON_ROOT_PATH` (`INFO`): Path `/login`.
- **Risk Category**: **`HIGH`** (Score: `77 / 100`)
- **Summary**: Severe deception technique attempting to deceive visual inspection.

### Example 3: Public IP-Literal with Targeted Query Parameters
- **Input**: `http://93.184.216.34:8080/portal?email=target@corp.com&redirect=https://other.com`
- **Parse Status**: `parsed`
- **Normalized Host**: `93.184.216.34` (`HostType.IPV4`, `HostClassification.PUBLIC`)
- **Triggered Rules**:
  - `RULE_PUBLIC_IP_HOST` (`MEDIUM`): Raw public IPv4 literal destination.
  - `RULE_NON_DEFAULT_PORT` (`MEDIUM`): Port 8080 specified.
  - `RULE_EMAIL_IN_QUERY` (`MEDIUM`): Pre-filled recipient email detected in query.
  - `RULE_OPEN_REDIRECT_PARAM` (`LOW`): Redirect parameter detected.
  - `RULE_HTTP_UNENCRYPTED` (`LOW`): Unencrypted cleartext transmission.
- **Risk Category**: **`MEDIUM`** (Score: `54 / 100`)
- **Summary**: Multi-indicator evasion: raw IP destination, custom service port, and harvested email parameter.

### Example 4: Punycode Internationalized Domain Spoofing
- **Input**: `https://xn--pple-43d.com/store` (Punycode encoding for `аpple.com` with Cyrillic 'а')
- **Parse Status**: `parsed`
- **Normalized Host**: `xn--pple-43d.com`
- **Triggered Rules**:
  - `RULE_PUNYCODE_HOST` (`MEDIUM`): Punycode label indicates potential IDN homoglyph spoofing.
  - `RULE_HTTPS_STANDARD` (`INFO`): Encrypted protocol.
- **Risk Category**: **`MEDIUM`** (Score: `40 / 100`)
- **Summary**: Visual lookalike domain requiring character validation.

### Example 5: Dangerous Protocol Scheme
- **Input**: `javascript:alert(document.cookie)`
- **Parse Status**: `unsupported_scheme`
- **Normalized Host**: `None`
- **Triggered Rules**:
  - `RULE_UNUSUAL_SCHEME` (`HIGH`): Script execution protocol scheme.
- **Risk Category**: **`HIGH`** (Score: `75 / 100`)
- **Summary**: Prohibited inline script execution vector.

---

## 6. Distinction: Parsed Hostname vs. Verified Reachable Domain

A fundamental tenet of local URL forensic analysis is the distinction between **lexical hostnames** and **verified DNS domains**:
1. **Parsed Hostname (Phase 4A)**: Extracted purely from character syntax. A validly parsed hostname string (e.g., `secure-update-bank.com`) confirms that the URL follows RFC 3986 grammar. It **does not prove** that the domain is registered, active, or reachable.
2. **Verified Reachable Domain (Future / External)**: Requires network DNS querying (A/AAAA/NS/MX records), WHOIS registration checking, and TLS certificate validation.
3. **PhishIntel Policy**: In strict accordance with Phase 4A safety rules, **zero DNS queries were executed**. All evaluations reflect syntactic and lexical properties only.

---

## 7. Comprehensive Test Suite Audit

The backend test suite was executed via `pytest backend/tests`. All tests passed with zero failures:

### Test Execution Summary
```text
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Lenovo\Desktop\PhishIntel\backend
configfile: pytest.ini
collected 40 items

backend\tests\test_api.py ........                                       [ 20%]
backend\tests\test_email_parser.py .........                             [ 42%]
backend\tests\test_url_intelligence.py .......................           [100%]

======================== 40 passed, 1 warning in 0.84s ========================
```

### URL Intelligence Test Matrix (`test_url_intelligence.py`)
| Test Function | Target Scenario | Network Guard | Result |
| :--- | :--- | :---: | :---: |
| `test_normal_https_url` | Standard HTTPS, root/non-root path | Socket Mocked | **PASS** |
| `test_normal_http_url` | Standard unencrypted HTTP | Socket Mocked | **PASS** |
| `test_multiple_subdomains` | Deep subdomain structure ($\ge 3$ subdomains) | Socket Mocked | **PASS** |
| `test_hostname_with_hyphens` | Multiple hyphens in domain label | Socket Mocked | **PASS** |
| `test_ipv4_literal_public` | Globally routable public IPv4 literal | Socket Mocked | **PASS** |
| `test_ipv4_literal_private` | RFC 1918 private IPv4 literal (`192.168.1.100`) | Socket Mocked | **PASS** |
| `test_ipv6_literal` | Bracketed IPv6 literal with custom port | Socket Mocked | **PASS** |
| `test_url_with_userinfo` | Authority `@` user-info spoofing lure | Socket Mocked | **PASS** |
| `test_non_default_port` | Non-standard port (`:8443`) | Socket Mocked | **PASS** |
| `test_default_port_not_flagged` | Standard port (`:443`) not flagged as anomalous | Socket Mocked | **PASS** |
| `test_punycode_hostname` | Punycode IDN label (`xn--...`) | Socket Mocked | **PASS** |
| `test_unicode_hostname` | Raw non-ASCII Unicode characters | Socket Mocked | **PASS** |
| `test_percent_encoding` | Multiple `%XX` hexadecimal escapes | Socket Mocked | **PASS** |
| `test_double_percent_encoding` | Double-encoding filter bypass attempt (`%252e`) | Socket Mocked | **PASS** |
| `test_query_and_fragment` | Query string and fragment handling | Socket Mocked | **PASS** |
| `test_email_in_query` | Harvested recipient email inside query | Socket Mocked | **PASS** |
| `test_malformed_url` | Whitespace/empty and missing host strings | Socket Mocked | **PASS** |
| `test_unsupported_scheme` | `javascript:` and `data:` schemes | Socket Mocked | **PASS** |
| `test_trailing_dot` | FQDN root dot normalization | Socket Mocked | **PASS** |
| `test_missing_scheme` | URL string without protocol prefix | Socket Mocked | **PASS** |
| `test_localhost` | Loopback `localhost` destination | Socket Mocked | **PASS** |
| `test_batch_analysis_and_deduplication`| Batch aggregation and deduplication count | Socket Mocked | **PASS** |
| `test_email_extracted_urls_bridge` | Integration with Phase 1 `ExtractedURL` | Socket Mocked | **PASS** |

---

## 8. Known Limitations & Research Boundaries

1. **Local Syntactic Scope Only**: The engine cannot detect compromised legitimate domains whose URLs adhere to standard syntax (e.g., an authentic corporate WordPress site hosting an uploaded malicious PDF under a normal path).
2. **No Dynamic Redirect Following**: Shortened URLs (e.g. `bit.ly`, `tinyurl.com`) cannot be expanded locally without network HTTP resolution.
3. **No Domain Age / WHOIS Telemetry**: Newly registered domains (NRDs) cannot be verified without external registry lookups.
4. **Heuristic Nature of Scoring**: Risk tiers provide structural triage, not mathematical proof. Legitimate web services occasionally use non-standard ports or long query parameters.

---

## 9. Deliverables & Invariance Audit

### Files Created
1. **`backend/app/schemas/url_intelligence.py`** [Link](file:///c:/Users/Lenovo/Desktop/PhishIntel/backend/app/schemas/url_intelligence.py)  
   Complete Pydantic schema models for URL intelligence.
2. **`backend/app/services/url_intelligence.py`** [Link](file:///c:/Users/Lenovo/Desktop/PhishIntel/backend/app/services/url_intelligence.py)  
   Core deterministic URL intelligence service module.
3. **`backend/tests/test_url_intelligence.py`** [Link](file:///c:/Users/Lenovo/Desktop/PhishIntel/backend/tests/test_url_intelligence.py)  
   Comprehensive unit test suite enforcing active network isolation.
4. **`docs/phase4/phase4a_url_intelligence.md`** [Link](file:///c:/Users/Lenovo/Desktop/PhishIntel/docs/phase4/phase4a_url_intelligence.md)  
   This technical engineering report.

### Cryptographic Invariance Check (Protected Artifacts)
All Phase 2 and Phase 3 assets were verified bit-identical:
- `train.csv`: `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` (**MATCH**)
- `validation.csv`: `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` (**MATCH**)
- `test.csv`: `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` (**MATCH**)
- `cleaned_email_dataset.csv`: `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` (**MATCH**)
- `model.safetensors`: `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` (**MATCH**)

---

## Final Status

# PHASE_4A_URL_ENGINE_COMPLETE
