# Phase 5A — Email Authentication Evidence Engine Technical Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 5A — Email Authentication Evidence Engine  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Service Path**: `backend/app/services/email_authentication.py`  
**Schema Path**: `backend/app/schemas/email_authentication.py`  
**Parser Path**: `backend/app/services/email_parser.py`  
**Test Path**: `backend/tests/test_email_authentication.py`  
**Status Verdict**: **`PHASE_5A_AUTHENTICATION_EVIDENCE_COMPLETE`**

---

## 1. Executive Summary & Objective

Phase 5A implements and integrates the **Email Authentication Evidence Engine** for PhishIntel. The engine provides deterministic, explainable, and local parsing of email authentication evidence explicitly recorded in uploaded `.eml` email headers, specifically:
- **`Authentication-Results`** (RFC 8601, RFC 7601, RFC 5451)
- **`Received-SPF`** (RFC 7208)
- **`DKIM-Signature`** (RFC 6376, presence detection and verification gap tracking)

### Operational Principles & Safety Guarantees
- **Strictly Offline & Local Execution**: Phase 5A performs purely local header parsing and token normalization. **Zero DNS queries, zero SMTP connections, zero public key fetches, and zero cryptographic DKIM signature verifications are performed.**
- **Header Evidence Interpretation vs Independent Verification**: The engine interprets assertions made by downstream receiving Mail Transfer Agents (MTAs). It clearly disclaims that header validity depends on the recipient mail gateway's trust boundary.
- **Explicit Result State Classification**: Rather than assuming missing evidence implies failure or inferring success from mere header presence, outcomes are mapped to explicit, standardized states (`PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `TEMPERROR`, `PERMERROR`, `UNKNOWN`, `NOT_PRESENT`, `CONFLICTING_EVIDENCE`).
- **Defensive Error Handling**: Malformed or conflicting headers are detected without throwing unhandled exceptions. If multiple MTAs report contradictory findings, the engine explicitly outputs `CONFLICTING_EVIDENCE`.
- **Full Backward Compatibility**: All Phase 1 forensic parser outputs and Phase 4B URL intelligence results remain intact. The existing `POST /api/v1/email/analyze` endpoint is extended with an optional `authentication_analysis` field.

---

## 2. Supported Headers & Result Tokens

### 2.1 Supported Header Types
1. **`Authentication-Results` (RFC 8601 / RFC 7601)**:
   - Evaluated for authserv-id (reporting MTA identifier, e.g. `mx.google.com`, `mail.protection.outlook.com`).
   - Parsed for method clauses: `spf=<result>`, `dkim=<result>`, and `dmarc=<result>`.
   - Extracts related properties:
     - SPF: `smtp.mailfrom`, `smtp.helo`, `client-ip`
     - DKIM: `header.d` (signing domain), `header.i` (AUID), `header.s` (selector), `header.b`
     - DMARC: `header.from`, `p` (policy), `sp` (subdomain policy), `dis` / `action` (disposition)
2. **`Received-SPF` (RFC 7208)**:
   - Evaluated for first-token result (`pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`).
   - Parsed for receiver comments, `client-ip`, `envelope-from`, and `identity`.
3. **`DKIM-Signature` (RFC 6376)**:
   - Recorded as raw signature headers.
   - If a `DKIM-Signature` header is present but no receiving MTA recorded a verification result in `Authentication-Results`, the engine records `status=UNKNOWN` and explicitly notes that the signature is unverified.

### 2.2 Result Token Normalization Mapping
| Raw Token in Header | Normalized `AuthResultStatus` | Semantic Definition |
| :--- | :--- | :--- |
| `pass`, `passed`, `success` | `PASS` | Receiving MTA recorded that authentication succeeded |
| `fail`, `failed`, `hardfail` | `FAIL` | Receiving MTA recorded an explicit authentication failure |
| `softfail`, `soft-fail` | `SOFTFAIL` | Host not permitted, but domain owner requested soft acceptance (`~all`) |
| `neutral` | `NEUTRAL` | Domain owner made no definitive statement regarding client host (`?all`) |
| `none` | `NONE` | No SPF record or DKIM signature published for the evaluated domain |
| `temperror`, `tempfail` | `TEMPERROR` | Transient error (e.g. DNS timeout) during downstream verification |
| `permerror`, `perm-error`, `error` | `PERMERROR` | Syntax or structural error in published record or signature |
| Unrecognized token / corruption | `UNKNOWN` | Result token could not be reliably interpreted |
| Header absent / method missing | `NOT_PRESENT` | No evidence found in any inspected headers |
| Contradictory findings across MTAs | `CONFLICTING_EVIDENCE` | Different headers reported conflicting results (e.g. `PASS` vs `FAIL`) |

---

## 3. Parsing & Classification Rules

```
Raw Email Headers
       │
       ├─► 1. Authentication-Results (RFC 8601)
       │       ├── Extract Authserv-ID (reporting gateway)
       │       ├── Tokenize clauses (CFWS comment-aware splitting)
       │       └── Extract spf=, dkim=, dmarc= and key=value pairs
       │
       ├─► 2. Received-SPF (RFC 7208)
       │       ├── Extract first token (result)
       │       └── Extract client-ip, envelope-from, comments
       │
       └─► 3. DKIM-Signature (RFC 6376)
               └── Check presence of raw signature headers
       │
       ▼
Per-Method Findings Collection (HeaderFinding records with source & index)
       │
       ▼
Consolidation & Contradiction Resolution
       ├── If all headers agree -> Consolidated Status (e.g. PASS, FAIL)
       ├── If headers contradict -> CONFLICTING_EVIDENCE
       ├── If no headers -> NOT_PRESENT
       └── If DKIM-Signature present without verification -> UNKNOWN
       │
       ▼
EmailAuthenticationAnalysis (Pydantic Schema attached to EmailAnalysisResponse)
```

### 3.1 Handling of Edge Cases
- **Missing Authentication Evidence**: When an email contains neither `Authentication-Results`, `Received-SPF`, nor `DKIM-Signature`, overall status is `NO_EVIDENCE`, and each method is assigned `NOT_PRESENT`. No error is thrown.
- **Multiple `Authentication-Results` Headers**: When an email passes through multiple internal or external MTAs (e.g. perimeter gateway -> internal security filter), all findings are captured. If they agree, the finding list maintains full hop provenance; if they report contradictory results (e.g. one reports `spf=pass` and another reports `spf=fail`), status is set to `CONFLICTING_EVIDENCE`.
- **Malformed Header Values**: Unrecognized tokens or corrupted clauses map safely to `UNKNOWN` and record non-fatal warnings without terminating parsing.
- **Misleading or Spoofed Content**: Comments containing misleading strings like `note="spf=pass was fake"` are parsed as comments, not as valid method key-values. Methods are strictly matched against standardized token formats.
- **DKIM-Signature Presence Without Verification**: A raw `DKIM-Signature` header alone is **NEVER** treated as proof that the signature is valid. If no downstream MTA verified it, DKIM status is set to `UNKNOWN` with an explicit caveat.
- **DMARC Identifier Alignment**: DMARC alignment is not claimed unless the reported evidence explicitly asserts alignment (`alignment_verified=True` only if explicitly reported by the MTA).

---

## 4. Header Provenance & Trust Limitations

### 4.1 Downstream MTA Claims vs Independent Cryptographic Verification
> [!IMPORTANT]
> The evidence interpreted by Phase 5A reflects **downstream MTA claims** recorded in email headers at the time the email was received.
>
> Phase 5A does **NOT**:
> - Perform live DNS lookups for SPF TXT records.
> - Query DNS for DKIM public keys (`selector._domainkey.domain.com`).
> - Cryptographically verify RSA/Ed25519 signatures or body hashes (`bh=`).
> - Evaluate DMARC organizational domain alignment policies in real time.

### 4.2 Trust Boundary Vulnerabilities
If an email was transmitted through an untrusted relay or generated synthetically by an attacker:
- An attacker can inject arbitrary `Authentication-Results: mx.google.com; spf=pass; dkim=pass` headers into an email if upstream border MTAs do not strip untrusted authentication headers.
- PhishIntel explicitly records the `authserv_id` and documents this trust limitation in every analysis response:
  > *"Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208). Phase 5A does not perform live DNS queries, fetch public keys, or cryptographically verify DKIM signatures. Authenticity of these headers depends on the recipient mail gateway trust boundary."*

---

## 5. API Response Schema & Synthetic Example

### 5.1 Response Schema Extension
The endpoint `POST /api/v1/email/analyze` returns `EmailAnalysisResponse`, which now includes:
```python
authentication_analysis: Optional[EmailAuthenticationAnalysis] = None
```

### 5.2 Synthetic Request & Response Example

#### Synthetic Request:
```http
POST /api/v1/email/analyze HTTP/1.1
Host: localhost:8000
Content-Type: multipart/form-data; boundary=----BoundaryXYZ

------BoundaryXYZ
Content-Disposition: form-data; name="file"; filename="sample_invoice_verified.eml"
Content-Type: message/rfc822

Received: from mail.partner-corp.example (mail.partner-corp.example [198.51.100.25])
    by mx.gateway.example with ESMTPS id xyz123;
    Mon, 12 Oct 2026 12:00:00 +0000
Authentication-Results: mx.gateway.example;
    dkim=pass header.i=@partner-corp.example header.s=s202610 header.d=partner-corp.example;
    spf=pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) smtp.mailfrom=billing@partner-corp.example;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=partner-corp.example
Received-SPF: pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25;
From: Accounts Receivable <billing@partner-corp.example>
To: accounting@my-company.example
Subject: Monthly Statement Notice
Date: Mon, 12 Oct 2026 12:00:00 +0000
Message-ID: <stmt-2026-99@partner-corp.example>
Content-Type: text/html; charset="utf-8"

<p>Your statement is available at <a href="https://billing.partner-corp.example/portal">Portal</a>.</p>
------BoundaryXYZ--
```

#### Response (HTTP 200 OK):
```json
{
  "filename": "sample_invoice_verified.eml",
  "file_size_bytes": 1048,
  "parsing_status": "success",
  "headers": {
    "from_header": "Accounts Receivable <billing@partner-corp.example>",
    "to_headers": ["accounting@my-company.example"],
    "subject": "Monthly Statement Notice",
    "authentication_results": [
      "mx.gateway.example;\n    dkim=pass header.i=@partner-corp.example header.s=s202610 header.d=partner-corp.example;\n    spf=pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) smtp.mailfrom=billing@partner-corp.example;\n    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=partner-corp.example"
    ],
    "received_spf": [
      "pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25;"
    ],
    "dkim_signatures": [],
    "received_headers": [
      "from mail.partner-corp.example (mail.partner-corp.example [198.51.100.25]) by mx.gateway.example with ESMTPS id xyz123; Mon, 12 Oct 2026 12:00:00 +0000"
    ]
  },
  "body": {
    "has_plain_text": false,
    "has_html": true,
    "html_extracted_text": "Your statement is available at Portal."
  },
  "urls": [
    {
      "url": "https://billing.partner-corp.example/portal",
      "scheme": "https",
      "domain": "billing.partner-corp.example",
      "source": "html_href"
    }
  ],
  "url_analysis": {
    "total_urls": 1,
    "unique_urls": 1,
    "highest_risk_category": "LOW",
    "risk_breakdown": { "INFO": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0 },
    "url_results": [
      {
        "url_index": 0,
        "original_url": "https://billing.partner-corp.example/portal",
        "normalized_hostname": "billing.partner-corp.example",
        "parse_status": "parsed",
        "heuristic_risk_score": 0,
        "heuristic_risk_category": "INFO",
        "risk_summary": "Informational / negligible heuristic risk: 0 observation(s) recorded."
      }
    ]
  },
  "authentication_analysis": {
    "status": "EVALUATED",
    "spf": {
      "status": "PASS",
      "findings": [
        {
          "method": "spf",
          "result": "PASS",
          "raw_result": "pass",
          "source_header": "Authentication-Results",
          "header_index": 0,
          "authserv_id": "mx.gateway.example",
          "properties": {
            "smtp.mailfrom": "billing@partner-corp.example"
          },
          "reason": "gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender",
          "raw_snippet": "spf=pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) smtp.mailfrom=billing@partner-corp.example"
        },
        {
          "method": "spf",
          "result": "PASS",
          "raw_result": "pass",
          "source_header": "Received-SPF",
          "header_index": 0,
          "authserv_id": null,
          "properties": {
            "client-ip": "198.51.100.25"
          },
          "reason": "gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender",
          "raw_snippet": "pass (gateway.example: domain of billing@partner-corp.example designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25;"
        }
      ],
      "domain": "billing@partner-corp.example",
      "client_ip": "198.51.100.25",
      "explanation": "SPF reported PASS by mx.gateway.example via Authentication-Results[0], Received-SPF[0].",
      "trust_limitation": "Result reflects downstream claim from mx.gateway.example. Offline analysis cannot verify if upstream mail relays stripped untrusted headers."
    },
    "dkim": {
      "status": "PASS",
      "findings": [
        {
          "method": "dkim",
          "result": "PASS",
          "raw_result": "pass",
          "source_header": "Authentication-Results",
          "header_index": 0,
          "authserv_id": "mx.gateway.example",
          "properties": {
            "header.i": "@partner-corp.example",
            "header.s": "s202610",
            "header.d": "partner-corp.example"
          },
          "reason": null,
          "raw_snippet": "dkim=pass header.i=@partner-corp.example header.s=s202610 header.d=partner-corp.example"
        }
      ],
      "has_dkim_signature_header": false,
      "dkim_signature_count": 0,
      "domain": "partner-corp.example",
      "selector": "s202610",
      "explanation": "DKIM reported PASS by mx.gateway.example via Authentication-Results[0].",
      "trust_limitation": "Result reflects downstream claim from mx.gateway.example. Offline analysis cannot verify if upstream mail relays stripped untrusted headers."
    },
    "dmarc": {
      "status": "PASS",
      "findings": [
        {
          "method": "dmarc",
          "result": "PASS",
          "raw_result": "pass",
          "source_header": "Authentication-Results",
          "header_index": 0,
          "authserv_id": "mx.gateway.example",
          "properties": {
            "p": "REJECT",
            "sp": "REJECT",
            "dis": "NONE",
            "header.from": "partner-corp.example"
          },
          "reason": "p=REJECT sp=REJECT dis=NONE",
          "raw_snippet": "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=partner-corp.example"
        }
      ],
      "policy": "REJECT",
      "subdomain_policy": "REJECT",
      "disposition": "NONE",
      "header_from": "partner-corp.example",
      "alignment_verified": false,
      "explanation": "DMARC reported PASS by mx.gateway.example via Authentication-Results[0].",
      "trust_limitation": "Result reflects downstream claim from mx.gateway.example. Offline analysis cannot verify if upstream mail relays stripped untrusted headers."
    },
    "headers_inspected": [
      "Authentication-Results",
      "Received-SPF"
    ],
    "authserv_ids": [
      "mx.gateway.example"
    ],
    "has_conflicts": false,
    "warnings": [],
    "disclaimer": "Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208). Phase 5A does not perform live DNS queries, fetch public keys, or cryptographically verify DKIM signatures. Authenticity of these headers depends on the recipient mail gateway trust boundary."
  },
  "warnings": [],
  "parsed_at": "2026-10-12T12:00:01.000000"
}
```

---

## 6. Test Suite Execution & Results

### 6.1 Test Breakdown
The complete backend test suite was executed:
```
backend/tests/test_api.py ................. [ 8 passed ]
backend/tests/test_email_authentication.py  [ 15 passed ]
backend/tests/test_email_parser.py ........ [ 9 passed ]
backend/tests/test_url_integration.py ..... [ 10 passed ]
backend/tests/test_url_intelligence.py .... [ 23 passed ]
--------------------------------------------------------
Total: 65 passed, 0 failed, 0 skipped (100% pass rate) in 0.95 seconds
```

### 6.2 Detailed Phase 5A Test Scenarios (`test_email_authentication.py`)
1. `test_01_spf_pass`: Validates `Authentication-Results` and `Received-SPF` pass token extraction, domain and client IP extraction.
2. `test_02_spf_fail`: Validates explicit SPF failure token handling (`spf=fail`).
3. `test_03_spf_softfail_and_neutral`: Validates `SOFTFAIL` (`~all`) and `NEUTRAL` (`?all`) token mappings.
4. `test_04_dkim_pass_and_fail`: Validates DKIM pass (with domain `header.d` and selector `header.s`) and DKIM failure.
5. `test_05_dmarc_pass_and_fail`: Validates DMARC pass with policy `p=reject`, disposition `dis=none`, and header from domain, plus failure.
6. `test_06_missing_authentication_evidence`: Validates `NOT_PRESENT` outcomes when no authentication headers exist.
7. `test_07_multiple_authentication_results_consistent`: Validates multiple `Authentication-Results` headers agreeing on outcomes.
8. `test_08_conflicting_results`: Validates contradiction handling (`spf=pass` vs `spf=fail`) producing `CONFLICTING_EVIDENCE`.
9. `test_09_malformed_header_values`: Validates graceful mapping of malformed tokens to `UNKNOWN`.
10. `test_10_unrelated_or_misleading_content`: Validates that deceptive text in notes or comments is not mistaken for valid authentication methods.
11. `test_11_dkim_signature_without_verification`: Validates that an unverified `DKIM-Signature` header maps to `UNKNOWN` and strictly **does NOT** infer pass.
12. `test_12_missing_optional_headers`: Validates minimal email parsing resilience without authentication headers.
13. `test_13_api_integration_with_url_analysis`: Validates endpoint `POST /api/v1/email/analyze` returning both URL intelligence and authentication evidence.
14. `test_14_regression_fixtures`: Validates existing multi-hop fixture `06_multiple_received_hops.eml` preserving hop IPs, URL analysis, and authentication analysis.
15. `test_15_network_isolation`: Verifies socket and DNS interception proving zero network access occurs.

---

## 7. Modified & Created Files

| File Path | Action | Description & Rationale |
| :--- | :--- | :--- |
| `backend/app/schemas/email_authentication.py` | Created | Defined `AuthResultStatus`, `OverallAuthStatus`, `HeaderFinding`, `SPFEvidence`, `DKIMEvidence`, `DMARCEvidence`, and `EmailAuthenticationAnalysis`. |
| `backend/app/services/email_authentication.py` | Created | Implemented standalone, deterministic RFC 8601 and RFC 7208 evidence parsing engine. |
| `backend/app/schemas/email.py` | Modified | Added `dkim_signatures` to `EmailHeaderInfo` and optional `authentication_analysis` to `EmailAnalysisResponse`. |
| `backend/app/services/email_parser.py` | Modified | Extracted `DKIM-Signature` headers into `EmailHeaderInfo` and integrated `analyze_email_authentication()` wrapped in non-fatal error handling. |
| `backend/tests/test_email_authentication.py` | Created | Implemented 15 comprehensive unit and integration tests covering all protocol states, edge cases, and network isolation. |
| `docs/phase5/phase5a_authentication_evidence.md` | Created | Technical documentation report for Phase 5A (this document). |

---

## 8. Protected Artifact Verification

Cryptographic SHA-256 hashes of all protected datasets and trained DistilBERT weights were verified and remain identical:

| Protected Artifact Path | Expected SHA-256 Hash | Verification Status |
| :--- | :--- | :---: |
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH (True)** |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH (True)** |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH (True)** |
| `data/processed/phishmmf/cleaned_email_dataset.csv` | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | **MATCH (True)** |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH (True)** |

---

## 9. Boundary Declarations & Known Limitations

1. **Header Interpretation Only**: Phase 5A does not perform live cryptographic verification. If an email originates from an internal lab or was crafted without passing through a legitimate receiving MTA, headers may be spoofed unless verified by a gateway within the investigator's trust boundary.
2. **No Live DNS Queries**: SPF record mechanisms (`ip4`, `include`, `redirect`, `a`, `mx`) are not resolved or verified against live DNS TXT records.
3. **No Key Fetching**: DKIM public keys are not fetched from DNS, and cryptographic signature mathematical validation is not performed.
4. **No Score Fusion**: Authentication evidence remains strictly isolated. It is not merged with DistilBERT NLP probabilities, Phase 4A URL heuristic scores, or IP intelligence. Evidence fusion is deferred to Phase 7.

---

## 10. Final Status

**`PHASE_5A_AUTHENTICATION_EVIDENCE_COMPLETE`**
