# Phase 10 — Stage A.2: Authentication Provenance and IP Classification Fallback Correction

**Project:** PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Stage:** A.2  
**Status:** `STAGE_A2_VERIFIED`  
**Date:** 2026-11-05  

---

## 1. Problem Statement

Stage A.1 improved authentication trust validation by checking authserv-id domain against `TRUSTED_AUTHSERV_DOMAINS`.  Stage A.2 identifies two residual defects:

### Issue 1 — Authentication Provenance (Insufficient for Offline Uploads)

The Stage A.1 implementation could return `is_boundary_trusted = True` and `AuthservTrustStatus.TRUSTED` when the boundary MTA's authserv-id matched a known mail gateway domain (e.g. `mx.google.com`).

**This is incorrect for offline `.eml` upload workflows.**

An attacker can write any string into an email header:

```
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
```

The presence of a known domain name in the authserv-id field does **not** prove the header was produced by Google's mail gateway.  Provenance requires an independently established trust chain from the ingestion mechanism itself — not text pattern matching on an uploaded file.

**Required semantics:**

| Scenario | ProvenanceStatus | is_boundary_trusted |
|---|---|---|
| No auth headers | `MISSING_AUTHENTICATION` | False |
| Suspicious/malformed authserv-id | `UNTRUSTED_AUTHENTICATION` | False |
| Any uploaded `.eml` with recognized authserv-id | `REPORTED_AUTHENTICATION` | False |
| Future: direct trusted mail gateway API | `TRUSTED_RECEIVER_EVIDENCE` | True |

### Issue 2 — IP Classification Fallback (Non-Global → PUBLIC)

The final `else` branch in `is_valid_ipv4_or_ipv6()` assigned `HostClassification.PUBLIC` to any address that failed all prior tests:

```python
elif ip_obj.is_global:
    classification = HostClassification.PUBLIC
else:
    classification = HostClassification.PUBLIC  # BUG: non-global falls to PUBLIC
```

The following address ranges could fall through to `PUBLIC`:
- `100.64.0.0/10` — RFC 6598 Shared Address Space
- `198.18.0.0/15` — RFC 2544 Benchmarking (Python 3.13: `is_private=True`)
- `240.0.0.0/4` — RFC 1112 Reserved (Python 3.13: `is_private=True`)
- `0.0.0.0/8` — Unspecified (Python 3.13: `is_private=True`)
- `::` — IPv6 unspecified

### Issue 3 — Regression Tests Required

No existing tests covered forged authserv-id domain match, header position not establishing provenance, reported PASS distinct from trusted evidence, missing provenance, or the full IP range classification matrix.

---

## 2. Changes Made

### 2.1 `backend/app/schemas/email_authentication.py`

**Added `REPORTED` to `AuthservTrustStatus`:**

```python
class AuthservTrustStatus(str, Enum):
    TRUSTED = "TRUSTED"       # Reserved — future trusted infrastructure only
    UNTRUSTED = "UNTRUSTED"
    MISSING = "MISSING"
    SUSPICIOUS = "SUSPICIOUS"
    REPORTED = "REPORTED"     # Stage A.2: domain matched but NOT provenance proof
```

**Added `ProvenanceStatus` enum (new):**

```python
class ProvenanceStatus(str, Enum):
    TRUSTED_RECEIVER_EVIDENCE = "TRUSTED_RECEIVER_EVIDENCE"    # Future infrastructure only
    REPORTED_AUTHENTICATION = "REPORTED_AUTHENTICATION"         # All offline .eml uploads
    UNTRUSTED_AUTHENTICATION = "UNTRUSTED_AUTHENTICATION"       # Suspicious/malformed
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"           # No auth headers
```

**Added `provenance_status` field to `EmailAuthenticationAnalysis`:**

```python
provenance_status: ProvenanceStatus = Field(
    default=ProvenanceStatus.REPORTED_AUTHENTICATION,
    description="Stage A.2 provenance classification..."
)
```

**Updated `disclaimer`** to explicitly state that authserv-id string matching is not provenance proof.

### 2.2 `backend/app/services/email_authentication.py`

**`validate_authserv_id_trust()` now returns `REPORTED` (not `TRUSTED`) for recognized domains:**

```python
# Before Stage A.2:
return True, AuthservTrustStatus.TRUSTED, f"authserv-id '{cleaned_id}' matches trusted gateway policy..."

# After Stage A.2:
return (
    True,
    AuthservTrustStatus.REPORTED,
    f"authserv-id '{cleaned_id}' matches known gateway policy '{domain}', "
    "but provenance is NOT independently established for offline .eml uploads. "
    "This string can be forged by any sender."
)
```

**`analyze_email_authentication()` — provenance_status computed from actual evidence:**

```python
# Stage A.2: provenance based on what we know, not authserv-id domain match
if not auth_results_headers and not header_info.received_spf:
    provenance_status = ProvenanceStatus.MISSING_AUTHENTICATION
elif boundary_authserv_trust == AuthservTrustStatus.SUSPICIOUS:
    provenance_status = ProvenanceStatus.UNTRUSTED_AUTHENTICATION
elif boundary_authserv_trust == AuthservTrustStatus.MISSING and not all_findings:
    provenance_status = ProvenanceStatus.MISSING_AUTHENTICATION
else:
    provenance_status = ProvenanceStatus.REPORTED_AUTHENTICATION

# is_boundary_trusted is ALWAYS False for offline .eml uploads
is_boundary_trusted = False
```

**Warning messages updated** to reflect the distinction between UNTRUSTED (unrecognized domain) and REPORTED (recognized domain, but unverifiable).

### 2.3 `backend/app/services/url_intelligence.py`

**Added `SPECIAL_PURPOSE_NETWORKS`** to cover ranges not caught by `is_reserved` on all Python versions:

```python
SPECIAL_PURPOSE_NETWORKS = (
    ipaddress.IPv4Network("100.64.0.0/10"),   # RFC 6598 Shared Address Space
    ipaddress.IPv4Network("192.0.0.0/24"),    # IANA Special-Purpose (RFC 6890)
    ipaddress.IPv4Network("198.18.0.0/15"),   # Benchmarking (RFC 2544)
    ipaddress.IPv4Network("240.0.0.0/4"),     # Reserved (RFC 1112)
    ipaddress.IPv4Network("0.0.0.0/8"),       # Unspecified / "This" network (RFC 1122)
)
```

**Fixed `is_valid_ipv4_or_ipv6()` classification order:**

```python
if ip_obj.is_loopback:
    classification = HostClassification.LOOPBACK
elif ip_obj.is_link_local:
    classification = HostClassification.LINK_LOCAL
elif any(ip_obj in net for net in DOCUMENTATION_NETWORKS):
    classification = HostClassification.DOCUMENTATION
elif (RFC1918 or RFC4193 or ip_obj.is_private):
    classification = HostClassification.PRIVATE
elif ip_obj.is_multicast:
    classification = HostClassification.RESERVED
elif ip_obj.is_reserved:
    classification = HostClassification.RESERVED
elif ip_obj.version == 4 and any(ip_obj in net for net in SPECIAL_PURPOSE_NETWORKS):
    classification = HostClassification.RESERVED      # explicit catch for shared/benchmarking/reserved ranges
elif ip_obj.is_global:
    classification = HostClassification.PUBLIC
else:
    classification = HostClassification.RESERVED      # Stage A.2: safe catch-all, NOT PUBLIC
```

> **Note:** Python 3.13 marks `198.18.0.0/15` (RFC 2544 Benchmarking) and `240.0.0.0/4` (RFC 1112 Reserved) and `0.0.0.0/8` as `is_private=True`.  These are caught by the `ip_obj.is_private` branch before reaching `SPECIAL_PURPOSE_NETWORKS`.  The result (`PRIVATE`) is still non-PUBLIC and correct for classification purposes.  The `SPECIAL_PURPOSE_NETWORKS` list ensures correctness on Python versions where `is_private` may not cover these ranges.

### 2.4 `backend/app/services/evidence_fusion.py`

**`_extract_auth_evidence()` updated to use `provenance_status`:**

```python
provenance_str = provenance_status.value if hasattr(provenance_status, "value") else "REPORTED_AUTHENTICATION"

# has_valid_authentication = True ONLY when provenance is independently established
if provenance_str == "TRUSTED_RECEIVER_EVIDENCE" and has_pass and is_boundary_trusted:
    has_valid_auth = True
else:
    has_valid_auth = False  # always False for offline .eml uploads
```

Contributing factor message updated for `REPORTED` boundary trust:

```python
elif boundary_trust_str == "REPORTED":
    contributing.append(
        f"Authentication results claim '{boundary_authserv}' as the recording MTA, but this is an offline .eml upload — "
        "the authserv-id string cannot be independently verified as genuine. "
        "Authentication assertions are REPORTED (unverified provenance)."
    )
```

### 2.5 `frontend/src/types/forensics.ts`

**Added `REPORTED` to `AuthservTrustStatus`:**

```typescript
export type AuthservTrustStatus = 'TRUSTED' | 'UNTRUSTED' | 'MISSING' | 'SUSPICIOUS' | 'REPORTED';
```

**Added `ProvenanceStatus` type (new):**

```typescript
export type ProvenanceStatus =
  | 'TRUSTED_RECEIVER_EVIDENCE'
  | 'REPORTED_AUTHENTICATION'
  | 'UNTRUSTED_AUTHENTICATION'
  | 'MISSING_AUTHENTICATION';
```

**Added `provenance_status` to `EmailAuthenticationAnalysis` interface (optional).**

---

## 3. Downstream Impact — Evidence Fusion Category

Stage A.2 changes `has_valid_authentication` to `False` for all offline uploads, which affects the evidence fusion category:

| Scenario (offline upload) | Before A.2 | After A.2 |
|---|---|---|
| All PASS + low model score (0.12) + clean URLs | `LOW_RISK_INDICATORS` | `INSUFFICIENT_EVIDENCE` |
| All PASS + HIGH model score + moderate URLs | `REVIEW_RECOMMENDED` (Condition 4) | `REVIEW_RECOMMENDED` (Condition 5/3) |
| All FAIL + HIGH model score | `HIGH_RISK_INDICATORS_PRESENT` | `HIGH_RISK_INDICATORS_PRESENT` (unchanged) |

**This is correct and accurate behavior.**  An offline `.eml` upload cannot establish authentication provenance.  The application now honestly represents that "authentication passed" cannot be used to reduce risk assessment — the PASS claims are present but their source cannot be verified.

The `LOW_RISK_INDICATORS` category (Condition 7) is now reserved for future scenarios where the ingestion mechanism independently establishes `TRUSTED_RECEIVER_EVIDENCE` provenance.

---

## 4. Test Results

### 4.1 New Stage A.2 Regression Tests

**File:** `backend/tests/test_stage_a2_corrections.py`  
**Result:** 54 passed in 0.30s ✅

| Test Class | Tests | Coverage |
|---|---|---|
| `TestForgedGoogleAuthservId` | 4 | Forged mx.google.com with SPF/DKIM/DMARC PASS |
| `TestForgedMicrosoftAuthservId` | 3 | Forged protection.outlook.com |
| `TestHeaderPositionDoesNotEstablishProvenance` | 2 | Index 0 ≠ provenance proof |
| `TestReportedPassDistinctFromTrustedEvidence` | 2 | has_valid_authentication=False for REPORTED |
| `TestMissingProvenanceExplicit` | 2 | No headers → MISSING_AUTHENTICATION |
| `TestValidateAuthservIdReturnedReported` | 5 | validate_authserv_id_trust() returns REPORTED |
| `TestNonGlobalIPsCannotFallThroughToPublic` | 8 | Shared space, benchmarking, reserved, unspecified |
| `TestCompleteIPRangeClassification` | 28 | Full coverage: RFC 1918, loopback, link-local, documentation, ULA, public, multicast, shared |

### 4.2 Updated Stage A.1 Tests

**File:** `backend/tests/test_stage_a1_corrections.py`  
**Updated:** `test_case_01`, `test_case_02` to reflect REPORTED semantics.

### 4.3 Updated Stage A/B Tests

**File:** `backend/tests/test_stage_a_b_corrections.py`  
**Updated:** `test_case_01`, `test_case_09`, `test_case_10`, `test_case_15` to reflect Stage A.2 provenance semantics.

### 4.4 Full Backend Test Suite

```
python -m pytest backend/tests/ -q
194 passed, 1 warning in 15.94s
```

✅ **194/194 passed**

### 4.5 TypeScript Type Check

```
npx tsc --noEmit
# Exit code 0 — 0 errors
```

✅ **0 TypeScript errors**

### 4.6 Frontend Tests

The 3 frontend test files in `src/tests/` use `node:test` (Node.js built-in test runner) which is incompatible with the project's Jest/create-react-app test harness.  This is a **pre-existing issue** unrelated to Stage A.2.  TypeScript compilation (the relevant validation for type changes) passes without errors.

---

## 5. Protected SHA-256 Hash Verification

| File | Expected | Verified |
|---|---|---|
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | ✅ |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | ✅ |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | ✅ |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | ✅ |

No protected files were modified.

---

## 6. Remaining Limitations

1. **`TRUSTED_RECEIVER_EVIDENCE` is not yet reachable.**  It is defined and documented as the future path for infrastructure-level integration (e.g., direct API call from a trusted mail gateway), but no such integration exists.  This is by design — the enum value is a documented contract, not a placeholder to be populated with weaker logic.

2. **Authentication PASS assertions in offline uploads are unverifiable by design.**  The application correctly represents this limitation in `provenance_status`, `is_boundary_trusted`, `has_valid_authentication`, and all disclaimer fields.  Downstream evidence fusion categories now accurately reflect this uncertainty.

3. **IP classification on Python 3.13.**  `198.18.0.0/15` (RFC 2544) and `240.0.0.0/4` (RFC 1112) are classified as `PRIVATE` by Python 3.13's `is_private` flag.  The result is still non-PUBLIC and correct for PhishIntel's purposes.  The `SPECIAL_PURPOSE_NETWORKS` constant ensures correctness on Python versions where `is_private` may behave differently for these ranges.

---

## 7. Files Modified

| File | Change |
|---|---|
| `backend/app/schemas/email_authentication.py` | Added `REPORTED` to `AuthservTrustStatus`; added `ProvenanceStatus` enum; added `provenance_status` field; updated `disclaimer` |
| `backend/app/services/email_authentication.py` | Imported `ProvenanceStatus`; `validate_authserv_id_trust()` returns `REPORTED` for domain match; `analyze_email_authentication()` sets `provenance_status` and keeps `is_boundary_trusted=False` for offline uploads; updated warning messages |
| `backend/app/services/url_intelligence.py` | Added `SPECIAL_PURPOSE_NETWORKS`; fixed classification order and final fallback to `RESERVED` |
| `backend/app/services/evidence_fusion.py` | `_extract_auth_evidence()` reads `provenance_status`; `has_valid_authentication` requires `TRUSTED_RECEIVER_EVIDENCE`; contributing factor messages updated for `REPORTED` boundary trust |
| `frontend/src/types/forensics.ts` | Added `REPORTED` to `AuthservTrustStatus`; added `ProvenanceStatus` type; added `provenance_status` to `EmailAuthenticationAnalysis` |
| `backend/tests/test_stage_a2_corrections.py` | New — 54 regression tests for Issues 1, 2, 3 |
| `backend/tests/test_stage_a1_corrections.py` | Updated `test_case_01`, `test_case_02` to reflect REPORTED semantics |
| `backend/tests/test_stage_a_b_corrections.py` | Updated `test_case_01`, `test_case_09`, `test_case_10`, `test_case_15` to reflect Stage A.2 semantics |

---

## Final Status: `STAGE_A2_VERIFIED`

All three issues were addressed, regression tested, and verified:
- 54 new tests pass for Issues 1, 2, 3
- 194 total backend tests pass (0 regressions introduced)
- 0 TypeScript errors
- All 4 protected SHA-256 hashes unchanged
- No DistilBERT retraining, no dataset modifications, no threshold changes, no sender whitelisting

