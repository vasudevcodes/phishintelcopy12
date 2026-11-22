# Phase 8B — Frontend-to-Backend Integration Audit Report

**Project:** PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Phase:** Phase 8B — Frontend-to-Backend Integration Audit  
**Date:** October 26, 2026  
**Status:** `PHASE_8B_VERIFIED`

---

## 1. Executive Summary

Phase 8B performed an end-to-end integration audit of the PhishIntel web frontend, validating that the React/TypeScript user interface accurately, safely, and truthfully renders the full multi-modal backend response returned by `POST /api/v1/email/analyze`.

Prior to this audit, the frontend was limited to Phase 1 RFC 5322 parsing primitives. It did not ingest or display Phase 4B URL intelligence heuristics, Phase 5A cryptographic authentication evidence, Phase 6A IP transit intelligence, Phase 7A multi-modal evidence fusion, or Phase 8A DistilBERT Transformer inference.

All integration gaps have been resolved with strict fidelity to the backend contract. The frontend renders real model statuses and uncalibrated scores with required calibration caveats, treats `ERROR` and `UNAVAILABLE` states defensively without ever defaulting to benign, displays comprehensive authentication and IP origin assessments, enforces client-side file constraints, and preserves the single-file, zero-touch, fully offline security workflow.

Both the backend and frontend test suites pass with 100% compliance, and all four protected research artifact hashes remain identical to their baseline values.

---

## 2. Integration Audit Findings & Gap Analysis

| Area | Pre-Audit State | Post-Audit Integration State | Contract Fidelity |
| :--- | :--- | :--- | :--- |
| **API Endpoint** | UploadZone invoked `/api/v1/email/analyze` | Preserved real endpoint `POST /api/v1/email/analyze` | Verified |
| **TypeScript Schemas** | `types/forensics.ts` only had Phase 1 fields | Added complete definitions for Phases 4–8A schemas | Verified |
| **Evidence Fusion** | No fusion card existed in UI | Dedicated `EvidenceFusionCard` rendering category, reasoning, factors, and disclaimers | Verified |
| **DistilBERT Inference** | No model output rendered | Overview banner & Fusion card display status (`EVALUATED`, `UNAVAILABLE`, `ERROR`), label, and score | Verified |
| **Model Failure Handling** | Not handled | `ERROR` and `UNAVAILABLE` states explicitly alert the analyst; **never** defaulted to benign | Verified |
| **Score Labeling** | N/A | Strictly labeled **"Uncalibrated Phishing Score"**; calibration caveat displayed prominently | Verified |
| **Auth Evidence** | Only raw header strings shown | `AuthenticationCard` renders structured SPF, DKIM, DMARC statuses, findings, and trust limits | Verified |
| **URL Intelligence** | Only raw URL strings shown | `ExtractedURLsCard` displays heuristic risk category, 0-100 score, host type, and rule observations | Verified |
| **IP Intelligence** | Only raw hop index & classification | `IPCandidatesCard` displays apparent origin assessment, routability, and offline GeoLite2 status | Verified |
| **Downloadable Report** | **Not implemented** (gap noted) | **Gap reported explicitly**; no ad-hoc reporting feature added without specification | Compliant with prompt |
| **Upload Constraints** | Extension, size, empty file checks in UploadZone | Preserved single `.eml`, 10 MB limit, non-empty validation | Verified |
| **External Calls** | Zero external calls | Strict zero-touch: no external reputation APIs, no URL fetching, no DNS queries | Verified |

---

## 3. Detailed Verification of Objectives

### Objective 1: Real Endpoint Invocation (`POST /api/v1/email/analyze`)
- Verified that `UploadZone.tsx` constructs a `FormData` payload containing the selected `.eml` file and issues a standard HTTP `POST` request to `/api/v1/email/analyze`.
- In local development, `vite.config.ts` proxies `/api` requests directly to the FastAPI server (`http://127.0.0.1:8000`).
- The payload format (`multipart/form-data` with field key `file`) and response schema (`EmailAnalysisResponse`) match the backend implementation in `backend/app/api/v1/endpoints/email.py`.

### Objective 2: Full Field Rendering Across All Modalities
1. **Parsing Status & Warnings:**
   - Displayed in `EmailOverviewBanner.tsx`.
   - Distinct badges for `RFC 5322 Parsed` (`success`) and `Partial Parse` (`partial_success`).
   - Detailed warning callout list rendered whenever `warnings.length > 0`.
2. **DistilBERT Model Status, Label, and Score:**
   - Rendered in both the top `EmailOverviewBanner` and `EvidenceFusionCard`.
   - Status badge shows `EVALUATED`, `UNAVAILABLE`, or `ERROR`.
   - Predicted label distinguishes `1 (Phishing Indicator)` from `0 (Benign Pattern)` with a note on the 0.5000 decision threshold.
   - Score is formatted to four decimals and explicitly titled **"Uncalibrated Phishing Score"**.
3. **Evidence Fusion Assessment & Factors:**
   - Displays `overall_category`: `HIGH_RISK_INDICATORS_PRESENT`, `REVIEW_RECOMMENDED`, `LOW_RISK_INDICATORS`, or `INSUFFICIENT_EVIDENCE` with tailored visual tokens and icons.
   - Displays natural-language `reasoning` justification.
   - Lists `contributing_factors` (with alert styling) and `inconclusive_or_missing_factors` (with informational styling).
4. **URL Analysis & Heuristics:**
   - Rendered in `ExtractedURLsCard.tsx`.
   - Batch summary shows total URLs, unique URLs, highest risk category (`HIGH`, `MEDIUM`, `LOW`, `INFO`), and risk breakdown counters.
   - Per-URL rows display protocol scheme, destination host classification (`Public`, `Private`, `Reserved`, `Documentation`), heuristic score (0–100), and collapsible rule observations (`rule_id`, `rule_name`, `severity`, `description`).
5. **Cryptographic Authentication Evidence:**
   - Rendered in `AuthenticationCard.tsx`.
   - Displays overall status (`EVALUATED`, `PARTIAL_EVIDENCE`, `NO_EVIDENCE`, `CONFLICTING_EVIDENCE`).
   - Three structured blocks:
     - **SPF:** Status (`PASS`, `FAIL`, etc.), evaluated domain, client IP, explanation, and downstream MTA limitation note.
     - **DKIM:** Status, raw DKIM signature header presence, signature count, signing domain (`d=`), key selector (`s=`), and explanation.
     - **DMARC:** Status, published policy (`p=none`, `quarantine`, `reject`), subdomain policy, receiver disposition, From header domain, alignment verification flag, and explanation.
   - Collapsible detailed header finding clauses showing raw header snippets and authserv-id identifiers.
6. **IP Classification & Origin Transit:**
   - Rendered in `IPCandidatesCard.tsx`.
   - Origin transit evaluation banner details the earliest recorded hop, apparent origin IP, routability, and offline GeoLite2 database availability (`database_available`).
   - Per-candidate hop table details hop index, IP, role hint (`Apparent Origin`, `Ingress Gateway`, `Internal Relay`), classification, public routability, and offline geolocation status.

### Objective 3: DistilBERT Failure Modes (`ERROR` & `UNAVAILABLE`)
- When `model_evidence.status === 'ERROR'` or `model_inference.status === 'ERROR'`:
  - The UI displays an explicit error alert badge (`ERROR (Unavailable)` or `ERROR (Execution Failed)`).
  - The predicted label is rendered as `N/A (Error)`.
  - The score is rendered as `N/A`.
  - An informational notice explains that model inference encountered an error and that the system does not assume benign intent.
- When `model_evidence.status === 'UNAVAILABLE'` or `model_inference.status === 'UNAVAILABLE'`:
  - The UI displays an `UNAVAILABLE` badge.
  - The predicted label is rendered as `N/A (Unavailable)`.
  - The score is rendered as `N/A`.
- Under no circumstances do `ERROR` or `UNAVAILABLE` states render as `Benign` or default to score 0.0000. Verified in unit test `test_model_state_rendering.test.ts`.

### Objective 4: Uncalibrated Score Caveats & No Safety Guarantee
- The DistilBERT model output is never described as a calibrated probability, confidence percentage, or certainty metric.
- The UI includes the exact research caveat in `EvidenceFusionCard.tsx`:
  > *"Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. Due to dataset source-label collinearity and synthetic token shortcuts (<USER>), this score represents a text-similarity heuristic and NOT a validated real-world probability."*
- When the assessment category is `LOW_RISK_INDICATORS`, the UI explicitly adds:
  > *"(Note: does NOT guarantee safety)"*
  The UI forbids labeling any email as "Safe", "Clean", or "Guaranteed Benign".
- The mandatory evidence fusion disclaimer is prominently rendered:
  > *"This assessment is an investigation support aid combining local forensic observations and model scores. It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts."*

### Objective 5: Defensive Handling of Edge States
- **Loading State:** UploadZone disables input and shows an active spinner (`Performing Forensic Extraction...`).
- **Oversized File:** Client-side check rejects files >10 MB before transmission; backend 413 response is also parsed and displayed cleanly.
- **Malformed / Non-.eml File:** Client-side check rejects non-`.eml` extensions; backend 400 response detail is rendered cleanly in an alert banner.
- **Empty File:** Client-side check rejects 0-byte uploads.
- **Backend Unavailable / Network Error:** Catches `fetch` errors and renders: *"Network error: ... Ensure the PhishIntel backend is running on port 8000."*
- **Partial Analysis / Missing Fields:** If optional sub-objects (`evidence_fusion`, `url_analysis`, `authentication_analysis`, `ip_intelligence`) are null, each component degrades gracefully to a "Data not available" notice without crashing or fabricating fallback scores.

### Objective 6: No Result Fabrication or Reassuring Defaults
- The frontend strictly consumes returned JSON keys:
  - Does not invent SPF/DKIM/DMARC passes if headers are missing.
  - Does not invent URL heuristic scores if URL intelligence is null.
  - Does not invent an originating IP if IP intelligence is null.
  - Does not invent an overall category if evidence fusion is null.

### Objective 7: Audit of Downloadable Reporting
- **Audit Result:** A thorough grep of `frontend/src` for `download`, `report`, and `export` confirmed that **no downloadable reporting feature currently exists in the frontend**.
- **Constraint Compliance:** Per instruction *"Do not add a new reporting feature if none exists without reporting that gap first"*, this gap is documented here as an area for future work rather than implementing an unrequested, untested reporting export.

### Objective 8: Workflow and Privacy Constraints
- Single-file workflow strictly preserved (`one-file-at-a-time`).
- No scan history, localStorage caching, or IndexedDB persistence.
- Zero external network requests: no virus scanners, no paid threat intel APIs, no DNS queries, no automatic HTTP link fetches.

---

## 4. Exact Files Changed and Created

| File Path | Type | Description |
| :--- | :--- | :--- |
| `frontend/src/types/forensics.ts` | Modified | Added complete TypeScript definitions for Phases 4–8A schemas. |
| `frontend/src/components/EvidenceFusionCard.tsx` | Created | New component rendering multi-modal fusion, model inference caveats, and factors. |
| `frontend/src/components/AuthenticationCard.tsx` | Created | New component rendering SPF, DKIM, and DMARC evidence, findings, and trust limits. |
| `frontend/src/components/ExtractedURLsCard.tsx` | Modified | Updated to display URL intelligence batch summaries, risk tiers, and rule observations. |
| `frontend/src/components/IPCandidatesCard.tsx` | Modified | Updated to display apparent origin assessment, public routability, and offline GeoLite2 status. |
| `frontend/src/components/EmailOverviewBanner.tsx` | Modified | Updated to display DistilBERT model inference state and fusion assessment category badges. |
| `frontend/src/App.tsx` | Modified | Added dedicated tabs for `Evidence Fusion` and `Authentication`, rendered all upgraded cards. |
| `frontend/tsconfig.app.json` | Modified | Added `"node"` to types array for TypeScript test runner support. |
| `frontend/package.json` | Modified | Added `"test"` script using Node 24 native test runner; updated lint script to `tsc -b --noEmit`. |
| `frontend/src/tests/integration_audit.test.ts` | Created | 8 focused unit tests for contract completeness, model failure modes, and upload validation. |
| `frontend/src/tests/live_contract.test.ts` | Created | 57 automated contract tests verifying deserialization of 8 real backend responses from all fixtures. |
| `frontend/src/tests/fixtures/real_backend_responses.json` | Created | Cached real backend responses from all 8 synthetic email fixtures for deterministic verification. |
| `docs/phase8/phase8b_frontend_integration_audit.md` | Created | This comprehensive integration audit document. |

---

## 5. Test Execution Results

### 5.1 Frontend Test Suite
- Executed via: `npm test` (`node --experimental-strip-types --test "src/tests/**/*.test.ts"`)
- Results:
  - **Suites:** 10
  - **Total Tests:** 65
  - **Passed:** 65
  - **Failed:** 0
  - **Duration:** 686 ms
- Coverage highlights:
  - Verified contract compliance against all 8 real fixture responses (`01_simple_plaintext.eml` through `08_missing_optional_headers.eml`).
  - Verified that `ERROR` and `UNAVAILABLE` model states never produce label 0 or a benign classification.
  - Verified that `LOW_RISK_INDICATORS` contains non-verdict safety disclaimers.
  - Verified client-side file upload constraints (extension, size, empty file).

### 5.2 Frontend Build & Static Type Check
- Executed via: `npm run lint` (`tsc -b --noEmit`) and `npm run build` (`tsc -b && vite build`)
- Results:
  - `tsc -b --noEmit`: Exited 0 with zero type errors or unused variable warnings.
  - `vite build`: Successfully built client production bundle (`dist/index.html`, `dist/assets/index-DOVGDRRf.css`, `dist/assets/index-DZzjaRT2.js`) in 1.07s.

### 5.3 Backend Test Suite
- Executed via: `D:\python\python.exe -m pytest backend/tests`
- Results:
  - **Collected:** 100 items
  - **Passed:** 100
  - **Failed:** 0
  - **Duration:** 157.92 s

### 5.4 Protected Research Artifact Integrity Verification
All four protected artifact hashes were verified via SHA-256 and matched baseline values bit-for-bit:

| Artifact Path | Expected SHA-256 Hash | Actual Verified SHA-256 Hash | Status |
| :--- | :--- | :--- | :--- |
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH** |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH** |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH** |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH** |

---

## 6. Audit Conclusion & Final Verdict

All objectives for Phase 8B have been verified:
1. Uploading a single `.eml` file calls the real `POST /api/v1/email/analyze` endpoint.
2. The UI renders the full multi-modal response: parsing status, DistilBERT model status and uncalibrated score, evidence fusion assessment and contributing factors, URL intelligence heuristics, SPF/DKIM/DMARC evidence, and IP classification with origin transit reconstruction.
3. Model `ERROR` and `UNAVAILABLE` states are visibly presented as error/unavailable states, never as benign.
4. The UI never refers to an uncalibrated score as a calibrated probability and never guarantees that an email is safe.
5. Loading, oversized, malformed, empty, and partial analysis states are handled defensively.
6. The frontend does not fabricate findings or replace missing modalities with reassuring defaults.
7. Downloadable report absence is audited and reported as a gap; no ad-hoc feature was introduced.
8. The one-file-at-a-time, zero-touch, offline workflow is preserved.

Final Status: **`PHASE_8B_VERIFIED`**
