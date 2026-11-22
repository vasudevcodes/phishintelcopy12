# Phase 9.1 — Final Validation Discrepancy Audit

**Project:** PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Environment:** Windows, Google Antigravity, React + TypeScript, FastAPI, DistilBERT, RTX 3050 6GB  
**Execution Date:** November 1, 2026  
**Final Status Verdict:** `PHASE_9_1_VERIFIED`

---

## 1. Executive Summary

Phase 9.1 executes a rigorous discrepancy audit of the Phase 9 validation deliverables, research metrics, dataset provenance terminology, Content Security Policy enforcement, and test evidence classification.

All identified discrepancies were investigated, verified against canonical source artifacts, and fully reconciled without modifying model weights, classification decision boundaries, or dataset partitions.

### Key Audit Outcomes
1. **Research Metrics Reconciled:** The canonical locked Phase 3C test metrics (Test Accuracy: 98.76%, Phishing F1: 96.50%, ROC-AUC: 0.9995) were reaffirmed against `models/distilbert_baseline/test_evaluation_results.json`. The errant `0.9822` figure was traced to an unverified documentation drafting placeholder and eliminated.
2. **Dataset-Source Terminology Corrected:** The canonical corpus composition was confirmed as 100% source-label collinear across `CEAS_08_0` (benign), `SpamAssasin_0` (benign), and `phishing_pot` (phishing). Unsupported references claiming Enron or Nazario were sources in this PhishMMF experiment were excised from Phase 8A and Phase 9 documentation.
3. **W3C Content Security Policy Spec Alignment:** The meta-delivered CSP in `frontend/src/utils/reportGenerator.ts` was audited against W3C CSP Level 2/3 specifications. The unsupported `sandbox` directive was removed from the meta tag, and explicit blocking directives (`script-src 'none'`, `object-src 'none'`, `connect-src 'none'`, `form-action 'none'`, `base-uri 'none'`, `frame-src 'none'`) were enforced and verified with focused regression tests.
4. **Test Evidence Types Explicitly Disambiguated:** All 12 validation scenarios were clearly classified into automated backend in-process tests (`TestClient`), frontend fixture/contract tests, live HTTP requests, and manual browser checks.
5. **Research Integrity Confirmed:** All four protected research artifact SHA-256 hashes remain bit-for-bit identical. All 112 backend tests and 76 frontend tests passed cleanly.

---

## 2. Research Metrics Reconciliation

### 2.1 Canonical Phase 3C Locked Test Evaluation Baseline
The locked test evaluation conducted in Phase 3C (`docs/phase3/phase3c_test_evaluation_report.md`) on the held-out test split (`data/processed/phishmmf/test.csv`, SHA-256: `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e`) produced the following exact results:

| Metric Name | Canonical Test Value | Exact Fraction | Canonical JSON Field (`test_evaluation_results.json`) |
| :--- | :---: | :---: | :--- |
| **Test Accuracy** | **98.76%** | $\frac{715}{724}$ | `"test_accuracy": 0.9875690607734806` |
| **Phishing Precision (Class 1)** | **96.12%** | $\frac{124}{129}$ | `"phishing_precision": 0.9612403100775194` |
| **Phishing Recall (Class 1)** | **96.88%** | $\frac{124}{128}$ | `"phishing_recall": 0.96875` |
| **Phishing F1-Score** | **96.50%** | $\frac{2 \cdot P \cdot R}{P + R}$ | `"phishing_f1": 0.9649805447470817` |
| **ROC-AUC** | **0.9995** | Continuous AUC | `"roc_auc": 0.9994756711409396` |
| **Cross-Entropy Loss** | **0.0376** | — | `"test_loss": 0.037584675609736155` |
| **False Positive Rate (FPR)** | **0.84%** | $\frac{5}{596}$ | `"false_positive_rate": 0.008389261744966443` |
| **False Negative Rate (FNR)** | **3.12%** | $\frac{4}{128}$ | `"false_negative_rate": 0.03125` |
| **Macro-F1 Score** | **97.87%** | — | `"macro_f1": 0.9787119348420548` |
| **Weighted-F1 Score** | **98.76%** | — | `"weighted_f1": 0.9875880267818992` |

### 2.2 Provenance of the Phase 9 Discrepancy
- **Observed Discrepancy:** The initial Phase 9 documentation text contained a statement: `(e.g., Test Accuracy = 0.9822, Test F1 = 0.9822)`.
- **Root Cause Analysis:** Investigation revealed that `0.9822` did not come from any model evaluation pass or test artifact. Neither `models/distilbert_baseline/test_evaluation_results.json` nor `validation_evaluation_results.json` contain `0.9822`. Instead, the figure was an unverified drafting placeholder introduced during documentation preparation.
- **Resolution:** The Phase 9 report ([docs/phase9/phase9_end_to_end_validation.md](file:///c:/Users/Lenovo/Desktop/PhishIntel/docs/phase9/phase9_end_to_end_validation.md)) was updated to cite exclusively the canonical, locked test evaluation metrics from Phase 3C. Zero model retraining or threshold adjustment was performed.

---

## 3. Dataset-Source Terminology Verification

### 3.1 Canonical Corpus Manifest & Split Verification
The canonical dataset manifest (`data/processed/phishmmf/dataset_manifest.json`) and Phase 3D research audit (`docs/phase3/phase3d_source_leakage_audit.md`) establish the definitive provenance of the PhishMMF corpus:

| Source Identifier | Description | Temporal Origin | Benign Records (`label=0`) | Phishing Records (`label=1`) | Total Records | Share |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`CEAS_08_0`** | CEAS 2008 Spam Challenge Ham | ~2007–2008 | **2,981** | **0** | 2,981 | 41.18% |
| **`SpamAssasin_0`** | Apache SpamAssassin Corpus Ham | ~2002–2006 | **2,978** | **0** | 2,978 | 41.14% |
| **`phishing_pot`** | Live Honeypot Captures | ~2023–2024 | **0** | **1,280** | 1,280 | 17.68% |
| **Total** | — | — | **5,959** | **1,280** | **7,239** | **100.0%** |

### 3.2 Correction of Unsupported Enron / Nazario References
- **Audit Finding:** Previous documentation drafting inadvertently referred to "Enron" as the benign source and "Nazario" as the phishing source (in `docs/phase9/phase9_end_to_end_validation.md` line 179 and `docs/phase8/phase8a_model_integration_audit.md` line 250).
- **Correction Applied:**
  - In `docs/phase9/phase9_end_to_end_validation.md`: Replaced `(e.g., Enron benign vs. Nazario/SpamAssassin phishing)` with the verified source composition: `(CEAS and SpamAssassin for benign vs. phishing_pot for phishing)`.
  - In `docs/phase8/phase8a_model_integration_audit.md`: Corrected line 250 to state `(CEAS and SpamAssassin for benign vs. phishing_pot for phishing)`.
  - Confirmed that Enron and Nazario represent external historical benchmarks discussed as candidates for future Tier 3 out-of-distribution evaluations, but were **not** part of the PhishMMF corpus used to train and evaluate this baseline.

---

## 4. Standalone HTML Content Security Policy Audit

### 4.1 W3C Specification Compliance: The `sandbox` Directive
- **W3C CSP Level 2 & Level 3 Standard:** The W3C specification explicitly mandates:
  > *"A policy specified via a meta element cannot define the report-uri, frame-ancestors, or sandbox directives. Such directives MUST be ignored if they appear in a policy delivered via a meta element."*
- **Audit Finding:** `frontend/src/utils/reportGenerator.ts` previously included `sandbox;` inside `<meta http-equiv="Content-Security-Policy" content="...">`. Compliant browsers (Chrome, Firefox, Safari) disregard `sandbox` in meta elements and log a console warning.
- **Remediation:** `sandbox` was removed from the `<meta>` element. Strict isolation is achieved through explicitly enforced CSP directives supported in `<meta>`:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';">
  ```

### 4.2 Directive-by-Directive Enforcement Verification

| Directive | Enforced Setting | Protection Delivered in Standalone HTML Report |
| :--- | :--- | :--- |
| **`default-src`** | `'none'` | Fallback denial for any resource type not explicitly allowed. |
| **`script-src`** | `'none'` | Completely blocks all JavaScript execution (inline `<script>`, event handlers, external `.js`). |
| **`object-src`** | `'none'` | Completely blocks plugins, Java applets, Flash, `<object>`, and `<embed>`. |
| **`connect-src`** | `'none'` | Completely blocks outbound network calls (`fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`). |
| **`form-action`** | `'none'` | Completely blocks form submissions to external phishing/credential collection endpoints. |
| **`base-uri`** | `'none'` | Completely blocks `<base href="...">` injection to prevent relative URL hijacking. |
| **`frame-src`** | `'none'` | Completely blocks embedding child `<iframe>` elements. |
| **`media-src`** | `'none'` | Completely blocks audio and video media streams. |
| **`font-src`** | `'none'` | Completely blocks external web font loading. |
| **`style-src`** | `'unsafe-inline'` | Safely permits the embedded CSS stylesheet required for offline visual styling and print media. |
| **`img-src`** | `data:` | Allows inline base64 images while blocking external image requests (tracking pixels/web beacons). |

### 4.3 HTML Entity Escaping Audit
Every email-derived text property rendered in the report is routed through `escapeHtml()`:
```typescript
export function escapeHtml(str: string | null | undefined): string {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
```
All email fields—including Subject, From, To, Cc, Bcc, Date, Message-ID, Return-Path, Reply-To, Content-Type, URL strings, URL domains, URL heuristic observation names and descriptions, attachment filenames, attachment MIME types, attachment SHA-256 hashes, forensic parser warnings, and fusion factor explanations—are sanitized.

### 4.4 Focused Regression Tests Added
Two focused regression tests were added to `frontend/src/tests/report_generator.test.ts`:
- **Test 10 (`Focused Content Security Policy Directive Audit`):** Extracts the meta CSP tag from the generated report, verifies presence of `script-src 'none'`, `object-src 'none'`, `connect-src 'none'`, `form-action 'none'`, `base-uri 'none'`, and confirms that `sandbox` is omitted per W3C specification.
- **Test 11 (`Comprehensive Script-Injection Payload Neutralization`):** Passes hostile multi-vector injection payloads across 20+ email fields (including `<script>`, `<svg onload>`, `<img onerror>`, `<iframe src>`, `<marquee onstart>`, event handlers) and confirms zero unescaped tags exist in the generated document.

---

## 5. Separation of Test Evidence Types

The Phase 9 validation scenarios were reviewed to ensure full transparency regarding the exact execution environment and evidence source:

| Scenario | Evidence Category | Execution Method & Test Harness | Live Application Execution Detail |
| :-: | :--- | :--- | :--- |
| **1: Ordinary plain-text email** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_01_ordinary_plaintext`) & `live_contract.test.ts` | Real `01_simple_plaintext.eml` parsed; local DistilBERT checkpoint invoked via PyTorch; full pipeline response verified. |
| **2: HTML-only email** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_02_html_only`) & `live_contract.test.ts` | Real `02_html_only.eml` parsed; BeautifulSoup sanitizes HTML; URLs extracted; local DistilBERT evaluated. |
| **3: Multipart plain-text & HTML** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_03_multipart_plain_and_html`) & `live_contract.test.ts` | Real `03_multipart_plain_html.eml` processed; multi-part structure verified; DistilBERT evaluated plain text. |
| **4: Email with multiple URLs** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_04_multiple_urls`) & `live_contract.test.ts` | Real `05_multiple_urls.eml` processed; 3 URLs parsed, normalized, and classified into risk tiers. |
| **5: Missing/malformed headers** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_05_missing_and_malformed_headers`) | Real `08_missing_optional_headers.eml` and `07_malformed.eml` parsed; handles omitted Subject/Message-ID/Return-Path gracefully. |
| **6: SPF/DKIM/DMARC auth states** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_06_authentication_absent_and_conflicting`) | Verified absent auth (`01_simple_plaintext`) vs conflicting auth (DKIM fail alongside SPF pass); non-verdict preserved. |
| **7: IP classification ranges** | Automated Backend Integration | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_07_ip_range_classifications`) | Verified `142.250.190.46` (Public), `198.51.100.99` (Documentation), `10.240.0.5` (Private), `127.0.0.1` (Loopback). |
| **8: Corrupted email payload** | Automated Backend Integration & Frontend Contract | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_08_corrupted_and_empty_payloads`) | Corrupted binary streams processed; parser returns partial success with warnings; zero unhandled 500 crashes. |
| **9: Zero-byte & oversized uploads** | Automated Backend Integration & Frontend Validation | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_09_upload_boundary_limits`) & `integration_audit.test.ts` | Gateway enforces boundary limits: zero-byte rejected with 400; 11 MB rejected with 413. Client-side guards verified. |
| **10: Model unavailable / error** | Automated Backend Integration & Frontend Unit Tests | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_10_model_failure_modes`) & `integration_audit.test.ts` | Model failure modes tested; status set to `ERROR` / `UNAVAILABLE`; score set to `None`; **never** treated as benign. |
| **11: Report download & CSP** | Frontend Contract & Report Generation Tests | `frontend/src/tests/report_generator.test.ts` (Tests 1–11) & `phase9_e2e_validation.py` (`test_scenario_11_report_download_contract`) | Real API response rendered into standalone HTML; CSP meta tag verified; XSS payloads neutralized; zero persistence. |
| **12: Missing optional modalities** | Frontend Defensive Unit Tests | `backend/tests/test_phase9_e2e_validation.py` (`test_scenario_12_defensive_partial_analysis`) & `report_generator.test.ts` (Test 8) | Partial responses omitting URL/Auth/IP intelligence render safely without client crashes or fabricated values. |

---

## 6. Research Integrity & Checksum Verification

All four protected research artifacts were re-verified using cryptographic SHA-256 checksums on the local filesystem:

```powershell
python -c "
import hashlib
files = {
    'train': ('data/processed/phishmmf/train.csv', '72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c'),
    'validation': ('data/processed/phishmmf/validation.csv', '40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab'),
    'test': ('data/processed/phishmmf/test.csv', '1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e'),
    'model_weights': ('models/distilbert_baseline/model.safetensors', 'fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8')
}
for name, (path, expected) in files.items():
    h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    assert h == expected, f'Mismatch for {name}: {h} != {expected}'
    print(f'{name}: MATCH ({h})')
print('ALL PROTECTED HASHES MATCH EXACTLY!')
"
```

**Verification Results:**
- `train.csv`: `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` (**MATCH**)
- `validation.csv`: `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` (**MATCH**)
- `test.csv`: `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` (**MATCH**)
- `model.safetensors`: `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` (**MATCH**)

---

## 7. Full Test Suite Execution Summary

### 7.1 Backend Automated Pytest Suite
- **Command:** `D:\python\python.exe -m pytest backend/tests`
- **Results:** **112 passed**, 1 warning in 105.69s.
- **Coverage:** Full API routing, RFC 5322 parsing, URL lexical heuristics, cryptographic SPF/DKIM/DMARC interpretation, IP transit classification, DistilBERT model inference, Evidence Fusion synthesis, and Phase 9 validation scenarios.

### 7.2 Frontend Test Suite
- **Command:** `npm test` in `frontend/`
- **Results:** **76 passed**, 0 failed, 11 test suites in 1.06s.
- **Coverage:** Integration contracts, 8 live backend fixture response contracts, report generator filename formatting, byte formatting, error/unavailable inference states, non-verdict safety disclaimers, defensive handling of null modalities, W3C CSP directive audit (Test 10), and multi-vector XSS payload neutralization (Test 11).

### 7.3 Frontend Linter & Typecheck
- **Command:** `npm run lint` (`tsc -b --noEmit`)
- **Results:** **0 errors**. Full TypeScript type conformance verified.

### 7.4 Frontend Production Build
- **Command:** `npm run build` (`tsc -b && vite build`)
- **Results:** Successfully built production bundle in 4.66s without warnings.

---

## 8. Changed Files in Phase 9.1

| File Path | Description of Change |
| :--- | :--- |
| `frontend/src/utils/reportGenerator.ts` | Updated Content Security Policy meta element to explicitly block scripts, objects, connections, and forms, while removing unsupported `sandbox` directive per W3C specification. |
| `frontend/src/tests/report_generator.test.ts` | Added focused regression tests (Tests 10 and 11) auditing W3C-compliant CSP directives and comprehensive script-injection payload neutralization across all email artifacts. |
| `docs/phase8/phase8a_model_integration_audit.md` | Corrected dataset source composition terminology (CEAS/SpamAssassin for benign vs. phishing_pot for phishing). |
| `docs/phase9/phase9_end_to_end_validation.md` | Updated Phase 9 validation report with canonical Phase 3C test metrics, verified dataset source composition, W3C CSP specification details, and explicit test evidence separation. |
| `docs/phase9/phase9_1_discrepancy_audit.md` | Created comprehensive Phase 9.1 discrepancy audit document reconciling all research metrics, dataset terminology, CSP enforcement, and test evidence classification. |

---

## 9. Final Status Verdict

```
PHASE_9_1_VERIFIED
```

All four audit objectives have been thoroughly verified and resolved. The canonical research metrics are confirmed against locked evaluation artifacts; dataset source composition accurately reflects CEAS, SpamAssassin, and phishing_pot; Content Security Policy directives adhere strictly to W3C meta element specifications; and all validation scenarios are transparently categorized by evidence type.
