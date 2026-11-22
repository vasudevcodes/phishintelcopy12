# Phase 10 — Final Application Acceptance Test Report

**Project:** PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Environment:** Windows 11, Google Antigravity, React 19 + TypeScript, FastAPI, PyTorch 2.6.0+cu124, DistilBERT Base Uncased, NVIDIA GeForce RTX 3050 6GB Laptop GPU  
**Execution Date:** November 1, 2026  
**Final Acceptance Verdict:** `PHASE_10_ACCEPTED`

---

## 1. Executive Summary & Environment Details

Phase 10 represents the final end-to-end operational acceptance testing of the PhishIntel application. In accordance with strict phase governance:
- **No Model Retraining:** DistilBERT model weights, classification decision boundary ($\tau = 0.5$), and tokenizer configuration were not altered.
- **Dataset Preservation:** All training, validation, and locked test datasets remain untouched.
- **Research Integrity:** All four protected cryptographic SHA-256 checksums were verified bit-for-bit identical.
- **Zero-Touch Protocol:** No external network requests, URL visits, or DNS lookups were performed.
- **End-to-End Live Validation:** The FastAPI backend and React frontend were launched as live services; all 8 test fixtures, boundary conditions, and model inference states were validated over live network sockets.

### Hardware & Software Environment Profile
- **Host OS:** Windows 11 (64-bit)
- **Python Runtime:** Python 3.13.15 (`D:\python\python.exe`)
- **Node Runtime:** Node.js v24.14.0
- **Frontend Stack:** React 19.2.8, TypeScript ~6.0.2, Vite 8.3.2, Tailwind CSS 3.4.19
- **Backend Stack:** FastAPI 0.115.0, Uvicorn 0.34.0, BeautifulSoup4 / lxml, Python standard `ipaddress` and `urllib.parse`
- **Acceleration Device:** NVIDIA GeForce RTX 3050 6GB Laptop GPU (CUDA 12.4, PyTorch 2.6.0+cu124)

---

## 2. Test 1 — Application Startup Results

Both backend and frontend services were started as background processes and monitored for operational readiness:

### 2.1 Backend Service Startup
- **Command:** `D:\python\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000`
- **Working Directory:** `c:\Users\Lenovo\Desktop\PhishIntel\backend`
- **Observed Startup Log:**
  ```text
  INFO:     Started server process [25168]
  INFO:     Waiting for application startup.
  INFO:     Application startup complete.
  INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
  ```
- **Health Endpoint Check:**
  - `GET http://127.0.0.1:8000/health` -> HTTP 200 OK
  - **Payload:** `{"status": "healthy", "service": "PhishIntel", "phase": "Phase 1 - Forensic Foundation"}`
- **Backend Error Status:** Zero startup errors or warnings.

### 2.2 Frontend Service Startup
- **Command:** `npm run dev -- --host 127.0.0.1 --port 5173`
- **Working Directory:** `c:\Users\Lenovo\Desktop\PhishIntel\frontend`
- **Observed Startup Log:**
  ```text
  > frontend@0.0.0 dev
  > vite --host 127.0.0.1 --port 5173

    VITE v8.3.2  ready in 464 ms

    ➜  Local:   http://127.0.0.1:5173/
  ```
- **Frontend Index Check:**
  - `GET http://127.0.0.1:5173/` -> HTTP 200 OK (952 bytes HTML containing `<div id="root">`)
- **Vite Proxy Verification:**
  - Requests sent to `http://127.0.0.1:5173/api/v1/email/analyze` successfully reverse-proxy to `http://127.0.0.1:8000/api/v1/email/analyze` with zero CORS anomalies.

---

## 3. Test 2 — Real Email Upload Scenarios

All operational fixtures were uploaded one by one across both the direct backend port (`8000`) and the frontend reverse proxy port (`5173`). The execution was automated via `scripts/phase10_live_acceptance_test.py` over real TCP sockets.

| # | Fixture Name | Test Scenario Description | File Size | Expected Status | Direct Backend (8000) | Frontend Proxy (5173) | Observed Forensic Outcome |
| :-: | :--- | :--- | :-: | :-: | :-: | :-: | :--- |
| **1** | `01_simple_plaintext.eml` | Ordinary plain-text email | 279 B | 200 OK | **200 OK** | **200 OK** | Status `success`; text extracted; model score `0.0538` (label `0`); SPF/DKIM/DMARC absent; category `INSUFFICIENT_EVIDENCE`. |
| **2** | `02_html_only.eml` | HTML-only email | 760 B | 200 OK | **200 OK** | **200 OK** | Status `success`; HTML sanitized to text; 1 URL extracted; model score `0.9953` (label `1`); category `REVIEW_RECOMMENDED`. |
| **3** | `03_multipart_plain_html.eml` | Multipart plain & HTML | 998 B | 200 OK | **200 OK** | **200 OK** | Status `success`; plain text preferred for inference; 2 URLs extracted; model score `0.8890` (label `1`); category `REVIEW_RECOMMENDED`. |
| **4** | `05_multiple_urls.eml` | Email with multiple URLs | 1,236 B | 200 OK | **200 OK** | **200 OK** | Status `success`; 4 URLs extracted; risk tier LOW; model score `0.9974` (label `1`); category `REVIEW_RECOMMENDED`. |
| **5** | `08_missing_optional_headers.eml` | Missing optional headers | 239 B | 200 OK | **200 OK** | **200 OK** | Status `success`; Subject, To, Msg-ID default to `None`/`[]`; model score `0.8589` (label `1`); zero crashes. |
| **6** | `07_malformed.eml` | Malformed structure | 633 B | 200 OK | **200 OK** | **200 OK** | Status `success` with non-fatal warnings captured; model score `0.0023` (label `0`); category `INSUFFICIENT_EVIDENCE`. |
| **7** | `04_attachments.eml` | Email with MIME attachments | 1,345 B | 200 OK | **200 OK** | **200 OK** | Status `success`; 2 attachments extracted (`invoice_october.pdf`, `payment_instructions.txt`); SHA-256 computed; zero disk writes. |
| **8** | `06_multiple_received_hops.eml` | Multiple Received transit hops | 1,598 B | 200 OK | **200 OK** | **200 OK** | Status `success`; 5 IP hops analyzed; apparent origin identified as `2001:db8:85a3::8a2e:370:7334` (Documentation range). |
| **9** | `zero_byte.eml` | Empty file boundary limit | 0 B | 400 Bad Req | **400 Bad Req** | **400 Bad Req** | Rejected immediately: `"Uploaded file is empty (0 bytes)."`. Client and gateway enforce rejection. |
| **10** | `oversized_11mb.eml` | Oversized 11 MB boundary limit | 11,534,336 B | 413 Payload Large | **413 Payload Large** | **413 Payload Large** | Rejected before full buffer allocation: `"File exceeds maximum upload limit of 10 MB (11534336 bytes read)."`. |

---

## 4. Test 3 — Model Inference Verification

- **Checkpoint Ingestion:** Verified that the live service loads weights from `models/distilbert_baseline/model.safetensors` (`267.8 MB`).
- **Cold-Start vs Cached Performance:** Initial model load completed in `0.88s` on RTX 3050 GPU VRAM; subsequent evaluations executed in `8–22 ms`.
- **Inference Results on Live Uploads:**
  - `01_simple_plaintext.eml`: Uncalibrated Score = `0.0538`, Predicted Label = `0 (Benign)`
  - `02_html_only.eml`: Uncalibrated Score = `0.9953`, Predicted Label = `1 (Phishing)`
  - `03_multipart_plain_html.eml`: Uncalibrated Score = `0.8890`, Predicted Label = `1 (Phishing)`
  - `05_multiple_urls.eml`: Uncalibrated Score = `0.9974`, Predicted Label = `1 (Phishing)`
  - `08_missing_optional_headers.eml`: Uncalibrated Score = `0.8589`, Predicted Label = `1 (Phishing)`
  - `07_malformed.eml`: Uncalibrated Score = `0.0023`, Predicted Label = `0 (Benign)`
- **Failure Mode Defense:**
  - When model inference is unavailable or experiences an internal exception, status strictly transitions to `UNAVAILABLE` or `ERROR`.
  - The model score and predicted label return `None` (`null` in JSON).
  - The application **never defaults failed inference to benign (`0`)**.
- **Calibration Caveat Integrity:**
  - In all responses and UI cards, the score is strictly labeled:
    `"uncalibrated_score: DistilBERT text output (0.0000 - 1.0000)"`.
  - The calibration caveat is explicitly attached:
    > *"Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. This score represents a text-similarity heuristic and NOT a validated real-world probability."*

---

## 5. Test 4 — Forensic Analysis Verification

### 5.1 RFC 5322 Email Header Analysis
- Headers are safely parsed and decoded according to RFC 2047.
- Missing optional headers (Date, Subject, Message-ID, Return-Path, To) are represented cleanly as `None` or empty lists without throwing runtime exceptions.
- Received headers are preserved in chronological order.

### 5.2 Cryptographic Authentication Evidence (SPF / DKIM / DMARC)
- Downstream MTA assertions (`Authentication-Results` and `Received-SPF`) are parsed deterministically.
- `01_simple_plaintext.eml`: SPF = `NOT_PRESENT`, DKIM = `NOT_PRESENT`, DMARC = `NOT_PRESENT`.
- Absent authentication evidence is strictly classified as absence of data, **never as standalone proof of phishing**.
- Conflicting evidence (e.g. DKIM failure alongside SPF pass) is flagged as conflicting evidence for analyst review.

### 5.3 URL Intelligence & Lexical Heuristics
- URLs are parsed and analyzed purely via regular expressions and Python's standard `urllib.parse` (RFC 3986).
- `05_multiple_urls.eml`: Extracted 4 URLs with detailed features:
  - Scheme, domain, host type (`domain`, `ipv4`, `ipv6`), IP literal checks, host classification (`public`, `private`, `reserved`, `documentation`).
  - Heuristic risk scores (0–100) and risk tiers (`HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Lexical rules triggered: `RULE_IP_LITERAL_HOST`, `RULE_SUSPICIOUS_KEYWORD`.
- **Zero-Touch Guarantee:** Confirmed zero network sockets, zero DNS queries, and zero external HTTP fetches.

### 5.4 IP Intelligence & Geolocation
- IP candidates from `Received` headers are classified via Python `ipaddress` RFC 6890 / 5737.
- `06_multiple_received_hops.eml`: Correctly identified transit origin hop `2001:db8:85a3::8a2e:370:7334` as IPv6 documentation block.
- Non-routable and private IPs are flagged neutrally and are **never interpreted as proof of maliciousness**.
- When offline MaxMind GeoLite2 databases are not installed, the engine gracefully reports `DATABASE_UNAVAILABLE` without erroring.

### 5.5 Evidence Fusion & Risk Categories
- Signals are synthesized into 4 transparent tiers:
  - `HIGH_RISK_INDICATORS_PRESENT`
  - `REVIEW_RECOMMENDED`
  - `LOW_RISK_INDICATORS (No Guarantee of Safety)`
  - `INSUFFICIENT_EVIDENCE`
- Contributing factors and missing factors are explicitly itemized.
- Non-verdict disclaimer is mandatory on all outputs.

---

## 6. Test 5 — HTML Forensic Report Verification

Standalone HTML reports were generated from actual live backend responses via `scripts/generate_sample_reports.js`:
- `report_01_simple_plaintext.html` (21,327 bytes)
- `report_04_attachments.html` (21,969 bytes)
- `report_05_multiple_urls.html` (29,410 bytes)
- `report_06_multiple_received_hops.html` (23,404 bytes)
- `report_08_missing_optional_headers.html` (21,329 bytes)

### 6.1 Security & Content Security Policy (CSP) Audit
Each report was audited and verified against the following criteria:
1. **W3C Content Security Policy Spec Alignment:**
   - Injected `<meta>` policy:
     ```html
     <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';">
     ```
   - Complies with W3C CSP Level 2/3: `sandbox` is omitted from `<meta>` as user agents ignore it.
   - Script execution is blocked (`script-src 'none'`).
   - Outbound network requests are blocked (`connect-src 'none'`).
   - Form actions and objects are blocked (`form-action 'none'`, `object-src 'none'`).
2. **Entity Escaping:** All email subjects, headers, URLs, rules, and attachment filenames are sanitized via `escapeHtml()`.
3. **Offline Self-Containment:** All styles are embedded inline; zero external scripts, CDNs, or web fonts are required.
4. **Print Media Styles:** Embedded `@media print` CSS ensures clean pagination and contrast when printing or saving as PDF in browsers.

---

## 7. Test 6 — Privacy and Security Review Observations

1. **Zero Persistence Guarantee:**
   - Checked filesystem for SQLite/database files: `0` found.
   - Checked for cached email files on disk: `0` found.
   - All email parsing and inference takes place 100% in ephemeral memory.
2. **Attachment Execution Isolation:**
   - In `04_attachments.eml`, attachments (`invoice_october.pdf` and `payment_instructions.txt`) were analyzed solely for MIME headers, byte sizes, and cryptographic SHA-256 hashes.
   - No attachment binaries were written to disk or executed.
3. **Zero External Communication:**
   - URL intelligence and IP intelligence ran completely offline.
   - No WHOIS, DNS, or socket requests were initiated.
4. **Error Masking:**
   - Gateway errors return standard structured JSON envelopes (`{"detail": "..."}`).
   - Server file paths, stack traces, and environment variables are never exposed to clients.

---

## 8. Test 7 — Research Integrity & Protected Hash Verification

All four protected research artifacts were recalculated using cryptographic SHA-256 checksums:

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

| Partition / Artifact | Expected SHA-256 Hash | Observed SHA-256 Hash | Integrity Status |
| :--- | :--- | :--- | :---: |
| **`train.csv`** | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH (BIT-IDENTICAL)** |
| **`validation.csv`** | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH (BIT-IDENTICAL)** |
| **`test.csv`** | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH (BIT-IDENTICAL)** |
| **`model.safetensors`** | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH (BIT-IDENTICAL)** |

---

## 9. Test Failures, Environment Constraints & Unresolved Issues

### 9.1 Browser Automation Driver Environment Constraint
- **Constraint Observed:** When launching automated browser driving via Playwright (`open_browser_url`), the subagent reported:
  `failed to create browser context: failed to run playwright manager: failed to install playwright: could not install driver: error: got non 200 status code: 404 (404 Not Found) from https://playwright.azureedge.net/builds/driver/playwright-1.57.0-win32_x64.zip`.
- **Handling & Resolution:** In accordance with user guidance, end-to-end testing was executed via live HTTP socket calls directly against both the running Vite frontend reverse proxy (`http://127.0.0.1:5173/api/v1/email/analyze`) and the live FastAPI backend (`http://127.0.0.1:8000/api/v1/email/analyze`), supplemented by the 76-test frontend TypeScript suite and report generator audit.
- **Unresolved Defects:** **Zero code defects.** All 112 backend tests pass, all 76 frontend tests pass, and zero TypeScript linting or build errors exist.

---

## 10. Complete Test Summary

| Test Harness / Suite | Tests Executed | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Backend Full Test Suite** (`pytest backend/tests`) | 112 | 112 | 0 | **PASS** |
| **Frontend Test Runner** (`npm test`) | 76 | 76 | 0 | **PASS** |
| **Frontend Type Check** (`npm run lint` / `tsc -b`) | — | — | 0 errors | **PASS** |
| **Frontend Production Build** (`npm run build`) | — | — | Clean bundle | **PASS** |
| **Live HTTP Acceptance Tests** (`phase10_live_acceptance_test.py`) | 10 | 10 | 0 | **PASS** |
| **Offline HTML Report Generation** (`generate_sample_reports.js`) | 5 | 5 | 0 | **PASS** |
| **Cryptographic Hash Verification** | 4 | 4 | 0 | **MATCH** |

---

## 11. Final Acceptance Verdict

```
PHASE_10_ACCEPTED
```

All required acceptance criteria have been verified against the running application services. The live backend, frontend proxy, local DistilBERT inference engine, forensic analyzers, offline HTML report generator, and security protections operate seamlessly together in strict accordance with scientific integrity and security mandates.
