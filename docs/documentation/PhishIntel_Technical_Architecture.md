# PhishIntel — Technical Architecture & Subsystem Specification

**Document Title:** Complete Technical Architecture & System Engineering Specification  
**Project:** PhishIntel – Transformer and NLP-Based Email Phishing Detection and IP Intelligence  
**Target Standard:** VTU Final Year Engineering Technical Documentation  
**Version:** 1.0.0-Production  

---

## 1. System Overview and Architectural Philosophy

PhishIntel is designed around the core cybersecurity principle of **defense-in-depth through multi-modal evidence corroboration**. Rather than relying on a single detection heuristic or treating a deep learning language model as an infallible oracle, PhishIntel integrates five complementary forensic dimensions:

1. **RFC 5322 Ingestion and Structural Decomposition**: Extracts standard internet email headers, decodes multi-part MIME entities, calculates cryptographic digests of attachments in memory, and preserves the complete chronological transit chain.
2. **Deterministic Lexical URL Intelligence**: Evaluates embedded hyperlinks through RFC 3986 lexical parsing, protocol inspection, authority deception detection, homoglyph decoding, and brand lookalike pattern matching—strictly without issuing outbound network requests.
3. **Cryptographic Authentication Evidence Analysis**: Evaluates receiver-reported assertions (SPF, DKIM, DMARC) across intermediate mail transfer agent (MTA) headers, while strictly enforcing offline provenance boundaries.
4. **IP Transit Intelligence & Topological Classification**: Analyzes candidate IP addresses across `Received` headers, classifies each into strict RFC network scopes, identifies apparent origin nodes, and matches infrastructure against verified provider catalogues.
5. **Transformer-Based NLP Classification with Corroboration Dampening**: Applies a fine-tuned DistilBERT model to evaluate textual lures, but explicitly dampens isolated textual predictions when external technical indicators confirm benign infrastructure alignment.

```
+---------------------------------------------------------------------------------------------------------+
|                                        PHISHINTEL ARCHITECTURE                                          |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|   +-----------------------+     HTTP POST (Multipart .eml)     +------------------------------------+   |
|   |   React 19 Frontend   | ---------------------------------> |       FastAPI Gateway (v1)         |   |
|   |  (Vite + TypeScript)  | <--------------------------------- |      (10 MB Buffer Enforcer)       |   |
|   +-----------------------+         JSON Analysis Payload      +-----------------+------------------+   |
|                                                                                  |                      |
|                                                                                  v                      |
|                                                                +------------------------------------+   |
|                                                                |       RFC 5322 Email Parser        |   |
|                                                                |   (MIME Walker & SHA-256 Hasher)   |   |
|                                                                +-----------------+------------------+   |
|                                                                                  |                      |
|               +--------------------+---------------------+-----------------------+                      |
|               |                    |                     |                       |                      |
|               v                    v                     v                       v                      |
|     +------------------+  +-----------------+  +-------------------+  +---------------------+           |
|     | URL Intelligence |  | IP Intelligence |  | Email Auth Engine |  | DistilBERT NLP      |           |
|     |  (Zero-Network   |  | (RFC Scopes &   |  | (SPF, DKIM, DMARC |  | (Uncalibrated Text  |           |
|     |  Lexical Rules)  |  | Apparent Origin)|  | Reported Headers) |  | Heuristic Engine)   |           |
|     +--------+---------+  +--------+--------+  +---------+---------+  +----------+----------+           |
|              |                     |                     |                       |                      |
|              +---------------------+---------------------+-----------------------+                      |
|                                    |                                                                    |
|                                    v                                                                    |
|     +---------------------------------------------------------------------------------------------+     |
|     |                           Evidence-Based Phishing Scoring Engine                            |     |
|     |   - Sender Auth: 25 pts  | URL Intel: 25 pts   | Content & Language: 20 pts                 |     |
|     |   - DistilBERT: 20 pts (Corroboration Dampening) | Header & IP Infrastructure: 10 pts       |     |
|     |   - Critical Threat Floor: >= 75 points  | Auth Failure Floor: >= 30 points                 |     |
|     +----------------------------------------------+----------------------------------------------+     |
|                                                    |                                                    |
|                                                    v                                                    |
|     +---------------------------------------------------------------------------------------------+     |
|     |                                   Final Forensic Output                                     |     |
|     |   - Structured JSON API Response (RFC Schema Compliant)                                     |     |
|     |   - Interactive React Forensic Dashboard with 0-100 Risk Meter                              |     |
|     |   - Standalone Downloadable HTML Forensic Report (W3C CSP Level 3 Strict)                   |     |
|     +---------------------------------------------------------------------------------------------+     |
|                                                                                                         |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. End-to-End Processing Pipeline

The execution lifecycle of an email analysis request proceeds through seven sequential stages:

```
[User .eml File]
       │
       ▼
[Stage 1: Validation & Ingestion] ────► 10 MB limit check, .eml extension verification, non-empty check
       │
       ▼
[Stage 2: RFC 5322 MIME Extraction] ─► Header decoding, body extraction, attachment SHA-256 calculation
       │
       ▼
[Stage 3: Subsystem Parallel Analysis]
       ├──► 3A: URL Intelligence (RFC 3986, homoglyphs, brand lookalikes, IP hosts)
       ├──► 3B: IP Intelligence (RFC 1918/5737/6598/2544 classification, transit hops)
       ├──► 3C: Authentication Analysis (SPF/DKIM/DMARC headers, authserv-id trust)
       └──► 3D: DistilBERT NLP Inference (Subject + Body tokenization, softmax logit)
       │
       ▼
[Stage 4: Corroboration & Scoring Engine]
       ├──► Calculate modality sub-scores ($S_1, S_2, S_3, S_5$)
       ├──► Apply corroboration dampening to DistilBERT score ($S_4$)
       ├──► Sum points and evaluate Critical Threat Floors ($\ge 75$ or $\ge 30$)
       └──► Assign categorical tier (HIGH_RISK, REVIEW_RECOMMENDED, LOW_RISK, INSUFFICIENT)
       │
       ▼
[Stage 5: Response Serialization] ──► Pydantic v2 schema validation, UTC timestamps, JSON response
       │
       ▼
[Stage 6: Client Visualization] ────► React UI updates, gauge animation, modal inspections
       │
       ▼
[Stage 7: Forensic Report Generation] ► In-memory HTML report generation with strict CSP
```

---

## 3. Subsystem Architectural Specifications

### 3.1 Upload Gateway & Security Enforcer

The API gateway layer is implemented in `backend/app/api/v1/endpoints/email.py` and guarded by `backend/app/core/config.py`.

- **Maximum Upload Ceiling:** Strictly configured to $10 \times 1024 \times 1024 = 10,485,760$ bytes. Streaming reads enforce chunk-by-chunk accumulation; if the accumulator exceeds the ceiling, the upload terminates immediately with HTTP 413.
- **File Type Enforcement:** Only filenames with a `.eml` extension (case-insensitive) are accepted. All other extensions receive HTTP 400.
- **Zero-Byte Guard:** If the payload evaluates to 0 bytes, an HTTP 400 Bad Request exception is raised immediately.
- **Zero Data Retention:** No uploaded email files, extracted attachments, or analysis results are written to local databases or cloud storage. Processing occurs entirely in ephemeral memory.

### 3.2 RFC 5322 Forensic Email Parser

Implemented in `backend/app/services/email_parser.py`, this engine ingests raw byte streams and handles encoding anomalies:

- **Parsing Policy:** Employs standard Python `email.policy.default` with automatic fallback to `email.policy.compat32` for malformed legacy headers.
- **Header Parsing:** Decodes MIME encoded-words (`=?utf-8?B?...?=`) via standard RFC 2047 decoders. Captures both single-occurrence and multi-occurrence headers (`Received`, `Authentication-Results`, `Received-SPF`, `DKIM-Signature`).
- **MIME Body Traversal:** Traverses multi-part MIME structures using depth-first tree walking:
  - Text parts with `text/plain` are extracted and decoded with UTF-8 replacement characters (`errors="replace"`).
  - HTML parts with `text/html` are sanitized using `BeautifulSoup4` with the `lxml` parser, completely decomposing `<script>`, `<style>`, `<meta>`, `<noscript>`, and `<link>` elements before extracting inner text.
- **Attachment Forensics:** Binary payloads are ingested directly into memory. The SHA-256 cryptographic digest is calculated via `hashlib.sha256(payload_bytes).hexdigest()`. Filenames are stripped of path traversal characters (`../`, `..\\`) using `sanitize_filename()`.
- **URL Extraction:** Combines regex harvesting across plain text with DOM `<a>` tag `href` extraction, tracking the link's contextual origin (`plain_text`, `html_href`, or `both`) and associated anchor text.

### 3.3 Zero-Network URL Intelligence Engine

Implemented in `backend/app/services/url_intelligence.py`, this engine analyzes extracted URLs purely through lexical, structural, and character-level heuristics:

```
+-----------------------------------------------------------------------------------------+
|                               URL INTELLIGENCE PIPELINE                                 |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   Extracted URL:  "http://paypal.com@192.168.1.1:8080/update%2520billing?id=admin"      |
|                                                                                         |
|        │                                                                                |
|        ▼                                                                                |
|   [RFC 3986 Lexical Deconstruction (urllib.parse.urlsplit)]                            |
|   ├── Scheme:     "http"                                                                |
|   ├── Userinfo:   "paypal.com"  ────────► Trigger: RULE_USERINFO_AUTH (HIGH)            |
|   ├── Host:       "192.168.1.1" ────────► Trigger: RULE_IP_LITERAL_HOST (HIGH)          |
|   ├── Port:       8080          ────────► Trigger: RULE_NON_DEFAULT_PORT (LOW)          |
|   ├── Path:       "/update%2520billing" ─► Trigger: RULE_DOUBLE_PERCENT_ENCODING (MED) |
|   └── Query:      "id=admin"                                                            |
|                                                                                         |
|        │                                                                                |
|        ▼                                                                                |
|   [Homoglyph & Confusable Evaluation (homoglyph_detector.py)]                           |
|   └── Evaluates mixed Cyrillic/Greek character sets in hostname and path                |
|                                                                                         |
|        │                                                                                |
|        ▼                                                                                |
|   [Anchor Text Deception Cross-Check]                                                   |
|   └── Compares visual anchor text against actual destination registered domain          |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

Key Architectural Invariants:
- **Zero Sockets:** Never initiates DNS requests, ping sweeps, or HTTP handshakes.
- **Scope Classification:** Identifies public IPs, private IPs (RFC 1918), documentation IPs (RFC 5737), benchmarking IPs (RFC 2544), and shared address space (RFC 6598).
- **Brand Protection:** Matches hostnames against an internal catalog of 25+ high-profile targeted enterprise brands (`TARGETED_DISPLAY_BRANDS`).

### 3.4 Email Authentication Evidence Engine

Implemented in `backend/app/services/email_authentication.py`, this engine parses downstream receiving gateway assertions while respecting the offline boundary:

- **SPF Interpretation:** Parses `Received-SPF` and `Authentication-Results` headers (RFC 7208).
- **DKIM Interpretation:** Identifies presence of `DKIM-Signature` headers (RFC 6376) and parses reported verification results from downstream MTAs.
- **DMARC Interpretation:** Evaluates policy alignment results (`pass`, `fail`, `reject`, `quarantine`).
- **Stage A.3 Boolean Safety Guarantee:** Because offline analysis inspects unauthenticated `.eml` files, header text matches cannot prove cryptographic trust. The attribute `is_trusted` is **guaranteed to evaluate to `False`** for all reported assertions.
- **Conflict Identification:** Scans multiple receiving hops for contradictory authentication results (e.g., an upstream hop reporting DKIM fail while a downstream hop reports pass).

### 3.5 IP Transit Intelligence & Provider Catalog Engine

Implemented in `backend/app/services/ip_intelligence.py`:

- **Hop Ordering:** Processes `Received` transit headers from index $0$ (latest receiving hop) to index $N-1$ (initial ingestion boundary).
- **Apparent Origin Discovery:** Evaluates candidate IPs in reverse chronological order, identifying the outermost non-private public IP address closest to the sender.
- **Provider Infrastructure Catalog:** Matches transit IPs against officially published cloud delivery subnets:
  - Microsoft 365 Exchange Online Protection (associated with Endpoint IDs 9 & 10).
  - Google Workspace / Gmail relay ranges.
  - SendGrid email infrastructure (`/17` CIDR precision).
  - Amazon Simple Email Service (SES).
  - Mailgun delivery networks.
- **Offline GeoLite2 Integration:** Reads local MaxMind GeoLite2 City/Country `.mmdb` files directly from disk without network access. If files are not installed, the engine gracefully reports `DATABASE_UNAVAILABLE`.

### 3.6 DistilBERT NLP Text Classification Engine

Implemented in `backend/app/services/model_inference.py`:

- **Model Specification:** 6-layer bidirectional transformer encoder with 12 self-attention heads, 768 hidden dimensions, 3,072 intermediate feed-forward dimensions, GELU activation, and a binary classification head (`DistilBertForSequenceClassification`).
- **Input Encoding:** Formats raw text as `[CLS] subject \n\n body [SEP]`, tokenized with WordPiece up to 256 tokens.
- **Inference Computation:** Computes uncalibrated softmax logits:
  $$P(\text{Phish}) = \frac{e^{z_1}}{e^{z_0} + e^{z_1}}$$
- **Defensive Error Handling:** If GPU VRAM or tensor allocation fails, the status transitions to `ERROR` or `UNAVAILABLE`. The application strictly avoids defaulting failed inference to benign (`0`).
- **Mandatory Caveat Attachment:** The output is explicitly documented as an **uncalibrated text-similarity heuristic** reflecting PhishMMF training patterns, not a real-world probability.

### 3.7 Evidence Fusion & Phishing Risk Scoring Engine

Implemented in `backend/app/services/scoring_engine.py`:

```
+-----------------------------------------------------------------------------------------------+
|                             EVIDENCE FUSION SCORING MATRIX                                    |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|   Category 1: Sender Identity & Authentication       [Max: 25 pts]  Weight: 25%               |
|   Category 2: URL & Link Intelligence               [Max: 25 pts]  Weight: 25%               |
|   Category 3: Content & Language Analysis           [Max: 20 pts]  Weight: 20%               |
|   Category 4: DistilBERT NLP Inference (Dampened)   [Max: 20 pts]  Weight: 20%               |
|   Category 5: Header & IP Infrastructure            [Max: 10 pts]  Weight: 10%               |
|                                                                                               |
|   ─────────────────────────────────────────────────────────────────────────────────────────   |
|   Base Numerical Score:  S_base = S_1 + S_2 + S_3 + S_4 + S_5        (Range: 0 - 100)         |
|   ─────────────────────────────────────────────────────────────────────────────────────────   |
|                                                                                               |
|   [Corroboration Dampening Algorithm for DistilBERT (S_4)]                                    |
|   ├── If (S_1 + S_2 + S_3 + S_5) <= 5:   S_4 = min(5, round(P_model * 20 * 0.25))           |
|   ├── If 5 < (S_1 + S_2 + S_3 + S_5) < 15: S_4 = min(10, round(P_model * 20 * 0.50))        |
|   └── If (S_1 + S_2 + S_3 + S_5) >= 15:  S_4 = min(20, round(P_model * 20 * 1.00))          |
|                                                                                               |
|   [Critical Threat Floor Overrides]                                                           |
|   ├── Executable / Double-Extension Attachment   ──────► S_final = max(S_base, 75)            |
|   ├── Anchor Text Deception (Displayed Link Spoof) ───► S_final = max(S_base, 75)            |
|   ├── Userinfo Authority Deception (@ trick)     ──────► S_final = max(S_base, 75)            |
|   ├── Lookalike Brand Impersonation Domain       ──────► S_final = max(S_base, 75)            |
|   ├── Homoglyph Brand Display Name Spoofing      ──────► S_final = max(S_base, 75)            |
|   └── Elevated Model Score (>= 0.70) + Brand Mismatch ─► S_final = max(S_base, 75)           |
|                                                                                               |
|   [Authentication Failure Floor Override]                                                     |
|   └── Explicit Reported SPF/DKIM/DMARC Failure   ──────► S_final = max(S_base, 30)            |
|                                                                                               |
|   ─────────────────────────────────────────────────────────────────────────────────────────   |
|   Categorical Risk Tier Assignment:                                                           |
|   ├── S_final >= 70:                           HIGH_RISK_INDICATORS_PRESENT                   |
|   ├── 30 <= S_final < 70:                      REVIEW_RECOMMENDED                             |
|   ├── S_final < 30 (Normal Coverage):          LOW_RISK_INDICATORS (No Guarantee of Safety)   |
|   └── Unparseable / Incomplete:                INSUFFICIENT_EVIDENCE                          |
|                                                                                               |
+-----------------------------------------------------------------------------------------------+
```

---

## 4. UML System Models

### 4.1 UML Use Case Diagram

```
+---------------------------------------------------------------------------------------+
|                                USE CASE: PHISHINTEL                                   |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|   +-------------------+                                                               |
|   | Security Analyst  |                                                               |
|   +---------+---------+                                                               |
|             |                                                                         |
|             ├───► [Upload RFC 5322 .eml File]                                         |
|             │            │                                                            |
|             │            ├───► <<include>> [Validate Extension & Size]                |
|             │            └───► <<include>> [Sanitize HTML & Extract MIME]             |
|             │                                                                         |
|             ├───► [Inspect Email Transit Chain]                                       |
|             │            └───► <<include>> [Classify Candidate IPs (RFC 1918/5737)]   |
|             │                                                                         |
|             ├───► [Examine Authentication Results]                                    |
|             │            └───► <<include>> [Parse Reported SPF, DKIM, DMARC]          |
|             │                                                                         |
|             ├───► [Review Extracted Hyperlinks]                                       |
|             │            └───► <<include>> [Inspect Deceptive Anchors & Userinfo]     |
|             │                                                                         |
|             ├───► [Evaluate Model Text Heuristic]                                     |
|             │            └───► <<include>> [View Corroboration Dampening Status]      |
|             │                                                                         |
|             ├───► [Inspect Multi-Modal Risk Score]                                    |
|             │            └───► <<include>> [Review 5-Modality Points & Threat Floors] |
|             │                                                                         |
|             └───► [Export Standalone Forensic Report]                                 |
|                          └───► <<include>> [Generate Offline HTML with Strict CSP]    |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

### 4.2 Sequence Diagram: Analysis Execution

```
Analyst            Frontend (React)         FastAPI Gateway        Email Parser        Intelligence Engines    Evidence Fusion
   │                      │                        │                     │                       │                    │
   │── Upload .eml ──────►│                        │                     │                       │                    │
   │                      │── POST /api/v1/analyze►│                     │                       │                    │
   │                      │   (multipart stream)   │                     │                       │                    │
   │                      │                        │── Validate size ───►│                       │                    │
   │                      │                        │   and extension     │                       │                    │
   │                      │                        │                     │                       │                    │
   │                      │                        │── parse_email() ───►│                       │                    │
   │                      │                        │                     │── Walk MIME parts ───►│                    │
   │                      │                        │                     │   & hash attachments  │                    │
   │                      │                        │                     │                       │                    │
   │                      │                        │                     │── Dispatch URLs ─────►│                    │
   │                      │                        │                     │── Dispatch IPs ──────►│                    │
   │                      │                        │                     │── Dispatch Auth ─────►│                    │
   │                      │                        │                     │── Dispatch Text ─────►│                    │
   │                      │                        │                     │                       │                    │
   │                      │                        │                     │◄── Subsystem Results ─│                    │
   │                      │                        │                     │                       │                    │
   │                      │                        │                     │── fuse_evidence() ────────────────────────►│
   │                      │                        │                     │                                            │── Calculate 5 scores
   │                      │                        │                     │                                            │── Apply dampening
   │                      │                        │                     │                                            │── Evaluate floors
   │                      │                        │                     │◄── Fusion Result & Score Breakdown ────────│
   │                      │                        │◄── JSON Response ───│
   │                      │◄── HTTP 200 OK ────────│
   │◄── Render Dashboard ─│
   │                      │
   │── Click Export ─────►│
   │                      │── Generate HTML Report (in-memory Blob with Level 3 CSP)
   │◄── Save .html file ──│
```

---

## 5. Security Invariants and Compliance Boundaries

1. **Zero Outbound Network Egress:** Analysis of untrusted emails executes strictly offline. The backend never performs DNS queries, WHOIS lookups, SMTP connections, or HTTP requests.
2. **Execution Neutralization:** Attachments are hashed in memory; binary files are never written to disk or executed.
3. **Rendering Isolation:** Untrusted HTML email content is stripped of all active elements (`<script>`, `<object>`, `<iframe>`, `<style>`) before extraction. Extracted URLs are rendered as inert non-clickable text strings.
4. **Ephemerality:** The application maintains zero server-side persistence. No email headers, bodies, or attachments are saved to databases or retained across sessions.
5. **Strict Content Security Policy:** Generated HTML reports embed W3C CSP Level 3 directives prohibiting script execution (`script-src 'none'`) and outbound connections (`connect-src 'none'`).

