# PhishIntel — Complete Project Forensic Inventory & Module Catalog

**Project Name:** PhishIntel – Transformer and NLP-Based Email Phishing Detection and IP Intelligence  
**Document Type:** Technical System Inventory & Architectural Catalog  
**Version:** 1.0.0-Production  
**Environment:** Windows 11 64-bit, Python 3.13.15, Node.js v24.14.0, React 19.2.8, Vite 8.3.2, FastAPI 0.115.0  
**Audit Date:** November 2026  

---

## 1. Executive Overview

This document presents a comprehensive, forensic inventory of every module, component, script, configuration file, test suite, and dataset artifact in the **PhishIntel** project workspace. Every entry reflects the **actual implementation** present on the filesystem. No imaginary or unimplemented components are documented.

PhishIntel is an enterprise-grade forensic email investigation and phishing detection platform designed to ingest raw RFC 5322 (`.eml`) messages, parse MIME structures, reconstruct mail transit hops, extract and classify candidate IP addresses, analyze embedded URLs through deterministic lexical heuristics, evaluate reported cryptographic authentication headers (SPF, DKIM, DMARC), perform deep NLP text classification using a fine-tuned DistilBERT transformer model, synthesize multi-modal signals into an explainable 0–100 risk score with corroboration dampening and critical threat floors, and render interactive cyber-forensic dashboards alongside standalone downloadable HTML forensic reports.

---

## 2. Workspace Directory Structure

```
PhishIntel/
├── backend/                               # Python FastAPI backend service
│   ├── app/                               # Application package
│   │   ├── api/                           # API routing and endpoints
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   └── email.py           # POST /api/v1/email/analyze endpoint
│   │   │       └── router.py              # Aggregates API v1 routers
│   │   ├── core/
│   │   │   └── config.py                  # Core system settings and security limits
│   │   ├── schemas/                       # Pydantic v2 data models & validation schemas
│   │   │   ├── email.py                   # RFC 5322 header, body, URL, attachment models
│   │   │   ├── email_authentication.py    # SPF, DKIM, DMARC validation schemas
│   │   │   ├── evidence_fusion.py         # 5-category scoring, categories, breakdowns
│   │   │   ├── ip_intelligence.py         # Candidate IP, classification, GeoIP schemas
│   │   │   └── url_intelligence.py        # URL features, observations, risk tiers
│   │   ├── services/                      # Core business logic and forensic engines
│   │   │   ├── email_authentication.py    # Offline SPF/DKIM/DMARC interpreter
│   │   │   ├── email_parser.py            # RFC 5322 ingestion, MIME traversal, hasher
│   │   │   ├── evidence_fusion.py         # Multi-modal fusion bridge
│   │   │   ├── homoglyph_detector.py      # Unicode mixed-script confusable detector
│   │   │   ├── ip_extractor.py            # Received header regex IP extractor
│   │   │   ├── ip_intelligence.py         # IP classifier & provider catalog engine
│   │   │   ├── model_inference.py         # DistilBERT PyTorch inference wrapper
│   │   │   ├── scoring_engine.py          # 0-100 evidence-based risk scoring engine
│   │   │   └── url_intelligence.py        # Deterministic zero-network URL analyzer
│   │   └── main.py                        # FastAPI entry point, CORS, health routes
│   ├── tests/                             # Automated backend test suites (317 node IDs)
│   │   ├── fixtures/                      # Real & synthetic .eml forensic test emails
│   │   ├── test_api.py                    # Endpoint upload, extension, boundary tests
│   │   ├── test_email_authentication.py   # SPF/DKIM/DMARC interpretation tests
│   │   ├── test_email_parser.py           # RFC 5322 parsing & attachment hashing tests
│   │   ├── test_evidence_based_scoring.py # 0-100 scoring & floor regression tests
│   │   ├── test_evidence_fusion.py        # Multi-modal fusion synthesis tests
│   │   ├── test_ip_intelligence.py        # IP classification & provider tests
│   │   ├── test_model_integration.py      # DistilBERT mock & live inference tests
│   │   ├── test_phase2_remediation.py     # Cleaned dataset & model regression tests
│   │   ├── test_phase9_e2e_validation.py  # End-to-end API pipeline validation tests
│   │   ├── test_stage_a1_corrections.py   # Security correctness & validation tests
│   │   ├── test_stage_a2_corrections.py   # Special-purpose IP classification tests
│   │   ├── test_stage_a3_corrections.py   # Semantic audit & provenance safety tests
│   │   ├── test_stage_a_b_corrections.py  # Stage A/B remediation integration tests
│   │   ├── test_url_integration.py        # EML-to-URL engine integration tests
│   │   └── test_url_intelligence.py       # Deterministic URL rule tests
│   ├── pytest.ini                         # Pytest configuration
│   └── requirements.txt                   # Backend Python dependencies
├── data/                                  # Datasets, audits, and manifests
│   ├── audit/                             # Audit reports & verification logs
│   │   ├── phase2_dataset_audit.json
│   │   ├── phase2_dataset_audit.md
│   │   ├── phase2b1_dataset_remediation.md
│   │   ├── phase2b_cleaned_dataset_verification.json
│   │   ├── phase2b_cleaned_dataset_verification.md
│   │   └── phase2c_split_verification.md
│   ├── processed/phishmmf/                # Cleaned PhishMMF corpus (7,239 records)
│   │   ├── cleaned_email_dataset.csv      # Remediated canonical dataset
│   │   ├── cleaning_report.md             # Dataset cleaning documentation
│   │   ├── dataset_manifest.json          # Cryptographic SHA-256 dataset manifest
│   │   ├── splits/                        # Leakage-safe train, val, test splits
│   │   │   ├── split_manifest.json        # Partition hashes & verification
│   │   │   ├── test.csv                   # Locked test partition (724 samples)
│   │   │   ├── train.csv                  # Training partition (5,791 samples)
│   │   │   └── validation.csv             # Validation partition (724 samples)
│   │   ├── test.csv                       # Symlink/copy of test partition
│   │   ├── train.csv                      # Symlink/copy of train partition
│   │   └── validation.csv                 # Symlink/copy of validation partition
│   └── raw/                               # Raw archives & external corpora
│       ├── meajor_cleaned_preprocessed.parquet.gzip
│       ├── Phishing_Email.csv
│       └── phishmmf/                      # Raw JSONL source archives (CEAS, SpamAssassin, phishing_pot)
├── docs/                                  # Engineering logs and phase documentation
│   ├── architecture.md                    # Core architecture design
│   ├── implementation_log.md              # Development milestone log
│   ├── phase1_validation.md               # Phase 1 verification results
│   ├── phase2_dataset_audit.md            # Raw corpus analysis
│   ├── phase3/                            # ML environment, training, testing reports
│   ├── phase4/                            # URL intelligence reports
│   ├── phase5/                            # Email authentication reports
│   ├── phase6/                            # IP intelligence reports
│   ├── phase7/                            # Evidence fusion reports
│   ├── phase8/                            # Integration & report generation reports
│   ├── phase9/                            # End-to-end discrepancy audit
│   └── phase10/                           # Live acceptance reports & sample HTML exports
├── frontend/                              # React 19 + TypeScript frontend application
│   ├── public/                            # Static SVG icons and favicon
│   ├── src/                               # Frontend source code
│   │   ├── assets/                        # Hero banner and styling assets
│   │   ├── components/                    # Cyber-forensic UI components
│   │   │   ├── AttachmentForensicsCard.tsx# Attachment list & SHA-256 display
│   │   │   ├── AuthenticationCard.tsx     # SPF, DKIM, DMARC results
│   │   │   ├── BodyForensicsCard.tsx      # Sanitized plain text & HTML text
│   │   │   ├── EmailOverviewBanner.tsx    # Executive summary & 0-100 risk meter
│   │   │   ├── EvidenceFusionCard.tsx     # 5-category breakdown & rule table
│   │   │   ├── ExtractedURLsCard.tsx      # Inert URL list & observation badges
│   │   │   ├── HeaderForensics.tsx        # RFC headers & transit hops
│   │   │   ├── IPCandidatesCard.tsx       # IP classification & GeoIP info
│   │   │   ├── Navbar.tsx                 # Application branding & status
│   │   │   └── UploadZone.tsx             # Drag-and-drop file ingestion
│   │   ├── tests/                         # Node test runner suite (78 tests passing)
│   │   │   ├── fixtures/real_backend_responses.json
│   │   │   ├── integration_audit.test.ts
│   │   │   ├── live_contract.test.ts
│   │   │   └── report_generator.test.ts
│   │   ├── types/
│   │   │   └── forensics.ts               # Complete TypeScript API interface types
│   │   ├── utils/
│   │   │   └── reportGenerator.ts         # Standalone HTML forensic report generator
│   │   ├── App.tsx                        # Main dashboard controller & tab state
│   │   ├── index.css                      # Tailwind base & custom cyber theme
│   │   └── main.tsx                       # React DOM entry point
│   ├── package.json                       # Frontend dependencies & scripts
│   ├── tailwind.config.js                 # Theme styling & palette configuration
│   ├── tsconfig.json                      # TypeScript compiler options
│   └── vite.config.ts                     # Vite build configuration & API reverse proxy
├── models/                                # Trained model checkpoints & artifacts
│   └── distilbert_baseline/               # Fine-tuned DistilBERT model
│       ├── config.json                    # Model architecture parameters
│       ├── model.safetensors              # Weights file (267.8 MB, SHA-256 verified)
│       ├── run_manifest.json              # Full training metadata & environment
│       ├── test_error_analysis.csv        # Detailed breakdown of 9 test errors
│       ├── test_evaluation_results.json   # Locked test metrics (98.76% acc, 96.50% F1)
│       ├── tokenizer.json                 # HuggingFace Fast Tokenizer
│       ├── tokenizer_config.json          # Tokenizer settings
│       ├── training_config.json           # Hyperparameters & hardware setup
│       ├── training_history.csv           # Epoch-by-epoch losses and metrics
│       ├── training_history.json          # Structured training metrics
│       ├── validation_evaluation_results.json # Best epoch validation results
│       └── vocab.txt                      # 30,522 WordPiece vocabulary tokens
└── scripts/                               # Evaluation, smoke test, and fixture scripts
    ├── generate_sample_reports.js         # Offline sample HTML report generator
    ├── phase10_extra_fixtures.py          # Synthetic fixture generation helper
    ├── phase10_live_acceptance_test.py    # Live socket acceptance test runner
    ├── phase3_check_environment.py        # CUDA & PyTorch pre-flight verifier
    ├── phase3_train_distilbert.py         # PyTorch fine-tuning pipeline
    ├── phase3_validate_distilbert.py      # Validation-set evaluator
    ├── phase3c_evaluate_test.py           # Locked test-set single-pass evaluator
    └── phase8a_smoke_test.py              # Backend inference smoke test
```

---

## 3. Detailed Module-by-Module Technical Inventory

### 3.1 Backend Application & API Gateway

#### Module: `backend/app/main.py`
- **Purpose:** Primary application factory for the FastAPI framework. Configures middleware, global CORS headers, registers sub-routers, and defines service health check endpoints.
- **Input:** Incoming HTTP requests from clients or frontend proxy.
- **Processing Logic:** 
  - Initializes `FastAPI(title="PhishIntel", version="1.0.0")`.
  - Configures `CORSMiddleware` with allowed origins `["http://127.0.0.1:5173", "http://localhost:5173"]`, enabling credentials, methods `["*"]`, and headers `["*"]`.
  - Exposes `GET /health` returning service health status and current development phase.
  - Exposes `GET /` returning root API metadata.
  - Mounts `/api/v1` router under prefix `/api/v1`.
- **Output:** JSON responses (`{"status": "healthy", ...}`).
- **Technologies Used:** FastAPI, Starlette CORS.
- **Key Functions/Objects:** `app`, `health_check()`, `root()`.
- **Interactions:** Serves as the outer entry point routing traffic to `app/api/v1/router.py`.

#### Module: `backend/app/core/config.py`
- **Purpose:** Centralized application configuration repository managing operational constraints, file limits, model paths, and trusted identity domains.
- **Input:** Environment variables or default constants.
- **Processing Logic:** Defines `Settings` Pydantic class:
  - `MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024` (10 MB).
  - `ALLOWED_EXTENSIONS: List[str] = [".eml"]`.
  - `MODEL_CHECKPOINT_DIR: str = "models/distilbert_baseline"`.
  - `TRUSTED_AUTHSERV_DOMAINS: List[str]` containing 15 major enterprise email gateways (`google.com`, `protection.outlook.com`, `proofpoint.com`, etc.).
- **Output:** Singleton instance `settings`.
- **Technologies Used:** Pydantic v2 `BaseModel`.

#### Module: `backend/app/api/v1/endpoints/email.py`
- **Purpose:** Upload controller executing multi-layer file validation and initiating forensic analysis.
- **Input:** `multipart/form-data` file stream (`UploadFile`).
- **Processing Logic:**
  - Validates file extension against `.eml`. Rejects invalid extensions with HTTP 400 Bad Request.
  - Reads content chunks up to `MAX_UPLOAD_SIZE_BYTES`. If size exceeds 10 MB, immediately raises HTTP 413 Payload Too Large.
  - Validates that byte buffer is greater than 0 bytes. If empty, raises HTTP 400 Bad Request (`"Uploaded file is empty (0 bytes)."`).
  - Dispatches validated byte sequence to `parse_email_message(file_bytes, file.filename)`.
  - Returns structured `EmailAnalysisResponse`.
- **Output:** HTTP 200 with JSON payload conforming to `EmailAnalysisResponse`.
- **Technologies Used:** FastAPI `UploadFile`, `HTTPException`.
- **Interactions:** Directly invokes `app/services/email_parser.py`.

---

### 3.2 Email Ingestion & Parsing Engine

#### Module: `backend/app/services/email_parser.py`
- **Purpose:** In-memory RFC 5322 email parser, MIME multipart walker, attachment digest calculator, and orchestration bridge for downstream intelligence modules.
- **Input:** Raw email bytes (`bytes`) and original filename (`str`).
- **Processing Logic:**
  1. Parses raw byte buffer using `email.message_from_bytes(file_bytes, policy=policy.default)`. Catches format exceptions and retries with `policy.compat32`.
  2. Extracts single-value headers (`From`, `Subject`, `Date`, `Message-ID`, `Reply-To`, `Return-Path`, `MIME-Version`, `Content-Type`) and decodes RFC 2047 encoded-words.
  3. Extracts multi-value headers: `Authentication-Results`, `Received-SPF`, `Received`, `DKIM-Signature`.
  4. Walks MIME multipart hierarchy:
     - Identifies attachments via `Content-Disposition: attachment` or explicit filenames.
     - Computes cryptographic SHA-256 digest (`hashlib.sha256`) in memory without writing binaries to disk.
     - Sanitizes filenames against directory traversal (`sanitize_filename`).
     - Decodes `text/plain` bodies with UTF-8 replacement fallback.
     - Decodes `text/html` bodies and sanitizes them using `BeautifulSoup` by stripping `<script>`, `<style>`, `<meta>`, `<noscript>`, and `<link>` tags.
  5. Extracts embedded URLs from both plain text and HTML `<a>` tags via regex `https?://[^\s<>'\"{}|\\^`\[\]]+`, deduplicating links and tracking source context (`plain_text`, `html_href`, `both`).
  6. Dispatches transit headers to `ip_extractor.py`.
  7. Invokes URL intelligence, authentication analysis, IP intelligence, and DistilBERT model inference.
  8. Passes all intermediate results to `evidence_fusion.py` to calculate final risk score.
- **Output:** Fully populated `EmailAnalysisResponse`.
- **Technologies Used:** Python standard `email`, `hashlib`, `urllib.parse`, `BeautifulSoup4` (`lxml` parser).
- **Key Functions:** `parse_email_message()`, `extract_urls()`, `extract_text_from_html()`, `sanitize_filename()`, `parse_address_list()`.

#### Module: `backend/app/services/ip_extractor.py`
- **Purpose:** Extracts candidate IP addresses from chronological `Received` headers and performs strict RFC classification.
- **Input:** List of raw `Received` header strings.
- **Processing Logic:**
  - Employs regex to identify IPv4 (`\b(?:\d{1,3}\.){3}\d{1,3}\b`) and IPv6 tokens.
  - Validates and parses candidates via `ipaddress.ip_address()`.
  - Classifies addresses into explicit topological scopes:
    - `Private` (RFC 1918 / RFC 4193)
    - `Documentation` (RFC 5737 TEST-NET-1/2/3, RFC 3849 IPv6)
    - `Shared Address Space / CGNAT` (RFC 6598 `100.64.0.0/10`)
    - `Benchmarking` (RFC 2544 `198.18.0.0/15`)
    - `IETF Protocol` (RFC 6890 `192.0.0.0/24`)
    - `Loopback`, `Link-Local`, `Multicast`, `Reserved`, or `Public`.
  - Preserves transit hop ordering (Hop 0 represents newest downstream hop; terminal hop represents initial sender boundary).
- **Output:** List of `IPCandidate` objects.
- **Technologies Used:** Python standard `ipaddress`, `re`.

---

### 3.3 Cyber Intelligence & Heuristic Engines

#### Module: `backend/app/services/url_intelligence.py`
- **Purpose:** Zero-network, deterministic structural and lexical analysis of extracted URLs.
- **Input:** List of `ExtractedURL` objects.
- **Processing Logic:**
  - Parses URLs via RFC 3986 using `urllib.parse.urlsplit`.
  - Determines host type (`domain`, `ipv4`, `ipv6`) and classifies host network scope.
  - Analyzes lexical features: URL length, domain length, path depth, query parameter count, percent-encoding density.
  - Applies deterministic heuristic rules across four severity tiers (`HIGH`, `MEDIUM`, `LOW`, `INFO`):
    - `RULE_USERINFO_AUTH`: Detects `@` character embedded in URL authority (userinfo deception).
    - `RULE_DECEPTIVE_DISPLAYED_LINK`: Detects anchor text displaying a legitimate domain while `href` navigates to an external target.
    - `RULE_LOOKALIKE_IMPERSONATION_DOMAIN`: Identifies typosquatting or brand impersonation targeting major brands (`paypal`, `microsoft`, etc.).
    - `RULE_PUBLIC_IP_HOST`: Flags raw public IPv4/IPv6 literals used as destination hosts.
    - `RULE_UNUSUAL_SCHEME`: Flags dangerous protocols (`javascript:`, `data:`, `file:`).
    - `RULE_EMAIL_IN_QUERY`: Identifies automated credential harvesting lures passing recipient email addresses in query strings.
    - `RULE_PUNYCODE_HOST`: Detects internationalized domain names (`xn--`) and homoglyphs.
    - `RULE_DOUBLE_PERCENT_ENCODING`: Detects `%25xx` evasion patterns designed to bypass web filters.
    - `RULE_EXCESSIVE_PATH_LENGTH`: Flags non-CDN URLs with paths exceeding 200 characters.
    - `RULE_NON_DEFAULT_PORT`: Identifies explicit non-standard web ports (e.g., `:8080`, `:8443`).
    - `RULE_OIDC_LOGIN_HINT_PARAMETER`: Whitelists standard enterprise identity federations on authentic domains.
  - Guarantees **zero external network requests** (no DNS lookups, no HTTP requests).
- **Output:** `URLBatchAnalysisResult` containing individual `URLAnalysisResult` entries and aggregate metrics.
- **Technologies Used:** Python standard `urllib.parse`, `ipaddress`, `unicodedata`, `re`.

#### Module: `backend/app/services/ip_intelligence.py`
- **Purpose:** Transit route reconstruction, apparent origin assessment, and offline provider infrastructure attribution.
- **Input:** List of `IPCandidate` objects and raw `Received` headers.
- **Processing Logic:**
  - Evaluates candidate IPs in reverse chronological order to identify the apparent originating public IP address.
  - Distinguishes between internal hops and external boundary hops.
  - Matches candidate IPs and transit hostnames against a local provider catalog:
    - Microsoft 365 / Exchange Online Protection (associated with Endpoint IDs 9 & 10).
    - Google Workspace / Gmail infrastructure.
    - SendGrid delivery ranges (`/17` precision).
    - Amazon Simple Email Service (SES).
    - Mailgun delivery infrastructure.
  - Integrates with optional offline MaxMind GeoLite2 databases via local `.mmdb` files. If database is absent, gracefully returns `GeolocationStatus.DATABASE_UNAVAILABLE` without crashing or querying online APIs.
- **Output:** `IPIntelligenceResult`.
- **Technologies Used:** Python standard `ipaddress`, `re`, `enum`.

#### Module: `backend/app/services/email_authentication.py`
- **Purpose:** Interprets downstream Mail Transfer Agent (MTA) cryptographic authentication assertions from email headers.
- **Input:** `EmailHeaderInfo` and raw `DKIM-Signature` headers.
- **Processing Logic:**
  - Evaluates `Authentication-Results` (RFC 8601 / RFC 7601) and `Received-SPF` (RFC 7208) headers.
  - Extracts normalized outcomes for SPF, DKIM, and DMARC (`PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `TEMPERROR`, `PERMERROR`).
  - Evaluates `authserv-id` identifier against `DEFAULT_TRUSTED_AUTHSERV_DOMAINS`.
  - **Stage A.3 Boolean Safety Guarantee:** Sets `is_trusted = False` for all offline uploads, recognizing that text inside an unverified `.eml` file does not constitute cryptographic proof.
  - Identifies contradictory assertions across multiple intermediate receiving gateways.
  - Emphasizes that an SPF or DKIM `PASS` on an attacker-controlled domain provides zero guarantee of benign sender intent.
- **Output:** `EmailAuthenticationAnalysis`.
- **Technologies Used:** Python standard `re`, `collections.Counter`.

#### Module: `backend/app/services/homoglyph_detector.py`
- **Purpose:** High-precision Unicode script analysis and confusable character detection for combating visual spoofing.
- **Input:** String text from display names, subject lines, body content, or URL anchor text.
- **Processing Logic:**
  - Maintains deterministic mapping tables of Cyrillic and Greek lookalike glyphs that visually emulate Latin characters (e.g., Cyrillic 'а' U+0430 $\to$ Latin 'a', Greek 'ο' U+03BF $\to$ Latin 'o').
  - Evaluates Unicode script property via `unicodedata.name()`.
  - Identifies mixed-script tokens containing combinations of Latin and non-Latin characters.
  - Provides `normalize_homoglyphs()` function to map lookalikes to Latin counterparts, allowing downstream regex engines to detect brand names disguised with Unicode confusables.
- **Output:** List of detected homoglyph tokens with Unicode code points and normalized strings.
- **Technologies Used:** Python standard `unicodedata`, `re`.

---

### 3.4 Machine Learning & Inference Pipeline

#### Module: `backend/app/services/model_inference.py`
- **Purpose:** Isolated local execution of the fine-tuned DistilBERT text classification model.
- **Input:** Email subject (`Optional[str]`) and body text (`Optional[str]`).
- **Processing Logic:**
  - Concatenates inputs: `text = (subject or "") + "\n\n" + (body or "")`.
  - Formats inputs using Hugging Face fast tokenizer with truncation to 256 tokens (`max_length=256`, `padding=True`).
  - Passes token tensors through `DistilBertForSequenceClassification` loaded from `models/distilbert_baseline/model.safetensors`.
  - Computes uncalibrated softmax probability for Class 1 (phishing):
    $$P(\text{Phish}) = \frac{e^{z_1}}{e^{z_0} + e^{z_1}}$$
  - Applies canonical threshold $\tau = 0.50$ to determine predicted label (0: Benign, 1: Phishing).
  - Handles runtime errors defensively: if PyTorch fails, records `ModelInferenceStatus.ERROR` or `UNAVAILABLE` and returns `None` for score and label. **Never defaults failures to benign.**
  - Explicitly labels the score as an **uncalibrated text-similarity heuristic**, attaching mandatory scientific caveats.
- **Output:** `ModelInferenceEvidence`.
- **Technologies Used:** PyTorch 2.6.0+cu124, Hugging Face Transformers 5.18.0, Safetensors.

---

### 3.5 Evidence Fusion & Scoring Engine

#### Module: `backend/app/services/scoring_engine.py`
- **Purpose:** Multi-modal forensic evidence synthesizer calculating an explainable 0–100 risk score across 5 structured categories.
- **Input:** All intermediate forensic outputs (headers, body, attachments, URLs, auth, IP, ML inference).
- **Processing Logic:**
  - **Category 1: Sender Identity & Authentication (Max 25 points):**
    - Display name homoglyph spoofing (+18 pts).
    - Display name brand impersonation with unaligned domain (+18 pts).
    - Reply-To redirection to disposable/throwaway inbox (+16 pts).
    - Reply-To redirection to free webmail address (+14 pts).
    - Unaligned Reply-To domain mismatch (+8 pts).
    - Explicit reported auth failure with DMARC enforcement (+15 pts).
    - Contradictory intermediate authentication headers (+8 pts).
  - **Category 2: URL & Link Intelligence (Max 25 points):**
    - User-info authority deception (`@` trick) (+25 pts).
    - Deceptive displayed hyperlink anchor spoofing (+20 pts).
    - Lookalike / brand impersonation domain (+20 pts).
    - Raw public IP-literal host (+15 pts).
    - Dangerous protocol schemes (`javascript:`, `data:`) (+15 pts).
    - Embedded recipient email address on unaligned domain (+8 pts).
    - Non-ASCII / homoglyph path or query parameters (+15 pts).
    - Punycode hostname (+10 pts).
    - Brand-to-URL mismatch (+15 pts).
  - **Category 3: Content & Language Analysis (Max 20 points):**
    - Executable or double-extension attachment (+20 pts).
    - Mixed-script homoglyphs in message body (+10 pts).
    - Coercive account suspension urgency threats (+8 pts).
    - Direct credential solicitation (+10 pts).
    - Non-standard cryptocurrency / gift card demands (+10 pts).
    - Rewards / loyalty points expiration urgency (+10 pts).
    - Mandatory 2FA activation / wallet protection lure (+10 pts).
  - **Category 4: DistilBERT NLP Model Analysis with Corroboration Dampening (Max 20 points):**
    - *Clean Technical Evidence ($S_{\text{other}} \le 5$):* Dampens model score by $0.25\times$, capping assigned points at 5. Neutralizes false-positive shortcut learning on benign corporate notifications.
    - *Partial Corroboration ($5 < S_{\text{other}} < 15$):* Applies $0.50\times$ multiplier, capping assigned points at 10.
    - *Full Corroboration ($S_{\text{other}} \ge 15$):* Operates at full linear weight up to 20 points ($round(P \times 20)$).
  - **Category 5: Header, IP & Infrastructure Intelligence (Max 10 points):**
    - Transit chain consisting entirely of non-routable IPs (+4 pts).
    - Documented provider infrastructure delivery matches (positive evidence).
  - **Critical Threat Floor ($\ge 75$ Points):** Escalates score to at least 75 (`HIGH_RISK_INDICATORS_PRESENT`) upon confirming dangerous executable attachments, anchor text deception, userinfo authority tricks, lookalike brand domains, homoglyph display spoofing, or model scores $\ge 0.70$ corroborated by brand mismatch.
  - **Authentication Failure Floor ($\ge 30$ Points):** Prevents emails with explicit authentication failures from receiving `LOW_RISK_INDICATORS`.
  - **Risk Category Mapping:**
    - $\text{Score} \ge 70 \implies \text{HIGH\_RISK\_INDICATORS\_PRESENT}$
    - $30 \le \text{Score} < 70 \implies \text{REVIEW\_RECOMMENDED}$
    - $\text{Score} < 30 \implies \text{LOW\_RISK\_INDICATORS (No Guarantee of Safety)}$
    - Unparseable / Empty $\implies \text{INSUFFICIENT\_EVIDENCE}$
- **Output:** Final score (0–100), risk category, structured breakdown, evidence completeness status, positive and negative findings.
- **Technologies Used:** Python standard `re`, `math`.

#### Module: `backend/app/services/evidence_fusion.py`
- **Purpose:** Formats and bridges outputs from `scoring_engine.py` into the canonical `EvidenceFusionResult` schema.
- **Input:** Intermediate outputs from all forensic modules.
- **Processing Logic:** Dispatches data to `calculate_phishing_risk_score()` and maps the resulting data into Pydantic models.
- **Output:** `EvidenceFusionResult`.

---

### 3.6 Frontend User Interface & Reporting

#### Module: `frontend/src/App.tsx`
- **Purpose:** Primary application layout and state management controller.
- **Input:** User file upload events and API responses.
- **Processing Logic:**
  - Manages active analysis state (`EmailAnalysisResponse | null`), loading status, error notifications, and active tab selection.
  - Implements tabbed navigation: **Overview**, **Headers & Transit**, **Authentication**, **URLs & Links**, **Body & Content**, **Evidence Fusion**.
  - Provides trigger button for standalone HTML forensic report generation.
- **Output:** Rendered React virtual DOM.
- **Technologies Used:** React 19, TypeScript, Lucide Icons.

#### Module: `frontend/src/components/UploadZone.tsx`
- **Purpose:** Interactive drag-and-drop file ingestion component.
- **Input:** User drag-and-drop or file selector events.
- **Processing Logic:** Enforces client-side validation: verifies `.eml` extension and validates that file size does not exceed 10 MB (`10,485,760 bytes`).
- **Output:** Dispatches valid file to API endpoint via `fetch('/api/v1/email/analyze')`.

#### Module: `frontend/src/components/EmailOverviewBanner.tsx`
- **Purpose:** Executive summary dashboard presenting file metadata and overall risk assessment.
- **Processing Logic:** Renders the 0–100 circular/linear risk meter, category badge, subject, sender, date, message ID, and prominent scientific caveat banners.

#### Module: `frontend/src/components/EvidenceFusionCard.tsx`
- **Purpose:** Deep forensic breakdown component detailing the 5 scoring modalities.
- **Processing Logic:** Renders progress bars for each modality (25%, 25%, 20%, 20%, 10%), displays triggered rules, highlights corroboration dampening status, and itemizes positive and negative evidence findings.

#### Module: `frontend/src/utils/reportGenerator.ts`
- **Purpose:** Client-side standalone HTML forensic report generator.
- **Input:** `EmailAnalysisResponse` JSON object.
- **Processing Logic:**
  - Formats complete forensic report as a single, self-contained HTML file.
  - Injects strict W3C Content Security Policy:
    `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';`
  - Sanitizes all dynamic text strings using `escapeHtml()` to eliminate XSS.
  - Embeds all CSS styles inline, including `@media print` rules for paper and PDF printing.
  - Generates deterministic filename: `phishintel-report-YYYYMMDD-HHmmss.html`.
- **Output:** Standalone HTML string downloaded directly via client browser blob URL.
- **Technologies Used:** Native TypeScript, DOM `Blob` and `URL.createObjectURL`.

---

## 4. Test Suites and Validation Inventory

### 4.1 Backend Test Suites (`backend/tests/`)
| Test File | Focus Area | Test Count | Key Scenarios Verified |
| :--- | :--- | :---: | :--- |
| `test_api.py` | API Endpoints & Gateway | 8 | File size limit (10 MB), `.eml` extension enforcement, 0-byte rejection, health check, schema validity. |
| `test_email_parser.py` | RFC 5322 Ingestion | 10 | Plain text extraction, HTML sanitization, attachment SHA-256 calculation, URL deduplication. |
| `test_email_authentication.py` | SPF/DKIM/DMARC | 15 | SPF pass/fail, DKIM verification status, DMARC alignment, untrusted header detection, network isolation. |
| `test_url_intelligence.py` | URL Lexical Engine | 23 | Userinfo authority deception, double percent-encoding, IP-literal hosts, punycode, unusual schemes. |
| `test_url_integration.py` | Parser-URL Pipeline | 10 | URL batch processing within EML, malformed URL handling, duplicate URL resolution. |
| `test_ip_intelligence.py` | IP Classification | 39 | Transit chain reconstruction, apparent origin, RFC 1918/5737/6598/2544 classification, GeoIP fallback. |
| `test_model_integration.py` | DistilBERT Pipeline | 11 | Tokenizer truncation, model inference state handling, error fallbacks without defaulting to benign. |
| `test_evidence_fusion.py` | Signal Synthesis | 17 | Multi-modal signal synthesis, dampening logic, conflicting evidence resolution. |
| `test_evidence_based_scoring.py` | 0–100 Scoring & Floors | 18 | Modality point assignments, corroboration dampening, critical threat floors, control email tests. |
| `test_stage_a1_corrections.py` | Security Correctness | 13 | Verification of authentication handling and network isolation invariants. |
| `test_stage_a2_corrections.py` | Special-Purpose IPs | 54 | Exhaustive boundary tests for RFC 6598 CGNAT, RFC 2544 benchmark, and RFC 6890 special ranges. |
| `test_stage_a3_corrections.py` | Semantic Provenance | 54 | Verification that `is_trusted` is strictly False for offline headers across all scenarios. |
| `test_stage_a_b_corrections.py` | Remediation Suite | 15 | Regression tests for long tracking URLs, homoglyphs, and display name spoofing. |
| `test_phase2_remediation.py` | Dataset Verification | 12 | Regression verification on clean dataset splits and model stability. |
| `test_phase9_e2e_validation.py` | End-to-End Pipeline | 12 | Full end-to-end integration over live file payloads. |
| **Total Backend Tests** | — | **317 node IDs** | Complete automated backend regression coverage. |

### 4.2 Frontend Test Suite (`frontend/src/tests/`)
| Test File | Focus Area | Test Count | Status |
| :--- | :--- | :---: | :---: |
| `integration_audit.test.ts` | API Contract Completeness | 8 | **PASS** (100%) |
| `live_contract.test.ts` | Real Fixture Contract Tests | 57 | **PASS** (100%) |
| `report_generator.test.ts` | HTML Report & CSP Security | 13 | **PASS** (100%) |
| **Total Frontend Tests** | — | **78 tests** | **78 passed in 960 ms** |

---

## 5. Dataset and Model Checkpoint Inventory

### 5.1 Dataset Partitions (`data/processed/phishmmf/`)
- **Corpus Name:** PhishMMF Cleaned & Remediated Dataset (`v1.0.1-remediated-leakage-aware`)
- **Total Records:** 7,239 emails (1,280 phishing [17.68%], 5,959 benign [82.32%])
- **Source Breakdown:**
  - `CEAS_08_0`: 2,981 benign emails (100% benign, label 0)
  - `SpamAssasin_0`: 2,978 benign emails (100% benign, label 0)
  - `phishing_pot`: 1,280 phishing emails (100% phishing, label 1)
- **Partitions & Cryptographic SHA-256 Hashes:**
  - `train.csv` (5,791 records): `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c`
  - `validation.csv` (724 records): `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab`
  - `test.csv` (724 records): `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e`

### 5.2 Model Checkpoint (`models/distilbert_baseline/`)
- **Base Architecture:** `distilbert-base-uncased` (6 transformer layers, 12 attention heads, 768 hidden dimension, 3,072 intermediate dimension, 66M parameters).
- **Weights File:** `model.safetensors` (267,832,560 bytes)
- **Weights SHA-256:** `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8`
- **Locked Test Evaluation Results (724 samples):**
  - Test Accuracy: **98.76%** ($\frac{715}{724}$)
  - Phishing Precision: **96.12%** ($\frac{124}{129}$)
  - Phishing Recall: **96.88%** ($\frac{124}{128}$)
  - Phishing F1-Score: **96.50%**
  - Benign F1-Score: **99.24%**
  - ROC-AUC: **0.9995**
  - Confusion Matrix: $\text{TN}=591, \text{FP}=5, \text{FN}=4, \text{TP}=124$.

