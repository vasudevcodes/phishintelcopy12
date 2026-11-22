"""
PhishIntel VTU Project Report — Chapters 4, 5, and 6 Content
Exhaustive, rigorous academic text formatted for VTU B.E. CSE submission.
"""

CHAPTER_4 = {
    "title": "CHAPTER 4: SYSTEM ANALYSIS AND DESIGN",
    "sections": [
        {
            "heading": "4.1 Overall Architectural Design",
            "content": (
                "The architecture of PhishIntel is structured around the principles of modularity, loose coupling, deterministic reproducibility, "
                "and strict isolation boundaries. The system follows a decoupled Client-Server architecture comprising a high-performance Python FastAPI "
                "backend service and a responsive React 19 + TypeScript single-page application (SPA) frontend, communicating over local HTTP REST sockets.\n\n"
                "The backend is decomposed into three logical tiers: (1) The Gateway Tier, enforcing input sanitization, file extension validation, and payload "
                "size constraints; (2) The Forensic Engine Tier, executing parallel, independent extraction and classification across email structures, URLs, "
                "IP hops, authentication headers, and text semantics; and (3) The Evidence Synthesis Tier, executing the multi-modal evidence fusion algorithm "
                "and calculating the explainable 0–100 risk score."
            )
        },
        {
            "heading": "4.2 High-Level Architecture Diagram and Subsystem Topology",
            "content": (
                "The overall system architecture and end-to-end data pipeline is structured as shown in Figure 4.1:\n\n"
                "```\n"
                "+───────────────────────────────────────────────────────────────────────────────────────────────────────────+\n"
                "|                                     PHISHINTEL SYSTEM TOPOLOGY                                            |\n"
                "+───────────────────────────────────────────────────────────────────────────────────────────────────────────+\n"
                "|                                                                                                           |\n"
                "|   [ Client Layer: React 19 + TypeScript (Vite Dev Server http://127.0.0.1:5173) ]                        |\n"
                "|   ├── Drag-and-Drop Ingestion Zone (UploadZone.tsx: .eml validation, 10 MB limit)                          |\n"
                "|   ├── Dynamic Executive Banner (EmailOverviewBanner.tsx: 0-100 Risk Gauge, Category Badge)                 |\n"
                "|   ├── Modality Cards (HeaderForensics, IPCandidates, ExtractedURLs, AttachmentForensics, BodyForensics)   |\n"
                "|   ├── Multi-Modal Fusion Breakdown (EvidenceFusionCard.tsx: 5 Modalities, Corroboration Dampening)       |\n"
                "|   └── Standalone Report Generator (reportGenerator.ts: W3C CSP Level 3 Self-Contained HTML Export)         |\n"
                "|                                                                                                           |\n"
                "|        │  HTTP POST multipart/form-data (Proxy /api/v1/email/analyze)                                    |\n"
                "|        ▼                                                                                                  |\n"
                "|                                                                                                           |\n"
                "|   [ Gateway Layer: FastAPI Server (Uvicorn Worker http://127.0.0.1:8000) ]                                |\n"
                "|   ├── CORS Middleware (Origins: localhost:5173, 127.0.0.1:5173; Methods: ALL)                           |\n"
                "|   ├── Streaming Buffer Allocator (10 MB Ceiling Enforcer, 0-Byte Empty Guard)                            |\n"
                "|   └── Exception Interceptor (Standardized RFC 7807 JSON Error Envelopes)                                  |\n"
                "|                                                                                                           |\n"
                "|        │  Raw In-Memory Byte Stream                                                                       |\n"
                "|        ▼                                                                                                  |\n"
                "|                                                                                                           |\n"
                "|   [ Forensic Ingestion Engine: email_parser.py ]                                                         |\n"
                "|   ├── RFC 5322 Ingestion (email.policy.default with compat32 fallback)                                   |\n"
                "|   ├── MIME Walker (Plain text UTF-8 decoder, HTML sanitizer via BeautifulSoup4 stripping active tags)    |\n"
                "|   ├── Attachment Hasher (In-memory SHA-256 digest calculation, directory traversal neutralization)       |\n"
                "|   └── URL Harvester (Regex text extraction + DOM <a> href extraction, context source tagging)             |\n"
                "|                                                                                                           |\n"
                "|        ├──────────────────────┬──────────────────────┬──────────────────────┬─────────────────────┤       |\n"
                "|        ▼                      ▼                      ▼                      ▼                     ▼       |\n"
                "|   +------------------+  +-----------------+  +-------------------+  +------------------+  +---------------+|\n"
                "|   | URL Intelligence |  | IP Intelligence |  | Email Auth Engine |  | DistilBERT NLP   |  | Homoglyph     ||\n"
                "|   | (url_intel.py)   |  | (ip_intel.py)   |  | (email_auth.py)   |  | (model_inf.py)   |  | Detector      ||\n"
                "|   | RFC 3986 Lexical |  | RFC Scopes      |  | SPF (RFC 7208)    |  | DistilBERT Base  |  | Cyrillic/Greek||\n"
                "|   | Userinfo Trick   |  | Apparent Origin |  | DKIM (RFC 6376)   |  | 66M Parameters   |  | Lookalikes    ||\n"
                "|   | Lookalike Domain |  | M365/SendGrid   |  | DMARC (RFC 7489)  |  | 256 Max Length   |  | Mixed-Script  ||\n"
                "|   | Non-default Port |  | Offline GeoIP   |  | Offline Safety:   |  | Uncalibrated     |  | Normalization ||\n"
                "|   | Zero Network     |  | Zero Network    |  | is_trusted=False  |  | Text Heuristic   |  | Unicodedata   ||\n"
                "|   +--------+---------+  +--------+--------+  +---------+---------+  +--------+---------+  +-------+-------+|\n"
                "|            │                     │                     │                     │                    │       |\n"
                "|            └─────────────────────┼─────────────────────┼─────────────────────┴────────────────────┘       |\n"
                "|                                  │ Intermediate Forensic Signals                                          |\n"
                "|                                  ▼                                                                        |\n"
                "|                                                                                                           |\n"
                "|   [ Multi-Modal Evidence Fusion & Scoring Engine: scoring_engine.py ]                                     |\n"
                "|   ├── Category 1: Sender Identity & Authentication (Max 25 pts)                                           |\n"
                "|   ├── Category 2: URL & Link Intelligence (Max 25 pts)                                                    |\n"
                "|   ├── Category 3: Content & Language Analysis (Max 20 pts)                                                |\n"
                "|   ├── Category 4: DistilBERT NLP Model Analysis with Corroboration Dampening (Max 20 pts)                 |\n"
                "|   ├── Category 5: Header, IP & Infrastructure Intelligence (Max 10 pts)                                  |\n"
                "|   ├── Critical Threat Floor Overrides (Escalation to >= 75 pts for Executables, Deceptive Anchors, etc.)   |\n"
                "|   └── Categorical Risk Band Assignment (HIGH_RISK, REVIEW_RECOMMENDED, LOW_RISK, INSUFFICIENT)             |\n"
                "|                                                                                                           |\n"
                "+───────────────────────────────────────────────────────────────────────────────────────────────────────────+\n"
                "```\n"
                "Figure 4.1: Comprehensive System Topology and Multi-Modal Data Pipeline of PhishIntel."
            )
        },
        {
            "heading": "4.3 Data Flow Diagrams",
            "content": (
                "The flow of data through PhishIntel is formally specified across three hierarchical Data Flow Diagram (DFD) abstractions:\n\n"
                "### DFD Level 0 (Context Diagram):\n"
                "Represents the entire platform as a single operational process interacting with external entities (The Security Analyst and the Local Filesystem):\n\n"
                "```\n"
                "                  Raw .eml File\n"
                "[ Security Analyst ] ──────────► ( 0.0 PhishIntel System ) ──────────► [ Interactive Dashboard ]\n"
                "         ▲                                │                   ──────────► [ Standalone HTML Report ]\n"
                "         │                                ▼\n"
                "         └──────────────────── In-Memory Volatile Processing (Zero Disk Persistence)\n"
                "```\n\n"
                "### DFD Level 1 (Subsystem Decomposition):\n"
                "Decomposes the primary process into four core functional processes:\n"
                "1. Process 1.0 (Gateway Validation): Validates file size (<10 MB) and extension (.eml).\n"
                "2. Process 2.0 (Forensic Parsing & Extraction): Decomposes MIME structures, extracts plain text, sanitizes HTML, computes attachment SHA-256 digests, and harvests URLs and IP transit headers.\n"
                "3. Process 3.0 (Parallel Subsystem Analysis): Executes URL lexical analysis, IP classification, SPF/DKIM interpretation, and DistilBERT inference.\n"
                "4. Process 4.0 (Evidence Fusion & Risk Scoring): Synthesizes signals, executes corroboration dampening, applies threat floors, and outputs the structured assessment.\n\n"
                "### DFD Level 2 (Evidence Fusion Sub-Process):\n"
                "Decomposes Process 4.0 into its internal scoring mathematical algorithms:\n"
                "- Process 4.1: Sender Authentication Scoring (0–25 pts).\n"
                "- Process 4.2: URL Heuristic Scoring (0–25 pts).\n"
                "- Process 4.3: Content Linguistic & Attachment Scoring (0–20 pts).\n"
                "- Process 4.4: Corroboration Dampening Evaluation (Checks $S_{\\text{tech}}$ and scales DistilBERT score to 0–20 pts).\n"
                "- Process 4.5: Infrastructure Routing Scoring (0–10 pts).\n"
                "- Process 4.6: Critical Threat Floor Evaluation & Tier Mapping."
            )
        },
        {
            "heading": "4.4 UML Use Case Modeling and Actor Analysis",
            "content": (
                "The functional interactions between human actors and PhishIntel are formalized in the UML Use Case Diagram.\n\n"
                "### Primary Actor:\n"
                "- Digital Forensics / SOC Analyst: The human security investigator seeking to inspect an email, understand risk indicators, verify sender authenticity, and export documentation.\n\n"
                "### Core Use Cases:\n"
                "1. UC-01 (Upload Email Message): Ingests an RFC 5322 .eml file via web drag-and-drop.\n"
                "2. UC-02 (Inspect Transit Routing Chain): Examines reconstructed Received hops, IP topological classifications, and apparent origin attribution.\n"
                "3. UC-03 (Analyze Authentication Evidence): Reviews receiver-reported SPF, DKIM, and DMARC results alongside offline provenance warnings.\n"
                "4. UC-04 (Inspect Embedded Hyperlinks): Reviews extracted URLs, anchor text deception warnings, lookalike domain indicators, and protocol schemes.\n"
                "5. UC-05 (Inspect Attachment Digests): Reviews extracted attachment metadata and cryptographic SHA-256 digests.\n"
                "6. UC-06 (Review DistilBERT Text Assessment): Inspects uncalibrated model text score, predicted class label, and corroboration dampening status.\n"
                "7. UC-07 (Review 0–100 Multi-Modal Score): Examines point breakdowns across all 5 modalities and reads positive/negative evidence findings.\n"
                "8. UC-08 (Export Standalone Forensic Report): Downloads a self-contained, single-file HTML report protected by strict W3C CSP Level 3 directives."
            )
        },
        {
            "heading": "4.5 UML Activity Diagram (End-to-End Processing Flow)",
            "content": (
                "The UML Activity Diagram defines the sequential execution logic and decision branch points across the email analysis lifecycle:\n\n"
                "```\n"
                "(*) ──► [ User Drags & Drops .eml File ]\n"
                "             │\n"
                "             ▼\n"
                "     < Extension == .eml? > ─── No ───► [ Return HTTP 400: Invalid Extension ] ──► (*)\n"
                "             │ Yes\n"
                "             ▼\n"
                "     < File Size <= 10 MB? > ── No ───► [ Return HTTP 413: Content Too Large ] ──► (*)\n"
                "             │ Yes\n"
                "             ▼\n"
                "     < File Size > 0 Bytes? > ─ No ───► [ Return HTTP 400: Empty File ] ─────────► (*)\n"
                "             │ Yes\n"
                "             ▼\n"
                "     [ Parse RFC 5322 Structure & Decode Encoded-Words ]\n"
                "             │\n"
                "             ▼\n"
                "     [ Traverse MIME Parts: Sanitize HTML & Hash Attachments (SHA-256) ]\n"
                "             │\n"
                "             ▼\n"
                "     [ Harvest Deduplicated URLs & Extract Transit IP Candidates ]\n"
                "             │\n"
                "             ├──────────────────────────┬──────────────────────────┬──────────────────────────┐\n"
                "             ▼                          ▼                          ▼                          ▼\n"
                "     [ Execute URL Intel ]      [ Execute IP Intel ]       [ Execute Auth Intel ]     [ Execute DistilBERT ]\n"
                "     (Lexical Rules)            (RFC Scopes)               (SPF/DKIM/DMARC)           (Subject + Body)\n"
                "             │                          │                          │                          │\n"
                "             └──────────────────────────┴──────────────────────────┴──────────────────────────┘\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                    [ Synthesize Evidence Fusion ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                 < Other Tech Evidence Score <= 5? >\n"
                "                                      ├── Yes ──► [ Dampen Model Score to Max 5 Pts ]\n"
                "                                      └── No ───► [ Apply Full Linear Model Weight ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                 < Critical Threat Condition Present? >\n"
                "                                      ├── Yes ──► [ Enforce Threat Floor: Score = max(Score, 75) ]\n"
                "                                      └── No ───► [ Maintain Calculated Sum ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                    [ Map Score to Category Tier ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                    [ Return JSON API Response ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                    [ Render Dashboard in React ]\n"
                "                                                   │\n"
                "                                                   ▼\n"
                "                                                  (*)\n"
                "```\n"
                "Figure 4.2: UML Activity Diagram Depicting Sequential Execution Logic and Decision Branches."
            )
        },
        {
            "heading": "4.6 UML Sequence Diagram (System Interaction & Async Data Flow)",
            "content": (
                "The UML Sequence Diagram formalizes the asynchronous object interaction lifecycle among the User, Frontend UI, FastAPI Gateway, "
                "Email Parser, Forensic Engines, and Evidence Fusion Engine during an analysis turn:\n\n"
                "1. User drops a file onto `UploadZone`.\n"
                "2. `UploadZone` performs client-side boundary checks and initiates an asynchronous HTTP POST `multipart/form-data` request.\n"
                "3. FastAPI `email.py` endpoint streams the bytes, verifying size and non-empty status.\n"
                "4. Endpoint invokes `parse_email_message(file_bytes, filename)` in `email_parser.py`.\n"
                "5. `email_parser.py` extracts headers, walks MIME structures, strips HTML scripts, hashes attachments, and harvests links and IPs.\n"
                "6. `email_parser.py` invokes `analyze_email_extracted_urls()`, `analyze_ip_candidates()`, `analyze_email_authentication()`, and `run_model_inference()`.\n"
                "7. Engines return intermediate Pydantic schemas.\n"
                "8. `email_parser.py` invokes `fuse_evidence()`, which delegates to `calculate_phishing_risk_score()` in `scoring_engine.py`.\n"
                "9. `scoring_engine.py` computes category points, applies corroboration dampening, evaluates critical threat floors, and maps the tier.\n"
                "10. Endpoint serializes `EmailAnalysisResponse` and returns HTTP 200 OK.\n"
                "11. Frontend updates React state, triggering reactive re-renders across all dashboard cards."
            )
        },
        {
            "heading": "4.7 UML Component Diagram and Subsystem Boundaries",
            "content": (
                "The UML Component Diagram defines the software module boundaries, dependencies, and interfaces:\n\n"
                "- Frontend Component (`frontend/src`): Encapsulates React components, TypeScript interfaces (`forensics.ts`), and the offline HTML report generator (`reportGenerator.ts`). Communicates via local reverse proxy (`vite.config.ts` mapping `/api` to port 8000).\n"
                "- Gateway Component (`backend/app/api`): Exposes RESTful endpoints, handles HTTP exception mapping, and manages CORS policies.\n"
                "- Ingestion Component (`backend/app/services/email_parser.py`): Ingests raw RFC 5322 streams and decomposes multi-part MIME entities.\n"
                "- Lexical URL Component (`backend/app/services/url_intelligence.py`): Encapsulates RFC 3986 lexical rules, homoglyph character analysis, and userinfo deception detection.\n"
                "- Transit Topology Component (`backend/app/services/ip_intelligence.py`): Encapsulates IP scope classification and provider catalog matching.\n"
                "- Cryptographic Evidence Component (`backend/app/services/email_authentication.py`): Encapsulates RFC 8601 header parsing and offline trust safety policies.\n"
                "- Deep Learning NLP Component (`backend/app/services/model_inference.py`): Encapsulates PyTorch execution, Safetensors model weight management, and Hugging Face tokenization.\n"
                "- Synthesis Component (`backend/app/services/scoring_engine.py`): Encapsulates 5-modality point calculation, corroboration dampening, and critical threat floor enforcement."
            )
        },
        {
            "heading": "4.8 Detailed Subsystem Design",
            "content": (
                "Every subsystem in PhishIntel is designed as an autonomous, self-contained forensic engine:\n\n"
                "1. Email Ingestion Subsystem: Implements strict memory sandboxing. Attached executables are never written to disk or assigned execution permissions. Cryptographic SHA-256 hashes are computed directly in memory buffers.\n\n"
                "2. URL Intelligence Subsystem: Implements a deterministic finite state machine (FSM) evaluating URL components against 14 lexical security rules across four severity tiers (INFO, LOW, MEDIUM, HIGH).\n\n"
                "3. IP Intelligence Subsystem: Implements strict hierarchical subnet matching against IANA special-purpose registers, eliminating the vulnerability where private or benchmarking IPs fall through to public classification.\n\n"
                "4. Email Authentication Subsystem: Implements the Stage A.3 Boolean Safety Guarantee, strictly separating receiver-reported assertions from verified cryptographic trust.\n\n"
                "5. DistilBERT NLP Subsystem: Implements isolated sequence classification with defensive error handlers that prevent unhandled exceptions from crashing the parent process.\n\n"
                "6. Evidence Fusion Subsystem: Implements transparent multi-modal scoring with Corroboration Dampening ($0.25\\times$ scaling on clean technical evidence) and Critical Threat Floors (>= 75 pts on severe threats).\n\n"
                "7. Report Generator Subsystem: Implements client-side in-memory HTML synthesis with embedded W3C CSP Level 3 directives and full entity escaping."
            )
        },
        {
            "heading": "4.9 Database and In-Memory Storage Design (Ephemerality Principles)",
            "content": (
                "PhishIntel deliberately implements an **ephemeral in-memory data architecture**. In contrast to traditional systems that record incoming messages in relational databases (PostgreSQL, MySQL) or document stores (MongoDB), PhishIntel maintains **zero server-side persistence**:\n\n"
                "- Zero Disk Caching: Raw email files, extracted attachments, and intermediate forensic objects reside exclusively in volatile RAM during the lifetime of the HTTP request.\n"
                "- Zero Analysis Logging: Message bodies and confidential headers are never written to disk logs or retained across user sessions.\n"
                "- Zero Persistence Verification: Forensic disk scans verify zero SQLite database files, zero cached message files, and zero temporary attachment dumps on disk.\n\n"
                "This architectural ephemerality guarantees absolute data privacy, eliminates the risk of sensitive email exposure during server compromise, and satisfies strict corporate data retention policies."
            )
        },
        {
            "heading": "4.10 User Interface Architecture (React 19 + TypeScript)",
            "content": (
                "The user interface is engineered as an enterprise-grade cyber-forensic dashboard using React 19.2.8, TypeScript ~6.0.2, and Tailwind CSS 3.4.19:\n\n"
                "- Component Tree Hierarchy: `App` serves as the root controller, orchestrating `Navbar`, `UploadZone` (when idle), `EmailOverviewBanner` (when analyzed), and tabbed views containing `HeaderForensics`, `IPCandidatesCard`, `ExtractedURLsCard`, `AttachmentForensicsCard`, `BodyForensicsCard`, and `EvidenceFusionCard`.\n"
                "- Dynamic Risk Meter: An animated circular/linear risk gauge visually communicating the 0–100 score, dynamically color-coded by risk category (Rose for High Risk, Amber for Review Recommended, Sky Blue for Low Risk, Slate for Insufficient Evidence).\n"
                "- Inert URL Protection: All extracted URLs are rendered as inert text spans (`select-all`) with explicit copy buttons, eliminating accidental user navigation.\n"
                "- Instant Client-Side Export: A dedicated 'Export Forensic Report' button triggers in-memory HTML synthesis via `reportGenerator.ts`, allowing analysts to download self-contained reports in under 5 milliseconds."
            )
        }
    ]
}

CHAPTER_5 = {
    "title": "CHAPTER 5: METHODOLOGY",
    "sections": [
        {
            "heading": "5.1 End-to-End Methodological Framework",
            "content": (
                "The research and engineering methodology of PhishIntel follows a rigorous, multi-stage scientific framework spanning dataset curation, "
                "forensic cleaning, leakage-safe partitioning, multi-modal feature extraction, transformer fine-tuning, corroboration-dampened scoring, "
                "and comprehensive software validation.\n\n"
                "The methodology explicitly addresses the core challenges identified in literature: data contamination, shortcut learning, offline provenance "
                "limitations, and unexplainable black-box classification."
            )
        },
        {
            "heading": "5.2 Dataset Acquisition and Curation (PhishMMF Corpus)",
            "content": (
                "The machine learning model was developed using the PhishMMF corpus, an extensive multi-modal email benchmark dataset consolidating "
                "both authentic and fraudulent communications across three foundational sub-corpora:\n\n"
                "1. `CEAS_08_0`: 2,981 legitimate messages from the 2008 Collaboration Against Executive Spam conference archive.\n"
                "2. `SpamAssasin_0`: 2,978 legitimate messages from the public Apache SpamAssassin ham corpus (~2002–2006).\n"
                "3. `phishing_pot`: 1,280 verified phishing attacks captured by modern university honeypots and spam traps.\n\n"
                "The resulting consolidated corpus contains $N = 7,239$ records, comprising 1,280 phishing samples (17.68%) and 5,959 benign samples (82.32%), "
                "accurately reflecting the class imbalance characteristic of real-world enterprise email traffic."
            )
        },
        {
            "heading": "5.3 Data Preprocessing and Cleansing Procedures (Phase 2B.1 Remediation)",
            "content": (
                "Prior to model training, a forensic data audit identified critical label contamination and synthetic shortcut artifacts that required remediation:\n\n"
                "1. Label Contamination Removal: Two records in the `phishing_pot` partition were identified as genuine benign messages erroneously labeled as phishing. "
                "Record `phishing_pot_00617` contained an authentic GitHub security alert regarding exposed private repository tokens. Record `phishing_pot_01785` contained "
                "an authentic developer recruitment inquiry regarding an open-source GitHub profile. Both records were purged to eliminate label noise.\n\n"
                "2. Deterministic Duplicate Resolution: Record `phishing_pot_00291` was found to be identical in body content to `phishing_pot_00278`, differing only by "
                "whitespace line endings (`\\r\\n` vs `\\n`). Following deterministic deduplication policy, the lexicographically higher ID was purged.\n\n"
                "3. Synthetic Shortcut Token Neutralization: The audit revealed that an exact bracketed token `[USER]` appeared 1,041 times across 453 records—and "
                "exclusively in phishing emails (100% label collinearity). This artifact resulted from synthetic anonymization scripts during raw dataset creation. "
                "If left uncorrected, a transformer model would learn an artificial shortcut: classifying any email containing `[USER]` as phishing with 100% confidence. "
                "All occurrences of `[USER]` were systematically neutralized to `<USER>`, eliminating the shortcut while preserving syntactic placeholder positions."
            )
        },
        {
            "heading": "5.4 Group-Level Leakage-Safe Stratified Partitioning",
            "content": (
                "Standard random splitting risks data leakage when identical email templates (e.g., promotional campaigns or phishing spam runs) appear in "
                "both training and testing partitions under slightly differing subject lines.\n\n"
                "To enforce strict research integrity, partitioning was conducted at the **group level** based on the SHA-256 digest of Unicode NFKC-normalized, "
                "lowercased, whitespace-collapsed email bodies. All emails sharing identical body content were strictly allocated to the same split. "
                "Splits were stratified across source and label partitions, yielding an 80/10/10 distribution:\n\n"
                "- Train Split: 5,791 records (1,024 phishing [17.68%], 4,767 benign [82.32%]), SHA-256: `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c`.\n"
                "- Validation Split: 724 records (128 phishing [17.68%], 596 benign [82.32%]), SHA-256: `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab`.\n"
                "- Test Split: 724 records (128 phishing [17.68%], 596 benign [82.32%]), SHA-256: `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e`.\n\n"
                "Cryptographic audits confirmed exact zero cross-partition leakage across all three sets."
            )
        },
        {
            "heading": "5.5 In-Memory RFC 5322 Email Parsing and Sanitization Methodology",
            "content": (
                "The email parsing methodology enforces complete memory isolation and robust malformed header resilience:\n\n"
                "1. The raw byte sequence is parsed via Python's standard `email` library under RFC 5322 policy (`policy.default`). If formatting exceptions occur, "
                "the parser automatically falls back to `policy.compat32`.\n"
                "2. Standard headers are decoded using RFC 2047 MIME encoded-word decoders, handling UTF-8, ISO-8859-1, and Windows-1252 encodings.\n"
                "3. Multi-part MIME trees are traversed depth-first. Text parts (`text/plain`) are extracted with UTF-8 replacement fallbacks. "
                "HTML parts (`text/html`) are processed via `BeautifulSoup4` with `lxml`, explicitly stripping executable and active tags (`<script>`, `<style>`, `<meta>`, `<noscript>`, `<link>`) "
                "before extracting sanitized human-readable text.\n"
                "4. Attachment metadata is extracted in memory: filenames are sanitized against path traversal (`../`), MIME content-types are cataloged, and cryptographic SHA-256 digests are calculated directly from memory buffers without writing files to disk."
            )
        },
        {
            "heading": "5.6 Deterministic URL Intelligence Methodology",
            "content": (
                "URL feature extraction operates purely deterministically under RFC 3986 without initiating outbound network connections:\n\n"
                "1. URLs are harvested across plain text and HTML `<a>` tags via regular expressions, tracking contextual source (`plain_text`, `html_href`, or `both`) and anchor text.\n"
                "2. URLs are parsed into scheme, userinfo, host, port, path, query, and fragment via `urllib.parse.urlsplit`.\n"
                "3. Hosts are classified into domain, IPv4, or IPv6, and scoped into public, private, documentation, or benchmarking ranges.\n"
                "4. Lexical security rules are triggered across four severity tiers (INFO, LOW, MEDIUM, HIGH), detecting userinfo authority deception (@ trick), "
                "anchor text mismatches, lookalike brand domains, IP literals, non-default ports, and double percent-encoding.\n"
                "5. Standard enterprise OIDC parameters (`login_hint` on authentic identity provider domains) are whitelisted as benign."
            )
        },
        {
            "heading": "5.7 IP Transit Hop Extraction and Classification Methodology",
            "content": (
                "Transit hop extraction reconstructs the chronological relay path of the email across Mail Transfer Agents:\n\n"
                "1. All `Received:` headers are extracted in physical order, where Hop 0 represents the latest receiving gateway and Hop $N-1$ represents the initial ingestion boundary.\n"
                "2. Regular expressions extract candidate IPv4 and IPv6 addresses from each hop string.\n"
                "3. Each IP address is classified using Python's `ipaddress` module against strict IANA allocations: RFC 1918 (Private), RFC 5737 (Documentation), RFC 6598 (CGNAT), RFC 2544 (Benchmarking), Loopback, Link-Local, Multicast, Reserved, or Public.\n"
                "4. The outermost non-private public IP address closest to the sender is identified as the Apparent Origin.\n"
                "5. Transit hops are matched against officially documented cloud delivery ranges (Microsoft 365, Google Workspace, SendGrid, Amazon SES, Mailgun)."
            )
        },
        {
            "heading": "5.8 Receiver-Reported Authentication Analysis Methodology",
            "content": (
                "Authentication analysis interprets downstream MTA assertions while enforcing offline boundary safety:\n\n"
                "1. Parses `Authentication-Results` (RFC 8601) and `Received-SPF` (RFC 7208) headers.\n"
                "2. Extracts normalized outcomes for SPF, DKIM, and DMARC (`PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `TEMPERROR`, `PERMERROR`).\n"
                "3. Checks `authserv-id` identifier against a trusted gateway domain catalog.\n"
                "4. Enforces the Stage A.3 Boolean Safety Guarantee: because offline analysis inspects unauthenticated static files, `is_trusted` is strictly set to `False` for all reported assertions.\n"
                "5. Identifies contradictory authentication assertions across intermediate receiving gateways."
            )
        },
        {
            "heading": "5.9 Machine Learning Classification Methodology",
            "content": (
                "The machine learning classification methodology applies fine-tuned DistilBERT to textual semantics:\n\n"
                "1. Input Formatting: Email subject and body are concatenated: $\\text{input} = \\text{subject} \\mathbin{\\Vert} \\text{\"\\n\\n\"} \\mathbin{\\Vert} \\text{body}$.\n"
                "2. Tokenization: Text is tokenized with WordPiece up to a maximum sequence length of 256 tokens (`max_length=256`, `padding=True`).\n"
                "3. Transformer Inference: Tensors pass through 6 bidirectional transformer layers on GPU hardware under FP16 precision.\n"
                "4. Softmax Probability: Computes uncalibrated softmax probability for Class 1 (phishing).\n"
                "5. Classification Boundary: Applies canonical decision boundary $\\tau = 0.50$.\n"
                "6. Exception Defense: Runtime exceptions transition to `ERROR` or `UNAVAILABLE` without defaulting to benign (`0`)."
            )
        },
        {
            "heading": "5.10 Evidence Fusion and Risk Scoring Methodology",
            "content": (
                "The evidence fusion methodology synthesizes multi-modal signals into an explainable 0–100 risk score:\n\n"
                "1. Five Modality Scoring: Allocates points across Sender Auth (max 25), URL Intel (max 25), Content & Language (max 20), DistilBERT NLP (max 20), and Header/IP Infrastructure (max 10).\n"
                "2. Corroboration Dampening: When other technical evidence is clean ($S_{\\text{tech}} \\le 5$), DistilBERT score is scaled by $0.25\\times$ (capped at 5 pts), neutralizing shortcut learning on corporate notifications.\n"
                "3. Critical Threat Floor Overrides: Enforces an automated escalation to $\\ge 75$ points (`HIGH_RISK_INDICATORS_PRESENT`) upon confirming dangerous attachments, anchor text deception, userinfo tricks, or lookalike brand domains.\n"
                "4. Authentication Failure Floor: Enforces a minimum score of 30 (`REVIEW_RECOMMENDED`) for emails with explicit authentication failures.\n"
                "5. Category Tier Mapping: Maps final scores to `HIGH_RISK_INDICATORS_PRESENT` (>= 70), `REVIEW_RECOMMENDED` (30–69), `LOW_RISK_INDICATORS` (< 30), or `INSUFFICIENT_EVIDENCE` (unparseable)."
            )
        },
        {
            "heading": "5.11 Standalone Offline Forensic Report Generation Methodology",
            "content": (
                "The forensic report generation methodology produces self-contained, tamper-proof HTML documentation:\n\n"
                "1. Client-Side Synthesis: Generated in-memory via TypeScript without external server rendering.\n"
                "2. Strict Content Security Policy: Injects W3C CSP Level 3 directives: `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';`.\n"
                "3. Entity Escaping: Sanitizes all user-controlled strings via `escapeHtml()` to eliminate XSS injection.\n"
                "4. Embedded Print Stylesheets: Incorporates `@media print` CSS rules ensuring clean pagination when printed to PDF or paper."
            )
        }
    ]
}

CHAPTER_6 = {
    "title": "CHAPTER 6: MACHINE LEARNING MODEL AND MATHEMATICAL FOUNDATION",
    "sections": [
        {
            "heading": "6.1 DistilBERT Architecture and Knowledge Distillation Theory",
            "content": (
                "DistilBERT is a distilled variant of the BERT transformer architecture developed by Sanh et al. (2019). The fundamental theory underlying "
                "DistilBERT is **knowledge distillation** (Hinton et al., 2015), a compression technique where a compact 'student' network is trained to reproduce "
                "the full output distribution of a larger 'teacher' network.\n\n"
                "During distillation pretraining, the student network minimizes a triple objective function combining distillation loss (soft cross-entropy over teacher "
                "probabilities with temperature $T$), masked language modeling loss, and cosine embedding similarity between student and teacher hidden vectors:\n\n"
                "$$\\mathcal{L}_{\\text{distil}} = \\alpha_{\\text{ce}} \\mathcal{L}_{\\text{ce}}(P_s, P_t) + \\alpha_{\\text{mlm}} \\mathcal{L}_{\\text{mlm}} + \\alpha_{\\text{cos}} \\mathcal{L}_{\\text{cos}}$$ \n\n"
                "Through this mechanism, DistilBERT removes token-type embeddings and the pooler layer, retaining 6 transformer layers (half of BERT-base's 12 layers) "
                "and 66 million parameters, while preserving 97% of BERT's downstream natural language understanding performance."
            )
        },
        {
            "heading": "6.2 Tokenization and Input Sequence Representation",
            "content": (
                "The model utilizes the WordPiece subword tokenization algorithm over a vocabulary of $V = 30,522$ tokens. Subword tokenization eliminates the "
                "out-of-vocabulary (OOV) problem by decomposing rare words into constituent morphemes and subwords prefixed with `##`.\n\n"
                "The email text is structured into a unified sequence:\n"
                "$$\\mathbf{T} = [\\text{[CLS]}] \\circ \\text{tokenize}(\\text{subject}) \\circ [\\text{[SEP]}] \\circ \\text{tokenize}(\\text{body}) \\circ [\\text{[SEP]}]$$\n\n"
                "The token sequence is mapped to token IDs $\\mathbf{x} \\in \\mathbb{N}^{N}$, padded or truncated to maximum sequence length $N = 256$. "
                "The initial hidden representation $\\mathbf{h}_i^{(0)} \\in \\mathbb{R}^{768}$ for token $i$ is formed by summing token embedding and learned positional embedding:\n"
                "$$\\mathbf{h}_i^{(0)} = \\mathbf{E}_{\\text{token}}(x_i) + \\mathbf{E}_{\\text{pos}}(i)$$"
            )
        },
        {
            "heading": "6.3 Mathematical Derivation of Scaled Dot-Product Attention",
            "content": (
                "Self-attention allows each token to dynamically attend to all other tokens in the sequence. For layer $l \\in \\{1, \\dots, 6\\}$, the sequence matrix "
                "is $\\mathbf{H}^{(l-1)} \\in \\mathbb{R}^{n \\times 768}$.\n\n"
                "For attention head $j \\in \\{1, \\dots, 12\\}$, linear projections project $\\mathbf{H}^{(l-1)}$ into Query, Key, and Value spaces of dimension $d_k = 64$:\n"
                "$$\\mathbf{Q}_j = \\mathbf{H}^{(l-1)} \\mathbf{W}_j^Q, \\quad \\mathbf{K}_j = \\mathbf{H}^{(l-1)} \\mathbf{W}_j^K, \\quad \\mathbf{V}_j = \\mathbf{H}^{(l-1)} \\mathbf{W}_j^V$$\n"
                "where $\\mathbf{W}_j^Q, \\mathbf{W}_j^K, \\mathbf{W}_j^V \\in \\mathbb{R}^{768 \\times 64}$.\n\n"
                "The scaled dot-product attention computes the affinity between token queries and keys, divided by scaling factor $\\sqrt{d_k} = \\sqrt{64} = 8$ to prevent "
                "dot-products from growing excessively large in high dimensions (which would push softmax gradients into regions with vanishing gradients):\n\n"
                "$$\\text{Attention}(\\mathbf{Q}_j, \\mathbf{K}_j, \\mathbf{V}_j) = \\text{softmax}\\left( \\frac{\\mathbf{Q}_j \\mathbf{K}_j^\\top}{\\sqrt{d_k}} + \\mathbf{M} \\right) \\mathbf{V}_j$$\n\n"
                "Where $\\mathbf{M} \\in \\{0, -\\infty\\}^{n \\times n}$ is the attention mask matrix. For padded positions ($x_k = \\text{PAD}$), $\\mathbf{M}_{ik} = -\\infty$, "
                "guaranteeing $\\exp(-\\infty) = 0$ so padding tokens receive exactly zero attention weight."
            )
        },
        {
            "heading": "6.4 Multi-Head Self-Attention Formalism",
            "content": (
                "Multi-head attention allows the model to jointly attend to information from different representation subspaces at different positions. "
                "Outputs from all 12 attention heads are concatenated and linearly transformed by $\\mathbf{W}^O \\in \\mathbb{R}^{768 \\times 768}$:\n\n"
                "$$\\text{MultiHead}(\\mathbf{H}^{(l-1)}) = \\left( \\text{head}_1 \\mathbin{\\Vert} \\text{head}_2 \\mathbin{\\Vert} \\dots \\mathbin{\\Vert} \\text{head}_{12} \\right) \\mathbf{W}^O$$\n\n"
                "A residual connection and layer normalization are applied:\n"
                "$$\\mathbf{Z}^{(l)} = \\text{LayerNorm}\\left(\\mathbf{H}^{(l-1)} + \\text{Dropout}_{0.1}\\left(\\text{MultiHead}(\\mathbf{H}^{(l-1)})\\right)\\right)$$\n"
                "where Layer Normalization normalizes activations across feature dimensions for each sample independently:\n"
                "$$\\text{LayerNorm}(\\mathbf{x}) = \\frac{\\mathbf{x} - \\mu}{\\sqrt{\\sigma^2 + \\epsilon}} \\odot \\gamma + \\beta$$"
            )
        },
        {
            "heading": "6.5 Position-Wise Feed-Forward Sublayers and GELU Non-Linearity",
            "content": (
                "The normalized attention representation $\\mathbf{Z}^{(l)}$ passes through a position-wise feed-forward network consisting of two linear transformations "
                "with an intermediate expansion to dimension $d_{\\text{ff}} = 3,072$:\n\n"
                "$$\\text{FFN}(\\mathbf{Z}^{(l)}) = \\text{GELU}\\left(\\mathbf{Z}^{(l)} \\mathbf{W}_1 + \\mathbf{b}_1\\right) \\mathbf{W}_2 + \\mathbf{b}_2$$\n"
                "where $\\mathbf{W}_1 \\in \\mathbb{R}^{768 \\times 3072}$, $\\mathbf{b}_1 \\in \\mathbb{R}^{3072}$, $\\mathbf{W}_2 \\in \\mathbb{R}^{3072 \\times 768}$, and $\\mathbf{b}_2 \\in \\mathbb{R}^{768}$.\n\n"
                "The non-linear activation is the Gaussian Error Linear Unit (GELU) (Hendrycks & Gimpel, 2016), defined as:\n"
                "$$\\text{GELU}(x) = x \\cdot \\Phi(x) = x \\cdot P(X \\le x), \\quad X \\sim \\mathcal{N}(0, 1)$$\n"
                "Approximated computationally by:\n"
                "$$\\text{GELU}(x) \\approx 0.5 x \\left(1 + \\tanh\\left( \\sqrt{\\frac{2}{\\pi}} \\left(x + 0.044715 x^3\\right) \\right)\\right)$$\n\n"
                "The sublayer output is normalized with a second residual connection:\n"
                "$$\\mathbf{H}^{(l)} = \\text{LayerNorm}\\left(\\mathbf{Z}^{(l)} + \\text{Dropout}_{0.1}\\left(\\text{FFN}(\\mathbf{Z}^{(l)})\\right)\\right)$$"
            )
        },
        {
            "heading": "6.6 Classification Projection Head and Logit Derivation",
            "content": (
                "At the final transformer layer $L = 6$, the contextual representation corresponding to the first token `[CLS]`, denoted $\\mathbf{h}_{\\text{[CLS]}}^{(6)} \\in \\mathbb{R}^{768}$, "
                "serves as the aggregate semantic summary of the email.\n\n"
                "The classification head applies a dropout probability of $0.20$ followed by a linear projection to binary class logits $\\mathbf{z} = [z_0, z_1]^\\top \\in \\mathbb{R}^2$:\n"
                "$$\\mathbf{z} = \\mathbf{W}_{\\text{clf}} \\left( \\text{Dropout}_{0.2}\\left(\\mathbf{h}_{\\text{[CLS]}}^{(6)}\\right) \\right) + \\mathbf{b}_{\\text{clf}}$$\n"
                "where $\\mathbf{W}_{\\text{clf}} \\in \\mathbb{R}^{2 \\times 768}$ and $\\mathbf{b}_{\\text{clf}} \\in \\mathbb{R}^2$.\n\n"
                "The uncalibrated probability for the phishing class ($y = 1$) is computed via softmax:\n"
                "$$P(\\text{Phish}) = \\frac{\\exp(z_1)}{\\exp(z_0) + \\exp(z_1)} = \\frac{1}{1 + \\exp(-(z_1 - z_0))}$$\n\n"
                "The binary prediction $\\hat{y} \\in \\{0, 1\\}$ is determined by comparing $P(\\text{Phish})$ against threshold $\\tau = 0.50$:\n"
                "$$\\hat{y} = \\begin{cases} 1 & \\text{if } P(\\text{Phish}) \\ge 0.50 \\\\ 0 & \\text{otherwise} \\end{cases}$$"
            )
        },
        {
            "heading": "6.7 Binary Cross-Entropy Loss Function",
            "content": (
                "During fine-tuning, model parameters $\\theta$ are optimized by minimizing the Binary Cross-Entropy loss over the labeled training batch $\\mathcal{B}$:\n\n"
                "$$\\mathcal{L}_{\\text{CE}}(\\theta) = - \\frac{1}{|\\mathcal{B}|} \\sum_{i=1}^{|\\mathcal{B}|} \\left[ y_i \\log P_i(\\text{Phish}) + (1 - y_i) \\log (1 - P_i(\\text{Phish})) \\right]$$\n\n"
                "Expressed directly in terms of unnormalized logits $z_0, z_1$:\n"
                "$$\\mathcal{L}_{\\text{CE}} = - \\left[ y \\log\\left(\\frac{e^{z_1}}{e^{z_0} + e^{z_1}}\\right) + (1 - y) \\log\\left(\\frac{e^{z_0}}{e^{z_0} + e^{z_1}}\\right) \\right]$$\n"
                "This formulation penalizes confident incorrect predictions exponentially, driving the classification boundary toward optimal margin separation."
            )
        },
        {
            "heading": "6.8 Gradient Optimization and AdamW Weight Decay Dynamics",
            "content": (
                "Optimization is performed using AdamW (Loshchilov & Hutter, 2019), which decouples weight decay regularization from gradient-based momentum updates. "
                "For parameter vector $\\theta_t$ and loss gradient $\\mathbf{g}_t = \\nabla_\\theta \\mathcal{L}(\\theta_t)$:\n\n"
                "$$\\mathbf{m}_t = \\beta_1 \\mathbf{m}_{t-1} + (1 - \\beta_1) \\mathbf{g}_t$$\n"
                "$$\\mathbf{v}_t = \\beta_2 \\mathbf{v}_{t-1} + (1 - \\beta_2) \\mathbf{g}_t^2$$\n"
                "$$\\hat{\\mathbf{m}}_t = \\frac{\\mathbf{m}_t}{1 - \\beta_1^t}, \\quad \\hat{\\mathbf{v}}_t = \\frac{\\mathbf{v}_t}{1 - \\beta_2^t}$$\n"
                "$$\\theta_{t+1} = \\theta_t - \\eta_t \\left( \\frac{\\hat{\\mathbf{m}}_t}{\\sqrt{\\hat{\\mathbf{v}}_t} + \\epsilon} + \\lambda \\theta_t \\right)$$\n\n"
                "Where hyperparameters are configured as: $\\beta_1 = 0.9, \\beta_2 = 0.999, \\epsilon = 10^{-8}$, weight decay coefficient $\\lambda = 0.01$, "
                "initial learning rate $\\eta_0 = 2 \\times 10^{-5}$, with gradient clipping at max norm $\\Vert \\mathbf{g} \\Vert_2 \\le 1.0$.\n\n"
                "The learning rate $\\eta_t$ follows a linear warmup schedule for 108 steps ($10\\%$ of total training steps), followed by linear decay to 0."
            )
        },
        {
            "heading": "6.9 Hyperparameters and Mixed-Precision FP16 Training Setup",
            "content": (
                "Training was executed natively on an NVIDIA GeForce RTX 3050 Laptop GPU (6 GB VRAM) using PyTorch Automatic Mixed Precision (AMP). "
                "Table 6.1 summarizes the complete hyperparameter configuration."
            )
        },
        {
            "heading": "6.10 Checkpoint Selection and Validation Loss Optimization",
            "content": (
                "To prevent overfitting, model checkpoint selection was governed by **minimum validation loss** ($\\min(\\mathcal{L}_{\\text{val}})$):\n\n"
                "- Epoch 1: $\\mathcal{L}_{\\text{train}} = 0.1500, \\mathcal{L}_{\\text{val}} = 0.031855, \\text{Val Acc} = 99.17\\%, \\text{Val F1} = 97.67\\%$.\n"
                "- Epoch 2: $\\mathcal{L}_{\\text{train}} = 0.0127, \\mathcal{L}_{\\text{val}} = 0.036015, \\text{Val Acc} = 99.31\\%, \\text{Val F1} = 98.04\\%$.\n"
                "- Epoch 3: $\\mathcal{L}_{\\text{train}} = 0.0034, \\mathcal{L}_{\\text{val}} = 0.036657, \\text{Val Acc} = 99.31\\%, \\text{Val F1} = 98.04\\%$.\n\n"
                "Although Epochs 2 and 3 achieved slightly higher nominal validation accuracy (+0.14%), validation loss increased from $0.0319$ to $0.0367$, "
                "indicating the onset of overconfidence on training features. In accordance with strict machine learning engineering governance, "
                "**Epoch 1 weights were locked as the canonical checkpoint** (`model.safetensors`, SHA-256: `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8`)."
            )
        },
        {
            "heading": "6.11 Corroboration Dampening: Mathematical Justification and Formula",
            "content": (
                "The mathematical justification for Corroboration Dampening arises from the statistical nature of deep language models trained on benchmark corpora. "
                "When a model outputs an elevated phishing score ($P_{\\text{model}} \\ge 0.50$) based solely on textual keywords (e.g., 'security notification', "
                "'urgent action required'), but the email's technical evidence is provably clean ($S_{\\text{tech}} \\le 5$), the model is exhibiting shortcut learning.\n\n"
                "The assigned model points $S_{\\text{ml}} \\in [0, 20]$ are computed via the piecewise corroboration function:\n\n"
                "$$S_{\\text{ml}} = \\begin{cases} \n"
                "\\min\\left(5, \\text{round}\\left(P_{\\text{model}} \\times 20 \\times 0.25\\right)\\right) & \\text{if } S_{\\text{tech}} \\le 5 \\quad \\text{(Clean Technical Evidence)} \\\\ \n"
                "\\min\\left(10, \\text{round}\\left(P_{\\text{model}} \\times 20 \\times 0.50\\right)\\right) & \\text{if } 5 < S_{\\text{tech}} < 15 \\quad \\text{(Moderate Corroboration)} \\\\ \n"
                "\\min\\left(20, \\text{round}\\left(P_{\\text{model}} \\times 20 \\times 1.00\\right)\\right) & \\text{if } S_{\\text{tech}} \\ge 15 \\quad \\text{(Full Corroboration)} \n"
                "\\end{cases}$$\n\n"
                "Where $S_{\\text{tech}} = S_{\\text{sender\\_auth}} + S_{\\text{url}} + S_{\\text{content}} + S_{\\text{infra}}$.\n\n"
                "This formula guarantees that an isolated model score can contribute at most 5 points toward the 100-point total, keeping authentic corporate emails "
                "securely within the `LOW_RISK_INDICATORS` band (< 30 points), while allowing corroborated model predictions to operate at full linear weight."
            )
        },
        {
            "heading": "6.12 Model Limitations: Source-Label Collinearity and Heuristic Nature",
            "content": (
                "In accordance with rigorous academic transparency, two foundational limitations of the machine learning pipeline must be explicitly documented:\n\n"
                "1. Source-Label Collinearity in Training Data: In the underlying PhishMMF corpus, benign samples originated from older open-source collections "
                "(`CEAS_08_0` from 2008, `SpamAssasin_0` from 2002–2006), whereas phishing samples originated from modern honeypots (`phishing_pot`). "
                "Consequently, the model learned legitimate corporate language patterns from 2000s-era mailing lists. Modern enterprise notifications that use clean, "
                "marketing-style prose risk triggering elevated model scores—a limitation decisively resolved by PhishIntel's corroboration dampening engine.\n\n"
                "2. Uncalibrated Text-Similarity Heuristic: The output of the softmax layer represents an uncalibrated text similarity metric within the embedding "
                "space of the training corpus, NOT a validated real-world probability. PhishIntel strictly attaches this scientific caveat to all UI displays and reports, "
                "never presenting the raw score as an authoritative real-world probability."
            )
        }
    ]
}

