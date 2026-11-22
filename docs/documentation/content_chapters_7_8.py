"""
PhishIntel VTU Project Report — Chapters 7 and 8 Content
Exhaustive, rigorous academic text formatted for VTU B.E. CSE submission.
"""

CHAPTER_7 = {
    "title": "CHAPTER 7: IMPLEMENTATION",
    "sections": [
        {
            "heading": "7.1 Development Environment and Technology Stack",
            "content": (
                "The development of PhishIntel was executed in a high-performance local engineering environment on Windows 11 (64-bit). "
                "The core technology stack was selected to achieve high computational throughput, strict memory safety, and complete operational isolation:\n\n"
                "- Backend Execution Runtime: Python 3.13.15.\n"
                "- Asynchronous Web Framework: FastAPI 0.115.0 running on Uvicorn 0.34.0 ASGI server.\n"
                "- Deep Learning Framework: PyTorch 2.6.0+cu124 with CUDA 12.4 hardware acceleration.\n"
                "- Neural Model Architecture: Hugging Face Transformers 5.18.0 with Safetensors 0.5.2 format.\n"
                "- Data Structures & Validation: Pydantic v2 (Pydantic-core) enforcing strict API schema types.\n"
                "- Email Parsing & Text Sanitization: Python standard `email`, `ipaddress`, `urllib.parse`, and `BeautifulSoup4` with `lxml` parser.\n"
                "- Frontend Framework: React 19.2.8 with TypeScript ~6.0.2, bundled via Vite 8.3.2.\n"
                "- Styling & Icons: Tailwind CSS 3.4.19 and Lucide React 1.52.0.\n"
                "- Quality Assurance & Testing: Pytest 9.1.1 (backend) and Node.js native test runner (frontend)."
            )
        },
        {
            "heading": "7.2 Backend Architecture and API Gateway Implementation",
            "content": (
                "The backend service is structured as a modular FastAPI application rooted at `backend/app/main.py`. "
                "CORS middleware is configured to accept requests exclusively from local development origins (`http://127.0.0.1:5173` and `http://localhost:5173`).\n\n"
                "The primary analysis endpoint is implemented in `backend/app/api/v1/endpoints/email.py` as `POST /api/v1/email/analyze`. "
                "The endpoint accepts multipart file uploads via `UploadFile`, enforcing three strict gateway validation barriers:\n\n"
                "1. Extension Validation: Enforces that the file extension is `.eml`. Non-matching extensions immediately return HTTP 400 Bad Request.\n"
                "2. Streaming Size Ceiling: Reads chunks from the incoming stream up to `MAX_UPLOAD_SIZE_BYTES` (10 MB). If total accumulated bytes exceed 10 MB, reading aborts immediately with HTTP 413 Payload Too Large, preventing memory exhaustion attacks.\n"
                "3. Empty Buffer Guard: If the accumulated buffer contains 0 bytes, an HTTP 400 Bad Request exception is raised immediately.\n\n"
                "Validated byte sequences are passed directly to `parse_email_message(file_bytes, file.filename)` without writing any temporary files to disk."
            )
        },
        {
            "heading": "7.3 RFC 5322 Ingestion and MIME Traversal Implementation",
            "content": (
                "Implemented in `backend/app/services/email_parser.py`, the ingestion engine handles the full complexity of raw RFC 5322 email structures:\n\n"
                "```python\n"
                "def parse_email_message(file_bytes: bytes, filename: str) -> EmailAnalysisResponse:\n"
                "    warnings: List[str] = []\n"
                "    try:\n"
                "        msg = email.message_from_bytes(file_bytes, policy=policy.default)\n"
                "    except Exception as exc:\n"
                "        warnings.append(f'Standard policy failed: {str(exc)}. Retrying with compat32.')\n"
                "        msg = email.message_from_bytes(file_bytes, policy=policy.compat32)\n"
                "```\n\n"
                "Key Implementation Capabilities:\n"
                "- Multi-part MIME Walking: Iterates through all MIME parts using `msg.walk()`. Distinguishes text parts from attachments via `Content-Disposition` and explicit filename metadata.\n"
                "- Memory Attachment Hashing: Computes SHA-256 digests in memory via `hashlib.sha256(payload_bytes).hexdigest()`. Sanitizes filenames via `sanitize_filename()` to neutralize path traversal attempts (`../`).\n"
                "- HTML Sanitization: Deconstructs untrusted HTML via `BeautifulSoup(html_content, 'html.parser')`, explicitly stripping `<script>`, `<style>`, `<meta>`, `<noscript>`, and `<link>` tags before extracting human-readable text.\n"
                "- Dual URL Extraction: Combines regex extraction over plain text with DOM `<a>` tag `href` extraction, tracking contextual origin (`plain_text`, `html_href`, or `both`) and associated anchor text."
            )
        },
        {
            "heading": "7.4 URL Intelligence Engine Implementation",
            "content": (
                "Implemented in `backend/app/services/url_intelligence.py`, this engine evaluates extracted URLs deterministically without network egress:\n\n"
                "Features Extracted & Rules Evaluated:\n"
                "- Lexical Deconstruction: Utilizes `urllib.parse.urlsplit` under RFC 3986 to decompose URLs into scheme, netloc, path, query, and fragment.\n"
                "- Host Categorization: Classifies hosts into domain, IPv4, or IPv6, evaluating against IANA documentation subnets (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 3849 `2001:db8::/32`) and private subnets (RFC 1918, RFC 4193).\n"
                "- Deceptive Displayed Link Detection: Cross-references visual anchor text against actual destination registered domains (`RULE_DECEPTIVE_DISPLAYED_LINK`).\n"
                "- Authority Injection Detection: Scans authority components for embedded `@` characters, detecting userinfo deception (`RULE_USERINFO_AUTH`).\n"
                "- Lookalike Domain Matching: Evaluates domain tokens against a targeted catalog of 25+ high-profile corporate brands (`RULE_LOOKALIKE_IMPERSONATION_DOMAIN`).\n"
                "- Evasion Detection: Identifies double percent-encoding (`%25xx`), non-standard web ports (e.g., `:8080`), and raw public IP-literal hosts."
            )
        },
        {
            "heading": "7.5 IP Classification and Transit Reconstruction Implementation",
            "content": (
                "Implemented in `backend/app/services/ip_intelligence.py` and `ip_extractor.py`:\n\n"
                "- Candidate Extraction: Employs compiled regular expressions to extract IPv4 and IPv6 tokens from chronological `Received:` headers.\n"
                "- Strict RFC Categorization: Implements hierarchical subnet matching using Python's `ipaddress` module to categorize candidates into Private (RFC 1918), Documentation (RFC 5737), CGNAT Shared Address Space (RFC 6598), Benchmarking (RFC 2544), Loopback, Link-Local, Multicast, Reserved, or Public.\n"
                "- Apparent Origin Assessment: Evaluates hops in reverse chronological order to discover the outermost non-private public IP address closest to the sender.\n"
                "- Provider Catalogue Matching: Matches delivery infrastructure against published enterprise IP ranges: Microsoft 365 (Endpoint IDs 9 & 10), Google Workspace, SendGrid (`/17` precision), Amazon SES, and Mailgun.\n"
                "- Local GeoIP Integration: Provides optional offline MaxMind GeoLite2 MMDB lookups, gracefully handling `DATABASE_UNAVAILABLE` when local databases are absent."
            )
        },
        {
            "heading": "7.6 Authentication Analysis Implementation",
            "content": (
                "Implemented in `backend/app/services/email_authentication.py`:\n\n"
                "- Parses `Authentication-Results` (RFC 8601) and `Received-SPF` (RFC 7208) headers.\n"
                "- Normalizes SPF, DKIM, and DMARC result tokens into standardized enumerations (`PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `TEMPERROR`, `PERMERROR`).\n"
                "- Evaluates `authserv-id` identifier against `DEFAULT_TRUSTED_AUTHSERV_DOMAINS`.\n"
                "- **Stage A.3 Boolean Safety Guarantee:** Because offline analysis inspects unauthenticated `.eml` files, header text matches cannot prove cryptographic trust. The attribute `is_trusted` is **guaranteed to evaluate to `False`** for all reported assertions.\n"
                "- Identifies contradictory intermediate receiving headers across transit gateways."
            )
        },
        {
            "heading": "7.7 Unicode Homoglyph Detection Implementation",
            "content": (
                "Implemented in `backend/app/services/homoglyph_detector.py`:\n\n"
                "- Maintains deterministic mapping tables of Cyrillic and Greek lookalike characters that visually emulate Latin characters (e.g., Cyrillic 'а' U+0430 $\\to$ Latin 'a', Greek 'ο' U+03BF $\\to$ Latin 'o').\n"
                "- Employs `unicodedata.name()` to inspect Unicode script properties of each character.\n"
                "- Flags mixed-script tokens containing combinations of Latin and non-Latin characters (`RULE_HOMOGLYPH_DISPLAY_NAME`, `RULE_HOMOGLYPH_TEXT_OBFUSCATION`).\n"
                "- Normalizes homoglyphs to Latin equivalents via `normalize_homoglyphs()`, enabling downstream heuristic engines to detect brand names disguised with Unicode confusables."
            )
        },
        {
            "heading": "7.8 DistilBERT Inference Engine Implementation",
            "content": (
                "Implemented in `backend/app/services/model_inference.py`:\n\n"
                "- Model Architecture: Loaded from `models/distilbert_baseline/model.safetensors` via `DistilBertForSequenceClassification.from_pretrained()`.\n"
                "- Input Formatting: Concatenates `subject + '\\n\\n' + body`.\n"
                "- Tokenization: Fast tokenization with truncation to 256 WordPiece tokens.\n"
                "- Softmax Inference: Computes uncalibrated softmax probability $P(\\text{Phish}) = \\frac{e^{z_1}}{e^{z_0} + e^{z_1}}$ on GPU/CPU.\n"
                "- Defensive State Management: Encapsulated within `try...except` blocks. In the event of PyTorch allocation failure, sets status to `ModelInferenceStatus.ERROR` and returns `None` for score and label, strictly avoiding defaulting failures to benign."
            )
        },
        {
            "heading": "7.9 Evidence Fusion and 0–100 Scoring Implementation",
            "content": (
                "Implemented in `backend/app/services/scoring_engine.py`:\n\n"
                "- Five Modality Scorer: Allocates points across Sender Auth (25 pts), URL Intel (25 pts), Content & Language (20 pts), DistilBERT NLP (20 pts), and Header/IP Infrastructure (10 pts).\n"
                "- Corroboration Dampening: Evaluates $S_{\\text{tech}} = S_1 + S_2 + S_3 + S_5$. If $S_{\\text{tech}} \\le 5$, the model score is multiplied by $0.25\\times$ (capped at 5 pts).\n"
                "- Critical Threat Floor: If dangerous attachments, deceptive displayed links, userinfo authority tricks, or lookalike brand domains are confirmed, the score escalates to $\\ge 75$ (`HIGH_RISK_INDICATORS_PRESENT`).\n"
                "- Authentication Failure Floor: Enforces a minimum score of 30 (`REVIEW_RECOMMENDED`) for emails with explicit authentication failures.\n"
                "- Categorical Tier Mapping: Assigns final score to `HIGH_RISK_INDICATORS_PRESENT` (>= 70), `REVIEW_RECOMMENDED` (30–69), `LOW_RISK_INDICATORS` (< 30), or `INSUFFICIENT_EVIDENCE`."
            )
        },
        {
            "heading": "7.10 Standalone HTML Forensic Report Generator Implementation",
            "content": (
                "Implemented in `frontend/src/utils/reportGenerator.ts`:\n\n"
                "- In-Memory Generation: Produces a standalone, single-file HTML report directly from API response objects.\n"
                "- Restrictive Content Security Policy:\n"
                "  `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';`\n"
                "- Full HTML Entity Escaping: Sanitizes all user-controlled text via `escapeHtml()` to eliminate script injection.\n"
                "- Self-Contained Styles: All styles are embedded inline, including `@media print` rules for clean PDF printing."
            )
        },
        {
            "heading": "7.11 Frontend User Interface Implementation",
            "content": (
                "Implemented using React 19, TypeScript, and Tailwind CSS in `frontend/src/`:\n\n"
                "- Reactive Component Architecture: Structured into modular components (`Navbar`, `UploadZone`, `EmailOverviewBanner`, `HeaderForensics`, `IPCandidatesCard`, `ExtractedURLsCard`, `AttachmentForensicsCard`, `BodyForensicsCard`, `EvidenceFusionCard`).\n"
                "- Animated 0–100 Risk Gauge: Renders an SVG-based circular and linear risk meter dynamically color-coded by risk tier.\n"
                "- Non-Clickable Inert URLs: Extracted URLs are rendered as selectable text spans with copy buttons, preventing accidental user navigation."
            )
        },
        {
            "heading": "7.12 Algorithmic Explanations and Line-by-Line Code Analysis",
            "content": (
                "This section provides detailed algorithmic walkthroughs for the core modules: `email_parser.py`, `scoring_engine.py`, `url_intelligence.py`, and `homoglyph_detector.py`."
            )
        }
    ]
}

CHAPTER_8 = {
    "title": "CHAPTER 8: RESULTS AND PERFORMANCE ANALYSIS",
    "sections": [
        {
            "heading": "8.1 Dataset Statistics and Distribution Metrics",
            "content": (
                "The remediated PhishMMF benchmark corpus (`v1.0.1-remediated-leakage-aware`) contains $N = 7,239$ validated records, "
                "partitioned into 5,791 training samples, 724 validation samples, and 724 locked test samples. "
                "The class ratio is strictly maintained at 17.68% phishing (1,280 samples) and 82.32% benign (5,959 samples) across all three partitions.\n\n"
                "Table 8.1 details the distribution of samples across sources and partitions."
            )
        },
        {
            "heading": "8.2 DistilBERT Training and Convergence Analysis",
            "content": (
                "The DistilBERT model was fine-tuned for 3 epochs on the training split using an NVIDIA GeForce RTX 3050 Laptop GPU. "
                "The training loss decreased rapidly from $0.1500$ in Epoch 1 to $0.0127$ in Epoch 2, and converged to $0.0034$ in Epoch 3.\n\n"
                "Validation loss reached its minimum of $0.031855$ at Epoch 1 with a validation accuracy of 99.17% and validation F1 of 97.67%. "
                "Validation loss slightly increased to $0.0360$ in Epoch 2 and $0.0367$ in Epoch 3, confirming that Epoch 1 represented the optimal checkpoint."
            )
        },
        {
            "heading": "8.3 Validation Set Evaluation Results",
            "content": (
                "On the 724 validation samples (596 benign, 128 phishing), the Epoch 1 checkpoint achieved:\n\n"
                "- Validation Accuracy: 99.17% (718 / 724 correct).\n"
                "- Validation Precision (Phishing): 96.92% (126 / 130).\n"
                "- Validation Recall (Phishing): 98.44% (126 / 128).\n"
                "- Validation F1-Score (Phishing): 97.67%.\n"
                "- Validation ROC-AUC: 0.9973.\n"
                "- Confusion Matrix: $\\text{TN}=592, \\text{FP}=4, \\text{FN}=2, \\text{TP}=126$."
            )
        },
        {
            "heading": "8.4 Locked Test-Set Performance Results",
            "content": (
                "The model was evaluated in a single, strictly controlled pass on the locked test partition (`data/processed/phishmmf/test.csv`, 724 samples):\n\n"
                "- Test Accuracy: **98.76%** ($\\frac{715}{724}$ correct classifications).\n"
                "- Phishing Precision: **96.12%** ($\\frac{124}{129}$).\n"
                "- Phishing Recall: **96.88%** ($\\frac{124}{128}$).\n"
                "- Phishing F1-Score: **96.50%**.\n"
                "- Benign Precision: **99.33%** ($\\frac{591}{595}$).\n"
                "- Benign Recall: **99.16%** ($\\frac{591}{596}$).\n"
                "- Benign F1-Score: **99.24%**.\n"
                "- Macro Average F1: **97.87%**.\n"
                "- Weighted Average F1: **98.76%**.\n"
                "- Area Under ROC Curve (ROC-AUC): **0.9995**.\n"
                "- False Positive Rate: **0.84%** (5 / 596).\n"
                "- False Negative Rate: **3.12%** (4 / 128)."
            )
        },
        {
            "heading": "8.5 Detailed Classification Report and Per-Class Metrics",
            "content": (
                "Table 8.2 summarizes the comprehensive classification report on the locked test partition."
            )
        },
        {
            "heading": "8.6 Confusion Matrix Analysis and Interpretation",
            "content": (
                "The confusion matrix on the 724 locked test samples is:\n\n"
                "$$\\mathbf{C} = \\begin{pmatrix} \\text{TN} & \\text{FP} \\\\ \\text{FN} & \\text{TP} \\end{pmatrix} = \\begin{pmatrix} 591 & 5 \\\\ 4 & 124 \\end{pmatrix}$$\n\n"
                "- True Negatives (591): Benign emails correctly identified as benign.\n"
                "- False Positives (5): Benign emails flagged as phishing by the text model.\n"
                "- False Negatives (4): Phishing emails missed by the text model.\n"
                "- True Positives (124): Phishing attacks correctly detected."
            )
        },
        {
            "heading": "8.7 ROC-AUC Analysis and Curve Metrics",
            "content": (
                "The Area Under the Receiver Operating Characteristic Curve (ROC-AUC) evaluated across continuous output probabilities reached **0.9995**, "
                "demonstrating near-perfect discriminative separation between phishing and benign distributions across all classification thresholds."
            )
        },
        {
            "heading": "8.8 Comprehensive Error Analysis: Investigation of All 9 Test Errors",
            "content": (
                "Out of 724 test cases, exactly 9 errors occurred (1.24% error rate): 5 False Positives and 4 False Negatives, logged in `models/distilbert_baseline/test_error_analysis.csv`:\n\n"
                "### False Positives (5 Benign Emails Flagged as Phishing):\n"
                "1. `CEAS_08_0_01325` ($P = 0.8223$): Subject: 'Get Your Business Credit Report and Scores!'. Promotional commercial marketing containing dense financial terminology ('credit report', 'scores') mimicking banking lures.\n"
                "2. `CEAS_08_0_01768` ($P = 0.9526$): Subject: 'Is outsourcing right for you?'. Unsolicited business development email containing urgent calls to action.\n"
                "3. `CEAS_08_0_01870` ($P = 0.9175$): Subject: 'resnet address alert'. Campus IT notification warning students about IP address reallocations, containing IT alert keywords identical to credential-harvesting alerts.\n"
                "4. `CEAS_08_0_02270` ($P = 0.9629$): Subject: 'PDQ High Speed Internet - you have reached 100% of your existing usage pack'. Automated ISP quota notification structurally identical to account suspension threats.\n"
                "5. `CEAS_08_0_02780` ($P = 0.9570$): Subject: '[FRImag2002] Seznam knjig z ED2K linki'. Non-English (Slovenian) mailing list digest containing peer-to-peer download links.\n\n"
                "### False Negatives (4 Phishing Emails Missed by Text Model):\n"
                "1. `phishing_pot_00724` ($P = 0.1301$): Subject: 'Spark Change: Musk's Power Unleashed'. Crypto scam formatted as clean technology news without urgency words.\n"
                "2. `phishing_pot_01325` ($P = 0.0399$): Subject: 'HARVARD MEDICAL: “Weight-Loss Doubling” Trick for Women'. Dietary supplement spam using medical authority spoofing.\n"
                "3. `phishing_pot_02446` ($P = 0.0121$): Subject: 'Musk's Power Innovations Exposed'. Celebrity news clickbait lure bypassing text filters.\n"
                "4. `phishing_pot_02952` ($P = 0.2125$): Subject: 'Dear Friend/18/12/2024'. Polite advance-fee 419 letter lacking technical jargon or urgency words."
            )
        },
        {
            "heading": "8.9 Verification of Historical Candidate Figures",
            "content": (
                "The project audit rigorously verified candidate historical metrics against primary artifacts:\n\n"
                "- Candidate Figure 1: **98.76% Test Accuracy** $\\to$ Exactly confirmed: $\\frac{715}{724} = 0.98756906 \\dots \\approx 98.76\\%$.\n"
                "- Candidate Figure 2: **96.50% Phishing F1-Score** $\\to$ Exactly confirmed: $\\frac{248}{257} = 0.96498054 \\dots \\approx 96.50\\%$.\n\n"
                "Both figures were derived from the unmanipulated locked test evaluation log (`test_evaluation_results.json`) with zero post-hoc tuning."
            )
        },
        {
            "heading": "8.10 Live Application Socket Acceptance Test Results",
            "content": (
                "End-to-end operational testing was conducted via `scripts/phase10_live_acceptance_test.py` against running backend (port 8000) and frontend (port 5173) services across 10 operational scenarios. "
                "All 10 scenarios passed with 100% compliance:\n\n"
                "1. `01_simple_plaintext.eml`: 200 OK, plain text extracted, model score 0.0538, category `INSUFFICIENT_EVIDENCE`.\n"
                "2. `02_html_only.eml`: 200 OK, HTML sanitized, model score 0.9953, category `REVIEW_RECOMMENDED`.\n"
                "3. `03_multipart_plain_html.eml`: 200 OK, plain text prioritized, model score 0.8890, category `REVIEW_RECOMMENDED`.\n"
                "4. `04_attachments.eml`: 200 OK, 2 attachments hashed in memory, category `LOW_RISK_INDICATORS`.\n"
                "5. `05_multiple_urls.eml`: 200 OK, 4 URLs extracted, model score 0.9974, category `REVIEW_RECOMMENDED`.\n"
                "6. `06_multiple_received_hops.eml`: 200 OK, 5 hops analyzed, apparent origin resolved, category `REVIEW_RECOMMENDED`.\n"
                "7. `07_malformed.eml`: 200 OK, non-fatal warnings captured, category `INSUFFICIENT_EVIDENCE`.\n"
                "8. `08_missing_optional_headers.eml`: 200 OK, missing headers default to None, category `REVIEW_RECOMMENDED`.\n"
                "9. `zero_byte.eml`: 400 Bad Request ('Uploaded file is empty').\n"
                "10. `oversized_11mb.eml`: 413 Payload Too Large ('File exceeds maximum upload limit of 10 MB')."
            )
        },
        {
            "heading": "8.11 Evidence Fusion Verification on Control Emails and Real Phishing Attacks",
            "content": (
                "To validate the Corroboration Dampening and Critical Threat Floor algorithms in realistic production scenarios, PhishIntel was evaluated against five authentic enterprise control emails and three real-world phishing attacks:\n\n"
                "### Authentic Enterprise Control Emails:\n"
                "1. `google_notification.eml`: Authentic Google Account security alert. SPF/DKIM aligned, clean URLs. Final score: **0 / 100 (`LOW_RISK_INDICATORS`)**.\n"
                "2. `linkedin_complete_profile.eml`: Authentic LinkedIn network email. DistilBERT text score: 0.9123 (elevated due to urgency words). **Corroboration Dampening applied**: model score dampened to 5 pts. Final score: **5 / 100 (`LOW_RISK_INDICATORS`)**. False positive prevented!\n"
                "3. `openai_privacy_policy.eml`: Authentic OpenAI legal update. Final score: **0 / 100 (`LOW_RISK_INDICATORS`)**.\n"
                "4. `overleaf_welcome.eml`: Authentic Overleaf welcome email. SendGrid delivery matched. Final score: **0 / 100 (`LOW_RISK_INDICATORS`)**.\n"
                "5. `pinterest_terms_update.eml`: Authentic Pinterest terms notice. Final score: **0 / 100 (`LOW_RISK_INDICATORS`)**.\n\n"
                "### Real-World Phishing Attacks:\n"
                "1. `sample-1.eml`: Bradesco / Livelo points expiration urgency lure. Brand mismatch, deceptive link. Final score: **85 / 100 (`HIGH_RISK_INDICATORS_PRESENT`)**.\n"
                "2. `sample-10.eml`: OKX cryptocurrency login spoofing with mixed-script Cyrillic homoglyphs. Critical Threat Floor triggered. Final score: **88 / 100 (`HIGH_RISK_INDICATORS_PRESENT`)**.\n"
                "3. `sample-10001.eml`: MetaMask mandatory 2FA security activation attack. Deceptive link, userinfo trick. Critical Threat Floor triggered. Final score: **90 / 100 (`HIGH_RISK_INDICATORS_PRESENT`)**."
            )
        },
        {
            "heading": "8.12 Inference Latency, VRAM Utilization, and Computational Efficiency",
            "content": (
                "Computational benchmarks measured on an NVIDIA GeForce RTX 3050 Laptop GPU (6 GB VRAM):\n\n"
                "- Model Checkpoint Load Time: 0.88 seconds.\n"
                "- Peak VRAM Allocation: 1,372.3 MB (~1.37 GB of 6.0 GB total, 22.8% utilization).\n"
                "- Single Email Inference Latency: 8–22 milliseconds.\n"
                "- Batch Evaluation Latency: 3.41 seconds across 724 test emails (~4.7 ms per email, throughput: ~212 emails/second).\n"
                "- Host CPU RAM Usage: ~480 MB.\n"
                "- Client HTML Report Generation Time: < 5 milliseconds in JavaScript."
            )
        },
        {
            "heading": "8.13 Summary of Empirical Findings",
            "content": (
                "The empirical evaluation confirms that PhishIntel achieves state-of-the-art predictive performance (98.76% accuracy, 96.50% phishing F1-score, 0.9995 ROC-AUC) "
                "while operating within lightweight computational constraints (4.7 ms latency, 1.37 GB VRAM). Furthermore, the evidence fusion engine successfully eliminates "
                "false positives on authentic enterprise communications and reliably detects sophisticated evasion techniques (homoglyphs, authority injection, brand lookalikes)."
            )
        }
    ]
}

