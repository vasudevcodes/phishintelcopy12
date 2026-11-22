"""
PhishIntel VTU Project Report — Tables and Figures Data
Contains structured data for all 22+ tables and figures in the report.
"""

TABLES_DATA = {
    "table_2_1": {
        "title": "Table 2.1: Comparative Analysis Matrix of State-of-the-Art Phishing Detection Paradigms",
        "headers": ["Paradigm / System", "Detection Mechanism", "Zero-Hour Latency", "Offline Execution", "Privacy / Egress Risk", "False Positive Susceptibility"],
        "rows": [
            ["DNSBL / RBL Blacklists", "Centralized IP/domain reputation feeds", "High (12–48 hr delay)", "Impossible (requires live DNS)", "High (queries leak recipient DNS)", "Low on cataloged domains; high on stale entries"],
            ["Heuristic Rule Engines (SpamAssassin)", "Static regular expressions on headers/body", "Moderate (manual rule updates)", "Supported (local evaluation)", "Zero (local regex execution)", "High (fails on corporate marketing prose)"],
            ["Classical ML (Random Forest, SVM)", "Bag-of-Words & engineered feature vectors", "Low (generalizes over features)", "Supported locally", "Zero (offline inference)", "Moderate (lacks word order & deep semantics)"],
            ["Recurrent Neural Networks (LSTM/CNN)", "Sequential word vector embeddings", "Low (semantic analysis)", "Supported on GPU/CPU", "Zero (offline inference)", "Moderate (gradient decay on long documents)"],
            ["Pretrained Transformers (BERT-base)", "12-layer bidirectional self-attention", "Very Low (deep semantic context)", "Hardware intensive (110M params)", "Zero (offline inference)", "High on corporate lures (shortcut learning)"],
            ["Proposed PhishIntel Platform", "DistilBERT + URL/IP Intel + Fusion Engine", "Zero (deterministic local inference)", "100% Offline (Zero Network)", "Zero (zero sockets, zero storage)", "Extremely Low (Corroboration Dampening)"]
        ]
    },
    "table_3_1": {
        "title": "Table 3.1: Comparative Architectural Advantages of PhishIntel",
        "headers": ["Architectural Dimension", "Traditional Perimeter SEGs", "Cloud Threat Scanners", "PhishIntel Platform"],
        "rows": [
            ["Network Dependency", "Mandatory active DNS/MX lookups", "Mandatory outbound cloud API calls", "Strict Zero-Network (100% Offline)"],
            ["Metadata Privacy", "Leaks query domains to external DNS", "Transmits email bodies/URLs to cloud", "Zero Data Egress (Strict Local Isolation)"],
            ["File Ingestion Mode", "Inline SMTP proxy stream only", "Browser extension / Outlook plugin", "Direct RFC 5322 .eml File Upload"],
            ["Machine Learning Head", "Proprietary black-box cloud models", "Cloud classifier with no explanation", "Fine-Tuned Local DistilBERT (66M params)"],
            ["Explainability", "Opaque spam score integer", "Binary flag (Safe / Phish)", "Transparent 5-Modality 0–100 Point Breakdown"],
            ["Corporate False Positives", "Frequent on urgent legal/HR alerts", "High on marketing tracking links", "Neutralized via Corroboration Dampening"],
            ["Offline Provenance Safety", "N/A (assumes live network boundary)", "N/A (queries cloud IdP)", "Stage A.3 Boolean Safety: is_trusted=False"],
            ["Forensic Documentation", "Ephemeral server syslog entries", "Transient web UI alert", "Self-Contained W3C CSP Level 3 HTML Report"]
        ]
    },
    "table_4_1": {
        "title": "Table 4.1: PhishIntel Subsystem Architecture & Technology Mapping",
        "headers": ["Subsystem Name", "Implementation File", "Core Technologies", "Input Artifacts", "Forensic Output"],
        "rows": [
            ["API Gateway", "app/api/v1/endpoints/email.py", "FastAPI, Starlette, Uvicorn", "HTTP Multipart .eml stream", "HTTP 200/400/413 JSON envelopes"],
            ["Email Ingestion Parser", "app/services/email_parser.py", "Python email, BeautifulSoup4, LXML", "Raw .eml byte sequence", "EmailAnalysisResponse Pydantic schema"],
            ["URL Intelligence Engine", "app/services/url_intelligence.py", "urllib.parse, ipaddress, unicodedata", "ExtractedURL objects", "URLBatchAnalysisResult (4 severity tiers)"],
            ["IP Intelligence Engine", "app/services/ip_intelligence.py", "ipaddress, re, MaxMind GeoLite2", "Received headers, candidate IPs", "IPIntelligenceResult (apparent origin, hops)"],
            ["Authentication Engine", "app/services/email_authentication.py", "RFC 8601/7208 regex, Counter", "Auth-Results, Received-SPF", "EmailAuthenticationAnalysis (SPF/DKIM/DMARC)"],
            ["Homoglyph Detector", "app/services/homoglyph_detector.py", "unicodedata, regex lookup tables", "Display names, bodies, anchor text", "Detected mixed-script tokens & normalized text"],
            ["DistilBERT NLP Engine", "app/services/model_inference.py", "PyTorch 2.6.0, Transformers, CUDA", "Subject + Body string", "ModelInferenceEvidence (uncalibrated score)"],
            ["Evidence Fusion Engine", "app/services/scoring_engine.py", "Mathematical piecewise functions", "All 5 modality intermediate outputs", "0–100 Risk Score, Category, Breakdown"],
            ["HTML Report Generator", "frontend/src/utils/reportGenerator.ts", "TypeScript, W3C Level 3 CSP", "EmailAnalysisResponse JSON", "Self-contained .html file blob"],
            ["User Interface Dashboard", "frontend/src/App.tsx", "React 19, TypeScript, Tailwind CSS", "JSON API response", "Interactive 0–100 cyber forensic UI"]
        ]
    },
    "table_5_1": {
        "title": "Table 5.1: PhishMMF Cleaned Dataset Provenance & Composition",
        "headers": ["Sub-Corpus Source", "Collection Era", "Nature of Messages", "Original Samples", "Retained Samples", "Ground-Truth Label"],
        "rows": [
            ["CEAS_08_0", "2008", "Legitimate corporate & personal email", "3,000", "2,981", "0 (Benign)"],
            ["SpamAssasin_0", "~2002–2006", "Public Apache SpamAssassin ham archive", "3,000", "2,978", "0 (Benign)"],
            ["phishing_pot", "Modern Honeypots", "Verified phishing attacks & lures", "3,000", "1,280", "1 (Phishing)"],
            ["Consolidated Total", "Multi-Decadal", "Forensic Email Threat Corpus", "9,000", "7,239", "1,280 Phish / 5,959 Benign"]
        ]
    },
    "table_5_2": {
        "title": "Table 5.2: Leakage-Safe Stratified Partition Manifest",
        "headers": ["Partition", "File Path", "Total Records", "Phishing Count (%)", "Benign Count (%)", "Partition SHA-256 Digest"],
        "rows": [
            ["Training Split (80%)", "data/processed/phishmmf/train.csv", "5,791", "1,024 (17.68%)", "4,767 (82.32%)", "72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c"],
            ["Validation Split (10%)", "data/processed/phishmmf/validation.csv", "724", "128 (17.68%)", "596 (82.32%)", "40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab"],
            ["Locked Test Split (10%)", "data/processed/phishmmf/test.csv", "724", "128 (17.68%)", "596 (82.32%)", "1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e"],
            ["Complete Canonical", "data/processed/phishmmf/cleaned_email_dataset.csv", "7,239", "1,280 (17.68%)", "5,959 (82.32%)", "6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af"]
        ]
    },
    "table_6_1": {
        "title": "Table 6.1: DistilBERT Model Architecture & Training Hyperparameters",
        "headers": ["Hyperparameter / Setting", "Configured Value", "Operational & Theoretical Rationale"],
        "rows": [
            ["Base Architecture", "distilbert-base-uncased", "Distilled 6-layer bidirectional transformer (66M parameters)"],
            ["Transformer Layers (L)", "6", "Half of BERT-base's 12 layers, retaining 97% language understanding"],
            ["Attention Heads (H)", "12", "Multi-head attention projections with head dimension d_k = 64"],
            ["Hidden Dimension (d_model)", "768", "Dimensionality of token vector representations"],
            ["Feed-Forward Dimension (d_ff)", "3,072", "Intermediate expansion dimension in position-wise FFN"],
            ["Activation Function", "GELU", "Gaussian Error Linear Unit x * Phi(x)"],
            ["Dropout Rates", "Attention: 0.1, Hidden: 0.1, Classifier: 0.2", "Stochastic regularization preventing co-adaptation of weights"],
            ["Vocabulary Size (V)", "30,522 tokens", "WordPiece subword vocabulary with special tokens [CLS], [SEP], [PAD]"],
            ["Maximum Sequence Length", "256 tokens", "Truncation boundary balancing linguistic context and VRAM footprint"],
            ["Effective Batch Size", "16 (4 per-device x 4 grad accum)", "Stabilizes stochastic gradient estimates on laptop GPU VRAM"],
            ["Optimizer", "AdamW (beta1=0.9, beta2=0.999, eps=1e-8)", "Adam with decoupled L2 weight decay regularization (lambda=0.01)"],
            ["Learning Rate Schedule", "Initial 2e-5 with linear warmup (108 steps)", "Prevents early gradient divergence during initial fine-tuning steps"],
            ["Gradient Clipping", "Max norm = 1.0", "Prevents exploding gradients across transformer residual layers"],
            ["Precision", "FP16 Automatic Mixed Precision (AMP)", "Accelerates tensor computations by 2.2x while reducing memory by 50%"],
            ["Training Hardware", "NVIDIA GeForce RTX 3050 Laptop GPU", "Ampere architecture, 6 GB VRAM, 2048 CUDA cores"]
        ]
    },
    "table_6_2": {
        "title": "Table 6.2: Epoch-by-Epoch Training & Validation Convergence Dynamics",
        "headers": ["Epoch", "Train Loss", "Val Loss", "Val Accuracy", "Val Precision (Phish)", "Val Recall (Phish)", "Val F1 (Phish)", "Val ROC-AUC", "Confusion Matrix (TN, FP, FN, TP)"],
        "rows": [
            ["1 (Selected)", "0.1500", "0.0319", "99.17%", "96.92%", "98.44%", "97.67%", "0.9973", "(592, 4, 2, 126)"],
            ["2", "0.0127", "0.0360", "99.31%", "98.43%", "97.66%", "98.04%", "0.9980", "(594, 2, 3, 125)"],
            ["3", "0.0034", "0.0367", "99.31%", "98.43%", "97.66%", "98.04%", "0.9982", "(594, 2, 3, 125)"]
        ]
    },
    "table_8_2": {
        "title": "Table 8.2: Comprehensive Classification Report on Locked Test Set (N=724)",
        "headers": ["Class Name", "Label ID", "Precision", "Recall", "F1-Score", "Support", "False Positive Rate", "False Negative Rate"],
        "rows": [
            ["Benign (Legitimate)", "0", "99.33% (591/595)", "99.16% (591/596)", "99.24%", "596", "3.12% (4/128)", "0.84% (5/596)"],
            ["Phishing (Attack)", "1", "96.12% (124/129)", "96.88% (124/128)", "96.50%", "128", "0.84% (5/596)", "3.12% (4/128)"],
            ["Macro Average", "—", "97.72%", "98.02%", "97.87%", "724", "—", "—"],
            ["Weighted Average", "—", "98.76%", "98.76%", "98.76%", "724", "—", "—"],
            ["Overall Accuracy", "—", "—", "—", "98.76% (715/724)", "724", "0.84%", "3.12%"]
        ]
    },
    "table_8_3": {
        "title": "Table 8.3: Confusion Matrix Breakdown on Locked Test Set",
        "headers": ["Metric Name", "Sample Count", "Percentage of Class", "Forensic Interpretation"],
        "rows": [
            ["True Negatives (TN)", "591", "99.16% of Benign", "Legitimate emails correctly identified as benign."],
            ["False Positives (FP)", "5", "0.84% of Benign", "Legitimate commercial/IT alerts incorrectly flagged by text model."],
            ["False Negatives (FN)", "4", "3.12% of Phishing", "Subtle/polite phishing attacks missed by text-only model."],
            ["True Positives (TP)", "124", "96.88% of Phishing", "Active phishing attacks accurately detected and classified."]
        ]
    },
    "table_8_4": {
        "title": "Table 8.4: Detailed Forensic Audit of All 9 Test Errors",
        "headers": ["Record ID", "Source", "True Class", "Predicted", "Model Prob P(Phish)", "Subject Line", "Forensic Root Cause Analysis"],
        "rows": [
            ["CEAS_08_0_01325", "CEAS", "0 (Benign)", "1 (Phish)", "0.8223", "Get Your Business Credit Report and Scores!", "Promotional credit marketing dense with financial lure keywords."],
            ["CEAS_08_0_01768", "CEAS", "0 (Benign)", "1 (Phish)", "0.9526", "Is outsourcing right for you?", "Unsolicited business development with urgent call-to-action phrasing."],
            ["CEAS_08_0_01870", "CEAS", "0 (Benign)", "1 (Phish)", "0.9175", "resnet address alert", "Authentic campus IT notice warning of dynamic IP changes; mimics credential lures."],
            ["CEAS_08_0_02270", "CEAS", "0 (Benign)", "1 (Phish)", "0.9629", "PDQ High Speed Internet - you reached 100% usage", "ISP quota notice structurally identical to account suspension threats."],
            ["CEAS_08_0_02780", "CEAS", "0 (Benign)", "1 (Phish)", "0.9570", "[FRImag2002] Seznam knjig z ED2K linki", "Non-English (Slovenian) academic digest with peer-to-peer download links."],
            ["phishing_pot_00724", "Pot", "1 (Phish)", "0 (Benign)", "0.1301", "Spark Change: Musk's Power Unleashed", "Crypto scam styled as clean technology news interview; lacks coercion words."],
            ["phishing_pot_01325", "Pot", "1 (Phish)", "0 (Benign)", "0.0399", "HARVARD MEDICAL: “Weight-Loss Doubling” Trick", "Dietary supplement spam; vocabulary absent from IT/banking phishing corpus."],
            ["phishing_pot_02446", "Pot", "1 (Phish)", "0 (Benign)", "0.0121", "Musk's Power Innovations Exposed", "Celebrity clickbait lure designed to bypass corporate spam filters."],
            ["phishing_pot_02952", "Pot", "1 (Phish)", "0 (Benign)", "0.2125", "Dear Friend/18/12/2024", "Polite advance-fee 419 letter lacking urgency threats or technical jargon."]
        ]
    },
    "table_8_5": {
        "title": "Table 8.5: Live Socket Fixture Verification Results (10 Scenarios Across Ports 8000 & 5173)",
        "headers": ["#", "Fixture File", "Scenario Tested", "File Size", "HTTP Status", "DistilBERT Score", "Fusion Risk Score", "Assigned Risk Category"],
        "rows": [
            ["1", "01_simple_plaintext.eml", "Plain text baseline", "279 B", "200 OK", "0.0538 (Label 0)", "0 / 100", "INSUFFICIENT_EVIDENCE"],
            ["2", "02_html_only.eml", "HTML-only email", "760 B", "200 OK", "0.9953 (Label 1)", "55 / 100", "REVIEW_RECOMMENDED"],
            ["3", "03_multipart_plain_html.eml", "Multipart alternative", "998 B", "200 OK", "0.8890 (Label 1)", "55 / 100", "REVIEW_RECOMMENDED"],
            ["4", "04_attachments.eml", "MIME attachments", "1,345 B", "200 OK", "0.0421 (Label 0)", "0 / 100", "LOW_RISK_INDICATORS"],
            ["5", "05_multiple_urls.eml", "Multiple embedded URLs", "1,236 B", "200 OK", "0.9974 (Label 1)", "60 / 100", "REVIEW_RECOMMENDED"],
            ["6", "06_multiple_received_hops.eml", "Transit hop chain", "1,598 B", "200 OK", "0.8982 (Label 1)", "60 / 100", "REVIEW_RECOMMENDED"],
            ["7", "07_malformed.eml", "Corrupted header syntax", "633 B", "200 OK", "0.0023 (Label 0)", "0 / 100", "INSUFFICIENT_EVIDENCE"],
            ["8", "08_missing_optional_headers.eml", "Missing optional headers", "239 B", "200 OK", "0.8589 (Label 1)", "55 / 100", "REVIEW_RECOMMENDED"],
            ["9", "zero_byte.eml", "Empty file boundary", "0 B", "400 Bad Req", "None (Rejected)", "None (Rejected)", "N/A (Gateway Blocked)"],
            ["10", "oversized_11mb.eml", "Oversized payload limit", "11.5 MB", "413 Payload", "None (Rejected)", "None (Rejected)", "N/A (Gateway Blocked)"]
        ]
    },
    "table_8_6": {
        "title": "Table 8.6: Evidence Fusion Validation on Control Emails and Real Phishing Attacks",
        "headers": ["Email Sample", "Email Classification Type", "Raw Model Score", "Corroboration Dampening Applied", "Threat Floor Override", "Final Score", "Outcome Category"],
        "rows": [
            ["google_notification.eml", "Authentic Google Security Alert", "0.0124 (Benign)", "No (Model naturally low)", "None", "0 / 100", "LOW_RISK_INDICATORS"],
            ["linkedin_complete_profile.eml", "Authentic LinkedIn Network Mail", "0.9123 (Phish Lure)", "YES: Dampened to 5 pts", "None", "5 / 100", "LOW_RISK_INDICATORS (Safe)"],
            ["openai_privacy_policy.eml", "Authentic OpenAI Legal Notice", "0.0215 (Benign)", "No (Model naturally low)", "None", "0 / 100", "LOW_RISK_INDICATORS"],
            ["overleaf_welcome.eml", "Authentic Overleaf Onboarding", "0.0340 (Benign)", "No (Model naturally low)", "None", "0 / 100", "LOW_RISK_INDICATORS"],
            ["pinterest_terms_update.eml", "Authentic Pinterest Notice", "0.0180 (Benign)", "No (Model naturally low)", "None", "0 / 100", "LOW_RISK_INDICATORS"],
            ["sample-1.eml", "Real Phish: Bradesco Livelo", "0.9854 (Phish Lure)", "No (Fully Corroborated)", "Brand Mismatch", "85 / 100", "HIGH_RISK_INDICATORS_PRESENT"],
            ["sample-10.eml", "Real Phish: OKX Homoglyph", "0.9912 (Phish Lure)", "No (Fully Corroborated)", "Critical Floor: Homoglyphs", "88 / 100", "HIGH_RISK_INDICATORS_PRESENT"],
            ["sample-10001.eml", "Real Phish: MetaMask 2FA", "0.9940 (Phish Lure)", "No (Fully Corroborated)", "Critical Floor: Deceptive Link", "90 / 100", "HIGH_RISK_INDICATORS_PRESENT"]
        ]
    },
    "table_9_1": {
        "title": "Table 9.1: Comprehensive Master Test Case Matrix",
        "headers": ["Test ID", "Subsystem", "Description", "Input Vector", "Expected Result", "Status"],
        "rows": [
            ["TC-GW-01", "Gateway", "Rejection of empty 0-byte file", "0 B .eml file", "HTTP 400 'Uploaded file is empty'", "PASS"],
            ["TC-GW-02", "Gateway", "Rejection of oversized file (>10MB)", "11.5 MB .eml file", "HTTP 413 'Exceeds maximum limit'", "PASS"],
            ["TC-GW-03", "Gateway", "Rejection of unsupported extension", "payload.exe / test.pdf", "HTTP 400 'Invalid file extension'", "PASS"],
            ["TC-GW-04", "Gateway", "Root & Health check endpoints", "GET /health and GET /", "HTTP 200 'status': 'healthy'", "PASS"],
            ["TC-EML-01", "Parser", "RFC 5322 plain text extraction", "01_simple_plaintext.eml", "Plain text extracted, headers valid", "PASS"],
            ["TC-EML-02", "Parser", "HTML sanitization script stripping", "HTML with <script> and <iframe>", "Active tags decomposed; text kept", "PASS"],
            ["TC-EML-03", "Parser", "In-memory attachment SHA-256", "04_attachments.eml (PDF+TXT)", "Correct SHA-256 digests; 0 disk writes", "PASS"],
            ["TC-EML-04", "Parser", "Malformed header resilience", "07_malformed.eml", "Fallback to compat32; warnings logged", "PASS"],
            ["TC-EML-05", "Parser", "Missing optional header defaults", "08_missing_optional_headers.eml", "None / empty lists; zero exceptions", "PASS"],
            ["TC-URL-01", "URL Intel", "Userinfo authority deception (@ trick)", "http://paypal.com@evil.com/", "Trigger RULE_USERINFO_AUTH (25 pts)", "PASS"],
            ["TC-URL-02", "URL Intel", "Anchor text display deception", "Anchor: bank.com, Href: evil.com", "Trigger RULE_DECEPTIVE_DISPLAYED_LINK", "PASS"],
            ["TC-URL-03", "URL Intel", "Raw public IP-literal host", "http://198.51.100.1/login", "Trigger RULE_PUBLIC_IP_HOST (15 pts)", "PASS"],
            ["TC-URL-04", "URL Intel", "Brand lookalike domain detection", "http://paypa1-security.com/", "Trigger RULE_LOOKALIKE_IMPERSONATION", "PASS"],
            ["TC-URL-05", "URL Intel", "Double percent-encoding evasion", "http://target.com/%252e%252e/", "Trigger RULE_DOUBLE_PERCENT_ENCODING", "PASS"],
            ["TC-URL-06", "URL Intel", "Non-default port detection", "http://legit.com:8080/index", "Trigger RULE_NON_DEFAULT_PORT (6 pts)", "PASS"],
            ["TC-URL-07", "URL Intel", "Safe OIDC login_hint parameter", "https://accounts.google.com?login_hint=...", "Whitelisted as benign IdP param", "PASS"],
            ["TC-IP-01", "IP Intel", "RFC 1918 Private classification", "10.0.0.1, 192.168.1.1", "Scope: Private, Malicious: False", "PASS"],
            ["TC-IP-02", "IP Intel", "RFC 5737 Documentation range", "192.0.2.1, 198.51.100.1", "Scope: Documentation, Malicious: False", "PASS"],
            ["TC-IP-03", "IP Intel", "RFC 6598 Shared Address Space", "100.64.0.1, 100.127.255.255", "Scope: Reserved / Special-Purpose", "PASS"],
            ["TC-IP-04", "IP Intel", "RFC 2544 Benchmarking range", "198.18.0.1, 198.19.255.255", "Scope: Reserved / Special-Purpose", "PASS"],
            ["TC-IP-05", "IP Intel", "Apparent Origin Discovery", "5 Received transit hops", "Resolved outermost non-private public IP", "PASS"],
            ["TC-IP-06", "IP Intel", "Provider Catalog Matching", "Microsoft 365 delivery hop", "Provider match: Microsoft 365 (EOP)", "PASS"],
            ["TC-AUTH-01", "Email Auth", "SPF & DKIM Pass reporting", "Authentication-Results: pass", "Status: PASS, is_trusted: False", "PASS"],
            ["TC-AUTH-02", "Email Auth", "Explicit DMARC failure", "dmarc=fail (p=reject)", "Trigger RULE_AUTH_EXPLICIT_FAILURE (15 pts)", "PASS"],
            ["TC-AUTH-03", "Email Auth", "Contradictory header detection", "Intermediate hop fail, final hop pass", "Trigger RULE_AUTH_CONTRADICTORY_HEADERS", "PASS"],
            ["TC-AUTH-04", "Email Auth", "Stage A.3 Boolean Safety Guarantee", "Any offline .eml upload", "is_trusted is guaranteed False", "PASS"],
            ["TC-ML-01", "DistilBERT", "Model Checkpoint Ingestion", "models/distilbert_baseline", "Loads 267.8 MB Safetensors correctly", "PASS"],
            ["TC-ML-02", "DistilBERT", "Sequence truncation at 256 tokens", "1,000-word email text", "Truncated to 256 WordPiece tokens", "PASS"],
            ["TC-ML-03", "DistilBERT", "Defensive runtime error handling", "Simulated GPU tensor exception", "Status: ERROR; score: None; never benign", "PASS"],
            ["TC-FUS-01", "Fusion", "Corroboration dampening on clean tech", "Clean tech (<=5 pts) + Model=0.90", "Model score dampened to 5 pts (Score <=10)", "PASS"],
            ["TC-FUS-02", "Fusion", "Full model corroboration on threat", "Threat URL + Model=0.90", "Model score assigned full linear weight (18 pts)", "PASS"],
            ["TC-FUS-03", "Fusion", "Critical Floor: Dangerous Attachment", "Attachment: invoice.pdf.exe", "Final score escalated to >= 75 (High Risk)", "PASS"],
            ["TC-FUS-04", "Fusion", "Critical Floor: Deceptive Anchor Link", "Anchor: paypal.com, Href: evil.com", "Final score escalated to >= 75 (High Risk)", "PASS"],
            ["TC-REP-01", "Reporting", "W3C CSP Level 3 Compliance", "Generated HTML report", "Validated CSP meta tag without 'sandbox'", "PASS"],
            ["TC-REP-02", "Reporting", "XSS Script Injection Neutralization", "Subject: <script>alert(1)</script>", "Escaped to &lt;script&gt;; zero execution", "PASS"],
            ["TC-REP-03", "Reporting", "Zero-Network Self-Containment", "Generated HTML report", "Zero external script, font, or CSS links", "PASS"],
            ["TC-SEC-01", "Security", "Network Egress Prohibition", "Parser, URL, IP, Auth engines", "guard_no_network verifies 0 socket egress", "PASS"],
            ["TC-SEC-02", "Security", "Zero Server Disk Persistence", "After 10 live uploads", "Verified 0 database files, 0 cached emails", "PASS"]
        ]
    }
}

