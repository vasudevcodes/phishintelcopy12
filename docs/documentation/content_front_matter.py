"""
PhishIntel VTU Project Report — Front Matter Content
Contains Cover Page, Certificate, Declaration, Acknowledgement, Abstract,
Table of Contents, List of Figures, List of Tables, and Abbreviations.
"""

FRONT_MATTER = {
    "title": "PHISHINTEL: TRANSFORMER AND NLP-BASED EMAIL PHISHING DETECTION AND IP INTELLIGENCE",
    "subtitle": "A Project Report submitted in partial fulfillment of the requirements for the award of the degree of Bachelor of Engineering in Computer Science and Engineering",
    "vtu_university": "VISVESVARAYA TECHNOLOGICAL UNIVERSITY, BELAGAVI",
    "academic_year": "2026–2027",
    "student_name": "VASUDEV M V",
    "student_usn": "[USN: 1XX20CSXXX]",
    "guide_name": "[Prof. / Dr. Project Guide Name]",
    "guide_designation": "[Associate Professor / Assistant Professor, Dept. of CSE]",
    "hod_name": "[Dr. Head of Department Name]",
    "hod_designation": "[Professor & Head, Dept. of CSE]",
    "principal_name": "[Dr. Principal Name]",
    "principal_designation": "[Principal, College of Engineering]",
    "college_name": "[COLLEGE OF ENGINEERING NAME]",
    "college_address": "[City, Karnataka, India - 5600XX]",
    "department_name": "DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING",
    
    "certificate_text": (
        "This is to certify that the project work entitled \"PHISHINTEL: TRANSFORMER AND NLP-BASED EMAIL PHISHING DETECTION AND IP INTELLIGENCE\" "
        "is a bona fide work carried out by VASUDEV M V ([USN: 1XX20CSXXX]) in partial fulfillment of the requirements for the award of the "
        "degree of Bachelor of Engineering in Computer Science and Engineering of Visvesvaraya Technological University, Belagavi during the "
        "academic year 2026–2027. It is certified that all corrections/suggestions indicated for internal assessment have been incorporated "
        "in the report deposited in the departmental library. The project report has been approved as it satisfies the academic requirements in "
        "respect of the project work prescribed for the said degree."
    ),
    
    "declaration_text": (
        "I, VASUDEV M V ([USN: 1XX20CSXXX]), student of Bachelor of Engineering in Computer Science and Engineering at [COLLEGE OF ENGINEERING NAME], "
        "hereby declare that the project entitled \"PHISHINTEL: TRANSFORMER AND NLP-BASED EMAIL PHISHING DETECTION AND IP INTELLIGENCE\" has been "
        "independently developed and executed by me under the esteemed guidance of [Prof. / Dr. Project Guide Name], Department of Computer Science "
        "and Engineering. I further declare that this report has not been submitted previously to any other university or institute for the award "
        "of any degree, diploma, fellowship, or other similar title or recognition."
    ),
    
    "acknowledgement_text": (
        "The successful completion of this project is the result of constant encouragement, constructive guidance, and intellectual support "
        "from numerous individuals and academic mentors. I take immense privilege in expressing my profound gratitude to all who contributed to the fruition of this work.\n\n"
        "First and foremost, I express my sincere gratitude to Dr. [Principal Name], Principal of [College of Engineering Name], for providing a conducive academic environment, "
        "state-of-the-art computational laboratories, and institutional infrastructure necessary for carrying out this engineering project.\n\n"
        "I express my deepest sense of gratitude to Dr. [Head of Department Name], Professor and Head of the Department of Computer Science and Engineering, for their visionary "
        "guidance, administrative support, continuous encouragement, and valuable suggestions throughout the course of our engineering curriculum.\n\n"
        "I owe my heartfelt appreciation and deepest gratitude to my esteemed project guide, [Prof. / Dr. Project Guide Name], [Designation], Department of Computer Science and Engineering, "
        "for their invaluable guidance, patient mentoring, perceptive technical feedback, and unwavering support from the initial conceptualization of PhishIntel to the final forensic verification "
        "and report compilation. Their deep insights into cybersecurity protocols and applied natural language processing have been instrumental in shaping the technical rigor of this system.\n\n"
        "I am deeply thankful to the project coordinators, laboratory technical staff, and faculty members of the Department of Computer Science and Engineering for their direct and indirect "
        "assistance, timely reviews, and constructive evaluations during the internal evaluation stages.\n\n"
        "Finally, I express my profound indebtedness to my parents, family members, and peers for their unconditional love, moral support, and constant motivation throughout my academic journey."
    ),
    
    "abstract": (
        "Email phishing represents the single most pervasive vector for initial enterprise access, ransomware delivery, and credential harvesting in modern cybersecurity, accounting for over 90% of successful corporate breaches. Conventional defense systems predominantly depend on static domain reputation blacklists, centralized DNS querying, and naive signature filtering. These traditional mechanisms exhibit critical vulnerabilities, including severe latency in intercepting ephemeral zero-hour domains, vulnerability to linguistic evasion and AI-generated social engineering lures, and catastrophic exposure of internal corporate communication metadata to external third-party lookup providers.\n\n"
        "To decisively overcome these operational and privacy limitations, this project presents PhishIntel: an enterprise-grade, zero-network, multi-modal forensic email investigation and phishing detection platform. PhishIntel combines fine-tuned deep bidirectional transformer language modeling with deterministic structural, lexical, and cryptographic intelligence. The system ingests raw RFC 5322 email files (.eml) in an isolated local execution environment, parsing multi-part MIME hierarchies, calculating cryptographic SHA-256 attachment digests in memory, and reconstructing chronological Mail Transfer Agent (MTA) transit hop sequences without external dependencies.\n\n"
        "PhishIntel incorporates five complementary forensic evaluation dimensions: (1) Deterministic Lexical URL Intelligence, deconstructing hyperlinks across RFC 3986 lexical rules, homoglyph character analysis, and userinfo authority deception without issuing outbound network handshakes; (2) Cryptographic Authentication Analysis, evaluating receiver-reported SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) assertions while enforcing strict offline provenance boundaries; (3) Topological IP Transit Intelligence, categorizing candidate IP addresses into strict RFC network scopes (RFC 1918, RFC 5737, RFC 6598, RFC 2544) and matching delivery hops against verified cloud provider catalogues; (4) DistilBERT NLP Text Classification, employing a fine-tuned 6-layer bidirectional transformer (66M parameters) to analyze semantic coercion; and (5) An Explainable 0–100 Evidence-Based Risk Scoring Engine featuring Corroboration Dampening and Critical Threat Floors. When an email exhibits clean, authenticated technical infrastructure, isolated high model scores on benign corporate notification language are mathematically dampened to prevent false positives; conversely, confirmed critical indicators (such as executable attachments, anchor text deception, or lookalike brand domains) trigger an automated risk floor escalation to 75+ points (High Risk).\n\n"
        "Empirical evaluation was conducted on a held-out locked test partition of 724 samples from the forensic PhishMMF corpus on an NVIDIA GeForce RTX 3050 GPU. PhishIntel achieved a test accuracy of 98.76%, a phishing detection precision of 96.12%, a phishing recall of 96.88%, a phishing F1-score of 96.50%, a benign F1-score of 99.24%, and an Area Under the ROC Curve (ROC-AUC) of 0.9995, with an average inference latency of 4.7 ms per message. Software verification across 317 backend automated pytest test node IDs and 78 frontend TypeScript contract tests confirmed 100% operational pass rates. Furthermore, PhishIntel dynamically generates self-contained, standalone HTML forensic reports protected by strict W3C Content Security Policy Level 3 directives, providing digital forensics and incident response (DFIR) teams with a robust, transparent, and legally defensible threat intelligence capability."
    ),
    
    "abbreviations": [
        ("MTA", "Mail Transfer Agent"),
        ("MUA", "Mail User Agent"),
        ("SPF", "Sender Policy Framework (RFC 7208)"),
        ("DKIM", "DomainKeys Identified Mail (RFC 6376)"),
        ("DMARC", "Domain-based Message Authentication, Reporting, and Conformance (RFC 7489)"),
        ("BERT", "Bidirectional Encoder Representations from Transformers"),
        ("DistilBERT", "Distilled Bidirectional Encoder Representations from Transformers"),
        ("NLP", "Natural Language Processing"),
        ("RFC", "Request for Comments (Internet Engineering Task Force Standard)"),
        ("MIME", "Multipurpose Internet Mail Extensions"),
        ("CSP", "Content Security Policy (W3C Specification)"),
        ("XSS", "Cross-Site Scripting"),
        ("DFIR", "Digital Forensics and Incident Response"),
        ("SOC", "Security Operations Center"),
        ("IOC", "Indicator of Compromise"),
        ("BEC", "Business Email Compromise"),
        ("URI", "Uniform Resource Identifier (RFC 3986)"),
        ("URL", "Uniform Resource Locator"),
        ("IP", "Internet Protocol"),
        ("IPv4", "Internet Protocol Version 4 (RFC 791)"),
        ("IPv6", "Internet Protocol Version 6 (RFC 8200)"),
        ("CIDR", "Classless Inter-Domain Routing"),
        ("CGNAT", "Carrier-Grade Network Address Translation (RFC 6598)"),
        ("ULA", "Unique Local Address (RFC 4193)"),
        ("IDN", "Internationalized Domain Name"),
        ("Punycode", "Bootstring Encoding of Unicode for IDNA (RFC 3492)"),
        ("DNS", "Domain Name System"),
        ("OIDC", "OpenID Connect"),
        ("SHA-256", "Secure Hash Algorithm 256-Bit (FIPS PUB 180-4)"),
        ("ROC-AUC", "Receiver Operating Characteristic – Area Under the Curve"),
        ("FPR", "False Positive Rate"),
        ("FNR", "False Negative Rate"),
        ("REST", "Representational State Transfer"),
        ("API", "Application Programming Interface"),
        ("CORS", "Cross-Origin Resource Sharing"),
        ("UI", "User Interface"),
        ("VRAM", "Video Random-Access Memory"),
        ("CUDA", "Compute Unified Device Architecture (NVIDIA)"),
        ("AMP", "Automatic Mixed Precision (FP16)"),
        ("GELU", "Gaussian Error Linear Unit"),
        ("AdamW", "Adam with Decoupled Weight Decay Optimization"),
        ("VTU", "Visvesvaraya Technological University")
    ]
}

