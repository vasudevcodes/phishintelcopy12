# Phase 7A — Evidence Fusion Design & Implementation Technical Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 7A — Evidence Fusion Design and Implementation  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Service Path**: `backend/app/services/evidence_fusion.py`  
**Schema Path**: `backend/app/schemas/evidence_fusion.py`  
**Parser Path**: `backend/app/services/email_parser.py`  
**Test Path**: `backend/tests/test_evidence_fusion.py`  
**Status Verdict**: **`PHASE_7A_EVIDENCE_FUSION_COMPLETE`**

---

## 1. Executive Summary & Objective

Phase 7A designs and implements the **PhishIntel Evidence Fusion Engine**. This module synthesizes the forensic outputs of four distinct security components:
1. **DistilBERT NLP Baseline** (Phase 3B/3C): Semantic text classification.
2. **URL Intelligence Engine** (Phase 4A/4B): Deterministic lexical and structural link heuristics.
3. **Email Authentication Evidence Engine** (Phase 5A): Reported SPF, DKIM, and DMARC header assertions.
4. **IP Intelligence Engine** (Phase 6A): Received-header transit hops and apparent origin analysis.

### Core Architectural Principles
- **Explicit Uncertainty Preservation**: The engine categorizes emails into cautious, explainable tiers (`INSUFFICIENT_EVIDENCE`, `LOW_RISK_INDICATORS`, `REVIEW_RECOMMENDED`, and `HIGH_RISK_INDICATORS_PRESENT`). It strictly refrains from emitting uncalibrated overall probability percentages (e.g. "87% phishing").
- **Clear Demarcation of Observations vs Inferences**: Individual component evidence (e.g. uncalibrated DistilBERT scores, 0–100 URL heuristic scores, MTA authentication results) remains isolated in their respective sections and is not directly summed or multiplied.
- **De-duplication & Correlation Handling**: Avoids double-counting multiple links pointing to the same destination host, and accounts for downstream dependency between SPF and DMARC failures.
- **Scientific Humility & Honest Limitations**: Fully acknowledges Phase 3D audit findings regarding dataset source-label collinearity and the `<USER>` token shortcut. Declares the fusion layer as an explainable design baseline, not an empirically validated real-world accuracy improvement.

---

## 2. Multi-Modal Evidence Fusion Architecture

```
                                  Uploaded .eml File
                                          │
                                          ▼
                      Phase 1 Forensic Parser (email_parser.py)
         ┌───────────────────┬────────────────────┬───────────────────┐
         ▼                   ▼                    ▼                   ▼
    Email Body           Email URLs          MTA Headers        Received Hops
         │                   │                    │                   │
         ▼                   ▼                    ▼                   ▼
   [DistilBERT NLP]    [Phase 4B URLs]      [Phase 5A Auth]     [Phase 6A IPs]
   • Uncalibrated      • Structural Rules   • SPF/DKIM/DMARC    • Transit Order
     similarity score    (0–100 score)        assertions        • Apparent origin
         │                   │                    │                   │
         └───────────────────┼────────────────────┴───────────────────┘
                             ▼
                 Phase 7A Evidence Fusion Engine (evidence_fusion.py)
                 ├── Component Evidence Normalization
                 ├── Host-Level URL De-duplication (Prevents Double-Counting)
                 ├── Auth Failure Correlation (SPF ──► DMARC Dependency)
                 ├── Transparent Rule-Based Aggregation
                 └── Categorization (Preserves Uncertainty, No Unified %)
                             │
                             ▼
                 EvidenceFusionResult Schema
                 ├── overall_category: AssessmentCategory
                 ├── model_evidence: ModelEvidenceInterpretation
                 ├── url_evidence: URLEvidenceSummary
                 ├── auth_evidence: AuthEvidenceSummary
                 ├── ip_evidence: IPEvidenceSummary
                 ├── contributing_factors: List[str]
                 ├── inconclusive_or_missing_factors: List[str]
                 ├── reasoning: str
                 └── disclaimer: str
```

---

## 3. Score Semantics, Calibration & Non-Probabilistic Output

### 3.1 Why No Overall Percentage is Emitted
A common pitfall in multi-modal cybersecurity systems is inventing arbitrary mathematical formulas to merge disparate scores—such as adding a 0–100 heuristic score to a neural network probability:
$$\text{Flawed Fusion}: \text{Score} = w_1 \cdot P_{\text{BERT}} + w_2 \cdot \frac{\text{URL\_Score}}{100} + w_3 \cdot \mathbb{I}(\text{Auth}=\text{FAIL})$$

Such pseudo-probabilities are mathematically invalid:
1. **Non-Calibrated Neural Outputs**: The DistilBERT model output represents a sigmoid probability from a model trained on a specific academic corpus (`phishmmf`). As documented in Phase 3D, it has not undergone temperature scaling, Platt scaling, or isotonic regression on a fresh, out-of-distribution real-world corpus.
2. **Heuristic Indicators are Not Likelihoods**: URL heuristic scores (0–100) are rule-based severity weights designed to flag structural anomalies (e.g. IP-literal hostnames or deceptive `@` userinfo). A URL score of 40 does not mean there is a 40% statistical probability of phishing.
3. **Authentication is Not a Direct Phishing Indicator**: Domain authentication verifies authorization, not intent. Threat actors can register throwaway domains with 100% valid SPF/DKIM/DMARC (`PASS`), while legitimate mailing lists or forwarded emails frequently break SPF (`FAIL`).

Accordingly, PhishIntel **strictly forbids** emitting an overall percentage. The output is bounded to explicit, qualitative assessment categories.

### 3.2 Standardized Assessment Categories
| Category | Definition & Criteria | Forensic Interpretation |
| :--- | :--- | :--- |
| **`HIGH_RISK_INDICATORS_PRESENT`** | Severe structural deception detected (e.g. high-risk URL heuristics such as IP-literal hostnames, embedded credential tricks, or dangerous schemes), OR explicit authentication failures corroborated by suspicious links/text. | High probability of credential theft or lure deception. Immediate security analyst review required. |
| **`REVIEW_RECOMMENDED`** | Anomalous or conflicting indicators present without definitive proof of malice (e.g. conflicting authentication headers across intermediate MTAs, moderate URL heuristics, or elevated text lure similarity without link corroboration). | Ambiguous or suspicious message structure. Manual analyst inspection advised. |
| **`LOW_RISK_INDICATORS`** | Legitimate domain authentication verified (`PASS` across present mechanisms), clean URLs (`INFO` or negligible), normal transit hops, and low model similarity. | Standard authorized message characteristics observed. |
| **`INSUFFICIENT_EVIDENCE`** | Missing or neutral signals (e.g. plaintext message without URLs, missing authentication headers, or internal transit only). | Forensic data is too sparse or neutral to justify an elevated risk category. |

---

## 4. De-Duplication & Correlation Handling

To prevent bias and distorted assessments, the fusion engine enforces two defensive principles:

### 4.1 Host-Level URL De-Duplication
Phishing emails frequently include 5–10 identical hyperlinks repeated across buttons, footers, and text lures pointing to the same server.
- **Engine Behavior**: Observations are grouped by `normalized_hostname`. Multiple links pointing to the identical target domain are collapsed into a single entity.
- **Result**: `URLEvidenceSummary.unique_domains` reflects distinct hosts, and `deduplication_applied=True`. High-risk rule violations are recorded once per distinct target infrastructure.

### 4.2 Correlated Authentication Failures
In email architecture (RFC 7489), DMARC evaluates whether the sender domain aligns with passing SPF or DKIM results. If an email has no DKIM signature and SPF fails, DMARC will automatically fail as a downstream consequence.
- **Engine Behavior**: The engine recognizes that DMARC failure is directly correlated with SPF failure rather than being an independent second vector of attack.
- **Result**: Flagged explicitly as `correlated_failure_noted=True` in `AuthEvidenceSummary`.

---

## 5. Dataset Research Limitations & Scientific Disclosure

In accordance with Phase 3D research findings, the PhishIntel evidence fusion engine is explicitly bound by the following documented scientific limitations:

### 5.1 Absolute Source-Label Collinearity
As established in `docs/phase3/phase3d_source_leakage_audit.md`:
- The approved `phishmmf` dataset exhibits **100% source-label collinearity**:
  - `CEAS_08_0` (2,981 records): 100.0% Benign / 0.0% Phishing
  - `SpamAssasin_0` (2,978 records): 100.0% Benign / 0.0% Phishing
  - `phishing_pot` (1,280 records): 0.0% Benign / 100.0% Phishing
- Zero sources contain both benign and phishing records. The conditional entropy $H(\text{Label} \mid \text{Source}) = 0$.

### 5.2 Artifact Shortcut (`<USER>` Token)
- Over one-third of all phishing records in the dataset (453 / 1,280 = 35.39%) contain the synthetic `<USER>` token (introduced during address remediation), while **zero benign records** contain this token.
- A neural network can exploit this single token as a shortcut ($P(\text{Phishing} \mid \text{"<USER>"}) = 1.0$), bypassing semantic comprehension of the email lure.

### 5.3 In-Distribution Test Split Invariance
- Because `test.csv` was partitioned via random stratified sampling from the same three source corpora, the identical source-label mapping was preserved.
- While the baseline achieved high held-out performance on `test.csv` ($F1 = 96.50\%$, $ROC\text{-}AUC = 0.9995$), this validates **in-distribution held-out generalization**, but does **not** prove resilience against out-of-distribution real-world phishing.

---

## 6. Design Baseline vs Validated Accuracy Improvement

> [!IMPORTANT]
> **Phase 7A represents an architectural design baseline, NOT an empirically validated accuracy improvement.**
>
> Passing unit tests and API integration tests proves software correctness, schema adherence, and defensive fault tolerance. It does **NOT** prove that multi-modal fusion improves real-world detection accuracy compared to standalone models.
>
> Any claim that this fusion layer improves precision, recall, or F1-score without an independent multi-source evaluation is scientifically unfounded.

### Required Future Experiments for Empirical Validation
To transition from a design baseline to a scientifically validated evidence fusion system:
1. **Independent Evaluation Corpus**: Compile a fresh, uncoupled test set containing modern benign and modern phishing emails collected simultaneously from identical enterprise environments.
2. **Statistical Calibration**: Apply temperature scaling or isotonic regression to model logit outputs on an independent validation set.
3. **Ablation Studies**: Measure performance across 5 distinct configurations:
   - Text classifier only
   - URL heuristics only
   - Authentication rules only
   - Text + URLs
   - Complete multi-modal fusion
4. **Adversarial Robustness Testing**: Evaluate evasion attacks, including compromised legitimate domains (valid SPF/DKIM with malicious links) and legitimate marketing lures (suspicious text with clean domains).

---

## 7. API Response Schema & Synthetic Example

### 7.1 Schema Integration
The endpoint `POST /api/v1/email/analyze` returns `EmailAnalysisResponse`, which now includes:
```python
evidence_fusion: Optional[EvidenceFusionResult] = None
```
All existing Phase 1, Phase 4B, Phase 5A, and Phase 6A fields remain untouched.

### 7.2 Synthetic Example

#### Request:
```http
POST /api/v1/email/analyze HTTP/1.1
Host: localhost:8000
Content-Type: multipart/form-data; boundary=----BoundaryFusionSample

------BoundaryFusionSample
Content-Disposition: form-data; name="file"; filename="synthetic_credential_phish.eml"
Content-Type: message/rfc822

Received: from mail.partner.example ([198.51.100.25]) by mx.target.example; Mon, 12 Oct 2026 10:00:00 +0000
Authentication-Results: mx.target.example;
    spf=fail (target.example: domain of secure-bank.example does not designate 198.51.100.25 as permitted sender) smtp.mailfrom=secure-bank.example;
    dkim=none;
    dmarc=fail (p=REJECT dis=NONE) header.from=secure-bank.example
From: Security Alert <alerts@secure-bank.example>
To: target-user@target.example
Subject: Immediate Verification Required
Content-Type: text/html

<p>Your online session expired. Please confirm credentials:</p>
<p><a href="http://secure-bank.example@192.168.1.50:8080/portal/auth">Verify Login</a></p>
------BoundaryFusionSample--
```

#### Response Payload (`evidence_fusion` section excerpt):
```json
{
  "evidence_fusion": {
    "overall_category": "HIGH_RISK_INDICATORS_PRESENT",
    "model_evidence": {
      "status": "UNAVAILABLE",
      "uncalibrated_score": null,
      "predicted_label": null,
      "interpretation": "Model inference was not supplied or executed.",
      "caveat": "Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. Due to dataset source-label collinearity and synthetic token shortcuts (<USER>), this score represents a text-similarity heuristic and NOT a validated real-world probability."
    },
    "url_evidence": {
      "total_urls": 1,
      "unique_domains": 1,
      "highest_heuristic_risk": "HIGH",
      "suspicious_indicators": [
        "IP Literal Used as Hostname (RULE_IP_LITERAL_HOST)",
        "Credentials / Deceptive Brand Embedded in Userinfo Authority (RULE_USERINFO_AUTH_TRICK)"
      ],
      "deduplication_applied": true,
      "explanation": "Analyzed 1 URL(s) pointing to 1 distinct host(s). Highest heuristic risk: HIGH. Deduplication applied across repeated link occurrences.",
      "heuristic_disclaimer": "URL risk scores are rule-based heuristic indicators (0-100) reflecting structural and lexical patterns, not statistical probabilities."
    },
    "auth_evidence": {
      "spf_status": "FAIL",
      "dkim_status": "NOT_PRESENT",
      "dmarc_status": "FAIL",
      "has_conflicts": false,
      "has_valid_authentication": false,
      "has_explicit_failure": true,
      "correlated_failure_noted": true,
      "explanation": "Authentication evaluation: SPF=FAIL, DKIM=NOT_PRESENT, DMARC=FAIL. Conflicting headers: False. Correlated failures accounted for: True.",
      "trust_limitation": "Authentication results reflect downstream MTA assertions (RFC 8601/RFC 7208). PASS does not guarantee benign intent (e.g. attacker-owned domain), and FAIL does not guarantee malice (e.g. forwarding breakage)."
    },
    "ip_evidence": {
      "apparent_origin_ip": "198.51.100.25",
      "origin_classification": "Documentation",
      "is_routable": false,
      "hop_count": 1,
      "explanation": "Analyzed 1 transit hop candidate(s). Apparent origin: 198.51.100.25 (Documentation).",
      "provenance_limitation": "Received headers prior to the recipient boundary MTA can be spoofed or omitted by untrusted relays. IP egress reflects network routing, not a person's physical location. Private IPs, proxies, and cloud hosts are not proof of maliciousness."
    },
    "contributing_factors": [
      "High-risk URL heuristics detected across 1 unique destination host(s): IP Literal Used as Hostname (RULE_IP_LITERAL_HOST), Credentials / Deceptive Brand Embedded in Userinfo Authority (RULE_USERINFO_AUTH_TRICK)",
      "Explicit authentication failure observed: SPF=FAIL, DKIM=NOT_PRESENT, with correlated downstream DMARC=FAIL."
    ],
    "inconclusive_or_missing_factors": [
      "Apparent origin relay is classified as non-routable Documentation (198.51.100.25).",
      "DistilBERT Transformer NLP model inference was not executed for this request."
    ],
    "reasoning": "High-risk indicators are present based on corroborated evidence: severe structural URL deception coinciding with authentication failure or elevated text model similarity.",
    "disclaimer": "This assessment is an investigation support aid combining local forensic observations and model scores. It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts."
  }
}
```

---

## 8. Complete Test Suite Execution & Results

### 8.1 Test Suite Breakdown
The complete backend test suite was executed:
```
backend/tests/test_api.py ................. [ 8 passed ]
backend/tests/test_email_authentication.py  [ 15 passed ]
backend/tests/test_email_parser.py ........ [ 9 passed ]
backend/tests/test_evidence_fusion.py ..... [ 13 passed ]
backend/tests/test_ip_intelligence.py ..... [ 11 passed ]
backend/tests/test_url_integration.py ..... [ 10 passed ]
backend/tests/test_url_intelligence.py .... [ 23 passed ]
--------------------------------------------------------
Total: 89 passed, 0 failed, 0 skipped (100% pass rate) in 1.04 seconds
```

### 8.2 Detailed Phase 7A Test Scenarios (`test_evidence_fusion.py`)
1. `test_all_evidence_sources_present`: Validates multi-modal synthesis when all 4 components (Model, URLs, Auth, IPs) report corroborated findings.
2. `test_missing_url_evidence`: Verifies clean handling and notation when no URLs are present.
3. `test_missing_authentication_results`: Verifies handling when no SPF/DKIM/DMARC headers were recorded.
4. `test_no_usable_public_ip`: Verifies internal submission chains (private/loopback IPs) do not artificially inflate risk.
5. `test_contradictory_authentication_evidence`: Verifies `has_conflicts=True` triggers `REVIEW_RECOMMENDED` with explanatory factors.
6. `test_high_url_heuristic_without_model_support`: Validates detection of severe structural link deception even when text model score is benign.
7. `test_high_model_score_without_corroborating_evidence`: Verifies isolated high model score triggers `REVIEW_RECOMMENDED` rather than jumping to a definitive phishing verdict.
8. `test_multiple_suspicious_urls_without_double_counting`: Verifies 3 identical host links are de-duplicated, preventing duplicated risk counting.
9. `test_multiple_related_authentication_headers`: Verifies correlated SPF and DMARC failures are flagged as dependent rather than independent events.
10. `test_malformed_component_output_graceful`: Verifies graceful fallback to `INSUFFICIENT_EVIDENCE` when inputs are empty or malformed.
11. `test_no_calibrated_overall_probability_emitted`: Strictly asserts that no unified percentage or probability float is emitted.
12. `test_api_integration_preserves_all_fields`: Verifies end-to-end integration via `POST /api/v1/email/analyze` preserves all parser, URL, auth, and IP fields.
13. `test_regression_existing_fixtures`: Verifies fixture `06_multiple_received_hops.eml` parses with full multi-modal fusion.

---

## 9. Modified & Created Files

| File Path | Action | Description & Rationale |
| :--- | :--- | :--- |
| `backend/app/schemas/evidence_fusion.py` | Created | Defined `AssessmentCategory`, `ModelEvidenceInterpretation`, `URLEvidenceSummary`, `AuthEvidenceSummary`, `IPEvidenceSummary`, and `EvidenceFusionResult`. |
| `backend/app/services/evidence_fusion.py` | Created | Implemented transparent rule-based fusion service, host de-duplication, auth correlation, and explainable categorization. |
| `backend/app/schemas/email.py` | Modified | Added optional `evidence_fusion: Optional[EvidenceFusionResult] = None` to `EmailAnalysisResponse`. |
| `backend/app/services/email_parser.py` | Modified | Integrated `fuse_evidence()` in `parse_email_message()` under non-fatal exception handling. |
| `backend/tests/test_evidence_fusion.py` | Created | 13 comprehensive unit and integration tests covering all evidence permutations, socket isolation, and regressions. |
| `docs/phase7/phase7a_evidence_fusion.md` | Created | Comprehensive technical report for Phase 7A (this document). |

---

## 10. Protected Artifact Verification

Cryptographic SHA-256 hashes of all protected datasets and trained DistilBERT weights remain bit-identical:

| Protected Artifact Path | Expected SHA-256 Hash | Verification Status |
| :--- | :--- | :---: |
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH (True)** |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH (True)** |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH (True)** |
| `data/processed/phishmmf/cleaned_email_dataset.csv` | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | **MATCH (True)** |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH (True)** |

---

## 11. Final Status

**`PHASE_7A_EVIDENCE_FUSION_COMPLETE`**
