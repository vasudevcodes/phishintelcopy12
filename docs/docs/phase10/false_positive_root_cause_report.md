# Phase 10 — False Positive Root Cause Investigation Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Incident**: False Positive Classification of Genuine LinkedIn Notification Email (`"Complete your profile"`)  
**Investigating Agent**: Antigravity Forensic Analysis Agent  
**Date**: November 1, 2026  
**Status**: Root Cause Established — Forensic Audit Completed (Read-Only)  
**Deliverable File**: `docs/phase10/false_positive_root_cause_report.md`  

---

## Executive Summary

A genuine transactional/promotional email from LinkedIn titled **"Complete your profile"** was uploaded to the PhishIntel application and classified as:
- **Model Output**: Predicted Label `1 (Phishing Indicator)`, Uncalibrated Score: `0.991801` (99.18%)
- **URL Intelligence**: Highest Risk `MEDIUM` (15 tracking URLs flagged for length > 250 characters)
- **Authentication**: `SPF: PASS`, `DKIM: PASS`, `DMARC: PASS` (`p=REJECT`), `has_conflicts: False`
- **Evidence Fusion Category**: **`HIGH_RISK_INDICATORS_PRESENT`**
- **Evidence Synthesis Wording**: *"Elevated risk indicators present: high model phishing score corroborated by moderate URL anomalies or conflicting authentication headers."*

This forensic investigation was conducted under strict zero-modification constraints (no code modified, no model retrained, no weights or thresholds altered, no dataset files touched, and no sender whitelisting). 

The investigation has conclusively established the root cause across three interacting architectural layers:
1. **NLP Text Model Layer (DistilBERT)**: The score of `0.9918` is driven entirely by severe **dataset source-label collinearity and temporal confounding** in the underlying PhishMMF training corpus (100% of benign training emails originate from 2004–2008 developer mailing lists, while 100% of phishing emails originate from modern 2023–2024 honeypots). Ablation testing proves that modern action-oriented imperative phrases—specifically `"Complete your profile"` ($P = 0.9948$) and `"Update your job preferences"` ($P = 0.9900$)—unconditionally trigger extreme phishing probabilities because no modern web notification emails exist in the benign training distribution.
2. **URL Intelligence Layer**: 15 legitimate LinkedIn click-tracking URLs (`https://t1.em.linkedin.com/r/?id=...`) exceeded 250 characters due to cryptographic tracking tokens, triggering heuristic rule `RULE_EXCESSIVE_URL_LENGTH` (Severity `MEDIUM`). This elevated the batch URL risk tier to `MEDIUM`, providing the "corroborating anomaly" needed for high-risk escalation.
3. **Evidence Fusion Layer**: 
   - **Reasoning String Defect**: In `backend/app/services/evidence_fusion.py` (lines 365–370), the rule `has_high_model and (has_med_url or has_auth_conflict)` hardcodes the static phrase *"or conflicting authentication headers"*. Because `has_med_url` was True, this branch triggered, erroneously reporting conflicting authentication headers to the analyst even though authentication checks showed `has_conflicts: False` and all three checks passed.
   - **Authentication Priority Defect**: The rule hierarchy evaluates high model scores combined with medium URL flags *before* considering cryptographic authentication passes. Consequently, verified cryptographic authentication (`SPF=PASS, DKIM=PASS, DMARC=PASS` with `p=REJECT`) was completely disregarded rather than acting as a mitigating factor against uncalibrated text similarity scores.

---

## 1. Incident Artifacts and Email Trace

### 1.1 Uploaded Email Provenance
- **File Name**: `Complete your profile.eml`
- **File Location**: `C:\Users\Lenovo\Downloads\Complete your profile.eml`
- **File Size**: 38,094 bytes
- **SHA-256 Checksum**: `8ea233b8fb3286071fb2c22dd0139b1a039755eb078feea3e0ef82bc52c77dbe`

### 1.2 Extracted RFC 5322 Headers
```http
From: LinkedIn <linkedin@em.linkedin.com>
To: vasudev.codes@gmail.com
Subject: Complete your profile
Date: Wed, 21 Oct 2026 07:14:28 -0700
Message-ID: <NMFFDA668d16bc-1fbc-479d-b32a-602ed5574986006C5B7Flnkd_mid_prod2@em.linkedin.com>
Return-Path: <bounce@em.linkedin.com>
Authentication-Results: mx.google.com;
  dkim=pass header.i=@em.linkedin.com header.s=lnkd header.b=fyVW4yb6;
  spf=pass (google.com: domain of bounce@em.linkedin.com designates 130.248.165.113 as permitted sender) smtp.mailfrom=bounce@em.linkedin.com;
  dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=linkedin.com
Received-SPF: pass (google.com: domain of bounce@em.linkedin.com designates 130.248.165.113 as permitted sender) client-ip=130.248.165.113;
DKIM-Signature: v=1; a=rsa-sha256; d=em.linkedin.com; s=lnkd; c=relaxed/relaxed; bh=S4aBPBI93w6FMxomMvCHlKpzBbRx0zOT...
```

### 1.3 Body Structure and Plain Text Extraction
The uploaded `.eml` contains a single `text/html` multipart structure with **no** `text/plain` alternative:
- `has_plain_text`: `False` (0 characters)
- `has_html`: `True` (raw HTML: 35,412 characters)
- `html_extracted_text`: 1,024 characters

Extraction is performed in `backend/app/services/email_parser.py` via `BeautifulSoup(html_content, "html.parser").get_text(separator="\n")` followed by newline-preserving whitespace collapsing.

### 1.4 Exact Text Fed to DistilBERT
In `backend/app/services/model_inference.py`, the input sequence is assembled as `f"{subject}\n\n{body}"`:

```text
Complete your profile

LinkedIn
Update your job preferences to get better recommendations.
‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌  ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌ ‌
Updating your job preferences adds value to your profile.
Complete your profile
Over 70% of recruiters look for candidates on LinkedIn.
Let them know you're open to new opportunities.
Complete your profile by adding roles you may be interested in.
Add job preferences
Footer Mercado English
This email was intended for VASUDEV MV (Engineering Student @ HKBK College of Engineering  CS)
Learn why we included this.
This is an occasional email to help you get the most out of LinkedIn.
Unsubscribe
·
Help
©2026,

LinkedIn Ireland Unlimited Company.

All rights reserved.
LinkedIn Ireland Unlimited Company, Gardner House, Wilton Plaza, Wilton Place, Dublin 2, Ireland.
LinkedIn and the LinkedIn logo are registered trademarks of LinkedIn.
```
*(Total length: 1,047 characters).*

---

## 2. Model Preprocessing, Tokenization, and Inference Trace

### 2.1 Tokenizer Pipeline Inspection
The model inference service uses `DistilBertTokenizerFast` loaded from `models/distilbert_baseline/`:
- **Vocabulary Size**: 30,522 (Standard WordPiece `vocab.txt`)
- **Max Sequence Length**: 256 tokens (`truncation=True, padding="max_length"`)
- **Actual Non-Pad Tokens**: **174 tokens**
- **Truncation Applied**: **No**. The entire email subject, body, invisible preview spacer, call-to-action, and legal footer fit comfortably within 174 tokens (68% of capacity).

First 40 WordPiece subwords:
`['[CLS]', 'complete', 'your', 'profile', 'linked', '##in', 'update', 'your', 'job', 'preferences', 'to', 'get', 'better', 'recommendations', '.', 'up', '##dating', 'your', 'job', 'preferences', 'adds', 'value', 'to', 'your', 'profile', '.', 'complete', 'your', 'profile', 'over', '70', '%', 'of', 'recruit', '##ers', 'look', 'for', 'candidates', 'on', 'linked']`

Last 20 WordPiece subwords:
`['gardner', 'house', ',', 'wilton', 'plaza', ',', 'wilton', 'place', ',', 'dublin', '2', ',', 'ireland', '.', 'linked', '##in', 'and', 'the', 'linked', '##in', 'logo', 'are', 'registered', 'trademark', '##s', 'of', 'linked', '##in', '.', '[SEP]']`

### 2.2 Model Classification Output
- **Raw Logits**:
  - Class 0 (Benign): `-2.287019`
  - Class 1 (Phishing): `+2.508375`
- **Softmax Probability**:
  $$\text{Softmax}(z)_1 = \frac{e^{2.508375}}{e^{-2.287019} + e^{2.508375}} = \frac{12.2847}{0.101569 + 12.2847} = \mathbf{0.9918006}$$
- **Decision Rule**: Threshold $\tau = 0.50$ $\implies$ **Predicted Label: 1 (Phishing Indicator)**.

### 2.3 Verification of Label Mapping
An audit of `models/distilbert_baseline/config.json`, `scripts/phase3_train_distilbert.py` (lines 8, 155), and `backend/app/services/model_inference.py` (lines 8–10, 160) confirms:
- Class `0` $\equiv$ Benign
- Class `1` $\equiv$ Phishing
- Probability returned $\equiv P(\text{Class } 1 \mid \mathbf{x})$.

There is **no label inversion or index permutation defect**. The model explicitly learned that this input strongly resembles the positive (phishing) class.

---

## 3. Systematic DistilBERT Ablation Analysis

To isolate the exact textual components influencing DistilBERT, an ablation experiment was conducted using the local model checkpoint:

| Input Text Variant | Length | Logit $z_0$ (Benign) | Logit $z_1$ (Phish) | Phishing Score $P(\hat{y}=1)$ | Predicted Class |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Original Full Extracted Text** | 1,047 | -2.2870 | +2.5084 | **0.991801** | **1 (Phish)** |
| **Subject Only**: `"Complete your profile"` | 21 | -2.5813 | +2.6813 | **0.994845** | **1 (Phish)** |
| **Subject Variant**: `"Complete your profile on LinkedIn"` | 33 | -2.4553 | +2.5834 | **0.993560** | **1 (Phish)** |
| **Headline Only**: `"LinkedIn Update your job preferences..."` | 67 | -2.2384 | +2.3559 | **0.989992** | **1 (Phish)** |
| **Call to Action**: `"Complete your profile by adding roles..."` | 63 | -2.6530 | +2.7405 | **0.995474** | **1 (Phish)** |
| **Full Text with ZWNJ (`\u200c`) & NBSP (`\xa0`) Stripped** | 943 | -2.2870 | +2.5084 | **0.991801** | **1 (Phish)** |
| **Zero-Width Character Sequence Only (`\u200c\xa0...`)** | 52 | -0.0615 | +0.1093 | **0.542584** | **1 (Phish)** |
| **Informational Callout**: `"Over 70% of recruiters look..."` | 55 | +0.6509 | -0.5786 | **0.226276** | **0 (Benign)** |
| **Footer Only**: `"Footer Mercado English... Unsubscribe..."` | 472 | -0.1469 | +0.4492 | **0.644764** | **1 (Phish)** |
| **Without Footer (Headline + Body only)** | 575 | -2.4299 | +2.5981 | **0.993490** | **1 (Phish)** |
| **Without Subject and without Footer** | 552 | -2.0472 | +2.2290 | **0.986296** | **1 (Phish)** |

### Key Findings from Ablation:
1. **Isolated Subject Score**: The subject line `"Complete your profile"` alone yields an extreme score of **0.9948**.
2. **Zero Influence from Encoded Preview / ZWNJ**: Stripping all 52 zero-width non-joiners (`\u200c`) and non-breaking spaces produces **bit-identical logits** (`-2.2870`, `+2.5084`). WordPiece tokenizer simply discards these control characters.
3. **No Influence from Tracking URLs**: The URLs were located solely in HTML `href` and `src` attributes. BeautifulSoup strips HTML tags prior to text inference, so DistilBERT never received any URL strings.
4. **Action Imperative Bias**: Any sentence containing short, imperative calls-to-action regarding account status, preferences, or profile completion triggers $>0.989$ phishing probability.

---

## 4. Dataset Provenance, Shortcut Learning, and Source Collinearity

### 4.1 Provenance of `train.csv` (Locked Checkpoint Training Corpus)
Inspection of `data/processed/phishmmf/train.csv` (5,791 rows, SHA-256 `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c`) confirms absolute source-label collinearity:

| Source | Temporal Origin | Benign Count (`label=0`) | Phishing Count (`label=1`) | Collinearity |
| :--- | :---: | :---: | :---: | :---: |
| **`CEAS_08_0`** | 2007–2008 | 2,385 | 0 | 100% Benign |
| **`SpamAssasin_0`** | 2002–2006 | 2,382 | 0 | 100% Benign |
| **`phishing_pot`** | 2023–2024 | 0 | 1,024 | 100% Phishing |
| **Total** | — | **4,767** | **1,024** | **100% Collinear** |

### 4.2 Keyword and Semantic Representation in `train.csv`
A search across all 5,791 training samples reveals:
- `"Complete your profile"`: **0 occurrences** across the entire training corpus.
- `"Job preferences"`: **0 occurrences**.
- `"LinkedIn"`: **16 occurrences**, but **all 16 are in 2008 Linux developer discussions** (e.g. OpenSUSE mailing list posts mentioning somebody's resume link). **Zero legitimate LinkedIn notification emails exist in the benign dataset.**
- `"Account"`: 595 occurrences (63.0% phishing in `phishing_pot`).
- `"Verify"`: 201 occurrences (70.1% phishing in `phishing_pot`).
- `"Update your"`: 94 occurrences (47.9% phishing in `phishing_pot`).

### 4.3 Root Cause of NLP Model False Positive
The benign class in PhishMMF consists entirely of 20-year-old developer mailing list threads (Apache, Linux kernel, Perl, Debian, SpamAssassin, CEAS 2008). These emails feature long conversational paragraphs, patch diffs, gcc compiler outputs, and academic debate.

The phishing class consists of modern 2023–2024 honeypot lures, heavily saturated with urgent imperatives directing recipients to "Update your account", "Complete your profile", "Confirm your credentials", and "Review your preferences".

Because the model was trained on this split without contemporary benign transactional or marketing emails, **DistilBERT learned modern web account notification phrasing as a near-perfect proxy for phishing.** When presented with legitimate LinkedIn account maintenance correspondence from 2026, the model categorizes it as phishing with $99.18\%$ confidence.

This confirms the warning documented in Phase 3D (`docs/phase3/phase3d_source_leakage_audit.md`, Section 6):
> *"The test evaluation provides zero empirical guarantee that the model will generalize to emails from unseen organizations, modern enterprise mailboxes, or emerging 2026 phishing toolkits."*

---

## 5. URL Intelligence Breakdown

The email contains **24 extracted URLs** across 5 destination hostnames. Zero URLs triggered `HIGH` risk rules (no IP-literal hostnames, no credential `@` syntax, no punycode). However, **15 URLs triggered `MEDIUM` risk**, driving the aggregate URL risk tier to `MEDIUM`:

| URL Index & Destination Hostname | Length | Heuristic Risk Tier | Rule Triggered | Severity & Score Impact | Individual Heuristic Rationale |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **URLs #1–12, 14–15**<br>`https://t1.em.linkedin.com/r/?id=h668d16bc...&e=...&s=...` | **297** | **MEDIUM** (40) | `RULE_EXCESSIVE_URL_LENGTH` | MEDIUM (+40) | Legitimate LinkedIn click-tracking redirects. URL length is 297 characters (exceeds the 250-character threshold). Contains cryptographic tracking parameters `id`, `e` (base64 context), and `s` (HMAC signature). |
| **URL #13**<br>`https://t1.em.linkedin.com/r/?id=...&e=...&p1=...&p2=...&p3=...&p4=...&s=...` | **465** | **MEDIUM** (40) | `RULE_EXCESSIVE_URL_LENGTH` | MEDIUM (+40) | Legitimate LinkedIn unsubscribe/preference redirect. Length is 465 characters due to additional tracking parameters (`p1` through `p4`). |
| **URL #16**<br>`http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd` | 49 | **LOW** (17) | `RULE_HTTP_UNENCRYPTED` | LOW (+17) | Standard W3C DTD schema declaration in HTML boilerplate. Uses unencrypted `http://`. |
| **URL #17**<br>`http://www.w3.org/1999/xhtml` | 28 | **LOW** (17) | `RULE_HTTP_UNENCRYPTED` | LOW (+17) | Standard XML namespace declaration in HTML boilerplate. Uses unencrypted `http://`. |
| **URL #18**<br>`https://res1.em.linkedin.com/res/tracking/...png` | 110 | **INFO** (0) | `RULE_HTTPS_STANDARD` | INFO (0) | Transparent 1x1 tracking pixel on LinkedIn's legitimate email subdomain. |
| **URL #19**<br>`https://media.licdn.com/dms/image/v2/...` | 189 | **LOW** (17) | `RULE_LONG_URL` | LOW (+17) | Recipient profile avatar image loaded from LinkedIn's official media CDN. Length 189 chars (exceeds 120-char threshold). |
| **URLs #20–22**<br>`https://delivery-p143253-e1476319.adobeaemcloud.com/...` | 186 | **LOW** (21) | `RULE_HYPHENATED_HOST`<br>`RULE_LONG_HOSTNAME`<br>`RULE_LONG_URL` | LOW (+21) | Static LinkedIn marketing icons hosted on Adobe Experience Manager Cloud CDN. Hostname has 2 hyphens, length 43 chars, URL length 186 chars. |
| **URL #23**<br>`https://res1.em.linkedin.com/res/tracking/linkedin-blue-80x20.png` | 65 | **INFO** (0) | `RULE_HTTPS_STANDARD` | INFO (0) | Official LinkedIn footer logo image. |
| **URL #24**<br>`https://t1.em.linkedin.com/r/?id=h668d16bc-1fbc-479d-b32a-602ed5574986,b5fb5a,1` | 79 | **INFO** (0) | `RULE_HTTPS_STANDARD` | INFO (0) | Truncated tracking link. |

### Evaluation:
`RULE_EXCESSIVE_URL_LENGTH` is designed to flag evasion and redirection nesting. However, in enterprise marketing communications, long signed query strings on authenticated subdomains are standard practice. The engine treated LinkedIn's legitimate HMAC-signed tracking links as suspicious anomalies.

---

## 6. Authentication Header Parsing and Representation

### 6.1 Authentication Parsing Results
The forensic authentication engine (`backend/app/services/email_authentication.py`) parsed the email headers:

| Protocol | Status | Raw Header Finding | Evaluated Identity / Domain | Result Validity |
| :--- | :---: | :--- | :--- | :---: |
| **SPF** | **PASS** | `pass (google.com: domain of bounce@em.linkedin.com designates 130.248.165.113 as permitted sender)` | `bounce@em.linkedin.com`<br>IP `130.248.165.113` | **Valid PASS** |
| **DKIM** | **PASS** | `dkim=pass header.i=@em.linkedin.com header.s=lnkd header.b=fyVW4yb6;` | Signing Domain: `em.linkedin.com`<br>Selector: `lnkd` | **Valid PASS** |
| **DMARC** | **PASS** | `dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=linkedin.com` | From Domain: `linkedin.com`<br>Policy: `p=REJECT`, `sp=REJECT` | **Valid PASS** |

### 6.2 Internal Authentication Object State
```json
{
  "status": "EVALUATED",
  "has_conflicts": false,
  "warnings": [],
  "auth_evidence": {
    "spf_status": "PASS",
    "dkim_status": "PASS",
    "dmarc_status": "PASS",
    "has_conflicts": false,
    "has_valid_authentication": true,
    "has_explicit_failure": false,
    "correlated_failure_noted": false
  }
}
```

The authentication parser **succeeded completely**. All three protocols passed, no contradictory headers were found, and the From header domain (`linkedin.com`) is protected by strict `p=REJECT` DMARC policy.

---

## 7. Evidence Fusion Root Cause & Reasoning Defect

### 7.1 Why the Synthesis Claimed "Conflicting Authentication Headers"
The user reported that the evidence synthesis stated:
> *"Elevated risk indicators present: high model phishing score corroborated by moderate URL anomalies or conflicting authentication headers."*

The root cause was located in `backend/app/services/evidence_fusion.py` (lines 365–370):

```python
elif has_high_model and (has_med_url or has_auth_conflict):
    category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    reasoning = (
        "Elevated risk indicators present: high model phishing score corroborated by moderate URL anomalies "
        "or conflicting authentication headers."
    )
```

#### The Mechanism:
1. `has_high_model` was `True` ($0.9918 \ge 0.70$).
2. `has_med_url` was `True` because 15 LinkedIn tracking URLs triggered `RULE_EXCESSIVE_URL_LENGTH` ($>250$ chars).
3. `has_auth_conflict` was `False`.
4. The boolean condition `(has_med_url or has_auth_conflict)` evaluated to `True` solely because of `has_med_url`.
5. However, the explanation string was **hardcoded as a single static text block** containing `"or conflicting authentication headers"`.
6. As a result, the user-facing explanation presented the disjunction as a finding, misleading the user into believing the engine had detected authentication conflicts when `auth_evidence.has_conflicts` was actually `False`.

### 7.2 Why Perfect Cryptographic Authentication Was Overridden
In `evidence_fusion.py`, the decision ladder evaluates rules in descending order:
1. High URL risk + Auth failure / High model $\implies$ `HIGH_RISK_INDICATORS_PRESENT` (lines 347–352)
2. High URL risk alone $\implies$ `HIGH_RISK_INDICATORS_PRESENT` (lines 353–358)
3. Auth failure + Med URL / High model $\implies$ `HIGH_RISK_INDICATORS_PRESENT` (lines 359–364)
4. **High model + Med URL / Auth conflict $\implies$ `HIGH_RISK_INDICATORS_PRESENT`** (lines 365–370)
5. Isolated High model $\implies$ `REVIEW_RECOMMENDED` (lines 371–378)
6. Med URL / Auth conflict / Auth failure / Med model $\implies$ `REVIEW_RECOMMENDED` (lines 379–384)
7. **Auth Pass + Clean URLs + Low model $\implies$ `LOW_RISK_INDICATORS`** (lines 385–390)

Because Rule 4 triggered at line 365, the evaluation stopped immediately. The engine assigned `HIGH_RISK_INDICATORS_PRESENT` without evaluating whether `has_auth_pass` was True.

Furthermore, line 385 requires:
```python
elif has_auth_pass and (url_summary.highest_heuristic_risk in ["INFO", "NONE"]) and (has_low_model or (model_score is None and not has_model_error)):
    category = AssessmentCategory.LOW_RISK_INDICATORS
```
Under this rule, even if the URL length issue were resolved, an email with valid SPF, DKIM, and DMARC `p=REJECT` can **never** receive `LOW_RISK_INDICATORS` if the text model outputs a score $\ge 0.30$. An uncalibrated NLP model trained on historical data effectively holds a complete veto over cryptographic email authentication.

---

## 8. Summary of Confirmed Defects vs. Disproven Hypotheses

| Area | Hypothesized Cause | Status | Forensic Evidence |
| :--- | :--- | :---: | :--- |
| **Model** | Label inversion (0 and 1 flipped) | **Disproven** | Labels are confirmed: 0 = Benign, 1 = Phishing across config, train, and inference scripts. Test error evaluation confirms identical mapping. |
| **Model** | Zero-width character (`\u200c`) evasion | **Disproven** | Ablation stripping all ZWNJ/NBSP produced identical logits (`-2.2870, +2.5084`). WordPiece tokenizer ignores zero-width non-joiners. |
| **Model** | Tracking URL strings leaking into model input | **Disproven** | BeautifulSoup removes all HTML tags and attributes. DistilBERT receives only inner text. URLs are analyzed solely in URL intelligence. |
| **Model** | Dataset source-label collinearity & temporal shortcut | **Confirmed Defect** | Benign corpus is 100% 2004–2008 mailing lists; phishing corpus is 100% 2023–2024 honeypot lures. `"Complete your profile"` alone yields $P=0.9948$. |
| **URL** | Legitimate tracking URLs trigger evasion rules | **Confirmed Defect** | 15 legitimate LinkedIn tracking URLs ($>250$ chars) triggered `RULE_EXCESSIVE_URL_LENGTH`, raising URL risk to `MEDIUM`. |
| **Auth** | Authentication parser failed to parse PASS headers | **Disproven** | Parser extracted SPF=PASS, DKIM=PASS, DMARC=PASS, `has_conflicts=False` with 100% precision. |
| **Fusion** | Templated reasoning string asserts false conflict | **Confirmed Defect** | Static string in `evidence_fusion.py` line 368 claims `"or conflicting authentication headers"` even when `has_auth_conflict` is False. |
| **Fusion** | Authentication PASS cannot mitigate high model scores | **Confirmed Defect** | Decision tree evaluates high model + medium URL before checking authentication pass, allowing an uncalibrated model to force `HIGH_RISK`. |

---

## 9. Established Root Cause Statement

The false positive classification of the LinkedIn notification email as `HIGH_RISK_INDICATORS_PRESENT` was caused by the compound interaction of four specific system behaviors:

1. **Text Classifier Shortcut Learning**: DistilBERT was trained on the PhishMMF dataset where benign emails are exclusively historical 2004–2008 mailing list discussions and phishing emails are exclusively modern 2023–2024 honeypot captures. The model learned that short imperative calls to action regarding profile/account updates are 99%+ indicative of phishing, giving `"Complete your profile"` an uncalibrated score of `0.9918`.
2. **URL Length Heuristic Trigger**: 15 legitimate LinkedIn email tracking redirects exceeded 250 characters due to cryptographic authentication and tracking tokens, triggering `RULE_EXCESSIVE_URL_LENGTH` and classifying the overall URL risk as `MEDIUM`.
3. **Fusion Decision Ladder Escalation**: Rule 4 in `evidence_fusion.py` escalated any email with `has_high_model` ($\ge 0.70$) and `has_med_url` directly to `HIGH_RISK_INDICATORS_PRESENT`, completely disregarding that the sender domain was cryptographically authenticated with `SPF=PASS`, `DKIM=PASS`, and `DMARC=PASS` under a strict `p=REJECT` policy.
4. **Templated Reasoning Defect**: The static synthesis string for Rule 4 included the wording `"or conflicting authentication headers"`, misleading the analyst by stating an authentication conflict was present when authentication checks showed zero conflicts.

---

## 10. Recommended Corrective Actions

*Note: In accordance with project instructions, no code or models were modified during this investigation. The following corrective actions are recommended for future implementation after review:*

### 10.1 Evidence Fusion Logic Correction (Immediate)
1. **Dynamic Synthesis Formatting**: Replace the static string in `evidence_fusion.py` line 367 with dynamic phrasing that reflects the actual triggering condition:
   - If `has_med_url` is True and `has_auth_conflict` is False: *"Elevated risk indicators present: high model phishing score corroborated by moderate URL anomalies."*
   - If `has_auth_conflict` is True and `has_med_url` is False: *"Elevated risk indicators present: high model phishing score corroborated by conflicting authentication headers."*
2. **Cryptographic Authentication Defense-in-Depth**:
   - Introduce an authentication mitigation rule: When an email possesses valid DMARC PASS (`p=REJECT` or `p=QUARANTINE`) and DKIM PASS from the exact From header domain, an uncalibrated text model score alone (or combined with mere URL length warnings) should **not** escalate to `HIGH_RISK_INDICATORS_PRESENT`.
   - Instead, assign `REVIEW_RECOMMENDED`, explicitly noting: *"Valid cryptographic domain authentication (DMARC p=REJECT) confirms origin from the claimed domain. High text model score reflects lexical similarity to credential lures but is uncalibrated and mitigated by verified sender authenticity."*

### 10.2 URL Intelligence Tuning
1. **Differentiate Query Length from Path/Host Length**: In `RULE_EXCESSIVE_URL_LENGTH`, evaluate whether the excessive length stems from query string parameters (`?id=...`) versus an obfuscated host or path. Query string length on HTTPS endpoints belonging to authenticated domains should be classified as `INFO` (tracking parameters) rather than `MEDIUM` risk.
2. **Domain-Aligned Redirect Awareness**: If a tracking URL belongs to an organizational subdomain matching the DKIM-signed domain (`t1.em.linkedin.com` matching DKIM `em.linkedin.com`), do not penalize length as a redirection anomaly.

### 10.3 NLP Model Training and Calibration (Future Research Phase)
1. **Address Temporal & Source Collinearity**: Retrain or fine-tune DistilBERT on a modern dataset that includes modern benign notification, newsletter, and transactional emails (e.g. LinkedIn, GitHub, Google, Slack, banking alerts).
2. **Probability Calibration**: Implement temperature scaling or Platt scaling on the validation split so that DistilBERT emits calibrated confidence values rather than saturated extreme logits ($\pm 2.5$) on out-of-distribution text formats.
