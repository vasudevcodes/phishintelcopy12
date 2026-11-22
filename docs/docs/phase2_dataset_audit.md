# Phase 2 — Dataset Audit Report

**Dataset Audited**: `data/raw/meajor_cleaned_preprocessed.parquet.gzip`  
**Audit Date**: October 2026  
**Auditor**: Antigravity Automated Verification Agent  
**Environment Status**: Python 3.13.15 (`pandas` 3.0.6, `pyarrow` 25.0.1 verified in `backend/.venv`)  
**Application Code Modification**: None (Read-only dataset audit)

---

## 1. Dataset Overview

The dataset is a compressed Parquet archive (`.parquet.gzip`) with a file size of **82.28 MB** (86,278,230 bytes). It contains preprocessed email records collected from the NIST Text REtrieval Conference (TREC) Spam Track benchmarks (2005, 2006, and 2007).

### Key Dataset Dimensions
- **Total Rows**: `108,685`
- **Total Columns**: `20`
- **Parquet File Format**: Format version 1.0, created by `fastparquet-python 2024.11.0`
- **Row Groups**: 1 single row group containing all 108,685 records
- **Completely Empty (All-Null) Rows**: `0`
- **Unreadable / Malformed Records**: Exactly **1 row** (`index 51258`) has `NaN` values across `label`, `source`, `language`, and `content_types`, paired with unreadable corrupted unicode text.

### Five Representative Sample Rows (Truncated)

| Row Index | Source | Label | Sender Domain | Receiver Domain | Subject | Body Snippet | URLs Populated |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | `trec5` | `0.0` (Ham) | `enron.com` | `enron.com` | `[ORGANIZATION] failover plan.` | `Hi [NAME], Tonight we are rolling out a new report. Currently, only you and [NAME] have access to it...` | No (`NaN`) |
| **3** | `trec5` | `1.0` (Spam) | `yahoo.com` | `enron.com` | `ÀÎÅÍ<\|SIMBOL\|>Ý Ä<\|SIMBOL\|>...` | `<\|EMOJI\|>FFFFB9<\|EMOJI\|>FFFFCF<\|EMOJI\|>FFFFC0... [Truncated raw non-Latin text]` | Yes (`2` URLs) |
| **49583** | `trec6` | `0.0` (Ham) | `sarto.budd-lake.nj.us` | `None` (`NaN`) | `new Catholic mailing list now up and running` | `The mailing list I queried about a few weeks ago is now up and running. I have also set up an archive...` | No (`NaN`) |
| **50000** | `trec6` | `1.0` (Spam) | `yahoo.com` | `groucho.cs.psu.edu` | `re[12]:` | `LUXURY WATCHES - BUY YOUR OWN [PRODUCT] FOR ONLY [FINANCIAL_INFO]!...` | Yes (`1` URL) |
| **64588** | `trec7` | `1.0` (Spam) | `aol.com` | `speedy.uwaterloo.ca` | `Generic [PRODUCT], branded quality@ ` | `Do you feel the pressure to perform and not rising to the occasion?? Try [PRODUCT] your anxiety...` | Yes (`1` URL) |

---

## 2. Schema and Column Specifications

The table below describes all 20 columns present in the Parquet file, including their data type, null count, null percentage, and semantic role.

| # | Column Name | Pandas Dtype | PyArrow Storage Type | Null Count | Null % | Description & Semantic Role |
| :- | :--- | :--- | :--- | :- | :- | :--- |
| 1 | `sender` | `object` (`str`) | `binary` (String) | 0 | 0.00% | SHA-256 hex hash of original sender address (local part) |
| 2 | `sender_domain` | `object` (`str`) | `binary` (String) | 494 | 0.45% | Extracted domain portion of sender email |
| 3 | `receiver` | `object` (`str`) | `binary` (String) | 0 | 0.00% | SHA-256 hex hash of recipient address (or semicolon-separated hashes) |
| 4 | `receiver_domain` | `object` (`str`) | `binary` (String) | 2,371 | 2.18% | Extracted recipient domain(s) |
| 5 | `date` | `object` (`str`) | `binary` (String) | 0 | 0.00% | RFC date string with timezone offset (e.g. `2001-06-29 09:37:04-05:00`) |
| 6 | `subject` | `object` (`str`) | `binary` (String) | 1,455 | 1.34% | Email subject line (contains anonymized tokens) |
| 7 | `content_types` | `object` (`str`) | `binary` (String) | 1 | <0.01% | MIME content types (e.g. `text/plain`, `text/plain;text/html`) |
| 8 | `body` | `object` (`str`) | `binary` (String) | 1 | <0.01% | Main email body text (heavily preprocessed and entity-masked) |
| 9 | `urls` | `object` (`str`) | `binary` (String) | 44,633 | 41.07% | Newline-separated raw URLs extracted from original email |
| 10 | `url_count` | `float64` | `double` | 0 | 0.00% | Pre-computed number of URLs found in email |
| 11 | `url_length_max` | `float64` | `double` | 0 | 0.00% | Maximum URL character length in email |
| 12 | `url_length_avg` | `float64` | `double` | 0 | 0.00% | Average URL character length in email |
| 13 | `url_subdom_max` | `float64` | `double` | 0 | 0.00% | Maximum subdomain count across extracted URLs |
| 14 | `url_subdom_avg` | `float64` | `double` | 0 | 0.00% | Average subdomain count across extracted URLs |
| 15 | `attachment_count` | `float64` | `double` | 0 | 0.00% | Number of attachments detected |
| 16 | `has_attachments` | `bool` | `boolean` | 0 | 0.00% | Boolean indicator (`True`/`False`) |
| 17 | `attachment_types` | `object` (`str`) | `binary` (String) | 107,019 | 98.47% | MIME type of attachments (e.g. `application/msword`) |
| 18 | `language` | `object` (`str`) | `binary` (String) | 1 | <0.01% | Detected language code (e.g. `en`, `en;en`, `ru`, `ja`, `de`) |
| 19 | `source` | `object` (`str`) | `binary` (String) | 1 | <0.01% | Origin benchmark corpus (`trec5`, `trec6`, `trec7`) |
| 20 | `label` | `float64` | `double` | 1 | <0.01% | Target class label (`0.0` = Benign/Ham, `1.0` = Spam/Phish) |

---

## 3. Class Distribution and Label Ambiguity

### Class Counts and Percentages

The target variable is located in column `label`:

| Label Value | Verified Semantic Meaning | Record Count | Percentage |
| :--- | :--- | :--- | :--- |
| **`0.0`** | Ham / Benign Email | 60,650 | **55.80%** |
| **`1.0`** | Spam / Malicious Email | 48,034 | **44.20%** |
| **`NaN`** | Missing / Corrupt (Row 51258) | 1 | **<0.01%** |
| **Total** | | **108,685** | **100.00%** |

### Verified Finding vs Assumption: The Label Ambiguity Problem

> [!WARNING]
> **CRITICAL LABEL AMBIGUITY**: The dataset label `1.0` does NOT represent pure phishing. It represents **generic email spam** from the 2005–2007 NIST TREC Spam Track.

- **Verified Origin**: The sources `trec5`, `trec6`, and `trec7` correspond to the TREC 2005, 2006, and 2007 Spam Track evaluation datasets. In the TREC evaluation protocol, the ground truth binary task was strictly defined as **Ham (0) vs. Spam (1)**.
- **Empirical Content Analysis of Class `1.0`**:
  - Direct keyword frequency analysis of all 48,034 records in Class `1.0` reveals heavy domination by commercial, pharmaceutical, and financial spam:
    - `"pills"`: 1,810 emails
    - `"pharmacy"`: 1,766 emails
    - `"replica"`: 914 emails
    - `"lottery"`: 582 emails
    - `"mortgage"`: 559 emails
    - `"debt"`: 344 emails
    - `"cialis"`: 221 emails
    - `"casino"`: 201 emails
    - `"viagra"`: 180 emails
  - Conversely, classic targeted credential phishing and account takeover lures are present in much smaller volumes:
    - `"banking"`: 327 emails
    - `"suspended"`: 100 emails
    - `"confirm your account"`: 84 emails
    - `"paypal"`: 21 emails
    - `"verify your account"`: 18 emails
    - `"ebay"`: 15 emails
    - `"update your billing"`: 14 emails
    - `"unauthorized access"`: 7 emails
    - `"click here to login"`: 4 emails
    - `"security notice"`: 2 emails
- **Impact on Modeling**: A transformer model trained blindly on `label` will learn to detect **unsolicited commercial email (spam)** rather than the subtle social engineering, credential harvesting, and spear-phishing tactics required for modern phishing protection.

---

## 4. Missing Values and Duplicates

### Missing Values Analysis

| Column | Missing Count | Missing % | Reason & Impact |
| :--- | :--- | :--- | :--- |
| `attachment_types` | 107,019 | 98.47% | Expected; exactly matches `has_attachments == False`. Only 1,666 emails have attachments. |
| `urls` | 44,633 | 41.07% | Expected; emails with no links (`url_count == 0.0`). |
| `receiver_domain` | 2,371 | 2.18% | Missing recipient domain in header or undisclosed recipients. |
| `subject` | 1,455 | 1.34% | Emails sent without a subject line. |
| `sender_domain` | 494 | 0.45% | Corrupted, malformed, or local non-FQDN sender headers. |
| `label` | 1 | <0.01% | Row index 51258 is corrupted and must be dropped. |
| `source` | 1 | <0.01% | Row index 51258. |
| `language` | 1 | <0.01% | Row index 51258. |
| `body` | 1 | <0.01% | Row index 51258. |
| `content_types` | 1 | <0.01% | Row index 51258. |

### Duplicate Records

1. **Exact Duplicate Rows**: Exactly **13 duplicate rows** (26 rows total involved) are completely identical across all 20 columns. These represent identical duplicate emails ingested during corpus consolidation (e.g. repeated corporate broadcasts from `williams.com` or `convene.com`).
2. **Text Duplicate Rows**:
   - `body`: **103,518 unique bodies** out of 108,684 valid text rows (**5,166 duplicate bodies**).
   - `(subject, body)` pairs: **104,934 unique pairs** (**3,751 duplicate pairs**).
3. **Cross-Label Conflicting Bodies (Data Quality Flaw)**:
   - **5 unique body strings** appear under **both** Class `0.0` (Ham) and Class `1.0` (Spam), affecting **54 total rows**.
   - These 5 snippets are:
     1. `"[FILE_NAME]"` (13 Ham, 6 Spam)
     2. `"[USERNAME]"` (2 Ham, 13 Spam)
     3. `"[NAME]"` (7 Ham, 9 Spam)
     4. `"[FINANCIAL_INFO]"` (1 Ham, 1 Spam)
     5. `"[USERNAME]<|EMAIL_SEPARATOR|>[USERNAME]"` (1 Ham, 1 Spam)
   - **Root Cause**: The anonymization preprocessor aggressively replaced the entire body of minimal emails with a single placeholder token. When different original emails were reduced to `[FILE_NAME]` or `[NAME]`, some were originally benign and others were spam.

### Categorical Column Integrity and Anomalies

- `sender_domain`: 28,465 unique domains. Severe skew: `enron.com` accounts for 21,684 rows.
- `receiver_domain`: 6,367 unique domains. Severe skew: `enron.com` accounts for 30,845 rows, and University of Waterloo domains (`flax9.uwaterloo.ca`, `plg.uwaterloo.ca`, `speedy.uwaterloo.ca`) account for 22,864 rows.
- `content_types`: 17 unique values. Top: `text/plain` (70,992), `text/plain;text/html` (21,174), `text/html` (15,270). Anomalies include repeated MIME types: `text/plain;text/plain;text/plain` (34 rows).
- `date`: Contains extreme anomalous years:
  - Minimum date: `1889-05-19 08:59:51+00:00`
  - Maximum date: `2102-03-16 15:16:56+00:00`
  - Spammers routinely spoofed the `Date` MIME header to force sorting to the top of email client inboxes.
- `language`: 82,175 rows are English (`en`), 21,250 are multi-part English (`en;en`). Foreign languages (`ru`: 827, `ja`: 602, `de`: 383, `es`: 332, `zh`: 315) are >98% concentrated in Class `1.0` (Spam).

---

## 5. Source Distribution and Cross-Tabulation

The dataset aggregates three historical TREC collections:

| Source | Collection Description | Total Rows | Share | Ham (`0.0`) | Spam (`1.0`) | Ham Rate | Spam Rate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`trec5`** | TREC 2005 Spam Track | 49,583 | 45.62% | 29,929 | 19,654 | 60.36% | 39.64% |
| **`trec7`** | TREC 2007 Spam Track | 44,096 | 40.57% | 19,513 | 24,583 | 44.25% | 55.75% |
| **`trec6`** | TREC 2006 Spam Track | 15,005 | 13.81% | 11,208 | 3,797 | 74.69% | 25.31% |
| **`NaN`** | Corrupt Record (Row 51258) | 1 | <0.01% | 0 | 0 | - | - |
| **Total** | | **108,685** | **100.00%** | **60,650** | **48,034** | **55.80%** | **44.20%** |

### Verified Biases in Source Data
1. `trec6` has a strong benign skew (74.69% ham).
2. `trec7` is the only collection with a majority spam class (55.75% spam).
3. The underlying collections drew their ham emails primarily from internal corporate archives (notably the Enron email release) and academic mailing lists, whereas spam emails were drawn from university spam honeypots and public spam traps.

---

## 6. Anonymization and Feature Availability

### Anonymization Findings
- **High Anonymization Prevalence**:
  - **96.32%** of all email bodies (104,686 rows) contain at least one placeholder token.
  - **39.40%** of all email subjects (42,251 rows) contain placeholder tokens.
- **Placeholder Types & Frequencies (Measured on 10,000 Sample Records)**:
  - Entities replaced with bracket notation:
    - `[PRODUCT]`: 27,682 occurrences
    - `[ORGANIZATION]`: 26,342 occurrences
    - `[NAME]`: 22,628 occurrences
    - `[FINANCIAL_INFO]`: 21,567 occurrences
    - `[REFERENCE_NUMBER]`: 11,037 occurrences
    - `[DATE]`: 8,622 occurrences
    - `[ADDRESS]`: 7,563 occurrences
    - `[URL]`: 4,138 occurrences
    - `[EMAIL_ADDRESS]`: 3,203 occurrences
    - `[TIME]`: 3,193 occurrences
    - `[PHONE_NUMBER]`: 3,100 occurrences
    - `[FILE_NAME]`: 2,409 occurrences
    - `[USERNAME]`: 2,407 occurrences
    - `[INITIALS]`: 1,570 occurrences
    - `[IP_ADDRESS]`: 1,120 occurrences
    - `[FILE_PATH]`: 928 occurrences
  - Tokens replaced with delimiter notation:
    - `<|SYMBOL|>` / `<|SIMBOL|>`: 9,237 occurrences
    - `<|EMOJI|>`: 7,812 occurrences
    - `<|URL|>`: 5,776 occurrences
    - `<|EMAIL|>`: 2,441 occurrences
    - `<|EMAIL_SEPARATOR|>`: 1,985 occurrences
    - `<|FILE|>`: 1,821 occurrences
    - `<|PHONE|>`: 1,143 occurrences
- **Sender and Receiver Masking**:
  - Sender and recipient local parts are irreversible SHA-256 hashes (e.g. `d66e9e64b006d6bca649f1c945129c42c43836872b2eadfb822b6af04b3212cb`).
  - Domain names were extracted prior to hashing and preserved in `sender_domain` and `receiver_domain`.

### Feature Availability Audit

| Telemetry / Feature Type | Available in Dataset? | Details |
| :--- | :--- | :--- |
| **Raw MIME / RFC 822 Headers** | **NO** | Headers were parsed into discrete tabular columns; raw header blocks are not present. |
| **SPF, DKIM, DMARC, ARC Results** | **NO (0%)** | Audit found 0 occurrences of `Authentication-Results`, `DKIM-Signature`, or `Received-SPF`. The 2005–2007 TREC collections predate modern email authentication standard enforcement. |
| **Original URLs** | **PARTIAL** | Raw URLs are provided in the `urls` column for 58.93% of emails. However, in the `body` text, URLs have been stripped and replaced by `[URL]` and `<|URL|>`. |
| **IP Addresses** | **MINIMAL** | IP addresses in body text were replaced with `[IP_ADDRESS]`. Raw IPs appear in only ~1.1% of raw URLs in the `urls` column. Network hop `Received: from [IP]` headers do not exist. |
| **Pre-computed URL Features** | **YES** | `url_count`, `url_length_max`, `url_length_avg`, `url_subdom_max`, `url_subdom_avg`. |
| **Attachment Metadata** | **MINIMAL** | `attachment_count` and `has_attachments` are present. `attachment_types` is 98.47% missing. Attachment binaries/hashes are not present. |

---

## 7. Leakage Risks

### 1. Domain Memorization Leakage (Critical Severity)
- **Enron Domain Ham Concentration**:
  - `enron.com` appears as the sender domain in **21,684 records**.
  - Of these, **21,660 are Ham (`0.0`)** and only **24 are Spam (`1.0`)** (99.89% Ham).
  - Enron emails account for **35.71% of the entire benign class**.
- **University of Waterloo Receiver Spam Concentration**:
  - Waterloo recipient domains (`uwaterloo.ca`) appear in **26,717 records**.
  - Of these, **23,495 are Spam (`1.0`)** (87.94% Spam), accounting for **48.91% of all spam** in the dataset.
- **Domain Disjointness**:
  - Across all 28,465 sender domains, **only 446 domains appear in both classes**.
  - Label `0.0` has 4,112 sender domains; Label `1.0` has 24,798 sender domains.
  - **Risk**: Any model that uses `sender_domain` or `receiver_domain` as a feature (or an NLP model where sender headers are included in prompt/text) will achieve deceptively high accuracy by simply learning that `enron.com` is safe and `uwaterloo.ca` is spam.

### 2. Campaign Template Leakage (High Severity)
- 5,166 duplicate email bodies and 3,751 duplicate `(subject, body)` pairs exist across rows.
- A standard random train/test split will assign identical duplicate emails to both the training set and the test set, creating strong test score inflation due to verbatim memorization.

### 3. Source-Specific Artifact Leakage (Moderate Severity)
- The three sources have different class balance (`trec6` is 74.7% ham; `trec7` is 55.7% spam).
- If source markers or source-correlated metadata remain in the dataset, models may exploit collection-specific artifacts.

### 4. Cross-Label Label Noise (Low to Moderate Severity)
- As noted in Section 4, 54 rows have identical single-placeholder text (`[FILE_NAME]`, `[USERNAME]`, `[NAME]`) assigned to conflicting labels (`0.0` and `1.0`), which introduces label ambiguity for ultra-short texts.

---

## 8. Suitability for Proposed Experiments

### Text Length Profile

| Metric | Subject (Characters) | Subject (Words) | Body (Characters) | Body (Words) | Combined (Words) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Minimum** | 1 | 1 | 1 | 1 | 1 |
| **25th Percentile** | 20 | 3 | 380 | 55 | 59 |
| **Median (50th)** | 32 | 5 | 797 | 121 | 126 |
| **Mean** | 42.6 | 5.4 | 1,168.1 | 171.8 | 177.0 |
| **75th Percentile** | 48 | 7 | 1,533 | 227 | 233 |
| **95th Percentile** | 104 | 11 | 3,629 | 547 | 554 |
| **99th Percentile** | 275 | 17 | 4,923 | 709 | 714 |
| **Maximum** | 3,701 | 578 | 30,574 | 1,199 | 1,204 |

### Assessment for Transformer-Based Architecture (e.g. ModernBERT / DeBERTa)

#### Strengths:
1. **Favorable Sequence Length Distribution**:
   - The median email length is 121 words (~160 subword tokens).
   - 95% of emails have fewer than 550 words (~720 tokens).
   - For a standard 512-token transformer, ~85% of emails require zero truncation.
   - For **ModernBERT** (which natively supports 8,192 token context), **100% of all emails in this dataset fit without any truncation**.
2. **Preserved Natural Language Structure**:
   - 99.05% of rows contain uppercase characters; sentence capitalization, punctuation, and formatting are intact.
   - HTML has already been cleanly stripped (only 3.45% of records have lingering HTML syntax).

#### Architectural Challenges & Failure Modes:
1. **Stripped URL Lexical Features**:
   - In modern phishing, deceptive URLs (typosquatting, open redirects, multiple subdomains) are primary threat indicators.
   - Because URLs in `body` are replaced with `[URL]` and `<|URL|>`, a transformer reading `body` cannot examine domain structure or path tokens in context.
2. **Tokenizer Subword Splitting on Placeholders**:
   - Standard tokenizers (e.g., BPE or WordPiece) do not treat `[ORGANIZATION]` or `<|EMAIL_SEPARATOR|>` as single tokens. They split them into 4 to 6 subwords (e.g., `['[', 'ORGAN', 'IZATION', ']']`).
   - If unaddressed, these placeholders consume token budget and disrupt semantic representation.
3. **Semantic Task Mismatch**:
   - The dataset represents historical spam from 2005–2007 (pill marketing, luxury watches, stock pumps).
   - It lacks modern phishing modalities: QR codes (quishing), cloud storage lure documents (OneDrive/Google Drive), multi-factor authentication (MFA) fatigue lures, and OAuth application consent phishing.

---

## 9. Limitations and Recommended Next Steps

### Critical Limitations Summary
1. **Target Task Misalignment**: The dataset is a Spam/Ham dataset, not a modern Phishing/Benign dataset.
2. **Severe Domain Collinearity**: Enron dominates benign emails; Waterloo dominates spam emails.
3. **Missing Telemetry**: Zero email authentication results (SPF/DKIM/DMARC) and zero raw email headers.
4. **URL Decoupling**: URL lexical structure is separated into the `urls` column rather than embedded in natural reading order in the text.

### Prescriptive Recommendations

#### A. Splitting Strategy (Do NOT use simple random split)
- **Recommendation 1 (Out-of-Distribution Domain Generalization)**:
  - Perform a **Source-Held-Out Split**:
    - **Train**: `trec5` + `trec6` (64,588 records)
    - **Test / Evaluation**: `trec7` (44,096 records)
  - This measures true transferability across different collection environments and years.
- **Recommendation 2 (In-Domain Grouped Split)**:
  - If a single train/validation/test split is required, use a **Stratified Group Split grouped on `sender_domain`** and deduplicated on `body` hash.
  - This guarantees that no company or domain seen during training is used to test the model.

#### B. Feature Selection Rules
- **EXCLUDE** `sender_domain`, `receiver_domain`, and `source` from feature inputs. These columns represent extreme shortcut learning opportunities.
- **EXCLUDE** `sender` and `receiver` (hashed strings).

#### C. Data Cleaning Actions Before Training
1. **Drop Index 51258**: Remove the single malformed record containing `NaN` in target and features.
2. **Drop Exact Duplicates**: Remove the 13 redundant identical records.
3. **Filter Conflicting Bodies**: Exclude the 54 rows where single-token bodies (`[FILE_NAME]`, `[USERNAME]`, `[NAME]`) have ambiguous dual labels.

#### D. Text Preprocessing & Tokenizer Preparation
1. **Register Special Tokens**: Add all 25+ placeholder tokens (`[ORGANIZATION]`, `[PRODUCT]`, `[NAME]`, `[FINANCIAL_INFO]`, `<|URL|>`, `<|EMOJI|>`, etc.) as custom atomic tokens in the tokenizer vocabulary so they are not fragmented into subwords.
2. **URL Re-Injection**: If testing transformer URL comprehension, replace `[URL]` tokens in `body` with the actual raw URLs stored in the `urls` column before tokenization.

---

## Audit Verification Summary
- **No models were trained.**
- **The raw parquet dataset was not modified.**
- **No application code in `backend/app/` or `frontend/` was modified.**
- **Machine-readable audit findings saved to**: `docs/phase2_dataset_audit.json`
- **Audit report saved to**: `docs/phase2_dataset_audit.md`
