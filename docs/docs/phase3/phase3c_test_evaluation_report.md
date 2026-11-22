# Phase 3C — Locked Test-Set Evaluation Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 3C — Locked Test-Set Evaluation  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Target Model**: `distilbert-base-uncased` (Sequence Classification, 2 Classes, Epoch 1 Checkpoint)  
**Hardware Profile**: NVIDIA GeForce RTX 3050 6GB Laptop GPU | 16 GB Host RAM  
**Dataset Reference**: PhishMMF Cleaned & Remediated Corpus (`v1.0.1-remediated-leakage-aware`)  
**Status Verdict**: **`PHASE_3C_TEST_EVALUATION_COMPLETE`**

---

## 1. Executive Summary

Phase 3C executed the strictly controlled, single-pass evaluation of the saved DistilBERT baseline on the approved, previously untouched test split (`data/processed/phishmmf/test.csv`).

### Core Governance & Compliance Highlights
- **Single Evaluation Pass**: The test set was evaluated **exactly once**. No retraining, fine-tuning, checkpoint switching, or threshold tuning was conducted.
- **Fixed Decision Threshold**: The canonical classification threshold ($\tau = 0.5$) was applied without post-hoc tuning.
- **Strict Input Invariance**: The input representation remained strictly identical to Phase 3B:
  $$\text{input\_text} = \text{subject} + \text{"\textbackslash n\textbackslash n"} + \text{body}$$
  All metadata fields (`id`, `source`, sender addresses, filenames) were strictly excluded from model inputs.
- **Zero Dataset Mutation**: SHA-256 hashes of `train.csv`, `validation.csv`, and `test.csv` were verified pre- and post-evaluation, confirming zero byte modifications.
- **Model Checkpoint Integrity**: SHA-256 hash of `model.safetensors` was confirmed identical before and after the evaluation pass.
- **Hardware Acceleration**: Executed natively on the **NVIDIA GeForce RTX 3050 6GB Laptop GPU** under PyTorch `2.6.0+cu124` AMP FP16 in 3.41 seconds.

---

## 2. Pre-Flight Cryptographic Dataset & Environment Verification

### Dataset Partitions Integrity
| Partition | File Path | Record Count | Expected SHA-256 | Observed SHA-256 | Integrity Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | `data/processed/phishmmf/train.csv` | 5,791 | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **PASS (BIT-IDENTICAL)** |
| **Validation** | `data/processed/phishmmf/validation.csv` | 724 | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **PASS (BIT-IDENTICAL)** |
| **Test** | `data/processed/phishmmf/test.csv` | 724 | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **PASS (BIT-IDENTICAL)** |

### Model Checkpoint Verification
- **Checkpoint Location**: `models/distilbert_baseline/`
- **Weights File**: `model.safetensors` (267,832,560 bytes)
- **Weights SHA-256**: `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` (Verified identical pre- and post-evaluation)
- **Checkpoint Origin**: Epoch 1 (Selected via minimum validation loss = `0.0319`)

---

## 3. Locked Test-Set Performance Metrics

Evaluated on all 724 held-out test samples (596 benign, 128 phishing) with **phishing (Class 1)** defined as the positive class:

### Primary Metric Summary
| Metric | Test Set Value | Validation Set Value | Delta ($\Delta$) | Definition / Note |
| :--- | :---: | :---: | :---: | :--- |
| **Cross-Entropy Loss** | **0.0376** | 0.0319 | $+0.0057$ | Average sequence cross-entropy loss |
| **Accuracy** | **98.76%** | 99.17% | $-0.41\%$ | $\frac{TP + TN}{Total} = \frac{124 + 591}{724} = \frac{715}{724}$ |
| **Phishing Precision** | **96.12%** | 96.92% | $-0.80\%$ | $\frac{TP}{TP + FP} = \frac{124}{124 + 5} = \frac{124}{129}$ |
| **Phishing Recall** | **96.88%** | 98.44% | $-1.56\%$ | $\frac{TP}{TP + FN} = \frac{124}{124 + 4} = \frac{124}{128}$ |
| **Phishing F1-Score** | **96.50%** | 97.67% | $-1.17\%$ | Harmonic mean of phishing precision & recall |
| **ROC-AUC** | **0.9995** | 0.9973 | $+0.0022$ | Area Under the ROC Curve (Continuous probabilities) |
| **False Positive Rate (FPR)** | **0.84%** | 0.67% | $+0.17\%$ | $\frac{FP}{FP + TN} = \frac{5}{5 + 591} = \frac{5}{596}$ |
| **False Negative Rate (FNR)** | **3.12%** | 1.56% | $+1.56\%$ | $\frac{FN}{FN + TP} = \frac{4}{4 + 124} = \frac{4}{128}$ |
| **Macro-F1 Score** | **97.87%** | 98.54% | $-0.67\%$ | Unweighted average of Class 0 & Class 1 F1 |
| **Weighted-F1 Score** | **98.76%** | 99.17% | $-0.41\%$ | Support-weighted average F1 across classes |

### Confusion Matrix Breakdown
$$\begin{pmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{pmatrix} = \begin{pmatrix} 591 & 5 \\ 4 & 124 \end{pmatrix}$$

- **True Negatives (TN)**: **591** benign emails correctly classified as benign.
- **False Positives (FP)**: **5** benign emails incorrectly classified as phishing.
- **False Negatives (FN)**: **4** phishing emails incorrectly classified as benign.
- **True Positives (TP)**: **124** phishing emails correctly detected.

### Per-Class Detailed Breakdown
| Class | Label | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 0 | 99.33% ($\frac{591}{595}$) | 99.16% ($\frac{591}{596}$) | **99.24%** | 596 |
| **Phishing** | 1 | 96.12% ($\frac{124}{129}$) | 96.88% ($\frac{124}{128}$) | **96.50%** | 128 |
| **Macro Average** | — | 97.72% | 98.02% | **97.87%** | 724 |
| **Weighted Average** | — | 98.76% | 98.76% | **98.76%** | 724 |

---

## 4. Error Analysis

Out of 724 test emails, exactly **9 errors (1.24%)** occurred: 5 False Positives and 4 False Negatives. The complete case log was exported to [`models/distilbert_baseline/test_error_analysis.csv`](file:///c:/Users/Lenovo/Desktop/PhishIntel/models/distilbert_baseline/test_error_analysis.csv).

### False Positives ($y = 0, \hat{y} = 1$)
Benign emails incorrectly classified as phishing by the text model:

| Record ID | Source | $P(\text{Phish})$ | Subject (Truncated) | Error Rationale & Linguistic Pattern |
| :--- | :--- | :---: | :--- | :--- |
| `CEAS_08_0_01325` | `CEAS_08_0` | 0.8223 | `Get Your Business Credit Report and Scores!` | Direct-marketing promotional email containing financial terminology ("Credit Report and Scores"), mimicking financial phishing lures. |
| `CEAS_08_0_01768` | `CEAS_08_0` | 0.9526 | `Is outsourcing right for you?` | Unsolicited commercial solicitation containing high-urgency call-to-action phrasing. |
| `CEAS_08_0_01870` | `CEAS_08_0` | 0.9175 | `resnet address alert` | Campus network administration notification containing alert keywords ("address alert"), closely resembling IT credential harvesting lures. |
| `CEAS_08_0_02270` | `CEAS_08_0` | 0.9629 | `PDQ High Speed Internet - you have reached 100% of your existing usage pack` | Automated ISP quota notification ("reached 100% of usage"), structurally indistinguishable in text from account suspension warnings. |
| `CEAS_08_0_02780` | `CEAS_08_0` | 0.9570 | `[FRImag2002] Seznam knjig z ED2K linki` | Non-English mailing list digest with peer-to-peer download hyperlinks. |

### False Negatives ($y = 1, \hat{y} = 0$)
Phishing emails that evaded text-only detection:

| Record ID | Source | $P(\text{Phish})$ | Subject (Truncated) | Evasion Rationale & Attack Characteristics |
| :--- | :--- | :---: | :--- | :--- |
| `phishing_pot_00724` | `phishing_pot` | 0.1301 | `Spark Change: Musk's Power Unleashed` | Celebrity impersonation / cryptocurrency / clean-energy investment scam formatted cleanly like a legitimate tech newsletter. |
| `phishing_pot_01325` | `phishing_pot` | 0.0399 | `HARVARD MEDICAL: “Weight-Loss Doubling” Trick for Women` | Health scam / deceptive brand-impersonation email with minimal aggressive urgent text, bypassing text classifier. |
| `phishing_pot_02446` | `phishing_pot` | 0.0121 | `Musk's Power Innovations Exposed` | Newsletter-styled fraudulent investment solicitation. |
| `phishing_pot_02952` | `phishing_pot` | 0.2125 | `Dear Friend/18/12/2024` | Short 419 advance-fee fraud email lacking conventional phishing urgency keywords (account suspension, password reset, click here). |

### Key Takeaway from Error Analysis
The false-negative profile proves why a **pure text Transformer is insufficient for end-to-end phishing protection**:
1. Attackers increasingly format lures as clean, conversational emails or tech newsletters without conventional urgent keywords.
2. Conversely, legitimate IT quota warnings and financial alerts share identical vocabulary with credential harvesting campaigns.
3. This highlights the indispensable necessity of upcoming phases: **URL analysis (Phase 4), cryptographic header verification (SPF/DKIM/DMARC in Phase 5), and IP intelligence (Phase 6)** to disambiguate benign administrative alerts from spoofed attack vectors.

---

## 5. Research Integrity & Scientific Limitations

> [!WARNING]
> **Source-Label Correlation Limitation**
> In the PhishMMF corpus, all phishing emails originate from `phishing_pot`, whereas all benign emails originate from `CEAS` and `SpamAssassin`.
> Although the held-out test set demonstrates high discrimination ($F1 = 96.50\%$, $ROC\text{-}AUC = 0.9995$), this performance represents **in-distribution held-out generalization**.
> It is probable that the DistilBERT model relies partly on stylistic and structural formatting cues unique to the source corpora rather than purely invariant semantic phishing constructs.
> **Consequently, this baseline must NOT be cited as evidence of real-world efficacy against live, modern, or unseen phishing infrastructure.** It constitutes an unweighted, single-modality baseline against which subsequent multi-modal enhancements must be scientifically benchmarked.

---

## 6. Generated Output Artifacts

| File Path | Description |
| :--- | :--- |
| [`scripts/phase3c_evaluate_test.py`](file:///c:/Users/Lenovo/Desktop/PhishIntel/scripts/phase3c_evaluate_test.py) | Standalone, audited single-pass test evaluation script |
| [`models/distilbert_baseline/test_evaluation_results.json`](file:///c:/Users/Lenovo/Desktop/PhishIntel/models/distilbert_baseline/test_evaluation_results.json) | Complete machine-readable test evaluation metrics and manifest |
| [`models/distilbert_baseline/test_error_analysis.csv`](file:///c:/Users/Lenovo/Desktop/PhishIntel/models/distilbert_baseline/test_error_analysis.csv) | Record-level audit of all 9 misclassifications with probabilities |
| [`docs/phase3/phase3c_test_evaluation_report.md`](file:///c:/Users/Lenovo/Desktop/PhishIntel/docs/phase3/phase3c_test_evaluation_report.md) | This comprehensive scientific evaluation report |

---

## 7. Compliance Verification Checklist

- [x] **Test split evaluated exactly once**: Verified.
- [x] **Pre- and post-evaluation dataset hashes match bit-for-bit**: Verified.
- [x] **Model weights unchanged during evaluation**: Verified (`fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8`).
- [x] **Zero retraining or hyperparameter/threshold tuning**: Verified.
- [x] **Metadata strictly excluded from model input**: Verified.
- [x] **All requested metrics calculated from actual model outputs**: Verified.
- [x] **Detailed error analysis logged with truncated subjects**: Verified.
- [x] **Scientific limitations and source correlation prominently stated**: Verified.

---

## Final Status

# PHASE_3C_TEST_EVALUATION_COMPLETE
