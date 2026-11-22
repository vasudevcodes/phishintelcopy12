# PhishIntel — Machine Learning Evaluation, DistilBERT Pipeline & Mathematical Foundation

**Document Title:** Deep Learning Model Architecture, Empirical Evaluation, and Error Forensic Report  
**Project:** PhishIntel – Transformer and NLP-Based Email Phishing Detection and IP Intelligence  
**Model Identifier:** `distilbert-base-uncased` (Sequence Classification Head)  
**Corpus:** Remediated PhishMMF Benchmark Dataset (`v1.0.1-remediated-leakage-aware`)  
**Audit Standard:** VTU Academic Engineering Evaluation & Research Rigor  

---

## 1. Executive Summary

This report documents the machine learning component of PhishIntel. The primary NLP engine is a fine-tuned **DistilBERT** (Distilled Bidirectional Encoder Representations from Transformers) model trained for sequence classification on email text (subject concatenated with body).

### Core Empirical Findings
- **Locked Test Accuracy:** **98.76%** ($\frac{715}{724}$ correct classifications).
- **Phishing Detection F1-Score:** **96.50%** (Precision: 96.12%, Recall: 96.88%).
- **Benign Identification F1-Score:** **99.24%** (Precision: 99.33%, Recall: 99.16%).
- **Area Under ROC Curve (ROC-AUC):** **0.9995** across continuous text probabilities.
- **Confusion Matrix:** $\text{TN} = 591, \text{FP} = 5, \text{FN} = 4, \text{TP} = 124$.
- **Error Count:** Exactly **9 misclassifications (1.24%)** across 724 held-out test emails.
- **Execution Speed:** 3.41 seconds for 724 test emails on an NVIDIA GeForce RTX 3050 Laptop GPU (~4.7 ms per email).

---

## 2. DistilBERT Architectural Specification

DistilBERT is a lightweight transformer model distilled from BERT-base via knowledge distillation (Sanh et al., 2019). It retains 97% of BERT's language understanding capabilities while reducing parameter count by 40% and accelerating inference by 60%.

### 2.1 Model Hyperparameters & Configuration
The architecture parameters extracted from `models/distilbert_baseline/config.json` are:

| Architectural Parameter | Configuration Value | Theoretical / Engineering Significance |
| :--- | :---: | :--- |
| **Model Type** | `distilbert` | Lightweight transformer encoder using knowledge distillation |
| **Sequence Classifier Head** | `DistilBertForSequenceClassification` | Linear projection head: $\mathbb{R}^{768} \to \mathbb{R}^{2}$ |
| **Number of Transformer Layers ($L$)** | 6 | Exactly half the layers of BERT-base (12 layers) |
| **Attention Heads ($H$)** | 12 | Multi-head self-attention parallel projections |
| **Hidden Dimension ($d_{\text{model}}$)** | 768 | Dimensionality of token embedding vectors |
| **Head Dimension ($d_k = d_v$)** | 64 | $\frac{d_{\text{model}}}{H} = \frac{768}{12} = 64$ |
| **Feed-Forward Dimension ($d_{\text{ff}}$)** | 3,072 | Intermediate dimension in point-wise feed-forward sublayers ($4 \times 768$) |
| **Activation Function** | GELU | Gaussian Error Linear Unit: $x \Phi(x)$ |
| **Attention Dropout** | 0.10 | Dropout applied to self-attention weights |
| **Hidden / FF Dropout** | 0.10 | Dropout applied to feed-forward residual layers |
| **Classifier Dropout** | 0.20 | Dropout applied before sequence classification projection |
| **Maximum Sequence Length** | 256 tokens | Truncation boundary balancing context retention and GPU VRAM |
| **Vocabulary Size ($V$)** | 30,522 | WordPiece subword vocabulary (`vocab.txt`) |
| **Total Parameter Count** | ~66.36 Million | Compact memory footprint (~267.8 MB serialized) |
| **Serialization Format** | Safetensors | `model.safetensors` (Zero-copy, secure deserialization) |

---

## 3. Mathematical Foundations of the Model

### 3.1 Tokenization and Input Representation
The input email is preprocessed by concatenating subject and body text:
$$\mathbf{T} = \text{subject} \mathbin{\Vert} \text{"\textbackslash n\textbackslash n"} \mathbin{\Vert} \text{body}$$

The WordPiece tokenizer breaks $\mathbf{T}$ into subword tokens and appends special delimiter tokens:
$$\mathbf{X}_{\text{tokens}} = [\text{[CLS]}, t_1, t_2, \dots, t_N, \text{[SEP]}]$$
where $N \le 254$. If $N > 254$, the sequence is truncated at 254 tokens and closed with `[SEP]`.

Each token receives an input vector $\mathbf{e}_i \in \mathbb{R}^{768}$ formed by summing token embedding $\mathbf{E}_{\text{token}}$, segment embedding $\mathbf{E}_{\text{segment}}$, and learned positional embedding $\mathbf{E}_{\text{pos}}$:
$$\mathbf{h}_i^{(0)} = \mathbf{E}_{\text{token}}(t_i) + \mathbf{E}_{\text{pos}}(i)$$

### 3.2 Scaled Dot-Product Self-Attention
For a sequence matrix $\mathbf{H}^{(l-1)} \in \mathbb{R}^{n \times d_{\text{model}}}$, each attention head $j \in \{1, \dots, 12\}$ computes Query, Key, and Value matrices via learned linear projections:
$$\mathbf{Q}_j = \mathbf{H}^{(l-1)} \mathbf{W}_j^Q, \quad \mathbf{K}_j = \mathbf{H}^{(l-1)} \mathbf{W}_j^K, \quad \mathbf{V}_j = \mathbf{H}^{(l-1)} \mathbf{W}_j^V$$
where $\mathbf{W}_j^Q, \mathbf{W}_j^K, \mathbf{W}_j^V \in \mathbb{R}^{768 \times 64}$.

The attention weights represent similarity between token queries and keys, scaled by $\sqrt{d_k} = \sqrt{64} = 8$:
$$\text{Attention}(\mathbf{Q}_j, \mathbf{K}_j, \mathbf{V}_j) = \text{softmax}\left(\frac{\mathbf{Q}_j \mathbf{K}_j^\top}{\sqrt{d_k}} + \mathbf{M}\right) \mathbf{V}_j$$
where $\mathbf{M}$ is an attention mask tensor ensuring padded positions ($pad\_id = 0$) receive a value of $-\infty$, zeroing out their attention probability:
$$\mathbf{M}_{ik} = \begin{cases} 0 & \text{if token } k \text{ is real} \\ -\infty & \text{if token } k \text{ is padding} \end{cases}$$

### 3.3 Multi-Head Attention Sublayer
Outputs from all 12 heads are concatenated and linearly transformed by $\mathbf{W}^O \in \mathbb{R}^{768 \times 768}$:
$$\text{MultiHead}(\mathbf{H}^{(l-1)}) = \left( \text{head}_1 \mathbin{\Vert} \text{head}_2 \mathbin{\Vert} \dots \mathbin{\Vert} \text{head}_{12} \right) \mathbf{W}^O$$

Residual connections and layer normalization are applied:
$$\mathbf{Z}^{(l)} = \text{LayerNorm}\left(\mathbf{H}^{(l-1)} + \text{Dropout}\left(\text{MultiHead}(\mathbf{H}^{(l-1)})\right)\right)$$

### 3.4 Position-Wise Feed-Forward Sublayer
The intermediate vector passes through a two-layer feed-forward network with GELU activation:
$$\text{FFN}(\mathbf{Z}^{(l)}) = \text{GELU}\left(\mathbf{Z}^{(l)} \mathbf{W}_1 + \mathbf{b}_1\right) \mathbf{W}_2 + \mathbf{b}_2$$
where $\mathbf{W}_1 \in \mathbb{R}^{768 \times 3072}$, $\mathbf{b}_1 \in \mathbb{R}^{3072}$, $\mathbf{W}_2 \in \mathbb{R}^{3072 \times 768}$, and $\mathbf{b}_2 \in \mathbb{R}^{768}$.

The sublayer output is normalized with a second residual connection:
$$\mathbf{H}^{(l)} = \text{LayerNorm}\left(\mathbf{Z}^{(l)} + \text{Dropout}\left(\text{FFN}(\mathbf{Z}^{(l)})\right)\right)$$

### 3.5 Classification Head and Objective Function
At layer $L = 6$, the final contextual embedding corresponding to the first token `[CLS]`, denoted $\mathbf{h}_{\text{[CLS]}}^{(6)} \in \mathbb{R}^{768}$, encapsulates the semantic representation of the entire email message.

The classification head projects $\mathbf{h}_{\text{[CLS]}}^{(6)}$ into unnormalized logit space $\mathbb{R}^2$:
$$\mathbf{z} = \mathbf{W}_{\text{clf}} \left(\text{Dropout}_{0.2}\left(\mathbf{h}_{\text{[CLS]}}^{(6)}\right)\right) + \mathbf{b}_{\text{clf}}$$
where $\mathbf{W}_{\text{clf}} \in \mathbb{R}^{2 \times 768}$ and $\mathbf{b}_{\text{clf}} \in \mathbb{R}^2$.

During training, parameters are optimized using cross-entropy loss over binary ground-truth labels $y \in \{0, 1\}$:
$$\mathcal{L}_{\text{CE}} = - \left[ y \log \left(\frac{e^{z_1}}{e^{z_0} + e^{z_1}}\right) + (1 - y) \log \left(\frac{e^{z_0}}{e^{z_0} + e^{z_1}}\right) \right]$$

During inference, the probability of the email being phishing is given by:
$$P(\text{Phish}) = \sigma(z_1 - z_0) = \frac{e^{z_1}}{e^{z_0} + e^{z_1}}$$

---

## 4. Dataset Curation, Cleansing, and Leakage Prevention

### 4.1 Dataset Provenance (PhishMMF Corpus)
The model was trained on the curated PhishMMF corpus. The raw dataset consolidation incorporates:
1. `CEAS_08_0`: 2,981 legitimate emails from the 2008 Collaboration Against Executive Spam conference.
2. `SpamAssasin_0`: 2,978 legitimate emails from the Apache SpamAssassin public ham corpus.
3. `phishing_pot`: 1,280 phishing emails collected from university spam traps and honeypots.

### 4.2 Forensic Remediation (Phase 2B.1)
Prior to model training, a forensic data audit identified critical contamination anomalies that were eliminated:
1. **Label Contamination Removal:**
   - Record `phishing_pot_00617`: Contained an authentic GitHub Trust & Safety alert regarding private repository tokens erroneously labeled as phishing. Removed.
   - Record `phishing_pot_01785`: Contained an authentic developer recruitment message regarding an open-source GitHub profile erroneously labeled as phishing. Removed.
2. **Deterministic Duplicate Resolution:**
   - Record `phishing_pot_00291`: Identical in body content to `phishing_pot_00278` differing only by line wrapping (`\r\n` vs `\n`). The lexicographically higher ID was deterministically removed.
3. **Synthetic Shortcut Token Remediation:**
   - In raw data, an exact bracketed token `[USER]` occurred 1,041 times across 453 records—and **exclusively in phishing records** (100% label collinearity). This artifact acted as an artificial shortcut. All instances of `[USER]` were systematically neutralized to `<USER>` to preserve syntactic structure without giving the model an artificial keyword shortcut.

### 4.3 Leakage-Safe Stratified Partitioning
To guarantee zero cross-partition contamination, dataset splitting was performed at the **group level** based on the SHA-256 hash of Unicode NFKC-normalized, lowercased, whitespace-collapsed email bodies:
- This prevents identical email bodies from appearing in both train and test splits under slightly altered subject lines.
- Splits were stratified across source and label partitions.

| Partition | Total Records | Phishing Samples | Benign Samples | Phishing Ratio | Partition SHA-256 Hash |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Train** | 5,791 | 1,024 | 4,767 | 17.68% | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` |
| **Validation** | 724 | 128 | 596 | 17.68% | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` |
| **Test** | 724 | 128 | 596 | 17.68% | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` |
| **Total** | **7,239** | **1,280** | **5,959** | **17.68%** | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` |

Audit verification confirmed **exact zero cross-split leakage** across train, validation, and test partitions.

---

## 5. Model Training Execution and Dynamics

### 5.1 Training Environment and Hyperparameters
- **Device:** NVIDIA GeForce RTX 3050 6GB Laptop GPU (Ampere Architecture, 2,048 CUDA cores).
- **Driver / Runtimes:** CUDA 12.4, PyTorch `2.6.0+cu124`, Transformers `5.18.0`.
- **Precision:** Mixed Precision FP16 via PyTorch Automatic Mixed Precision (AMP).
- **Batch Size:** Per-device train batch size = 4; Gradient accumulation steps = 4; **Effective batch size = 16**.
- **Optimizer:** AdamW ($\beta_1 = 0.9, \beta_2 = 0.999, \epsilon = 10^{-8}$, Weight Decay = $0.01$).
- **Learning Rate Schedule:** Initial $LR = 2 \times 10^{-5}$, linear warmup for 108 steps (~10% of total steps), followed by linear decay to 0.
- **Gradient Clipping:** Maximum gradient norm $\Vert \mathbf{g} \Vert_2 \le 1.0$.
- **Training Epochs:** 3 epochs (362 optimizer steps per epoch; 1,086 total steps). Total training time: 272.4 seconds (~4.5 minutes).

### 5.2 Training History and Checkpoint Selection

```
Epoch 1: Train Loss = 0.1500 | Val Loss = 0.0319 | Val Acc = 99.17% | Val F1 = 97.67%  <-- BEST CHECKPOINT
Epoch 2: Train Loss = 0.0127 | Val Loss = 0.0360 | Val Acc = 99.31% | Val F1 = 98.04%
Epoch 3: Train Loss = 0.0034 | Val Loss = 0.0367 | Val Acc = 99.31% | Val F1 = 98.04%
```

| Epoch | Training Loss | Validation Loss | Validation Accuracy | Validation Phish Precision | Validation Phish Recall | Validation Phish F1 | Validation ROC-AUC | Val Confusion Matrix (TN, FP, FN, TP) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | **0.1500** | **0.0319** | **99.17%** | **96.92%** | **98.44%** | **97.67%** | **0.9973** | **(592, 4, 2, 126)** |
| **2** | 0.0127 | 0.0360 | 99.31% | 98.43% | 97.66% | 98.04% | 0.9980 | (594, 2, 3, 125) |
| **3** | 0.0034 | 0.0367 | 99.31% | 98.43% | 97.66% | 98.04% | 0.9982 | (594, 2, 3, 125) |

**Checkpoint Selection Policy:** The best checkpoint was selected based on **minimum validation loss** ($\min(\mathcal{L}_{\text{val}})$) to prevent overfitting. Epoch 1 achieved $\mathcal{L}_{\text{val}} = 0.031855$, whereas Epoch 2 and Epoch 3 showed slight validation loss divergence ($0.0360$ and $0.0367$) despite lower training loss. Thus, **Epoch 1 weights were locked as the production model**.

---

## 6. Locked Test-Set Performance Evaluation

The model was evaluated **exactly once** on the locked test partition (`data/processed/phishmmf/test.csv`, 724 samples) with decision threshold $\tau = 0.50$:

### 6.1 Test Performance Metrics
$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}} = \frac{124 + 591}{124 + 591 + 5 + 4} = \frac{715}{724} = 98.7569\% \approx \mathbf{98.76\%}$$

$$\text{Precision}_{\text{phish}} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{124}{124 + 5} = \frac{124}{129} = 96.1240\% \approx \mathbf{96.12\%}$$

$$\text{Recall}_{\text{phish}} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{124}{124 + 4} = \frac{124}{128} = 96.8750\% \approx \mathbf{96.88\%}$$

$$\text{F1}_{\text{phish}} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 2 \times \frac{0.96124 \times 0.96875}{0.96124 + 0.96875} = 96.4981\% \approx \mathbf{96.50\%}$$

### 6.2 Confusion Matrix
$$\begin{pmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{pmatrix} = \begin{pmatrix} 591 & 5 \\ 4 & 124 \end{pmatrix}$$

- **True Negatives (591):** Correctly identified benign emails.
- **False Positives (5):** Benign emails flagged as phishing.
- **False Negatives (4):** Phishing emails missed by the text model.
- **True Positives (124):** Phishing attacks correctly detected.

### 6.3 Comprehensive Classification Report
| Class | Support | Precision | Recall | F1-Score | False Positive Rate | False Negative Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign (Class 0)** | 596 | 99.33% ($\frac{591}{595}$) | 99.16% ($\frac{591}{596}$) | 99.24% | 3.12% ($\frac{4}{128}$) | 0.84% ($\frac{5}{596}$) |
| **Phishing (Class 1)** | 128 | 96.12% ($\frac{124}{129}$) | 96.88% ($\frac{124}{128}$) | 96.50% | 0.84% ($\frac{5}{596}$) | 3.12% ($\frac{4}{128}$) |
| **Macro Average** | 724 | 97.72% | 98.02% | 97.87% | — | — |
| **Weighted Average**| 724 | 98.76% | 98.76% | 98.76% | — | — |

---

## 7. Deep Error Analysis: Forensic Investigation of All 9 Errors

Out of 724 test cases, exactly 9 errors occurred ($1.24\%$). Each case was extracted from `models/distilbert_baseline/test_error_analysis.csv` and audited:

### 7.1 False Positives ($y = 0, \hat{y} = 1$) — Benign Flagged as Phishing
1. `CEAS_08_0_01325` ($P = 0.8223$): Subject: *"Get Your Business Credit Report and Scores!"*
   - *Linguistic Driver:* Promotional business marketing containing high densities of financial terms ("credit report", "scores", "free access"). Because phishing honeypots frequently use financial lures, the model triggered a false positive based on lexical similarity.
2. `CEAS_08_0_01768` ($P = 0.9526$): Subject: *"Is outsourcing right for you?"*
   - *Linguistic Driver:* Unsolicited business development email containing urgent calls to action ("Click here to speak with an advisor immediately").
3. `CEAS_08_0_01870` ($P = 0.9175$): Subject: *"resnet address alert"*
   - *Linguistic Driver:* Authentic university campus network administration notification warning students about dynamic IP address changes. Contains IT alert keywords ("address alert", "network reconfiguration") that mirror credential harvesting alerts.
4. `CEAS_08_0_02270` ($P = 0.9629$): Subject: *"PDQ High Speed Internet - you have reached 100% of your existing usage pack"*
   - *Linguistic Driver:* Authentic ISP quota alert. Structurally and semantically identical to account suspension threats ("100% usage", "immediate top-up required").
5. `CEAS_08_0_02780` ($P = 0.9570$): Subject: *"[FRImag2002] Seznam knjig z ED2K linki"*
   - *Linguistic Driver:* Non-English (Slovenian) academic mailing list digest containing raw peer-to-peer ed2k links. The unusual language distribution and link structures triggered outlier classification.

### 7.2 False Negatives ($y = 1, \hat{y} = 0$) — Phishing Missed by Text Model
1. `phishing_pot_00724` ($P = 0.1301$): Subject: *"Spark Change: Musk's Power Unleashed"*
   - *Evasion Driver:* Crypto scam formatted as a tech news digest or editorial interview regarding clean energy. Lacked traditional coercion words ("urgent", "verify account"), instead relying on an embedded malicious link.
2. `phishing_pot_01325` ($P = 0.0399$): Subject: *"HARVARD MEDICAL: “Weight-Loss Doubling” Trick for Women"*
   - *Evasion Driver:* Health/dietary supplement spam using medical authority spoofing. Scored very low on phishing probability because the PhishMMF phishing partition primarily contained IT/banking lures rather than medical spam.
3. `phishing_pot_02446` ($P = 0.0121$): Subject: *"Musk's Power Innovations Exposed"*
   - *Evasion Driver:* Celebrity/innovation clickbait lure designed to bypass corporate spam filters by discussing technology news before presenting a link.
4. `phishing_pot_02952` ($P = 0.2125$): Subject: *"Dear Friend/18/12/2024"*
   - *Evasion Driver:* Advance-fee (419) letter with polite, non-technical prose ("Dear Friend", "I have a mutual proposition"). Lacks technical keywords or urgency threats.

---

## 8. Scientific Limitations & Justification for Corroboration Dampening

### 8.1 Source-Label Collinearity
The dataset audit reveals an important scientific nuance:
- Benign samples originated from `CEAS_08_0` (2008) and `SpamAssasin_0` (~2002–2006).
- Phishing samples originated from `phishing_pot` (modern honeypots).
Consequently, the model learned legitimate corporate and academic writing styles from older open-source mailings. Modern corporate notifications (e.g., LinkedIn, OpenAI, Google Account notifications) that use clean modern marketing prose risk triggering elevated model scores.

### 8.2 Why Corroboration Dampening Was Implemented
Because the model output is an **uncalibrated text-similarity heuristic**, PhishIntel implements **Corroboration Dampening** in `scoring_engine.py`:
- When external technical evidence (SPF, DKIM, DMARC, registered sender domain alignment, and clean URLs) proves that an email is authentically delivered from a legitimate domain, the model score is **dampened by $0.25\times$** (max 5 points).
- Conversely, when external evidence detects unaligned domains, deceptive links, or authentication failures, the model operates at **full linear weight** (up to 20 points).
This hybrid design bridges deep learning text semantics with rigid cryptographic verification, delivering high accuracy without the vulnerability of standalone machine learning false positives.

