# PhishIntel — Mathematical Formulations, Metrics & Quantitative Calculations

**Document Title:** Mathematical Formulations, Evaluation Calculations & Algorithm Proofs  
**Project:** PhishIntel – Transformer and NLP-Based Email Phishing Detection and IP Intelligence  
**Target Standard:** VTU Final Year Engineering Academic Documentation  

---

## 1. Machine Learning Evaluation Metrics

All performance calculations are derived from the single-pass evaluation on the locked test partition (`data/processed/phishmmf/test.csv`), consisting of $N = 724$ samples ($596$ benign, $128$ phishing).

### 1.1 Confusion Matrix Elements
The observed confusion matrix on the locked test partition is:
$$\mathbf{C} = \begin{pmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{pmatrix} = \begin{pmatrix} 591 & 5 \\ 4 & 124 \end{pmatrix}$$

Where:
- $\text{True Negatives (TN)} = 591$: Benign emails correctly identified as benign ($y = 0, \hat{y} = 0$).
- $\text{False Positives (FP)} = 5$: Benign emails incorrectly flagged as phishing ($y = 0, \hat{y} = 1$).
- $\text{False Negatives (FN)} = 4$: Phishing emails incorrectly flagged as benign ($y = 1, \hat{y} = 0$).
- $\text{True Positives (TP)} = 124$: Phishing emails correctly identified as phishing ($y = 1, \hat{y} = 1$).
- $\text{Total Ground-Truth Benign} = \text{TN} + \text{FP} = 591 + 5 = 596$.
- $\text{Total Ground-Truth Phishing} = \text{FN} + \text{TP} = 4 + 124 = 128$.
- $\text{Total Samples} = \text{TN} + \text{FP} + \text{FN} + \text{TP} = 591 + 5 + 4 + 124 = 724$.

---

### 1.2 Overall Classification Accuracy
Accuracy measures the proportion of correct predictions across all classes:
$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$$

Substituting the empirical values:
$$\text{Accuracy} = \frac{124 + 591}{124 + 591 + 5 + 4} = \frac{715}{724} \approx \mathbf{0.98756906} \implies \mathbf{98.76\%}$$

---

### 1.3 Class-Specific Metrics: Phishing (Positive Class, $y = 1$)

#### A. Phishing Precision ($P_1$)
Precision measures the proportion of predicted phishing emails that are genuinely phishing:
$$P_1 = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{124}{124 + 5} = \frac{124}{129} \approx \mathbf{0.96124031} \implies \mathbf{96.12\%}$$

#### B. Phishing Recall ($R_1$)
Recall (Sensitivity / True Positive Rate) measures the proportion of genuine phishing emails detected:
$$R_1 = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{124}{124 + 4} = \frac{124}{128} = \mathbf{0.96875000} \implies \mathbf{96.88\%}$$

#### C. Phishing F1-Score ($F1_1$)
The harmonic mean of phishing precision and recall:
$$F1_1 = 2 \times \frac{P_1 \times R_1}{P_1 + R_1} = 2 \times \frac{\frac{124}{129} \times \frac{124}{128}}{\frac{124}{129} + \frac{124}{128}} = \frac{2 \times 124}{129 + 128} = \frac{248}{257} \approx \mathbf{0.96498054} \implies \mathbf{96.50\%}$$

---

### 1.4 Class-Specific Metrics: Benign (Negative Class, $y = 0$)

#### A. Benign Precision ($P_0$)
$$P_0 = \frac{\text{TN}}{\text{TN} + \text{FN}} = \frac{591}{591 + 4} = \frac{591}{595} \approx \mathbf{0.99327731} \implies \mathbf{99.33\%}$$

#### B. Benign Recall ($R_0$) (Specificity / True Negative Rate)
$$R_0 = \frac{\text{TN}}{\text{TN} + \text{FP}} = \frac{591}{591 + 5} = \frac{591}{596} \approx \mathbf{0.99161074} \implies \mathbf{99.16\%}$$

#### C. Benign F1-Score ($F1_0$)
$$F1_0 = 2 \times \frac{P_0 \times R_0}{P_0 + R_0} = 2 \times \frac{\frac{591}{595} \times \frac{591}{596}}{\frac{591}{595} + \frac{591}{596}} = \frac{2 \times 591}{595 + 596} = \frac{1182}{1191} \approx \mathbf{0.99244332} \implies \mathbf{99.24\%}$$

---

### 1.5 Aggregate Averaging Metrics

#### A. Macro Average F1-Score
The unweighted arithmetic mean of per-class F1-scores, giving equal importance to both classes regardless of class imbalance:
$$\text{Macro F1} = \frac{F1_0 + F1_1}{2} = \frac{0.99244332 + 0.96498054}{2} = \frac{1.95742386}{2} \approx \mathbf{0.97871193} \implies \mathbf{97.87\%}$$

#### B. Weighted Average F1-Score
The class-support-weighted average of per-class F1-scores:
$$\text{Weighted F1} = \frac{N_0 \times F1_0 + N_1 \times F1_1}{N_0 + N_1} = \frac{596 \times 0.99244332 + 128 \times 0.96498054}{724}$$
$$\text{Weighted F1} = \frac{591.49622 + 123.51751}{724} = \frac{715.01373}{724} \approx \mathbf{0.98758803} \implies \mathbf{98.76\%}$$

---

### 1.6 Error Rates

#### A. False Positive Rate (FPR / Fall-out)
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{5}{5 + 591} = \frac{5}{596} \approx \mathbf{0.00838926} \implies \mathbf{0.84\%}$$

#### B. False Negative Rate (FNR / Miss Rate)
$$\text{FNR} = \frac{\text{FN}}{\text{FN} + \text{TP}} = \frac{4}{4 + 124} = \frac{4}{128} = \mathbf{0.03125000} \implies \mathbf{3.12\%}$$

---

## 2. Transformer Mathematical Derivations

### 2.1 Self-Attention Projection
Given input sequence representation $\mathbf{H} \in \mathbb{R}^{n \times d_{\text{model}}}$, where sequence length $n \le 256$ and $d_{\text{model}} = 768$:

Each attention head $j \in \{1, \dots, 12\}$ projects $\mathbf{H}$ into Query, Key, and Value spaces of dimension $d_k = 64$:
$$\mathbf{Q}_j = \mathbf{H} \mathbf{W}_j^Q, \quad \mathbf{K}_j = \mathbf{H} \mathbf{W}_j^K, \quad \mathbf{V}_j = \mathbf{H} \mathbf{W}_j^V$$
where $\mathbf{W}_j^Q, \mathbf{W}_j^K, \mathbf{W}_j^V \in \mathbb{R}^{768 \times 64}$.

### 2.2 Scaled Dot-Product Formulation
The attention affinity matrix $\mathbf{A}_j \in \mathbb{R}^{n \times n}$ between token pairs $(i, k)$ is:
$$\mathbf{S}_{ik} = \frac{\mathbf{q}_i^\top \mathbf{k}_k}{\sqrt{d_k}} = \frac{1}{8} \sum_{m=1}^{64} Q_{im} K_{km}$$

Applying the attention mask $\mathbf{M} \in \{0, -\infty\}^{n \times n}$ for padded positions:
$$\mathbf{A}_{ik} = \frac{\exp(\mathbf{S}_{ik} + \mathbf{M}_{ik})}{\sum_{p=1}^n \exp(\mathbf{S}_{ip} + \mathbf{M}_{ip})}$$

The contextual representation for head $j$ is:
$$\text{head}_j = \mathbf{A}_j \mathbf{V}_j \in \mathbb{R}^{n \times 64}$$

### 2.3 Multi-Head Output Aggregation
$$\text{MultiHead}(\mathbf{H}) = \left( \text{head}_1 \mathbin{\Vert} \text{head}_2 \mathbin{\Vert} \dots \mathbin{\Vert} \text{head}_{12} \right) \mathbf{W}^O$$
where $\mathbf{W}^O \in \mathbb{R}^{768 \times 768}$.

---

## 3. Evidence Fusion & Scoring Calculations

### 3.1 Five-Modality Scoring Decomposition
The total unconstrained risk score $S_{\text{raw}}$ is computed as:
$$S_{\text{raw}} = S_{\text{sender\_auth}} + S_{\text{url}} + S_{\text{content}} + S_{\text{ml}} + S_{\text{infra}}$$

Subject to the modality constraints:
- $S_{\text{sender\_auth}} = \min(25, \sum \text{rules}_{\text{auth}})$
- $S_{\text{url}} = \min(25, \sum \text{rules}_{\text{url}})$
- $S_{\text{content}} = \min(20, \sum \text{rules}_{\text{content}})$
- $S_{\text{infra}} = \min(10, \sum \text{rules}_{\text{infra}})$

### 3.2 DistilBERT Corroboration Dampening Algorithm
Let $S_{\text{tech}} = S_{\text{sender\_auth}} + S_{\text{url}} + S_{\text{content}} + S_{\text{infra}}$.  
Let $P_{\text{model}} \in [0.0, 1.0]$ denote the DistilBERT uncalibrated text heuristic score.

The assigned ML score $S_{\text{ml}} \in [0, 20]$ is determined by:
$$S_{\text{ml}} = \begin{cases}
\min\left(5, \text{round}\left(P_{\text{model}} \times 20 \times 0.25\right)\right) & \text{if } S_{\text{tech}} \le 5 \quad \text{(Clean Technical Evidence)} \\
\min\left(10, \text{round}\left(P_{\text{model}} \times 20 \times 0.50\right)\right) & \text{if } 5 < S_{\text{tech}} < 15 \quad \text{(Moderate Corroboration)} \\
\min\left(20, \text{round}\left(P_{\text{model}} \times 20 \times 1.00\right)\right) & \text{if } S_{\text{tech}} \ge 15 \quad \text{(Full Corroboration)}
\end{cases}$$

#### Numerical Case Demonstrations:
1. **Case A (LinkedIn Marketing Notification):**
   - Technical evidence: $S_{\text{tech}} = 0$ (Valid SPF/DKIM pass, clean tracking URLs on `licdn.com`).
   - Raw model score: $P_{\text{model}} = 0.9123$ (Text model triggers on urgency terms).
   - Dampened calculation:
     $$S_{\text{ml}} = \min\left(5, \text{round}(0.9123 \times 20 \times 0.25)\right) = \min(5, \text{round}(4.5615)) = \min(5, 5) = \mathbf{5\text{ points}}$$
   - Final score: $S_{\text{final}} = 0 + 5 = 5 \implies \mathbf{LOW\_RISK\_INDICATORS}$. False positive avoided!
2. **Case B (OKX Crypto Phishing Attack):**
   - Technical evidence: $S_{\text{tech}} = 68$ (Homoglyph display spoofing = 18 pts, Cyrillic homoglyph body tokens = 10 pts, unaligned URL = 15 pts, etc.).
   - Raw model score: $P_{\text{model}} = 0.9912$.
   - Fully corroborated calculation:
     $$S_{\text{ml}} = \min\left(20, \text{round}(0.9912 \times 20 \times 1.00)\right) = \min(20, \text{round}(19.824)) = \mathbf{20\text{ points}}$$
   - Final score: $S_{\text{final}} = 68 + 20 = 88 \implies \mathbf{HIGH\_RISK\_INDICATORS\_PRESENT}$.

### 3.3 Critical Threat Floor Formulation
Let $\mathcal{C}$ denote the set of critical threat conditions:
$$\mathcal{C} = \left\{ \text{Dangerous Attachment}, \text{Anchor Spoofing}, \text{Userinfo Trick}, \text{Lookalike Domain}, \text{Homoglyph Spoofing}, \text{Corroborated Brand Mismatch} \right\}$$

The final operational risk score $S_{\text{final}}$ is governed by:
$$S_{\text{final}} = \begin{cases}
\max(S_{\text{raw}}, 75) & \text{if } \exists c \in \mathcal{C} \\
\max(S_{\text{raw}}, 30) & \text{if } \text{Explicit Auth Failure} \lor \text{Auth Conflict} \lor \text{Model Error} \\
\min(100, \max(0, S_{\text{raw}})) & \text{otherwise}
\end{cases}$$

---

## 4. Empirical Verification of Historical Claims

The user prompt identified two candidate historical project metrics:
- **Candidate Claim 1:** 98.76% Test Accuracy.
- **Candidate Claim 2:** 96.50% Phishing F1-Score.

### Verification Status: **MATHEMATICALLY & EMPIRICALLY CONFIRMED**
1. Evaluation log `models/distilbert_baseline/test_evaluation_results.json` records:
   - `"test_accuracy": 0.9875690607734806` $\to$ Rounds precisely to **98.76%**.
   - `"phishing_f1": 0.9649805447470817` $\to$ Rounds precisely to **96.50%**.
2. Both metrics are independently verifiable from the confusion matrix entries ($\text{TP}=124, \text{TN}=591, \text{FP}=5, \text{FN}=4$) over $N=724$ locked test samples.
3. Zero post-hoc adjustments or threshold tuning was applied ($\tau = 0.50$ fixed).

