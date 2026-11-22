# Phase 3A — Transformer Environment & Model Setup Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 3A — Transformer Environment & Model Setup  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Target Model**: `distilbert-base-uncased`  
**Hardware Profile**: NVIDIA GeForce RTX 3050 6GB Laptop GPU | 16 GB Host RAM  
**Dataset Reference**: PhishMMF Cleaned & Remediated Corpus (`v1.0.1-remediated-leakage-aware`)  
**Readiness Status**: **`READY_FOR_PHASE_3B`**

---

## 1. Executive Summary

Phase 3A prepares and certifies the local computing environment for fine-tuning the first Transformer baseline (`distilbert-base-uncased`) on dedicated GPU acceleration. 

In strict adherence to project safeguards:
- **Zero dataset modification**: All canonical and split datasets remain byte-for-byte identical to Phase 2C.
- **Zero training**: No model training or gradient optimization was performed.
- **Free/Open-Source only**: Only official open-source PyTorch wheels and open Hugging Face pretrained weights were utilized.
- **Controlled installation**: The previous CPU-only PyTorch build (`2.14.1+cpu`) was upgraded to a CUDA-enabled PyTorch build (`2.6.0+cu124`) compatible with Windows and Python 3.13.
- **Model cache verified**: Pretrained weights, tokenizer, and configuration for `distilbert-base-uncased` were safely retrieved and validated locally.
- **Hardware acceleration verified**: The NVIDIA GeForce RTX 3050 6GB GPU was confirmed operational via CUDA 12.4 runtime, successfully executing a synthetic forward-pass smoke test.

### Readiness Scorecard
| Component | Requirement | Result | Status |
| :--- | :--- | :--- | :--- |
| **Python Runtime** | Python 3.13 64-bit AMD64 | Python 3.13.15 | **PASS** |
| **PyTorch Acceleration** | CUDA-enabled build detecting RTX 3050 | `2.6.0+cu124` (CUDA 12.4, 6.0 GB VRAM) | **PASS** |
| **GPU Detection** | Active GPU device detected via PyTorch | NVIDIA GeForce RTX 3050 6GB Laptop GPU | **PASS** |
| **Transformers Ecosystem** | All required ML/NLP packages present | All installed (`transformers`, `tokenizers`, `accelerate`, etc.) | **PASS** |
| **DistilBERT Assets** | Model weights & tokenizer cached | Full offline cache (`model.safetensors`, `config.json`, `vocab.txt`) | **PASS** |
| **Smoke Test** | Non-training forward-pass on synthetic text | Successfully executed on `cuda:0` (logits shape: `[1, 2]`) | **PASS** |
| **Dataset Invariance** | Phase 2C dataset files unchanged | `train.csv`, `validation.csv`, `test.csv` hashes bit-identical | **PASS** |
| **Phase Status** | Final Phase 3A determination | **`READY_FOR_PHASE_3B`** | **PASS** |

---

## 2. Python Environment & Dependency Inspection

### Environment Baseline vs. Post-Authorization
Prior to making changes, the installed environment was recorded into `scratch/pre_install_packages.json`. The minimal change policy was applied: only PyTorch was transitioned to a CUDA-enabled build (`torch-2.6.0+cu124`).

| Attribute | Baseline State | Current Phase 3A State | Evaluation |
| :--- | :--- | :--- | :--- |
| **Python Executable** | `D:\python\python.exe` | `D:\python\python.exe` | Main project interpreter |
| **Python Version** | `3.13.15` | `3.13.15` | Fully supported |
| **Pip Version** | `26.2.1` | `26.2.1` | Fully supported |
| **PyTorch Version** | `2.14.1+cpu` | **`2.6.0+cu124`** | Upgraded to CUDA 12.4 build |
| **Torch CUDA Status** | `False` | **`True`** | GPU acceleration active |

---

## 3. Hardware Acceleration & CUDA Runtime Verification

### Hardware GPU Profile
- **Device Name**: NVIDIA GeForce RTX 3050 6GB Laptop GPU
- **Compute Capability**: `SM 8.6` (Ampere architecture)
- **Dedicated Hardware Memory**: 6,144 MiB (6.00 GB)
- **Host Display Driver**: `581.04` (NVIDIA Studio / Game Ready Driver)
- **Host CUDA Driver API**: CUDA 13.0 support

### PyTorch Device Diagnostics
```python
import torch
print(torch.__version__)                # 2.6.0+cu124
print(torch.cuda.is_available())        # True
print(torch.cuda.get_device_name(0))    # NVIDIA GeForce RTX 3050 6GB Laptop GPU
print(torch.cuda.get_device_properties(0).total_memory) # 6,441,926,656 bytes (6.0 GB)
```

| Parameter | Value | Status |
| :--- | :--- | :--- |
| **PyTorch Build** | `2.6.0+cu124` | **INSTALLED** |
| **PyTorch CUDA Runtime** | CUDA 12.4 | **COMPATIBLE** |
| **CUDA Available** | `True` | **ACTIVE** |
| **Device 0 Name** | NVIDIA GeForce RTX 3050 6GB Laptop GPU | **DETECTED** |
| **Total VRAM Reported** | 6.00 GB (6,441,926,656 Bytes) | **VERIFIED** |
| **Device Placement** | Native tensor allocation to `cuda:0` verified | **OPERATIONAL** |

---

## 4. Transformers Ecosystem Package Verification

All dependencies necessary for sequence classification, tokenization, training loop acceleration, and metric calculation are present in the active environment:

| Package Name | Installed Version | Status | Pipeline Function |
| :--- | :--- | :--- | :--- |
| **`transformers`** | `5.18.0` | **INSTALLED** | Hugging Face model architecture & Trainer |
| **`tokenizers`** | `0.23.2` | **INSTALLED** | Fast Rust-backed WordPiece tokenization |
| **`datasets`** | `5.0.1` | **INSTALLED** | Dataset structuring and PyArrow backing |
| **`accelerate`** | `1.15.0` | **INSTALLED** | GPU device placement & mixed-precision execution |
| **`scikit-learn`** | `1.6.1` | **INSTALLED** | Metrics (Precision, Recall, F1, ROC-AUC, PR-AUC) |
| **`pandas`** | `2.2.3` | **INSTALLED** | Dataset ingestion & split validation |
| **`numpy`** | `2.5.3` | **INSTALLED** | Numerical array computing & metric calculation |

---

## 5. Pretrained Model Cache Status (`distilbert-base-uncased`)

Under explicit user authorization, the pretrained Hugging Face model and tokenizer assets were downloaded and placed into the local Hugging Face hub cache directory:
`C:\Users\Lenovo\.cache\huggingface\hub\models--distilbert-base-uncased`

### Asset Audit
```text
C:\Users\Lenovo\.cache\huggingface\hub\models--distilbert-base-uncased
├── refs/main
└── snapshots/12040accade4e8a0f71eabdb258fecc2e7e948be/
    ├── config.json               (483 bytes)      [Architecture Specification]
    ├── tokenizer.json            (466,062 bytes)  [Fast Tokenizer Rules]
    ├── tokenizer_config.json     (48 bytes)       [Tokenizer Settings]
    ├── vocab.txt                 (231,508 bytes)  [WordPiece Vocabulary - 30,522 tokens]
    └── model.safetensors         (~268 MB)        [Pretrained Transformer Weights]
```

- **Tokenizer Load Status**: Verified (`BertTokenizer`, vocab size: 30,522).
- **Model Config Load Status**: Verified (`DistilBertConfig`, `hidden_size=768`, `n_layers=6`, `n_heads=12`, `num_labels=2`).
- **Model Weights Load Status**: Verified (`model.safetensors` successfully loaded and cached).

---

## 6. Synthetic Forward-Pass Smoke Test

To guarantee end-to-end functionality of PyTorch CUDA tensor execution without touching project datasets or training weights, a controlled synthetic smoke test was executed.

### Test Specifications
- **Synthetic Input Text**: `"This is a synthetic test message for environment verification."`
- **Execution Device**: `cuda:0` (NVIDIA GeForce RTX 3050 6GB Laptop GPU)
- **Model Initialized**: `AutoModelForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=2)`
- **Evaluation Mode**: `model.eval()`, `torch.no_grad()`
- **Training Performed**: **ZERO** (No loss computation, no backward pass, no optimizer steps)

### Tokenization & Output Results
- **Tokenized Tokens**: `['[CLS]', 'this', 'is', 'a', 'synthetic', 'test', 'message', 'for', 'environment', 'verification', '.', '[SEP]']`
- **Input Tensor Shape**: `torch.Size([1, 12])` (Input IDs & Attention Mask placed on `cuda:0`)
- **Forward-Pass Logits Shape**: `torch.Size([1, 2])`
- **Output Logits**: `[[0.0265, -0.1835]]`
- **Softmax Probabilities**: `Class 0 (Benign): 55.23% | Class 1 (Phishing): 44.77%`
- **Status**: **PASS (Forward pass completed without error)**

### GPU Memory Tracking
| Phase | VRAM Allocated | VRAM Reserved | Peak VRAM |
| :--- | :--- | :--- | :--- |
| **Initial (Clean GPU State)** | 0.00 MB | 0.00 MB | 0.00 MB |
| **Model Loaded on `cuda:0`** | 256.50 MB | 292.00 MB | 256.50 MB |
| **Post-Forward Pass (Smoke Test)** | 264.62 MB | 292.00 MB | **265.91 MB** |

The baseline DistilBERT model occupies only ~265 MB of the available 6,144 MB VRAM, leaving over **5.7 GB of free VRAM** available for batching and mixed precision during Phase 3B.

---

## 7. Phase 2C Dataset Integrity Verification

All Phase 2C dataset files and split partitions were verified against their approved cryptographic signatures.

| File Path | Expected Rows | Observed Rows | Expected SHA-256 | Observed SHA-256 | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `data/processed/phishmmf/train.csv` | 5,791 | 5,791 | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **PASS** |
| `data/processed/phishmmf/validation.csv` | 724 | 724 | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **PASS** |
| `data/processed/phishmmf/test.csv` | 724 | 724 | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **PASS** |
| `data/processed/phishmmf/cleaned_email_dataset.csv` | 7,239 | 7,239 | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | **PASS** |

- **Verification Verdict**: Zero files were altered, regenerated, or moved. Integrity is 100% intact.

---

## 8. Diagnostic Utility Script

The automated diagnostic script [`scripts/phase3_check_environment.py`](file:///c:/Users/Lenovo/Desktop/PhishIntel/scripts/phase3_check_environment.py) has been updated and certified:
- **Command**: `python scripts/phase3_check_environment.py`
- **Execution Mode**: Non-destructive, read-only diagnostic and synthetic forward-pass test.
- **Output**: Full diagnostic table, GPU VRAM report, split validation, and status verdict.
- **Latest Output Result**: Exited with code `0`, reporting `STATUS: READY_FOR_PHASE_3B`.

---

## 9. Observations & Technical Warnings

1. **Classification Head Initialization (Expected)**:
   - When instantiating `AutoModelForSequenceClassification` from `distilbert-base-uncased`, Hugging Face reports that `pre_classifier` and `classifier` are freshly initialized while MLM heads are unused. This is standard behavior for adapting a pretrained Masked Language Model to a 2-class downstream sequence classifier.
2. **Hugging Face Hub Symlinks Warning on Windows**:
   - The HF cache issues a standard warning regarding Windows symlinks. This does not affect functionality, as weights and configs are stored and loaded reliably.
3. **No Project Code Alterations**:
   - No Phase 1 backend, frontend, or feature extraction files were altered.

---

## 10. Final Status Verdict

All prerequisites authorized by the user have been completed and verified:
- GPU acceleration is active and functional on the NVIDIA GeForce RTX 3050 6GB Laptop GPU.
- DistilBERT pretrained weights, configuration, and tokenizer are fully cached and validated locally.
- Forward pass smoke test on GPU succeeded with minimal VRAM footprint (~266 MB peak).
- Phase 2C dataset files remain bit-for-bit identical to approved baselines.

# READY_FOR_PHASE_3B
