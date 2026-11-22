# PhishIntel — Complete Report Evidence Index & Audit Trail

**Document Title:** Evidence Traceability Index, File Registry & Cryptographic Hash Directory  
**Project:** PhishIntel – Transformer and NLP-Based Email Phishing Detection and IP Intelligence  
**Target Standard:** VTU Final Year Engineering Academic Forensic Traceability  

---

## 1. Master Evidence Registry

This document establishes the bidirectional traceability between every technical claim made in the **PhishIntel VTU Final Project Report** and the physical files, logs, and artifacts present in the workspace.

| Report Section / Metric | Primary Source Artifact | Exact File Location | Verification Evidence & Method |
| :--- | :--- | :--- | :--- |
| **Model Architecture** | `config.json` | `models/distilbert_baseline/config.json` | 6 layers, 12 heads, 768 dim, GELU, 30522 vocab. |
| **Model Weights Hash** | `model.safetensors` | `models/distilbert_baseline/model.safetensors` | SHA-256: `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` |
| **Hyperparameters** | `training_config.json` | `models/distilbert_baseline/training_config.json` | LR: $2\times 10^{-5}$, Batch: 16, Warmup: 108, FP16, Epochs: 3. |
| **Training History** | `training_history.json` | `models/distilbert_baseline/training_history.json` | Epoch 1 val loss: 0.0319; Epoch 2: 0.0360; Epoch 3: 0.0367. |
| **Validation Results** | `validation_results.json`| `models/distilbert_baseline/validation_evaluation_results.json` | Val Acc: 99.17%, Val F1: 97.67%, TN: 592, FP: 4, FN: 2, TP: 126. |
| **Locked Test Metrics** | `test_evaluation.json` | `models/distilbert_baseline/test_evaluation_results.json` | Test Acc: 98.76%, Phish F1: 96.50%, ROC-AUC: 0.9995. |
| **Error Log (9 cases)**| `test_error_analysis.csv`| `models/distilbert_baseline/test_error_analysis.csv` | 5 False Positives, 4 False Negatives explicitly itemized. |
| **Train Dataset Hash** | `train.csv` | `data/processed/phishmmf/train.csv` | SHA-256: `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` (5,791 rows). |
| **Val Dataset Hash** | `validation.csv` | `data/processed/phishmmf/validation.csv` | SHA-256: `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` (724 rows). |
| **Test Dataset Hash** | `test.csv` | `data/processed/phishmmf/test.csv` | SHA-256: `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` (724 rows). |
| **Dataset Splits Hash** | `split_manifest.json` | `data/processed/phishmmf/splits/split_manifest.json` | Stratified NFKC body hash grouping; 0 cross-split leakage. |
| **Clean Corpus Hash** | `cleaned_dataset.csv` | `data/processed/phishmmf/cleaned_email_dataset.csv` | SHA-256: `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` (7,239 rows). |
| **Remediation Actions** | `dataset_manifest.json`| `data/processed/phishmmf/dataset_manifest.json` | Removal of `00617`, `01785`, `00291`; `[USER]` token replaced. |
| **Backend Test Suite** | 15 test files | `backend/tests/test_*.py` | 317 test node IDs in `.pytest_cache/v/cache/nodeids`. |
| **Frontend Test Suite** | 3 test files | `frontend/src/tests/*.test.ts` | 78 tests passed, 0 failed in 960 ms (`npm test`). |
| **Live API Responses** | `live_api_responses.json`| `docs/phase10/live_api_responses.json` | 10 live socket fixture responses captured on ports 8000 & 5173. |
| **Sample HTML Reports**| 5 `.html` files | `docs/phase10/sample_reports/report_*.html` | Standalone HTML forensic reports with strict Level 3 CSP. |
| **Corroboration Logic** | `scoring_engine.py` | `backend/app/services/scoring_engine.py` | 5 modalities, dampening formula, critical threat floors. |
| **Zero-Network Logic** | `url_intelligence.py` | `backend/app/services/url_intelligence.py` | Python stdlib `urllib.parse`, RFC 3986 lexical rules. |
| **IP Classification** | `ip_intelligence.py` | `backend/app/services/ip_intelligence.py` | Python `ipaddress`, RFC 1918/5737/6598/2544, M365 & SendGrid catalogs. |
| **Offline Auth Safety** | `email_auth.py` | `backend/app/services/email_authentication.py` | Stage A.3 Boolean Safety: `is_trusted = False` for all offline uploads. |

---

## 2. Protected Research Artifact Hashes

The following four protected cryptographic SHA-256 hashes serve as immutable baseline anchors across all phases:

```powershell
# Verification Command:
python -c "
import hashlib
files = {
    'train.csv': ('data/processed/phishmmf/train.csv', '72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c'),
    'validation.csv': ('data/processed/phishmmf/validation.csv', '40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab'),
    'test.csv': ('data/processed/phishmmf/test.csv', '1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e'),
    'model.safetensors': ('models/distilbert_baseline/model.safetensors', 'fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8')
}
for name, (path, expected) in files.items():
    h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    assert h == expected, f'MISMATCH for {name}'
    print(f'{name}: MATCH ({h})')
print('ALL 4 ARTIFACTS VERIFIED BIT-IDENTICAL!')
"
```

Result: **100% BIT-IDENTICAL MATCH VERIFIED.**
Zero model weights or dataset splits were modified during this audit.

