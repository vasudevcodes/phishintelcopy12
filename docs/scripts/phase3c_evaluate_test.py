"""
PhishIntel - Phase 3C Locked Test-Set Evaluation Script

Evaluates the saved DistilBERT baseline (models/distilbert_baseline/) exactly once
on the previously untouched test partition (data/processed/phishmmf/test.csv).

Strict Rules:
- Evaluates existing saved checkpoint (Epoch 1 selected by validation loss).
- Zero training, zero fine-tuning, zero threshold tuning (fixed threshold 0.5).
- Input: subject + "\\n\\n" + body (max_length = 256, metadata excluded).
- Binary mapping: 0 = benign, 1 = phishing (positive class = 1).
- Cryptographic hash verification of train.csv, validation.csv, and test.csv.
- Saves:
    - models/distilbert_baseline/test_evaluation_results.json
    - models/distilbert_baseline/test_error_analysis.csv
"""

import os
import sys
import time
import json
import hashlib
import argparse
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification

EXPECTED_HASHES = {
    "train": {
        "path": "data/processed/phishmmf/train.csv",
        "sha256": "72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c",
        "rows": 5791,
        "phish": 1024,
        "benign": 4767
    },
    "validation": {
        "path": "data/processed/phishmmf/validation.csv",
        "sha256": "40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab",
        "rows": 724,
        "phish": 128,
        "benign": 596
    },
    "test": {
        "path": "data/processed/phishmmf/test.csv",
        "sha256": "1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e",
        "rows": 724,
        "phish": 128,
        "benign": 596
    }
}

EXPECTED_COLUMNS = ["id", "subject", "body", "label", "source"]


def compute_sha256(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class PhishEmailTestDataset(Dataset):
    """
    Dataset for test evaluation.
    Only combines subject and body: text = subject + "\\n\\n" + body
    Preserves record ID, source, and truncated subject strictly for error analysis.
    Does NOT use ID, source, or any metadata as model inputs.
    """
    def __init__(self, df):
        self.texts = []
        self.labels = []
        self.ids = []
        self.sources = []
        self.raw_subjects = []

        for _, row in df.iterrows():
            sub = str(row["subject"]) if pd.notna(row["subject"]) else ""
            bdy = str(row["body"]) if pd.notna(row["body"]) else ""
            text = f"{sub}\n\n{bdy}"
            self.texts.append(text)
            self.labels.append(int(row["label"]))
            self.ids.append(row["id"])
            self.sources.append(str(row["source"]))
            self.raw_subjects.append(sub)

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        return {
            "text": self.texts[idx],
            "label": self.labels[idx],
            "id": self.ids[idx],
            "source": self.sources[idx],
            "subject": self.raw_subjects[idx]
        }


def make_collate_fn(tokenizer, max_length=256):
    def collate_fn(batch):
        texts = [b["text"] for b in batch]
        labels = [b["label"] for b in batch]
        ids = [b["id"] for b in batch]
        sources = [b["source"] for b in batch]
        subjects = [b["subject"] for b in batch]

        encodings = tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        )
        encodings["labels"] = torch.tensor(labels, dtype=torch.long)
        encodings["ids"] = ids
        encodings["sources"] = sources
        encodings["subjects"] = subjects
        return encodings
    return collate_fn


def compute_roc_auc(y_true, y_probs):
    pos_mask = (y_true == 1)
    neg_mask = (y_true == 0)
    n_pos = int(np.sum(pos_mask))
    n_neg = int(np.sum(neg_mask))

    if n_pos == 0 or n_neg == 0:
        return float("nan")

    order = np.argsort(y_probs)
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.arange(1, len(y_probs) + 1)

    sorted_probs = y_probs[order]
    unique_probs, inverse_indices, counts = np.unique(sorted_probs, return_inverse=True, return_counts=True)
    tie_indices = np.where(counts > 1)[0]
    for tie_idx in tie_indices:
        tied_positions = np.where(inverse_indices == tie_idx)[0]
        avg_rank = np.mean(tied_positions + 1)
        ranks[order[tied_positions]] = avg_rank

    pos_rank_sum = np.sum(ranks[pos_mask])
    u_stat = pos_rank_sum - (n_pos * (n_pos + 1)) / 2.0
    return float(u_stat / (n_pos * n_neg))


def evaluate_test_set(
    checkpoint_dir="models/distilbert_baseline",
    test_path=EXPECTED_HASHES["test"]["path"],
    batch_size=4,
    max_length=256
):
    print("=" * 75)
    print("PHISHINTEL — PHASE 3C LOCKED TEST-SET EVALUATION")
    print("=" * 75)

    # 1. Pre-Flight Cryptographic Dataset Verification
    print("\n--- 1. PRE-FLIGHT DATASET INTEGRITY CHECKS ---")
    verified_hashes = {}
    for s_name in ["train", "validation", "test"]:
        p = EXPECTED_HASHES[s_name]["path"]
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing required dataset: {p}")
        h = compute_sha256(p)
        expected_h = EXPECTED_HASHES[s_name]["sha256"]
        if h != expected_h:
            raise ValueError(
                f"FATAL: Hash mismatch on {s_name} ({p})!\n"
                f"  Expected: {expected_h}\n"
                f"  Observed: {h}"
            )
        verified_hashes[s_name] = h
        print(f"  [PASS] {s_name}.csv: SHA-256 = {h}")

    # Inspect test CSV specifically
    test_df = pd.read_csv(test_path)
    if len(test_df) != EXPECTED_HASHES["test"]["rows"]:
        raise ValueError(f"Test row count mismatch: {len(test_df)} vs expected {EXPECTED_HASHES['test']['rows']}")
    for col in EXPECTED_COLUMNS:
        if col not in test_df.columns:
            raise ValueError(f"Missing column '{col}' in test dataset.")

    test_phish = int((test_df["label"] == 1).sum())
    test_benign = int((test_df["label"] == 0).sum())
    if test_phish != EXPECTED_HASHES["test"]["phish"] or test_benign != EXPECTED_HASHES["test"]["benign"]:
        raise ValueError(
            f"Test label distribution mismatch: {test_phish} phish / {test_benign} benign vs "
            f"{EXPECTED_HASHES['test']['phish']} phish / {EXPECTED_HASHES['test']['benign']} benign"
        )
    print(f"Test split schema verified: {len(test_df)} rows ({test_phish} phishing, {test_benign} benign).")

    # 2. Hardware and Model Checkpoint Verification
    print("\n--- 2. HARDWARE & CHECKPOINT VERIFICATION ---")
    if not torch.cuda.is_available():
        raise RuntimeError("FATAL: CUDA is not available. Phase 3C mandates GPU evaluation on RTX 3050.")

    device = torch.device("cuda:0")
    device_name = torch.cuda.get_device_name(device)
    print(f"CUDA Device:          {device_name}")
    print(f"Total Dedicated VRAM: {round(torch.cuda.get_device_properties(device).total_memory / (1024**3), 2)} GB")
    print(f"PyTorch Version:      {torch.__version__}")
    print(f"CUDA Runtime Version: {torch.version.cuda}")

    if not os.path.isdir(checkpoint_dir):
        raise FileNotFoundError(f"Checkpoint directory not found: {checkpoint_dir}")

    # Record model weights hash before evaluation
    weights_path = os.path.join(checkpoint_dir, "model.safetensors")
    if not os.path.exists(weights_path):
        raise FileNotFoundError(f"Missing model weights at: {weights_path}")
    weights_sha_before = compute_sha256(weights_path)
    print(f"Model Checkpoint Path:{os.path.abspath(checkpoint_dir)}")
    print(f"Model Weights SHA-256:{weights_sha_before}")

    print("\nLoading tokenizer and model checkpoint...")
    tokenizer = AutoTokenizer.from_pretrained(checkpoint_dir, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint_dir, local_files_only=True).to(device)
    model.eval()
    print("Model loaded successfully in evaluation mode.")

    # 3. Build Test DataLoader
    test_dataset = PhishEmailTestDataset(test_df)
    collate_fn = make_collate_fn(tokenizer, max_length=max_length)
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_fn
    )

    # 4. Execute Test Evaluation Pass
    print(f"\n--- 3. EXECUTING TEST EVALUATION PASS ({len(test_dataset)} SAMPLES) ---")
    start_eval_time = time.time()
    total_loss = 0.0
    all_probs = []
    all_preds = []
    all_labels = []
    all_ids = []
    all_sources = []
    all_subjects = []

    with torch.no_grad():
        for step, batch in enumerate(test_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            with torch.amp.autocast('cuda'):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                logits = outputs.logits

            total_loss += loss.item() * len(labels)
            probs = torch.softmax(logits, dim=-1)[:, 1]
            preds = (probs >= 0.5).long()

            all_probs.extend(probs.cpu().numpy().tolist())
            all_preds.extend(preds.cpu().numpy().tolist())
            all_labels.extend(labels.cpu().numpy().tolist())
            all_ids.extend(batch["ids"])
            all_sources.extend(batch["sources"])
            all_subjects.extend(batch["subjects"])

    eval_duration = time.time() - start_eval_time
    avg_loss = total_loss / len(test_dataset)

    # 5. Metric Calculations
    print("\n--- 4. COMPUTING TEST METRICS ---")
    y_true = np.asarray(all_labels, dtype=int)
    y_probs = np.asarray(all_probs, dtype=float)
    y_pred = np.asarray(all_preds, dtype=int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    total = len(y_true)

    # Global Accuracy
    accuracy = (tp + tn) / total if total > 0 else 0.0

    # Phishing (Class 1) - Primary Positive Class
    phish_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    phish_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    phish_f1 = (2 * phish_precision * phish_recall) / (phish_precision + phish_recall) if (phish_precision + phish_recall) > 0 else 0.0

    # Benign (Class 0)
    benign_precision = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    benign_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    benign_f1 = (2 * benign_precision * benign_recall) / (benign_precision + benign_recall) if (benign_precision + benign_recall) > 0 else 0.0

    # Macro & Weighted F1
    macro_f1 = (benign_f1 + phish_f1) / 2.0
    support_benign = int(np.sum(y_true == 0))
    support_phish = int(np.sum(y_true == 1))
    weighted_f1 = (benign_f1 * support_benign + phish_f1 * support_phish) / total

    # Rates
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    # ROC-AUC
    roc_auc = compute_roc_auc(y_true, y_probs)

    print(f"Test Loss:               {avg_loss:.4f}")
    print(f"Test Accuracy:           {accuracy*100:.2f}% ({tp+tn}/{total})")
    print(f"Phishing Precision:      {phish_precision*100:.2f}% ({tp}/{tp+fp})")
    print(f"Phishing Recall:         {phish_recall*100:.2f}% ({tp}/{tp+fn})")
    print(f"Phishing F1-Score:       {phish_f1*100:.2f}%")
    print(f"ROC-AUC:                 {roc_auc:.4f}")
    print(f"False-Positive Rate (FPR):{fpr*100:.2f}% ({fp}/{fp+tn})")
    print(f"False-Negative Rate (FNR):{fnr*100:.2f}% ({fn}/{fn+tp})")
    print(f"Macro-F1 Score:          {macro_f1*100:.2f}%")
    print(f"Weighted-F1 Score:       {weighted_f1*100:.2f}%")
    print(f"\nPer-Class Breakdown:")
    print(f"  - Class 0 (Benign):   Precision={benign_precision*100:.2f}%, Recall={benign_recall*100:.2f}%, F1={benign_f1*100:.2f}%, Support={support_benign}")
    print(f"  - Class 1 (Phishing): Precision={phish_precision*100:.2f}%, Recall={phish_recall*100:.2f}%, F1={phish_f1*100:.2f}%, Support={support_phish}")
    print(f"\nConfusion Matrix [[TN, FP], [FN, TP]]:")
    print(f"  [[{tn}, {fp}],")
    print(f"   [{fn}, {tp}]]")
    print(f"  TN = {tn}, FP = {fp}, FN = {fn}, TP = {tp}")
    print(f"Evaluation Duration:     {eval_duration:.2f} seconds")

    # 6. Error Analysis
    print("\n--- 5. ERROR ANALYSIS (FALSE POSITIVES & FALSE NEGATIVES) ---")
    error_records = []
    for i in range(total):
        gt = y_true[i]
        pr = y_pred[i]
        if gt != pr:
            err_type = "FALSE_POSITIVE" if (gt == 0 and pr == 1) else "FALSE_NEGATIVE"
            sub_raw = str(all_subjects[i]).replace("\r", " ").replace("\n", " ").strip()
            sub_trunc = sub_raw[:80] + ("..." if len(sub_raw) > 80 else "")
            error_records.append({
                "id": all_ids[i],
                "ground_truth": int(gt),
                "predicted_label": int(pr),
                "error_type": err_type,
                "phishing_probability": round(float(all_probs[i]), 4),
                "source": all_sources[i],
                "subject_truncated": sub_trunc
            })

    error_df = pd.DataFrame(error_records)
    error_csv_path = os.path.join(checkpoint_dir, "test_error_analysis.csv")
    error_df.to_csv(error_csv_path, index=False)
    print(f"Total misclassifications: {len(error_records)} (FP: {fp}, FN: {fn})")
    print(f"Error analysis saved to:  {error_csv_path}")

    # 7. Post-Evaluation Cryptographic Integrity Checks
    print("\n--- 6. POST-EVALUATION INTEGRITY VERIFICATION ---")
    for s_name in ["train", "validation", "test"]:
        p = EXPECTED_HASHES[s_name]["path"]
        h_post = compute_sha256(p)
        if h_post != verified_hashes[s_name]:
            raise ValueError(f"FATAL: Post-evaluation hash altered for {s_name} ({p})!")
        print(f"  [PASS] {s_name}.csv remains bit-identical: {h_post}")

    weights_sha_after = compute_sha256(weights_path)
    if weights_sha_after != weights_sha_before:
        raise ValueError("FATAL: Model weights were modified during evaluation!")
    print(f"  [PASS] Model weights remain bit-identical: {weights_sha_after}")

    # 8. Save Machine-Readable Results JSON
    eval_timestamp = datetime.now(timezone.utc).isoformat()
    results_dict = {
        "evaluation_phase": "Phase 3C — Locked Test-Set Evaluation",
        "evaluation_timestamp_utc": eval_timestamp,
        "model_checkpoint_path": os.path.abspath(checkpoint_dir),
        "model_weights_sha256": weights_sha_before,
        "test_dataset_path": os.path.abspath(test_path),
        "test_dataset_sha256": verified_hashes["test"],
        "dataset_integrity_verified": True,
        "hardware_environment": {
            "device": device_name,
            "torch_version": torch.__version__,
            "cuda_version": torch.version.cuda
        },
        "evaluation_settings": {
            "batch_size": batch_size,
            "max_sequence_length": max_length,
            "decision_threshold": 0.5,
            "positive_class": "1 (phishing)",
            "negative_class": "0 (benign)",
            "input_format": "subject + '\\n\\n' + body",
            "metadata_used_as_features": False
        },
        "test_sample_counts": {
            "total_test_samples": total,
            "benign_support": support_benign,
            "phishing_support": support_phish
        },
        "metrics": {
            "test_loss": float(avg_loss),
            "test_accuracy": float(accuracy),
            "phishing_precision": float(phish_precision),
            "phishing_recall": float(phish_recall),
            "phishing_f1": float(phish_f1),
            "roc_auc": float(roc_auc),
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr),
            "macro_f1": float(macro_f1),
            "weighted_f1": float(weighted_f1),
            "per_class": {
                "benign_class_0": {
                    "precision": float(benign_precision),
                    "recall": float(benign_recall),
                    "f1": float(benign_f1),
                    "support": support_benign
                },
                "phishing_class_1": {
                    "precision": float(phish_precision),
                    "recall": float(phish_recall),
                    "f1": float(phish_f1),
                    "support": support_phish
                }
            },
            "confusion_matrix": [[tn, fp], [fn, tp]],
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "error_analysis_summary": {
            "total_errors": len(error_records),
            "false_positives_count": fp,
            "false_negatives_count": fn,
            "error_analysis_file": os.path.abspath(error_csv_path)
        },
        "evaluation_duration_sec": round(eval_duration, 2),
        "scientific_limitation_note": (
            "The current dataset has known source-label correlation (phishing from phishing_pot, "
            "benign from CEAS and SpamAssassin). Performance reflects held-out test generalization "
            "within this corpus structure, not generalization across independent sources or real-world inboxes."
        )
    }

    results_json_path = os.path.join(checkpoint_dir, "test_evaluation_results.json")
    with open(results_json_path, "w", encoding="utf-8") as f:
        json.dump(results_dict, f, indent=2)

    print(f"\nMachine-readable metrics saved to: {results_json_path}")
    print("\nSTATUS: PHASE_3C_TEST_EVALUATION_COMPLETE")
    return results_dict


def main():
    parser = argparse.ArgumentParser(description="PhishIntel Phase 3C Locked Test-Set Evaluation")
    parser.add_argument("--checkpoint-dir", type=str, default="models/distilbert_baseline", help="Model checkpoint dir")
    parser.add_argument("--test-path", type=str, default=EXPECTED_HASHES["test"]["path"], help="Test dataset CSV")
    parser.add_argument("--batch-size", type=int, default=4, help="Evaluation batch size")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    args = parser.parse_args()

    try:
        evaluate_test_set(
            checkpoint_dir=args.checkpoint_dir,
            test_path=args.test_path,
            batch_size=args.batch_size,
            max_length=args.max_length
        )
    except Exception as e:
        print(f"\nFATAL ERROR during Phase 3C evaluation: {e}")
        import traceback
        traceback.print_exc()
        print("STATUS: BLOCKED — ACTION REQUIRED")
        sys.exit(1)


if __name__ == "__main__":
    main()
