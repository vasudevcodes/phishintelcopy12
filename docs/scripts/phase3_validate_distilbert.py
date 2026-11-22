"""
PhishIntel - Phase 3B Standalone DistilBERT Baseline Validation Script

Loads the saved model checkpoint from models/distilbert_baseline/
and performs evaluation strictly on validation.csv.
Adheres strictly to Phase 3B rules:
- NEVER loads, inspects, or evaluates test.csv
- Evaluates validation.csv (724 rows)
- Positive class: 1 (phishing)
- Computes Loss, Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrix
"""

import os
import sys
import json
import hashlib
import argparse
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification

VALIDATION_PATH = "data/processed/phishmmf/validation.csv"
VALIDATION_EXPECTED_SHA = "40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab"
VALIDATION_EXPECTED_ROWS = 724
EXPECTED_COLUMNS = ["id", "subject", "body", "label", "source"]


def compute_sha256(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class PhishEmailDataset(Dataset):
    def __init__(self, df):
        self.texts = []
        self.labels = []
        for _, row in df.iterrows():
            sub = str(row["subject"]) if pd.notna(row["subject"]) else ""
            bdy = str(row["body"]) if pd.notna(row["body"]) else ""
            text = f"{sub}\n\n{bdy}"
            self.texts.append(text)
            self.labels.append(int(row["label"]))

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        return self.texts[idx], self.labels[idx]


def make_collate_fn(tokenizer, max_length=256):
    def collate_fn(batch):
        texts, labels = zip(*batch)
        encodings = tokenizer(
            list(texts),
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        )
        encodings["labels"] = torch.tensor(labels, dtype=torch.long)
        return encodings
    return collate_fn


def compute_binary_metrics(y_true, y_probs, threshold=0.5):
    y_true = np.asarray(y_true, dtype=int)
    y_probs = np.asarray(y_probs, dtype=float)
    y_pred = (y_probs >= threshold).astype(int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    pos_mask = (y_true == 1)
    neg_mask = (y_true == 0)
    n_pos = int(np.sum(pos_mask))
    n_neg = int(np.sum(neg_mask))

    if n_pos == 0 or n_neg == 0:
        roc_auc = float("nan")
    else:
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
        roc_auc = float(u_stat / (n_pos * n_neg))

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "tp": tp, "tn": tn, "fp": fp, "fn": fn
    }


def validate_checkpoint(
    checkpoint_dir="models/distilbert_baseline",
    val_path=VALIDATION_PATH,
    batch_size=4,
    max_length=256
):
    print("=" * 70)
    print("PHISHINTEL — PHASE 3B STANDALONE VALIDATION EVALUATION")
    print("=" * 70)

    # 1. Verification of checkpoint directory
    if not os.path.isdir(checkpoint_dir):
        raise FileNotFoundError(f"Checkpoint directory not found: {checkpoint_dir}")

    # 2. Verification of validation file integrity
    if not os.path.exists(val_path):
        raise FileNotFoundError(f"Validation dataset file not found: {val_path}")

    val_sha = compute_sha256(val_path)
    if val_sha != VALIDATION_EXPECTED_SHA:
        raise ValueError(
            f"Validation hash mismatch!\n"
            f"  Expected: {VALIDATION_EXPECTED_SHA}\n"
            f"  Actual:   {val_sha}"
        )
    print(f"Validation dataset verified: {val_path} (SHA-256: {val_sha})")

    # 3. Check hardware
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    print(f"Evaluation device: {device} ({torch.cuda.get_device_name(device) if device.type == 'cuda' else 'CPU'})")

    # 4. Load model and tokenizer
    print(f"Loading checkpoint from: {checkpoint_dir}...")
    tokenizer = AutoTokenizer.from_pretrained(checkpoint_dir, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint_dir, local_files_only=True).to(device)
    model.eval()

    # 5. Load validation dataset
    val_df = pd.read_csv(val_path)
    if len(val_df) != VALIDATION_EXPECTED_ROWS:
        raise ValueError(f"Validation row count mismatch: {len(val_df)} vs {VALIDATION_EXPECTED_ROWS}")

    dataset = PhishEmailDataset(val_df)
    collate_fn = make_collate_fn(tokenizer, max_length=max_length)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False, collate_fn=collate_fn)

    # 6. Evaluation loop
    total_loss = 0.0
    all_probs = []
    all_preds = []
    all_labels = []

    print(f"Running evaluation on {len(dataset)} validation samples...")
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            if device.type == "cuda":
                with torch.amp.autocast('cuda'):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                    loss = outputs.loss
                    logits = outputs.logits
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                logits = outputs.logits

            total_loss += loss.item() * len(labels)
            probs = torch.softmax(logits, dim=-1)[:, 1]
            preds = torch.argmax(logits, dim=-1)

            all_probs.extend(probs.cpu().numpy().tolist())
            all_preds.extend(preds.cpu().numpy().tolist())
            all_labels.extend(labels.cpu().numpy().tolist())

    avg_loss = total_loss / len(dataset)
    metrics = compute_binary_metrics(all_labels, all_probs, threshold=0.5)
    metrics["loss"] = float(avg_loss)
    metrics["total_samples"] = len(dataset)
    metrics["checkpoint_dir"] = os.path.abspath(checkpoint_dir)
    metrics["validation_file_sha256"] = val_sha

    print("\n--- STANDALONE VALIDATION RESULTS ---")
    print(f"Total Validation Samples: {metrics['total_samples']}")
    print(f"Validation Loss:         {metrics['loss']:.4f}")
    print(f"Validation Accuracy:     {metrics['accuracy']*100:.2f}%")
    print(f"Validation Precision:    {metrics['precision']*100:.2f}% (Phishing = Positive Class)")
    print(f"Validation Recall:       {metrics['recall']*100:.2f}%")
    print(f"Validation F1-Score:     {metrics['f1']*100:.2f}%")
    print(f"Validation ROC-AUC:      {metrics['roc_auc']:.4f}")
    print(f"Confusion Matrix:        {metrics['confusion_matrix']}")
    print(f"  - True Negatives (TN):  {metrics['tn']}")
    print(f"  - False Positives (FP): {metrics['fp']}")
    print(f"  - False Negatives (FN): {metrics['fn']}")
    print(f"  - True Positives (TP):  {metrics['tp']}")

    out_json = os.path.join(checkpoint_dir, "validation_evaluation_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nResults saved to: {out_json}")

    return metrics


def main():
    parser = argparse.ArgumentParser(description="PhishIntel Phase 3B Standalone Validation")
    parser.add_argument("--checkpoint-dir", type=str, default="models/distilbert_baseline", help="Checkpoint directory")
    parser.add_argument("--val-path", type=str, default=VALIDATION_PATH, help="Validation CSV file")
    parser.add_argument("--batch-size", type=int, default=4, help="Evaluation batch size")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    args = parser.parse_args()

    validate_checkpoint(
        checkpoint_dir=args.checkpoint_dir,
        val_path=args.val_path,
        batch_size=args.batch_size,
        max_length=args.max_length
    )


if __name__ == "__main__":
    main()
