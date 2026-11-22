"""
PhishIntel - Phase 3B DistilBERT Baseline Training Script

Trains the baseline text-only DistilBERT model for phishing email detection.
Adheres strictly to Phase 3B specifications:
- Model: distilbert-base-uncased (loaded from local Hugging Face cache)
- Input: subject + "\\n\\n" + body (metadata excluded)
- Labels: 0 = benign, 1 = phishing
- Training split: train.csv (5,791 rows, locked natural distribution)
- Validation split: validation.csv (724 rows, checkpoint selection on val loss)
- Test set: NEVER loaded or evaluated during training or model selection
- Hardware: NVIDIA GeForce RTX 3050 6GB Laptop GPU (PyTorch CUDA + FP16 AMP)
"""

import os
import sys
import time
import math
import json
import random
import hashlib
import argparse
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import (
    AutoConfig,
    AutoTokenizer,
    AutoModelForSequenceClassification,
    get_linear_schedule_with_warmup
)

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


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    os.environ["PYTHONHASHSEED"] = str(seed)


def verify_split_integrity(split_name, check_data=True):
    meta = EXPECTED_HASHES[split_name]
    path = meta["path"]
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required dataset file: {path}")

    actual_hash = compute_sha256(path)
    if actual_hash != meta["sha256"]:
        raise ValueError(
            f"Integrity check FAILED for {split_name} ({path}):\n"
            f"  Expected SHA-256: {meta['sha256']}\n"
            f"  Actual SHA-256:   {actual_hash}"
        )

    if check_data:
        df = pd.read_csv(path)
        if len(df) != meta["rows"]:
            raise ValueError(f"{split_name} row count mismatch: {len(df)} vs expected {meta['rows']}")
        # Schema verification
        for col in EXPECTED_COLUMNS:
            if col not in df.columns:
                raise ValueError(f"Missing column '{col}' in {path}")
        # Label values verification
        unique_labels = set(df["label"].unique())
        if not unique_labels.issubset({0, 1}):
            raise ValueError(f"Invalid label values in {path}: {unique_labels}. Expected only {{0, 1}}.")

    return actual_hash


class PhishEmailDataset(Dataset):
    """
    Email dataset combining subject and body:
    text = subject + "\\n\\n" + body
    Defensively replaces null subject or body with empty string.
    Does NOT use any metadata (id, source, sender, etc.).
    """
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
    """
    Computes classification metrics for binary labels (0 = benign, 1 = phishing).
    Positive class: 1 (phishing).
    """
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


def evaluate(model, dataloader, device):
    model.eval()
    total_loss = 0.0
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            with torch.amp.autocast('cuda'):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                logits = outputs.logits

            batch_size = labels.size(0)
            total_loss += loss.item() * batch_size

            probs = torch.softmax(logits, dim=-1)[:, 1]
            all_probs.extend(probs.cpu().numpy().tolist())
            all_labels.extend(labels.cpu().numpy().tolist())

    avg_loss = total_loss / len(dataloader.dataset)
    metrics = compute_binary_metrics(all_labels, all_probs, threshold=0.5)
    metrics["loss"] = avg_loss
    return metrics


def train_distilbert(
    model_name="distilbert-base-uncased",
    output_dir="models/distilbert_baseline",
    batch_size=4,
    eval_batch_size=4,
    gradient_accumulation_steps=4,
    epochs=3,
    lr=2e-5,
    weight_decay=0.01,
    max_length=256,
    seed=42,
    patience=2,
    enable_gradient_checkpointing=False
):
    print("=" * 70)
    print("PHISHINTEL — PHASE 3B DISTILBERT BASELINE TRAINING")
    print("=" * 70)

    # 1. Pre-flight checks
    print("\n--- 1. PRE-FLIGHT CHECKS ---")
    if not torch.cuda.is_available():
        raise RuntimeError("FATAL: CUDA is not available. Phase 3B mandates GPU training on RTX 3050. Cannot proceed.")

    device = torch.device("cuda:0")
    device_name = torch.cuda.get_device_name(device)
    vram_bytes = torch.cuda.get_device_properties(device).total_memory
    vram_gb = round(vram_bytes / (1024**3), 2)
    print(f"CUDA Device:          {device_name}")
    print(f"Total Dedicated VRAM: {vram_gb} GB ({vram_bytes} bytes)")
    print(f"PyTorch Version:      {torch.__version__}")
    print(f"CUDA Runtime Version: {torch.version.cuda}")

    # Verify all 3 split hashes
    print("\nVerifying approved dataset split files & hashes...")
    verified_hashes = {}
    for s_name in ["train", "validation", "test"]:
        h = verify_split_integrity(s_name, check_data=True)
        verified_hashes[s_name] = h
        print(f"  [PASS] {s_name}.csv: SHA-256 = {h}")
    print("All dataset hashes certified.")

    # 2. Reproducibility setup
    set_seed(seed)
    print(f"\nRandom seed locked to: {seed} (Python, NumPy, PyTorch, CUDA)")

    # 3. Load datasets
    print("\n--- 2. DATASET INGESTION & CLASS DISTRIBUTION ---")
    train_df = pd.read_csv(EXPECTED_HASHES["train"]["path"])
    val_df = pd.read_csv(EXPECTED_HASHES["validation"]["path"])

    train_phish = int((train_df["label"] == 1).sum())
    train_benign = int((train_df["label"] == 0).sum())
    val_phish = int((val_df["label"] == 1).sum())
    val_benign = int((val_df["label"] == 0).sum())

    print(f"Train split records:       {len(train_df):,}")
    print(f"  - Phishing (class 1):     {train_phish:,} ({train_phish/len(train_df)*100:.2f}%)")
    print(f"  - Benign (class 0):       {train_benign:,} ({train_benign/len(train_df)*100:.2f}%)")
    print(f"  - Natural Imbalance:      1 : {train_benign/train_phish:.2f} (phishing : benign)")
    print(f"Validation split records:  {len(val_df):,}")
    print(f"  - Phishing (class 1):     {val_phish:,} ({val_phish/len(val_df)*100:.2f}%)")
    print(f"  - Benign (class 0):       {val_benign:,} ({val_benign/len(val_df)*100:.2f}%)")
    print("NOTE: Test set is LOCKED and will NOT be accessed during training or validation.")

    # 4. Tokenizer & Dataset Objects
    print("\n--- 3. MODEL & TOKENIZER INITIALIZATION ---")
    print(f"Loading local tokenizer for '{model_name}'...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)

    print(f"Loading local config and pretrained model for '{model_name}'...")
    config = AutoConfig.from_pretrained(model_name, num_labels=2, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        config=config,
        local_files_only=True
    ).to(device)

    if enable_gradient_checkpointing:
        print("Enabling gradient checkpointing for model...")
        model.gradient_checkpointing_enable()

    train_dataset = PhishEmailDataset(train_df)
    val_dataset = PhishEmailDataset(val_df)

    collate_fn = make_collate_fn(tokenizer, max_length=max_length)

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=collate_fn,
        generator=torch.Generator().manual_seed(seed)
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=eval_batch_size,
        shuffle=False,
        collate_fn=collate_fn
    )

    # 5. Optimizer, Scheduler, Mixed Precision
    effective_batch_size = batch_size * gradient_accumulation_steps
    num_update_steps_per_epoch = math.ceil(len(train_loader) / gradient_accumulation_steps)
    max_train_steps = epochs * num_update_steps_per_epoch
    warmup_steps = int(0.10 * max_train_steps)

    print("\n--- 4. TRAINING CONFIGURATION ---")
    print(f"Per-device Train Batch Size:  {batch_size}")
    print(f"Per-device Eval Batch Size:   {eval_batch_size}")
    print(f"Gradient Accumulation Steps:  {gradient_accumulation_steps}")
    print(f"Effective Training Batch Size:{effective_batch_size}")
    print(f"Epochs:                       {epochs}")
    print(f"Base Learning Rate:           {lr}")
    print(f"Weight Decay:                 {weight_decay}")
    print(f"Max Sequence Length:          {max_length}")
    print(f"Total Optimizer Update Steps: {max_train_steps}")
    print(f"Warmup Steps (10%):           {warmup_steps}")
    print(f"Mixed Precision (AMP FP16):   Enabled (RTX 3050 Tensor Cores)")
    print(f"Gradient Clipping (max_norm): 1.0")
    print(f"Early Stopping Patience:      {patience} epochs (monitored metric: validation loss)")

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=max_train_steps
    )
    scaler = torch.amp.GradScaler('cuda')

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # 6. Training Loop
    print("\n--- 5. COMMENCING MODEL TRAINING ---")
    training_history = []
    best_val_loss = float("inf")
    best_epoch = -1
    best_metrics = None
    patience_counter = 0

    torch.cuda.empty_cache()
    torch.cuda.reset_peak_memory_stats()
    train_start_time = time.time()

    for epoch in range(1, epochs + 1):
        epoch_start_time = time.time()
        model.train()
        running_train_loss = 0.0
        optimizer.zero_grad()

        print(f"\n[Epoch {epoch}/{epochs}] Training...")
        step_in_epoch = 0

        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            with torch.amp.autocast('cuda'):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                # Normalize loss for gradient accumulation
                loss_scaled = loss / gradient_accumulation_steps

            scaler.scale(loss_scaled).backward()
            running_train_loss += loss.item() * len(labels)

            if (step + 1) % gradient_accumulation_steps == 0 or (step + 1) == len(train_loader):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad()
                step_in_epoch += 1

            if (step + 1) % 200 == 0 or (step + 1) == len(train_loader):
                current_lr = scheduler.get_last_lr()[0]
                allocated_mb = torch.cuda.memory_allocated(device) / (1024**2)
                print(
                    f"  Step {step+1:4d}/{len(train_loader):4d} | "
                    f"Avg Step Loss: {loss.item():.4f} | "
                    f"LR: {current_lr:.2e} | "
                    f"VRAM: {allocated_mb:.1f} MB"
                )

        epoch_train_loss = running_train_loss / len(train_loader.dataset)
        epoch_train_duration = time.time() - epoch_start_time

        # Validation evaluation
        print(f"[Epoch {epoch}/{epochs}] Evaluating on validation.csv...")
        val_start_time = time.time()
        val_metrics = evaluate(model, val_loader, device)
        val_duration = time.time() - val_start_time

        val_loss = val_metrics["loss"]
        val_acc = val_metrics["accuracy"]
        val_prec = val_metrics["precision"]
        val_rec = val_metrics["recall"]
        val_f1 = val_metrics["f1"]
        val_auc = val_metrics["roc_auc"]

        print(
            f"--> Epoch {epoch} Results:\n"
            f"    Train Loss:     {epoch_train_loss:.4f}\n"
            f"    Val Loss:       {val_loss:.4f}\n"
            f"    Val Accuracy:   {val_acc*100:.2f}%\n"
            f"    Val Precision:  {val_prec*100:.2f}%\n"
            f"    Val Recall:     {val_rec*100:.2f}%\n"
            f"    Val F1-Score:   {val_f1*100:.2f}%\n"
            f"    Val ROC-AUC:    {val_auc:.4f}\n"
            f"    Confusion Mat:  {val_metrics['confusion_matrix']} [ [TN={val_metrics['tn']}, FP={val_metrics['fp']}], [FN={val_metrics['fn']}, TP={val_metrics['tp']}] ]\n"
            f"    Epoch Duration: {epoch_train_duration:.1f}s train, {val_duration:.1f}s eval"
        )

        epoch_record = {
            "epoch": epoch,
            "train_loss": float(epoch_train_loss),
            "val_loss": float(val_loss),
            "val_accuracy": float(val_acc),
            "val_precision": float(val_prec),
            "val_recall": float(val_rec),
            "val_f1": float(val_f1),
            "val_roc_auc": float(val_auc),
            "confusion_matrix": val_metrics["confusion_matrix"],
            "tp": val_metrics["tp"],
            "tn": val_metrics["tn"],
            "fp": val_metrics["fp"],
            "fn": val_metrics["fn"],
            "learning_rate": float(scheduler.get_last_lr()[0]),
            "train_duration_sec": round(epoch_train_duration, 2),
            "val_duration_sec": round(val_duration, 2)
        }
        training_history.append(epoch_record)

        # Checkpoint selection based on validation loss
        if val_loss < best_val_loss:
            print(f"  *** Val loss improved from {best_val_loss:.4f} to {val_loss:.4f}. Saving best checkpoint to {output_dir} ***")
            best_val_loss = val_loss
            best_epoch = epoch
            best_metrics = val_metrics

            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)
            patience_counter = 0
        else:
            patience_counter += 1
            print(f"  Notice: Val loss did not improve ({val_loss:.4f} >= {best_val_loss:.4f}). Patience: {patience_counter}/{patience}")
            if patience_counter >= patience:
                print(f"  Early stopping triggered at epoch {epoch} (patience reached).")
                break

    total_training_duration = time.time() - train_start_time
    peak_vram_mb = torch.cuda.max_memory_allocated(device) / (1024**2)

    print("\n" + "=" * 70)
    print("TRAINING RUN COMPLETE")
    print("=" * 70)
    print(f"Total Training Duration:  {total_training_duration:.2f} seconds ({total_training_duration/60:.2f} minutes)")
    print(f"Peak GPU VRAM Allocated:  {peak_vram_mb:.2f} MB ({peak_vram_mb/1024:.2f} GB)")
    print(f"Best Validation Epoch:    {best_epoch}")
    print(f"Best Validation Loss:     {best_val_loss:.4f}")
    print(f"Best Validation F1-Score: {best_metrics['f1']*100:.2f}%")
    print(f"Best Validation ROC-AUC:  {best_metrics['roc_auc']:.4f}")
    print(f"Model Checkpoint Path:    {output_dir}")

    # 7. Save outputs
    print("\n--- 6. SAVING TRAINING ARTIFACTS ---")
    # Training configuration
    config_dict = {
        "model_name": model_name,
        "max_length": max_length,
        "per_device_train_batch_size": batch_size,
        "per_device_eval_batch_size": eval_batch_size,
        "gradient_accumulation_steps": gradient_accumulation_steps,
        "effective_batch_size": effective_batch_size,
        "epochs": epochs,
        "learning_rate": lr,
        "weight_decay": weight_decay,
        "warmup_steps": warmup_steps,
        "seed": seed,
        "mixed_precision": "fp16",
        "checkpoint_selection_metric": "validation_loss",
        "early_stopping_patience": patience,
        "gradient_clipping_max_norm": 1.0,
        "device": device_name,
        "total_vram_gb": vram_gb
    }
    with open(os.path.join(output_dir, "training_config.json"), "w", encoding="utf-8") as f:
        json.dump(config_dict, f, indent=2)

    # Training history JSON & CSV
    with open(os.path.join(output_dir, "training_history.json"), "w", encoding="utf-8") as f:
        json.dump(training_history, f, indent=2)

    pd.DataFrame(training_history).to_csv(os.path.join(output_dir, "training_history.csv"), index=False)

    # Package versions
    import transformers
    import tokenizers
    pkg_versions = {
        "python": sys.version.split()[0],
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "transformers": transformers.__version__,
        "tokenizers": tokenizers.__version__,
        "pandas": pd.__version__,
        "numpy": np.__version__
    }

    # Run Manifest
    manifest = {
        "model_identifier": model_name,
        "checkpoint_directory": os.path.abspath(output_dir),
        "seed": seed,
        "hardware": {
            "device": device_name,
            "vram_gb": vram_gb,
            "peak_vram_allocated_mb": round(peak_vram_mb, 2)
        },
        "software_environment": pkg_versions,
        "dataset_hashes": verified_hashes,
        "dataset_split_sizes": {
            "train": len(train_df),
            "validation": len(val_df),
            "test": EXPECTED_HASHES["test"]["rows"]
        },
        "class_distribution_train": {
            "phishing": train_phish,
            "benign": train_benign,
            "phishing_ratio": round(train_phish / len(train_df), 4)
        },
        "hyperparameters": config_dict,
        "training_execution": {
            "total_duration_sec": round(total_training_duration, 2),
            "total_epochs_trained": len(training_history),
            "best_epoch": best_epoch,
            "best_validation_loss": float(best_val_loss),
            "checkpoint_selection_metric": "min(validation_loss)",
            "test_set_evaluated": False,
            "test_set_access_during_training": False
        },
        "best_validation_metrics": best_metrics
    }
    with open(os.path.join(output_dir, "run_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("Saved training artifacts:")
    print(f"  - {os.path.join(output_dir, 'training_config.json')}")
    print(f"  - {os.path.join(output_dir, 'training_history.json')}")
    print(f"  - {os.path.join(output_dir, 'training_history.csv')}")
    print(f"  - {os.path.join(output_dir, 'run_manifest.json')}")
    print(f"  - {output_dir}/ (model weights & tokenizer files)")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="PhishIntel Phase 3B DistilBERT Baseline Training")
    parser.add_argument("--batch-size", type=int, default=4, help="Per-device training batch size")
    parser.add_argument("--eval-batch-size", type=int, default=4, help="Per-device evaluation batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    parser.add_argument("--epochs", type=int, default=3, help="Maximum epochs")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--weight-decay", type=float, default=0.01, help="Weight decay")
    parser.add_argument("--max-length", type=int, default=256, help="Maximum sequence length")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output-dir", type=str, default="models/distilbert_baseline", help="Output directory")
    parser.add_argument("--enable-gradient-checkpointing", action="store_true", help="Enable gradient checkpointing")
    args = parser.parse_args()

    # Attempt primary training run
    try:
        manifest = train_distilbert(
            output_dir=args.output_dir,
            batch_size=args.batch_size,
            eval_batch_size=args.eval_batch_size,
            gradient_accumulation_steps=args.grad_accum,
            epochs=args.epochs,
            lr=args.lr,
            weight_decay=args.weight_decay,
            max_length=args.max_length,
            seed=args.seed,
            enable_gradient_checkpointing=args.enable_gradient_checkpointing
        )
        print("\nSTATUS: PHASE_3B_TRAINING_COMPLETE")
    except torch.cuda.OutOfMemoryError as oom_err:
        print(f"\n[CUDA OOM WARNING] GPU ran out of memory with batch_size={args.batch_size}.")
        print("Executing controlled single retry: batch_size=2, grad_accum=8 (effective batch size 16 preserved)...")
        torch.cuda.empty_cache()
        try:
            manifest = train_distilbert(
                output_dir=args.output_dir,
                batch_size=2,
                eval_batch_size=2,
                gradient_accumulation_steps=8,
                epochs=args.epochs,
                lr=args.lr,
                weight_decay=args.weight_decay,
                max_length=args.max_length,
                seed=args.seed,
                enable_gradient_checkpointing=True
            )
            print("\nSTATUS: PHASE_3B_TRAINING_COMPLETE (completed via OOM fallback: batch_size=2, grad_accum=8)")
        except Exception as retry_err:
            print(f"\nFATAL: OOM retry also failed: {retry_err}")
            print("STATUS: BLOCKED — ACTION REQUIRED")
            sys.exit(1)
    except Exception as e:
        print(f"\nFATAL ERROR during Phase 3B training: {e}")
        import traceback
        traceback.print_exc()
        print("STATUS: BLOCKED — ACTION REQUIRED")
        sys.exit(1)


if __name__ == "__main__":
    main()
