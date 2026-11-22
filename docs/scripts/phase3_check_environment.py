"""
PhishIntel - Phase 3A Environment & Diagnostic Verification Script
Read-only diagnostic inspection and smoke-test script.
Does NOT train any models, does NOT modify datasets.
"""

import sys
import subprocess
import os
import hashlib
import json
import argparse

def get_hash(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def check_package(pkg_name):
    try:
        mod = __import__(pkg_name)
        return getattr(mod, "__version__", "installed")
    except Exception as e:
        return f"UNAVAILABLE ({type(e).__name__})"

def run_smoke_test(device_str="cuda:0"):
    print("\n--- SYNTHETIC FORWARD-PASS SMOKE TEST ---")
    try:
        import torch
        from transformers import AutoTokenizer, AutoConfig, AutoModelForSequenceClassification

        model_name = "distilbert-base-uncased"
        print(f"Loading local tokenizer for {model_name}...")
        tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)

        print(f"Loading local config for {model_name}...")
        config = AutoConfig.from_pretrained(model_name, num_labels=2, local_files_only=True)

        device = torch.device(device_str if (torch.cuda.is_available() and "cuda" in device_str) else "cpu")
        print(f"Smoke test execution device: {device}")

        if device.type == "cuda":
            torch.cuda.empty_cache()
            torch.cuda.reset_peak_memory_stats()
            mem_before = torch.cuda.memory_allocated(device) / (1024**2)
            res_before = torch.cuda.memory_reserved(device) / (1024**2)
            print(f"GPU Memory Before Model Load: Allocated = {mem_before:.2f} MB, Reserved = {res_before:.2f} MB")

        print(f"Loading model weights into {device}...")
        model = AutoModelForSequenceClassification.from_pretrained(model_name, config=config, local_files_only=True)
        model = model.to(device)
        model.eval()

        if device.type == "cuda":
            mem_loaded = torch.cuda.memory_allocated(device) / (1024**2)
            res_loaded = torch.cuda.memory_reserved(device) / (1024**2)
            print(f"GPU Memory After Model Load:  Allocated = {mem_loaded:.2f} MB, Reserved = {res_loaded:.2f} MB")

        synthetic_text = "This is a synthetic test message for environment verification."
        inputs = tokenizer(synthetic_text, return_tensors="pt")
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        probs = torch.softmax(logits, dim=-1)

        print(f"Input text:            '{synthetic_text}'")
        print(f"Token IDs shape:       {tuple(inputs['input_ids'].shape)}")
        print(f"Output logits shape:   {tuple(logits.shape)}")
        print(f"Output logits:         {logits.cpu().numpy().tolist()}")
        print(f"Softmax probabilities: {probs.cpu().numpy().tolist()}")

        if device.type == "cuda":
            mem_after = torch.cuda.memory_allocated(device) / (1024**2)
            res_after = torch.cuda.memory_reserved(device) / (1024**2)
            peak_mem = torch.cuda.max_memory_allocated(device) / (1024**2)
            print(f"GPU Memory After Test:        Allocated = {mem_after:.2f} MB, Reserved = {res_after:.2f} MB")
            print(f"Peak GPU Memory Allocated:    {peak_mem:.2f} MB")

        print("Smoke test status:     PASS (forward pass succeeded)")
        return True, None
    except Exception as e:
        print(f"Smoke test status:     FAIL ({e})")
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description="PhishIntel Phase 3A Environment Diagnostic")
    parser.add_argument("--smoke-test", action="store_true", default=True, help="Run synthetic forward-pass smoke test")
    parser.add_argument("--skip-smoke-test", action="store_true", help="Skip synthetic forward-pass smoke test")
    args = parser.parse_args()

    print("=" * 60)
    print("PhishIntel — Phase 3A Environment Diagnostic")
    print("=" * 60)

    # 1. Python Environment
    print("\n1. PYTHON & PIP")
    print(f"Python Executable: {sys.executable}")
    print(f"Python Version:    {sys.version.split()[0]}")
    try:
        import pip
        print(f"Pip Version:       {pip.__version__}")
    except Exception:
        print("Pip Version:       Unavailable")

    # 2. PyTorch & CUDA
    print("\n2. PYTORCH & ACCELERATION")
    torch_version = check_package("torch")
    print(f"PyTorch Version:   {torch_version}")
    
    cuda_available = False
    device_name = "N/A"
    total_mem_gb = "N/A"
    cuda_version = "N/A"

    if torch_version != "NOT INSTALLED":
        import torch
        cuda_available = torch.cuda.is_available()
        print(f"PyTorch CUDA Available: {cuda_available}")
        if cuda_available:
            cuda_version = torch.version.cuda
            device_name = torch.cuda.get_device_name(0)
            props = torch.cuda.get_device_properties(0)
            total_mem_gb = round(props.total_memory / (1024**3), 2)
            print(f"Torch CUDA Version:     {cuda_version}")
            print(f"Active Device Name:     {device_name}")
            print(f"Device VRAM (GB):       {total_mem_gb} GB")
        else:
            print("Notice: Current PyTorch build is CPU-only (+cpu).")

    # 3. System GPU (NVIDIA-SMI fallback inspection)
    print("\n3. HARDWARE GPU INSPECTION (NVIDIA-SMI)")
    try:
        smi_out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"],
            text=True
        ).strip()
        print(f"System GPU Hardware:    {smi_out}")
    except Exception as e:
        print(f"System GPU Hardware:    Could not query nvidia-smi ({e})")

    # 4. Transformers Ecosystem
    print("\n4. TRANSFORMERS ECOSYSTEM PACKAGES")
    packages = [
        "transformers",
        "tokenizers",
        "datasets",
        "accelerate",
        "scikit-learn",
        "pandas",
        "numpy"
    ]
    pkg_status = {}
    for p in packages:
        mod_key = "sklearn" if p == "scikit-learn" else p
        ver = check_package(mod_key)
        pkg_status[p] = ver
        print(f"  - {p:15}: {ver}")

    # 5. DistilBERT Model Cache Status
    print("\n5. PRETRAINED MODEL CACHE STATUS")
    model_name = "distilbert-base-uncased"
    hf_hub_cache = os.path.expanduser(r"~/.cache/huggingface/hub/models--distilbert-base-uncased")
    
    tokenizer_cached = False
    config_cached = False
    weights_cached = False

    if os.path.exists(hf_hub_cache):
        cached_files = []
        for root, dirs, files in os.walk(hf_hub_cache):
            for f in files:
                cached_files.append(f)
        
        if "tokenizer.json" in cached_files or "vocab.txt" in cached_files:
            tokenizer_cached = True
        if "config.json" in cached_files:
            config_cached = True
        if "model.safetensors" in cached_files or "pytorch_model.bin" in cached_files:
            weights_cached = True

    print(f"Target Model:            {model_name}")
    print(f"Cache Directory Exists:  {os.path.exists(hf_hub_cache)}")
    print(f"Tokenizer Cached:        {tokenizer_cached}")
    print(f"Model Config Cached:     {config_cached}")
    print(f"Model Weights Cached:    {weights_cached}")

    # 6. Dataset Split Verification
    print("\n6. DATASET SPLIT VERIFICATION")
    splits = {
        "train.csv": {
            "path": r"data/processed/phishmmf/train.csv",
            "expected_rows": 5791,
            "expected_phish": 1024,
            "expected_benign": 4767,
            "expected_sha256": "72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c"
        },
        "validation.csv": {
            "path": r"data/processed/phishmmf/validation.csv",
            "expected_rows": 724,
            "expected_phish": 128,
            "expected_benign": 596,
            "expected_sha256": "40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab"
        },
        "test.csv": {
            "path": r"data/processed/phishmmf/test.csv",
            "expected_rows": 724,
            "expected_phish": 128,
            "expected_benign": 596,
            "expected_sha256": "1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e"
        }
    }

    import pandas as pd
    all_dataset_pass = True
    for name, meta in splits.items():
        p = meta["path"]
        exists = os.path.exists(p)
        if not exists:
            print(f"  [FAIL] {name}: File not found at {p}")
            all_dataset_pass = False
            continue
        
        df_split = pd.read_csv(p)
        actual_rows = len(df_split)
        actual_phish = int((df_split["label"] == 1).sum())
        actual_benign = int((df_split["label"] == 0).sum())
        actual_sha = get_hash(p)

        rows_match = actual_rows == meta["expected_rows"]
        labels_match = (actual_phish == meta["expected_phish"]) and (actual_benign == meta["expected_benign"])
        sha_match = actual_sha == meta["expected_sha256"]

        status = "PASS" if (rows_match and labels_match and sha_match) else "FAIL"
        if status == "FAIL":
            all_dataset_pass = False

        print(f"  [{status}] {name}:")
        print(f"         Rows:   {actual_rows} (Expected: {meta['expected_rows']})")
        print(f"         Labels: {actual_phish} phish / {actual_benign} benign")
        print(f"         SHA:    {actual_sha}")

    # 7. Smoke Test Execution
    smoke_test_pass = True
    if not args.skip_smoke_test and weights_cached:
        smoke_test_pass, smoke_err = run_smoke_test("cuda:0" if cuda_available else "cpu")
    elif not weights_cached:
        print("\nNotice: Model weights are not cached locally; skipping smoke test.")
        smoke_test_pass = False

    # 8. Overall Readiness Status
    print("\n" + "=" * 60)
    print("PHASE 3A READINESS EVALUATION")
    print("=" * 60)
    
    blockers = []
    if not weights_cached:
        blockers.append("DistilBERT model weights (~268MB safetensors) are not cached locally.")
    if not cuda_available:
        blockers.append("Current PyTorch build is CPU-only. CUDA acceleration on the RTX 3050 6GB requires CUDA torch.")
    if not all_dataset_pass:
        blockers.append("One or more Phase 2C dataset files fail integrity or hash verification.")
    if not smoke_test_pass:
        blockers.append("Synthetic forward-pass smoke test failed or could not execute.")

    if blockers:
        print("STATUS: BLOCKED — ACTION REQUIRED")
        print("\nIdentified Blockers / Required Approvals:")
        for b in blockers:
            print(f"  - {b}")
    else:
        print("STATUS: READY_FOR_PHASE_3B")

if __name__ == "__main__":
    main()
