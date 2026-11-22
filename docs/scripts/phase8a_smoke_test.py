"""
Phase 8A Real Checkpoint Smoke Test and Protected Hash Verification Script.
PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence.
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import torch
from app.services.email_parser import parse_email_message
from app.services.model_inference import DEFAULT_CHECKPOINT_DIR, get_model_inference_engine

PROTECTED_HASHES = {
    "train.csv": {
        "path": "data/processed/phishmmf/train.csv",
        "expected": "72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c",
    },
    "validation.csv": {
        "path": "data/processed/phishmmf/validation.csv",
        "expected": "40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab",
    },
    "test.csv": {
        "path": "data/processed/phishmmf/test.csv",
        "expected": "1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e",
    },
    "model.safetensors": {
        "path": "models/distilbert_baseline/model.safetensors",
        "expected": "fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8",
    },
}


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    print("=" * 80)
    print("PHISHINTEL — PHASE 8A REAL CHECKPOINT SMOKE TEST & HASH AUDIT")
    print("=" * 80)

    # 1. Cryptographic Verification of Protected Artifacts
    print("\n--- 1. PROTECTED ARTIFACT HASH VERIFICATION ---")
    all_hashes_valid = True
    for name, info in PROTECTED_HASHES.items():
        p = info["path"]
        if not os.path.exists(p):
            print(f"  [FAIL] Missing file: {p}")
            all_hashes_valid = False
            continue
        actual = compute_sha256(p)
        expected = info["expected"]
        if actual == expected:
            print(f"  [PASS] {name}: {actual}")
        else:
            print(f"  [MISMATCH] {name}:")
            print(f"    Expected: {expected}")
            print(f"    Actual:   {actual}")
            all_hashes_valid = False

    if not all_hashes_valid:
        print("FATAL: Protected artifact hash verification failed! Halting.")
        sys.exit(1)

    # 2. Hardware and Checkpoint Inspection
    print("\n--- 2. HARDWARE & CHECKPOINT STATUS ---")
    cuda_available = torch.cuda.is_available()
    device_name = torch.cuda.get_device_name(0) if cuda_available else "CPU"
    print(f"CUDA Available:     {cuda_available}")
    print(f"Execution Device:   {device_name}")
    print(f"Checkpoint Dir:     {DEFAULT_CHECKPOINT_DIR}")
    print(f"Checkpoint Weights: {DEFAULT_CHECKPOINT_DIR / 'model.safetensors'}")

    # 3. Model Engine Loading
    print("\n--- 3. MODEL INFERENCE ENGINE INITIALIZATION ---")
    start_init = time.time()
    engine = get_model_inference_engine()
    engine.load_model()
    init_duration = time.time() - start_init
    print(f"Model initialized in {init_duration:.3f}s on device: {engine.device}")
    print(f"Model loaded: {engine._model is not None}, Tokenizer loaded: {engine._tokenizer is not None}")

    # 4. Standalone Synthetic Inferences
    print("\n--- 4. SYNTHETIC EMAIL INFERENCE CHECKS ---")
    samples = [
        {
            "name": "Synthetic Phishing Lure",
            "subject": "Urgent: Verify your credentials now",
            "body": "Your account has been compromised. Log in immediately at our portal to prevent permanent suspension.",
        },
        {
            "name": "Synthetic Benign Internal Message",
            "subject": "Team standup notes - Tuesday",
            "body": "Good morning team, attached are the action items from our sprint planning session yesterday.",
        },
        {
            "name": "Synthetic Missing Subject Message",
            "subject": None,
            "body": "Please click here to update your security settings before end of day.",
        },
    ]

    for s in samples:
        t0 = time.time()
        res = engine.predict(subject=s["subject"], body=s["body"])
        dt = (time.time() - t0) * 1000
        print(f"\n  Sample: {s['name']}")
        print(f"    Subject:          {s['subject']!r}")
        print(f"    Status:           {res.status}")
        print(f"    Uncalibrated:     {res.uncalibrated_score:.5f}")
        print(f"    Predicted Label:  {res.predicted_label} ({'Phishing' if res.predicted_label == 1 else 'Benign'})")
        print(f"    Inference Latency:{dt:.2f} ms")

    # 5. Full End-to-End Pipeline Smoke Test
    print("\n--- 5. FULL END-TO-END PIPELINE AUDIT (.eml -> Parser -> Model -> Fusion) ---")
    test_eml = (
        b"From: security-notice@portal-access-check.org\n"
        b"To: analyst@phishintel.internal\n"
        b"Subject: Critical: Security Certificate Update Required\n"
        b"Received: from [198.51.100.99] by mx.phishintel.internal; Sun, 11 Oct 2026 15:30:00 +0000\n"
        b"Authentication-Results: mx.phishintel.internal; spf=fail smtp.mailfrom=portal-access-check.org\n"
        b"Content-Type: text/html\n\n"
        b"<html><body>"
        b"<p>Your security certificate expired. Please <a href=\"http://198.51.100.99/renew\">renew here</a>.</p>"
        b"</body></html>"
    )

    t_pipe_0 = time.time()
    analysis = parse_email_message(test_eml, "phase8a_smoke_test.eml")
    pipe_dt = (time.time() - t_pipe_0) * 1000

    print(f"Pipeline executed in {pipe_dt:.2f} ms")
    print(f"Filename:               {analysis.filename}")
    print(f"Parsing Status:         {analysis.parsing_status}")
    print(f"Warnings:               {analysis.warnings}")

    print("\nExtracted Components:")
    print(f"  Subject:              {analysis.headers.subject}")
    print(f"  Body (HTML extracted):{analysis.body.html_extracted_text!r}")
    print(f"  URLs Extracted:       {len(analysis.urls)}")
    print(f"  IP Candidates:        {len(analysis.ip_candidates)}")

    print("\nDirect Model Evidence:")
    print(f"  Status:               {analysis.model_inference.status}")
    print(f"  Uncalibrated Score:   {analysis.model_inference.uncalibrated_score:.5f}")
    print(f"  Predicted Label:      {analysis.model_inference.predicted_label}")

    print("\nEvidence Fusion Synthesized Assessment:")
    fusion = analysis.evidence_fusion
    print(f"  Overall Category:     {fusion.overall_category}")
    print(f"  Fusion Model Status:  {fusion.model_evidence.status}")
    print(f"  Fusion Model Score:   {fusion.model_evidence.uncalibrated_score:.5f}")
    print(f"  Fusion Model Label:   {fusion.model_evidence.predicted_label}")
    print(f"  Model Interpretation: {fusion.model_evidence.interpretation}")
    print(f"  Model Caveat:         {fusion.model_evidence.caveat[:80]}...")
    print(f"  Contributing Factors: {fusion.contributing_factors}")
    print(f"  Reasoning:            {fusion.reasoning}")

    # 6. Phase 8A.1 Forensic Accuracy Audit Verification
    print("\n--- 6. PHASE 8A.1 FORENSIC ACCURACY AUDIT ---")
    from app.services.ip_intelligence import classify_ip_string
    from app.services.url_intelligence import is_valid_ipv4_or_ipv6, analyze_url
    from app.schemas.ip_intelligence import IPClassification
    from app.schemas.url_intelligence import HostClassification

    # Check 1: 198.51.100.99 classification
    ip_cls, _ = classify_ip_string("198.51.100.99")
    _, _, url_cls = is_valid_ipv4_or_ipv6("198.51.100.99")
    url_res = analyze_url("http://198.51.100.99/renew")
    rules_fired = [o.rule_id for o in url_res.observations]

    print(f"  IP Intelligence 198.51.100.99:  {ip_cls} (Expected: Documentation)")
    print(f"  URL Intelligence 198.51.100.99: {url_cls} (Expected: Reserved)")
    print(f"  URL Rules for 198.51.100.99:    {rules_fired}")
    assert ip_cls == IPClassification.DOCUMENTATION, "Mismatch on IP intelligence documentation classification"
    assert url_cls == HostClassification.RESERVED, "Mismatch on URL intelligence reserved classification"
    assert "RULE_RESERVED_IP_HOST" in rules_fired, "RULE_RESERVED_IP_HOST should fire for documentation/reserved IP"
    assert "RULE_PRIVATE_IP_HOST" not in rules_fired, "RULE_PRIVATE_IP_HOST must NOT fire for documentation IP"
    print("  [PASS] 198.51.100.99 correctly preserved as Documentation/Reserved (RFC 5737 TEST-NET-2).")

    # Check 2: Genuine RFC 1918 Private IP
    _, _, priv_cls = is_valid_ipv4_or_ipv6("192.168.1.100")
    priv_url_res = analyze_url("http://192.168.1.100/admin")
    priv_rules = [o.rule_id for o in priv_url_res.observations]
    assert priv_cls == HostClassification.PRIVATE
    assert "RULE_PRIVATE_IP_HOST" in priv_rules
    print("  [PASS] 192.168.1.100 correctly classified as Private (RFC 1918).")

    # Check 3: Wording verification
    assert "confidence score" not in fusion.model_evidence.interpretation.lower()
    assert "uncalibrated phishing score" in fusion.model_evidence.interpretation.lower()
    print("  [PASS] Model evidence interpretation verified: 'uncalibrated phishing score' used, 'confidence score' eliminated.")

    print("\n=" * 80)
    print("STATUS: PHASE_8A1_VERIFIED")
    print("=" * 80)


if __name__ == "__main__":
    main()
