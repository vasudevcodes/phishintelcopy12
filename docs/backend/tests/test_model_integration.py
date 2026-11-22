"""
Comprehensive Integration Tests for DistilBERT Model Integration (Phase 8A).
Verifies:
1. API calls the local model inference service.
2. Extracted subject and body reach preprocessing correctly (subject + "\\n\\n" + body).
3. Inference output is passed into evidence fusion and reflected in model_evidence.
4. Missing subject and missing body handling works defensively.
5. Truncation to 256 tokens functions properly on long texts.
6. Missing model checkpoint produces an explicit UNAVAILABLE status.
7. Model exceptions produce an explicit ERROR status and NEVER result in an automatic benign verdict.
8. URL, authentication, and IP analysis co-exist with model evidence in the API response.
9. Zero network requests occur (strictly offline execution).
10. Real local checkpoint smoke test on synthetic email (distinguished from mocks).
"""

import io
from pathlib import Path
import socket
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest
import torch

from app.main import app
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.services.evidence_fusion import fuse_evidence
from app.services.model_inference import (
    DEFAULT_CHECKPOINT_DIR,
    ModelInferenceEngine,
    run_model_inference,
)

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces strict zero network access during model integration tests.
    Outbound socket connections and non-local DNS resolutions raise RuntimeError.
    """
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def fail_connect(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"Network connect attempted during test: {addr}")
        return orig_connect(self, addr)

    def fail_dns(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver", None, ""):
            raise RuntimeError(f"DNS resolution attempted during test: {host}")
        return orig_getaddrinfo(host, *args, **kwargs)

    def fail_gethostbyname(host):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise RuntimeError(f"DNS resolution attempted during test: {host}")
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(socket, "gethostbyname", fail_gethostbyname)


# ---------------------------------------------------------------------------
# 1. Deterministic Mocked Integration Tests
# ---------------------------------------------------------------------------

def test_api_calls_local_model_inference_mocked():
    """
    Proves that POST /api/v1/email/analyze invokes the model inference service,
    extracts the correct text, and passes output into evidence fusion.
    """
    mock_inference_output = ModelInferenceEvidence(
        uncalibrated_score=0.942,
        predicted_label=1,
        status=ModelInferenceStatus.EVALUATED,
        error_message=None,
    )

    with patch("app.services.email_parser.run_model_inference", return_value=mock_inference_output) as mock_inf:
        eml_bytes = (
            b"From: security@paypal-verify.com\n"
            b"To: victim@target.com\n"
            b"Subject: Urgent Account Verification\n"
            b"Content-Type: text/plain\n\n"
            b"Please update your login information immediately.\n"
        )
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("urgent_verify.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

        assert response.status_code == 200
        data = response.json()

        # Verify mock inference called with extracted subject and plain text body
        mock_inf.assert_called_once()
        call_kwargs = mock_inf.call_args[1]
        assert call_kwargs["subject"] == "Urgent Account Verification"
        assert "Please update your login information immediately." in call_kwargs["body"]

        # Verify direct model_inference in response
        assert "model_inference" in data
        assert data["model_inference"]["status"] == "EVALUATED"
        assert abs(data["model_inference"]["uncalibrated_score"] - 0.942) < 1e-4
        assert data["model_inference"]["predicted_label"] == 1

        # Verify inference output passed into evidence_fusion.model_evidence
        fusion = data["evidence_fusion"]
        assert fusion is not None
        assert fusion["model_evidence"]["status"] == "EVALUATED"
        assert abs(fusion["model_evidence"]["uncalibrated_score"] - 0.942) < 1e-4
        assert fusion["model_evidence"]["predicted_label"] == 1
        assert "phishing" in fusion["model_evidence"]["interpretation"].lower()
        # Verify caveat exists
        assert "uncalibrated DistilBERT output" in fusion["model_evidence"]["caveat"]


def test_preprocessing_subject_and_body_construction():
    """
    Proves that input text construction strictly follows training:
    subject + "\n\n" + body
    """
    engine = ModelInferenceEngine()
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }
    mock_model = MagicMock()
    mock_outputs = MagicMock()
    mock_outputs.logits = torch.tensor([[2.5, -2.5]])  # benign prediction
    mock_model.return_value = mock_outputs

    engine._initialized = True
    engine._tokenizer = mock_tokenizer
    engine._model = mock_model
    engine._device = torch.device("cpu")

    result = engine.predict(subject="System Alert", body="Maintenance scheduled.")
    assert result.status == ModelInferenceStatus.EVALUATED
    assert result.predicted_label == 0

    # Verify input text passed to tokenizer
    called_text = mock_tokenizer.call_args[0][0]
    assert called_text == "System Alert\n\nMaintenance scheduled."
    assert mock_tokenizer.call_args[1]["max_length"] == 256
    assert mock_tokenizer.call_args[1]["truncation"] is True


def test_missing_subject_handling():
    """
    Proves that emails with missing or null Subject header are handled safely
    by constructing "\n\n" + body without throwing an exception.
    """
    engine = ModelInferenceEngine()
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }
    mock_model = MagicMock()
    mock_outputs = MagicMock()
    mock_outputs.logits = torch.tensor([[-3.0, 3.0]])  # phishing prediction
    mock_model.return_value = mock_outputs

    engine._initialized = True
    engine._tokenizer = mock_tokenizer
    engine._model = mock_model
    engine._device = torch.device("cpu")

    result = engine.predict(subject=None, body="Click here to claim prize")
    assert result.status == ModelInferenceStatus.EVALUATED
    assert result.predicted_label == 1

    called_text = mock_tokenizer.call_args[0][0]
    assert called_text == "\n\nClick here to claim prize"


def test_missing_body_handling():
    """
    Proves that emails with an empty or null body are handled defensively.
    """
    engine = ModelInferenceEngine()
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }
    mock_model = MagicMock()
    mock_outputs = MagicMock()
    mock_outputs.logits = torch.tensor([[1.0, 1.0]])
    mock_model.return_value = mock_outputs

    engine._initialized = True
    engine._tokenizer = mock_tokenizer
    engine._model = mock_model
    engine._device = torch.device("cpu")

    result = engine.predict(subject="Subject Only", body=None)
    assert result.status == ModelInferenceStatus.EVALUATED

    called_text = mock_tokenizer.call_args[0][0]
    assert called_text == "Subject Only\n\n"


def test_missing_checkpoint_produces_explicit_unavailable_status():
    """
    Proves that a non-existent model checkpoint directory returns an explicit
    UNAVAILABLE status rather than crashing or inventing benign results.
    """
    non_existent_dir = "C:/tmp_non_existent_checkpoint_path_12345"
    engine = ModelInferenceEngine(checkpoint_dir=non_existent_dir)

    assert engine.is_checkpoint_available() is False
    result = engine.predict(subject="Test", body="Hello")

    assert result.status == ModelInferenceStatus.UNAVAILABLE
    assert result.uncalibrated_score is None
    assert result.predicted_label is None
    assert result.error_message is not None
    assert "not found" in result.error_message.lower()


def test_model_exception_does_not_result_in_automatic_benign_verdict():
    """
    Proves that when model inference encounters a runtime exception (e.g. OOM or corrupt tensor):
    1. An explicit ERROR status is returned.
    2. uncalibrated_score is None.
    3. The evidence fusion layer does NOT categorize the email as LOW_RISK_INDICATORS (benign).
    """
    engine = ModelInferenceEngine()
    mock_tokenizer = MagicMock(side_effect=RuntimeError("Simulated tokenizer tensor failure"))

    engine._initialized = True
    engine._tokenizer = mock_tokenizer
    engine._model = MagicMock()
    engine._device = torch.device("cpu")

    error_result = engine.predict(subject="Important", body="Message")
    assert error_result.status == ModelInferenceStatus.ERROR
    assert error_result.uncalibrated_score is None
    assert error_result.predicted_label is None
    assert error_result.error_message is not None
    assert "Simulated tokenizer tensor failure" in error_result.error_message

    # Test fusion behavior with this error:
    # Even if authentication passed and URL heuristic was NONE,
    # the failure must NOT produce LOW_RISK_INDICATORS.
    from app.schemas.email_authentication import (
        AuthResultStatus,
        DKIMEvidence,
        DMARCEvidence,
        EmailAuthenticationAnalysis,
        OverallAuthStatus,
        SPFEvidence,
    )
    auth_pass = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.EVALUATED,
        spf=SPFEvidence(status=AuthResultStatus.PASS, explanation="SPF pass"),
        dkim=DKIMEvidence(status=AuthResultStatus.PASS, explanation="DKIM pass"),
        dmarc=DMARCEvidence(status=AuthResultStatus.PASS, explanation="DMARC pass"),
        has_conflicts=False,
    )

    fusion_res = fuse_evidence(
        authentication_analysis=auth_pass,
        model_inference=error_result,
    )

    assert fusion_res.model_evidence.status == ModelInferenceStatus.ERROR
    # Must NOT masquerade as benign:
    assert fusion_res.overall_category != AssessmentCategory.LOW_RISK_INDICATORS
    assert fusion_res.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert any("inference encountered an error" in f.lower() for f in fusion_res.inconclusive_or_missing_factors)


def test_url_auth_ip_and_model_coexist_in_api_response():
    """
    Proves that adding model inference does not break or omit URL,
    authentication, or IP intelligence components in the response.
    """
    mock_model_evidence = ModelInferenceEvidence(
        uncalibrated_score=0.88,
        predicted_label=1,
        status=ModelInferenceStatus.EVALUATED,
    )

    eml_sample = (
        b"From: notify@accounts.org\n"
        b"To: recipient@target.com\n"
        b"Subject: Account Audit Required\n"
        b"Received: from [198.51.100.25] by mx.target.com; Mon, 12 Oct 2026 12:00:00 +0000\n"
        b"Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=accounts.org; dkim=pass header.d=accounts.org\n"
        b"Content-Type: text/html\n\n"
        b'<p>Review statement: <a href="https://billing.accounts.org/review">Click here</a></p>\n'
    )

    with patch("app.services.email_parser.run_model_inference", return_value=mock_model_evidence):
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("full_evidence.eml", io.BytesIO(eml_sample), "message/rfc822")},
        )

        assert response.status_code == 200
        data = response.json()

        # 1. URL intelligence present
        assert data["url_analysis"] is not None
        assert data["url_analysis"]["total_urls"] == 1

        # 2. Authentication analysis present
        assert data["authentication_analysis"] is not None
        assert data["authentication_analysis"]["spf"]["status"] == "PASS"

        # 3. IP intelligence present
        assert data["ip_intelligence"] is not None
        assert data["ip_intelligence"]["total_candidates"] >= 1

        # 4. Model inference present
        assert data["model_inference"] is not None
        assert data["model_inference"]["status"] == "EVALUATED"
        assert abs(data["model_inference"]["uncalibrated_score"] - 0.88) < 1e-4

        # 5. Evidence fusion presents all four summaries
        fusion = data["evidence_fusion"]
        assert fusion is not None
        assert fusion["url_evidence"]["total_urls"] == 1
        assert fusion["auth_evidence"]["spf_status"] == "PASS"
        assert fusion["ip_evidence"]["hop_count"] >= 1
        assert fusion["model_evidence"]["status"] == "EVALUATED"


# ---------------------------------------------------------------------------
# 2. Real Checkpoint Smoke Tests (Clearly Distinguished from Mocks)
# ---------------------------------------------------------------------------

def test_real_checkpoint_smoke_test_cpu():
    """
    SMOKE TEST (REAL LOCAL CHECKPOINT - CPU FALLBACK):
    Loads the real saved checkpoint from models/distilbert_baseline onto CPU
    and executes inference on a synthetic test email.
    """
    checkpoint_dir = DEFAULT_CHECKPOINT_DIR
    if not checkpoint_dir.is_dir() or not (checkpoint_dir / "model.safetensors").is_file():
        pytest.skip("Local model checkpoint not found; skipping real checkpoint smoke test.")

    # Explicitly test CPU execution
    engine = ModelInferenceEngine(checkpoint_dir=str(checkpoint_dir), device="cpu")
    engine.load_model()

    assert engine.device.type == "cpu"
    assert engine._model is not None
    assert engine._tokenizer is not None

    # Synthetic phishing email
    phish_result = engine.predict(
        subject="Urgent Security Alert: Account Suspended",
        body="Your account access has been revoked. Click here immediately to verify credentials.",
    )
    assert phish_result.status == ModelInferenceStatus.EVALUATED
    assert phish_result.uncalibrated_score is not None
    assert 0.0 <= phish_result.uncalibrated_score <= 1.0
    assert phish_result.predicted_label in [0, 1]

    # Synthetic benign email
    benign_result = engine.predict(
        subject="Team lunch on Friday",
        body="Hi everyone, let's meet in the cafeteria for our quarterly project retrospective.",
    )
    assert benign_result.status == ModelInferenceStatus.EVALUATED
    assert benign_result.uncalibrated_score is not None
    assert 0.0 <= benign_result.uncalibrated_score <= 1.0
    assert benign_result.predicted_label in [0, 1]


def test_real_checkpoint_end_to_end_api_smoke():
    """
    SMOKE TEST (REAL LOCAL CHECKPOINT - END-TO-END VIA API):
    Uploads a synthetic email to POST /api/v1/email/analyze WITHOUT mocks.
    Demonstrates that the uploaded .eml passes through the real DistilBERT
    model and produces a model-backed result in evidence fusion.
    """
    checkpoint_dir = DEFAULT_CHECKPOINT_DIR
    if not checkpoint_dir.is_dir() or not (checkpoint_dir / "model.safetensors").is_file():
        pytest.skip("Local model checkpoint not found; skipping real checkpoint smoke test.")

    synthetic_eml = (
        b"From: billing@secure-services-alert.com\n"
        b"To: target-user@domain.com\n"
        b"Subject: Urgent: Invoice Past Due Notice\n"
        b"Received: from [198.51.100.77] by mx.domain.com; Sun, 11 Oct 2026 15:00:00 +0000\n"
        b"Content-Type: text/plain\n\n"
        b"Immediate action required. Your invoice is past due. Verify payment details immediately.\n"
    )

    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("real_model_smoke.eml", io.BytesIO(synthetic_eml), "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()

    # Verify model inference was executed by the real model
    assert data["model_inference"] is not None
    assert data["model_inference"]["status"] == "EVALUATED"
    assert data["model_inference"]["uncalibrated_score"] is not None
    assert 0.0 <= data["model_inference"]["uncalibrated_score"] <= 1.0
    assert data["model_inference"]["predicted_label"] in [0, 1]

    # Verify model evidence reached evidence fusion
    fusion = data["evidence_fusion"]
    assert fusion is not None
    assert fusion["model_evidence"]["status"] == "EVALUATED"
    assert fusion["model_evidence"]["uncalibrated_score"] == data["model_inference"]["uncalibrated_score"]
    assert fusion["model_evidence"]["predicted_label"] == data["model_inference"]["predicted_label"]
    assert "Score is an uncalibrated DistilBERT output" in fusion["model_evidence"]["caveat"]


# ---------------------------------------------------------------------------
# 3. Phase 8A.1 Forensic Accuracy Regression Tests
# ---------------------------------------------------------------------------

def test_documentation_ip_classification_distinction():
    """
    REGRESSION TEST (Phase 8A.1):
    Proves that 198.51.100.99 (TEST-NET-2, RFC 5737) is classified as RESERVED /
    DOCUMENTATION rather than RFC 1918 PRIVATE, preserving the four-way distinction
    between private, documentation, reserved, and public IP addresses.
    """
    from app.schemas.ip_intelligence import IPClassification
    from app.schemas.url_intelligence import HostClassification
    from app.services.ip_intelligence import classify_ip_string
    from app.services.url_intelligence import analyze_url, is_valid_ipv4_or_ipv6

    # 1. URL Intelligence IP Classification
    is_ip, ver, classification = is_valid_ipv4_or_ipv6("198.51.100.99")
    assert is_ip is True
    assert ver == 4
    # Must NOT be classified as private:
    assert classification == HostClassification.DOCUMENTATION
    assert classification != HostClassification.PRIVATE

    # 2. URL Rule Trigger
    doc_url_res = analyze_url("http://198.51.100.99/renew")
    obs_rules = [o.rule_id for o in doc_url_res.observations]
    assert "RULE_DOCUMENTATION_IP_HOST" in obs_rules
    assert "RULE_PRIVATE_IP_HOST" not in obs_rules

    # 3. Genuine RFC 1918 Private IP
    priv_url_res = analyze_url("http://192.168.1.100/admin")
    priv_rules = [o.rule_id for o in priv_url_res.observations]
    assert "RULE_PRIVATE_IP_HOST" in priv_rules
    assert priv_url_res.features.host_classification == HostClassification.PRIVATE

    # 4. Public IP
    pub_url_res = analyze_url("http://93.184.216.34/login")
    pub_rules = [o.rule_id for o in pub_url_res.observations]
    assert "RULE_PUBLIC_IP_HOST" in pub_rules
    assert pub_url_res.features.host_classification == HostClassification.PUBLIC

    # 5. IP Intelligence Classification (RFC 5737 TEST-NET-2)
    ip_cls, ip_obj = classify_ip_string("198.51.100.99")
    assert ip_cls == IPClassification.DOCUMENTATION


def test_model_evidence_wording_uncalibrated_phishing_score():
    """
    REGRESSION TEST (Phase 8A.1):
    Proves that user-facing and API-generated wording uses 'uncalibrated phishing score'
    and strictly avoids calling model output a 'confidence score' or 'calibrated probability'.
    """
    from app.schemas.evidence_fusion import ModelInferenceEvidence
    from app.services.evidence_fusion import fuse_evidence

    # High model score
    high_evidence = ModelInferenceEvidence(uncalibrated_score=0.985, predicted_label=1)
    res_high = fuse_evidence(model_inference=high_evidence)
    interp_high = res_high.model_evidence.interpretation
    assert "uncalibrated phishing score" in interp_high
    assert "confidence score" not in interp_high.lower()
    assert "calibrated probability" not in interp_high.lower()

    # Moderate model score
    med_evidence = ModelInferenceEvidence(uncalibrated_score=0.550, predicted_label=1)
    res_med = fuse_evidence(model_inference=med_evidence)
    contrib = " ".join(res_med.contributing_factors)
    assert "confidence" not in contrib.lower()
