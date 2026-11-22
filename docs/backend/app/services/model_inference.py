"""
DistilBERT Baseline Model Inference Engine for PhishIntel (Phase 8A).
Executes local sequence classification inference on extracted email subject and body text.

Design Principles:
1. Offline Execution: strictly local checkpoint loading (local_files_only=True). No external network access.
2. Training Consistency: identical text input construction (subject + "\\n\\n" + body),
   tokenizer, and max_length=256 truncation.
3. Label Mapping: 0 = Benign, 1 = Phishing.
4. Uncalibrated Output: raw DistilBERT class-1 probability score, explicitly labeled
   as an uncalibrated text heuristic, NOT a real-world phishing probability.
5. Defensive Robustness: handles missing checkpoints and inference errors explicitly;
   never allows a failure to masquerade as a benign verdict.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

# PyTorch can be unavailable (not installed, or blocked by a Windows Application Control policy
# that refuses to load torch's DLLs). That must not crash the whole API: the text model then
# reports UNAVAILABLE, exactly like a missing checkpoint, and every other analysis still runs.
_INSTALL_HINT = (
    "Fix: activate the backend virtual environment and run "
    "'pip install -r requirements.txt' (it now includes torch + transformers), "
    "then restart uvicorn. Diagnostics: GET /health/model"
)
_BLOCKED_DLL_HINT = (
    "Windows blocked a PyTorch DLL (WinError 4551 / Application Control). Install the Microsoft "
    "Visual C++ Redistributable (x64), reinstall torch inside this venv, and make sure the venv "
    "folder is not under a policy-restricted path. See FIX_TRANSFORMERS.md"
)

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, PreTrainedTokenizerBase

    _TORCH_IMPORT_ERROR = None
except Exception as _torch_exc:  # ImportError (not installed), OSError (blocked/broken DLL), etc.
    torch = None  # type: ignore[assignment]
    AutoModelForSequenceClassification = AutoTokenizer = PreTrainedTokenizerBase = None  # type: ignore[assignment,misc]
    _hint = _BLOCKED_DLL_HINT if isinstance(_torch_exc, OSError) else _INSTALL_HINT
    _TORCH_IMPORT_ERROR = (
        f"PyTorch/transformers could not be loaded: {type(_torch_exc).__name__}: {_torch_exc}. "
        f"(running under Python: {sys.executable}) {_hint}"
    )

from app.schemas.evidence_fusion import (
    ModelInferenceEvidence,
    ModelInferenceStatus,
)

logger = logging.getLogger(__name__)

# Default checkpoint directory relative to project root
DEFAULT_CHECKPOINT_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent / "models" / "distilbert_baseline"
)


class ModelInferenceEngine:
    """
    Manages DistilBERT model loading, device selection, preprocessing, and inference.
    """

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        device: Optional[str] = None,
    ):
        env_dir = os.environ.get("PHISHINTEL_MODEL_DIR")
        self.checkpoint_dir = Path(checkpoint_dir or env_dir or DEFAULT_CHECKPOINT_DIR)
        self.preferred_device = device
        self._device: Optional[torch.device] = None
        self._tokenizer: Optional[PreTrainedTokenizerBase] = None
        self._model: Optional[AutoModelForSequenceClassification] = None
        self._load_error: Optional[str] = None
        self._initialized: bool = False

    @property
    def device(self) -> torch.device:
        if self._device is None:
            if self.preferred_device:
                self._device = torch.device(self.preferred_device)
            elif torch.cuda.is_available():
                self._device = torch.device("cuda:0")
            else:
                self._device = torch.device("cpu")
        return self._device

    def is_checkpoint_available(self) -> bool:
        """
        Verifies existence of local checkpoint directory, config, and weights.
        """
        if not self.checkpoint_dir.is_dir():
            return False
        config_file = self.checkpoint_dir / "config.json"
        weights_file = self.checkpoint_dir / "model.safetensors"
        bin_weights = self.checkpoint_dir / "pytorch_model.bin"
        has_weights = weights_file.is_file() or bin_weights.is_file()
        return config_file.is_file() and has_weights

    def load_model(self) -> None:
        """
        Loads tokenizer and model weights from local files only.
        """
        if self._initialized:
            return

        if torch is None:
            logger.warning(_TORCH_IMPORT_ERROR)
            self._load_error = _TORCH_IMPORT_ERROR
            self._initialized = True
            return

        if not self.is_checkpoint_available():
            err = f"Model checkpoint directory or weights not found at: {self.checkpoint_dir}"
            logger.warning(err)
            self._load_error = err
            self._initialized = True
            return

        try:
            logger.info("Loading DistilBERT tokenizer and weights from %s", self.checkpoint_dir)
            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self.checkpoint_dir),
                local_files_only=True,
            )
            model = AutoModelForSequenceClassification.from_pretrained(
                str(self.checkpoint_dir),
                local_files_only=True,
            )
            # Safe device placement with CPU fallback
            try:
                model = model.to(self.device)
            except Exception as dev_err:
                logger.warning(
                    "Failed to place model on preferred device %s (%s). Falling back to CPU.",
                    self.device,
                    dev_err,
                )
                self._device = torch.device("cpu")
                model = model.to(self._device)

            model.eval()
            self._model = model
            self._load_error = None
            self._initialized = True
            logger.info("DistilBERT model loaded successfully on %s", self.device)
        except Exception as exc:
            err = f"Failed to initialize DistilBERT model: {str(exc)}"
            logger.error(err, exc_info=True)
            self._load_error = err
            self._tokenizer = None
            self._model = None
            self._initialized = True

    def predict(
        self,
        subject: Optional[str] = None,
        body: Optional[str] = None,
    ) -> ModelInferenceEvidence:
        """
        Performs inference on email text using identical input construction as training:
        subject + "\\n\\n" + body

        Returns ModelInferenceEvidence with uncalibrated score and predicted label.
        Handles missing subject, missing body, missing checkpoint, or runtime errors safely.
        """
        if not self._initialized:
            self.load_model()

        if self._load_error is not None or self._model is None or self._tokenizer is None:
            return ModelInferenceEvidence(
                uncalibrated_score=None,
                predicted_label=None,
                status=ModelInferenceStatus.UNAVAILABLE,
                error_message=self._load_error or "Model checkpoint unavailable",
            )

        # Consistent input construction (Phase 3B): subject + "\n\n" + body
        sub_str = subject if subject is not None else ""
        body_str = body if body is not None else ""
        input_text = f"{sub_str}\n\n{body_str}"

        try:
            with torch.no_grad():
                encoded = self._tokenizer(
                    input_text,
                    max_length=256,
                    truncation=True,
                    padding=True,
                    return_tensors="pt",
                )
                inputs = {k: v.to(self.device) for k, v in encoded.items()}
                outputs = self._model(**inputs)
                logits = outputs.logits  # shape [1, 2]
                probs = torch.softmax(logits, dim=-1)

                # Class 0: benign, Class 1: phishing
                phishing_score = float(probs[0, 1].item())
                predicted_label = 1 if phishing_score >= 0.5 else 0

                return ModelInferenceEvidence(
                    uncalibrated_score=phishing_score,
                    predicted_label=predicted_label,
                    status=ModelInferenceStatus.EVALUATED,
                    error_message=None,
                )
        except Exception as inf_err:
            logger.error("Error during DistilBERT inference: %s", inf_err, exc_info=True)
            return ModelInferenceEvidence(
                uncalibrated_score=None,
                predicted_label=None,
                status=ModelInferenceStatus.ERROR,
                error_message=f"Inference exception: {str(inf_err)}",
            )

    def diagnostics(self) -> dict:
        """
        Cheap, side-effect-free status report (does not load the weights).
        Used by GET /health/model so setup problems are visible without reading logs.
        """
        return {
            "python_executable": sys.executable,
            "python_version": sys.version.split()[0],
            "torch_importable": torch is not None,
            "torch_version": getattr(torch, "__version__", None) if torch is not None else None,
            "cuda_available": bool(torch.cuda.is_available()) if torch is not None else False,
            "checkpoint_dir": str(self.checkpoint_dir),
            "checkpoint_found": self.is_checkpoint_available(),
            "import_error": _TORCH_IMPORT_ERROR,
            "load_error": self._load_error,
            "model_loaded": self._model is not None,
        }

    def reset(self) -> None:
        """
        Resets cached model and tokenizer state (useful for tests).
        """
        self._tokenizer = None
        self._model = None
        self._load_error = None
        self._initialized = False
        self._device = None


# Module-level singleton
_engine_instance: Optional[ModelInferenceEngine] = None


def get_model_inference_engine() -> ModelInferenceEngine:
    """
    Returns the singleton ModelInferenceEngine instance.
    """
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ModelInferenceEngine()
    return _engine_instance


def run_model_inference(
    subject: Optional[str] = None,
    body: Optional[str] = None,
) -> ModelInferenceEvidence:
    """
    Convenience functional interface for DistilBERT inference.
    """
    engine = get_model_inference_engine()
    return engine.predict(subject=subject, body=body)
