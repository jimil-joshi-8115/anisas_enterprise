"""Device-type classifier inference (RandomForest over port/service features)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .features import build_device_features

log = logging.getLogger("anisas.ai.device_classifier")

_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        import joblib
        path = _MODELS_DIR / "device_classifier.joblib"
        if not path.exists():
            log.error("model file missing: %s", path)
            return None
        try:
            _bundle = joblib.load(path)
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to load device model: %s", exc)
            return None
    return _bundle


def classify(open_ports: List[int], banner_text: str = "", org_hint: str = "",
             service_names: str = "") -> Optional[Dict[str, Any]]:
    """Return prediction dict or None when the model is unavailable.

    With zero open ports there is no port/service evidence at all, so the
    honest answer is 'Unclassified' - never a low-confidence guess.
    """
    bundle = _load()
    if not bundle:
        return None
    if not open_ports:
        return {
            "predictedDeviceType": "Unclassified (no open ports detected)",
            "confidenceScore": 0.0,
            "topAlternatives": [],
            "modelVersion": bundle.get("version", "dev-clf-v1"),
            "isClassified": False,
        }
    try:
        vec = [build_device_features(open_ports, banner_text=banner_text,
                                     org_hint=org_hint, service_names=service_names)]
        proba = bundle["model"].predict_proba(vec)[0]
        classes = bundle["model"].classes_
        order = sorted(range(len(classes)), key=lambda i: -proba[i])
        top = [{"class": str(classes[i]), "probability": round(float(proba[i]), 4)}
               for i in order[:3]]
        return {
            "predictedDeviceType": top[0]["class"],
            "confidenceScore": round(top[0]["probability"] * 100.0, 1),
            "topAlternatives": top[1:],
            "modelVersion": bundle.get("version", "dev-clf-v1"),
            "isClassified": bool(top[0]["probability"] >= 0.50),
        }
    except Exception as exc:  # noqa: BLE001
        log.exception("classify failed: %s", exc)
        return None
