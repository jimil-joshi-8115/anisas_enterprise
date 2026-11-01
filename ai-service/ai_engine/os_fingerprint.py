"""OS fingerprint inference from measured TCP/IP stack behaviour.

Model input is strictly the MEASURED feature vector (TTL, window, DF, MSS
plus weak port-family priors). When a measurement is missing it stays NaN
and the model imputes - the response always echoes which fields were real.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .features import build_os_features

log = logging.getLogger("anisas.ai.os_fingerprint")

_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        import joblib
        path = _MODELS_DIR / "os_fingerprint.joblib"
        if not path.exists():
            log.error("model file missing: %s", path)
            return None
        try:
            _bundle = joblib.load(path)
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to load OS model: %s", exc)
            return None
    return _bundle


def _version_band(banner_text: str) -> Optional[str]:
    """Best-effort version band from banners; only when a banner states one."""
    t = (banner_text or "").lower()
    if "ubuntu" in t or "debian" in t or "nginx" in t or "apache" in t:
        return "Linux (banner-corroborated)"
    if "iis" in t or "microsoft" in t:
        return "Windows (banner-corroborated)"
    if "ios" in t and "cisco" in t:
        return "Cisco IOS (banner-corroborated)"
    return None


def fingerprint(stack: Dict[str, Any], open_ports: List[int],
                banner_text: str = "", org_hint: str = "") -> Dict[str, Any]:
    """Predict OS family from stack features. Never fabricates measurements."""
    bundle = _load()
    result: Dict[str, Any] = {
        "predictedOs": None,
        "osFamily": None,
        "matchConfidence": 0.0,
        "measuredStack": {
            "ttl": stack.get("ttl"),
            "ttlInitialGuess": stack.get("ttlInitialGuess"),
            "hopEstimate": stack.get("hopEstimate"),
            "windowSize": stack.get("windowSize"),
            "dfBit": stack.get("dfBit"),
            "mss": stack.get("mss"),
            "tcpOptions": stack.get("tcpOptions") or "",
        },
        "probeTier": stack.get("probeTier", "NONE"),
        "topAlternatives": [],
        "modelVersion": None,
    }
    if not bundle or stack.get("ttl") is None:
        # No probe data at all -> say so instead of inventing an OS.
        result["predictedOs"] = "UNKNOWN - no stack response measurable from this vantage point"
        result["stackFeatureCoverage"] = f"{sum(1 for k in ('ttl', 'windowSize', 'dfBit', 'mss') if stack.get(k) is not None)}/4"
        return result

    try:
        vec = [build_os_features(stack, open_ports,
                                 tcp_options=stack.get("tcpOptions") or "",
                                 org_hint=org_hint)]
        proba = bundle["model"].predict_proba(vec)[0]
        classes = bundle["model"].classes_
        order = sorted(range(len(classes)), key=lambda i: -proba[i])
        family = str(classes[order[0]])
        band = _version_band(banner_text)

        # Confidence shrinkage: a prediction built on fewer measured features
        # deserves proportionally less certainty. Core stack features:
        # ttl, windowSize, dfBit, mss.
        measured = sum(
            1 for k in ("ttl", "windowSize", "dfBit", "mss")
            if stack.get(k) is not None)
        coverage = measured / 4.0

        result.update({
            "predictedOs": band or family,
            "osFamily": family,
            "matchConfidence": round(float(proba[order[0]]) * 100.0 * (0.55 + 0.45 * coverage), 1),
            "stackFeatureCoverage": f"{measured}/4",
            "topAlternatives": [
                {"family": str(classes[i]), "probability": round(float(proba[i]), 4)}
                for i in order[1:3]
            ],
            "modelVersion": bundle.get("version", "os-fp-v1"),
        })
    except Exception as exc:  # noqa: BLE001
        log.exception("fingerprint failed: %s", exc)
        result["predictedOs"] = "UNKNOWN - inference error"
    return result
