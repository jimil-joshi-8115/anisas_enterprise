from typing import List, Dict, Any

CLASSIFICATION_THRESHOLD = 0.50

def score_classification(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Pure, independently testable weighted classification function.
    
    Rules Enforced:
    1. If zero signals -> confidence = 0.0, classification = "not surveillance-related"
    2. If only LOW-tier signals -> confidence capped <= 0.30 regardless of count, label = "unclassified - LOW tier evidence only"
    3. If only single RTSP port open signal -> confidence <= 0.30, label = "unclassified - RTSP port open only"
    4. Multi-signal stacking (MEDIUM + HIGH) crosses threshold >= 0.50 -> classified ("CCTV Camera" / "NVR" / "DVR")
    """
    if not signals:
        return {
            "classification": "not surveillance-related",
            "confidence": 0.0,
            "is_classified": False,
            "score_breakdown": {"total_weight": 0.0, "high_count": 0, "medium_count": 0, "low_count": 0}
        }

    high_signals = [s for s in signals if s.get("tier") == "HIGH"]
    medium_signals = [s for s in signals if s.get("tier") == "MEDIUM"]
    low_signals = [s for s in signals if s.get("tier") in ["LOW", "LOW_MEDIUM"]]

    total_weight = sum(s.get("weight", 0.0) for s in signals)

    # RULE: Capped if single RTSP port open signal
    if len(signals) == 1 and signals[0].get("signal") == "rtsp_port_open":
        return {
            "classification": "unclassified - RTSP port open only",
            "confidence": 0.20,
            "is_classified": False,
            "score_breakdown": {"total_weight": 0.20, "high_count": 0, "medium_count": 0, "low_count": 1}
        }

    # RULE: Capped if only LOW-tier signals present
    if low_signals and not high_signals and not medium_signals:
        confidence = min(total_weight, 0.30)
        return {
            "classification": "unclassified - LOW tier evidence only",
            "confidence": round(confidence, 2),
            "is_classified": False,
            "score_breakdown": {"total_weight": round(total_weight, 2), "high_count": 0, "medium_count": 0, "low_count": len(low_signals)}
        }

    # Calculate stacked confidence bounded to [0.0, 1.0]
    confidence = min(total_weight, 0.98)

    if confidence >= CLASSIFICATION_THRESHOLD:
        # Determine classification label based on signal evidence
        sig_str = str(signals).lower()
        if any(kw in sig_str for kw in ["synology", "qnap", "nas", "diskstation", "dsm", "qts", "mycloud"]):
            label = "NAS Storage Device"
        elif any(kw in sig_str for kw in ["nvr", "dvr"]):
            label = "NVR / DVR Recorder"
        else:
            label = "CCTV Camera"
        is_classified = True
    else:
        label = "unclassified - insufficient evidence signals"
        is_classified = False

    return {
        "classification": label,
        "confidence": round(confidence, 2),
        "is_classified": is_classified,
        "score_breakdown": {
            "total_weight": round(total_weight, 2),
            "high_count": len(high_signals),
            "medium_count": len(medium_signals),
            "low_count": len(low_signals)
        }
    }
