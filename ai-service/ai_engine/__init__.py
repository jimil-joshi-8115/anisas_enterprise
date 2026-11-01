"""ANISAS Module 5 - AI Risk Engine.

Real ML pipeline replacing the previous hardcoded heuristics:
- stack_probe: TCP/IP stack feature collection (TTL, DF, window, MSS)
- train: builds seed datasets and trains sklearn models into models/
- device_classifier / os_fingerprint: joblib model inference
- topology / anomaly: graph-based subnet inference + unsupervised outlier detection
- risk_scorer: transparent multi-factor risk scoring
- nl_reporter: LLM-backed natural language reporting with honest fallback
"""

__version__ = "1.0.0"
