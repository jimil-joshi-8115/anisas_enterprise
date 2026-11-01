"""Train Module 5 models and persist them under ai-service/models/.

Datasets are synthetic-but-grounded: archetypes are seeded from public
well-known port conventions (IANA assignments, nmap nmap-services, vendor
documentation) and perturbed with realistic noise (partial port sets,
decoy ports). Provenance is documented here so results are never passed
off as measurements.

Run:  python -m ai_engine.train
Outputs:
  models/device_classifier.joblib
  models/os_fingerprint.joblib
  models/metrics.json
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

from .features import (
    DEVICE_CLASSES,
    OS_CLASSES,
    build_device_features,
    build_os_features,
)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
SEED = 42

# ---------------------------------------------------------------------------
# Device-type seed archetypes: label -> list of representative port sets.
# Grounded in IANA/nmap well-known conventions.
# ---------------------------------------------------------------------------
DEVICE_ARCHETYPES = {
    "Router / Firewall": [
        [80, 443], [8291, 8728], [23, 80], [443, 8291], [22, 80, 443],
        [500, 4500], [1723, 47], [53, 80, 443], [8080, 8443],
        [22, 80, 443, 8291], [7547, 80], [1900, 5000],
    ],
    "Switch (Managed)": [
        [161, 80], [22, 161], [23, 161], [80, 443, 161], [22, 23, 161],
    ],
    "IP Surveillance Camera": [
        [554], [554, 80], [554, 80, 8080], [554, 8004, 80], [554, 8899],
        [554, 80, 443], [8006, 554, 80], [2342, 554], [2020, 554, 80],
    ],
    "NVR / DVR Recorder": [
        [8000, 554, 80], [37777, 37778, 80], [34567, 8000, 554, 80],
        [8000, 8001, 554], [9010, 554, 80], [49152, 8000, 554],
    ],
    "NAS Storage": [
        [445, 5000], [5000, 5001, 443], [445, 139, 5000], [5000, 5001, 5002, 443],
        [445, 5000, 5001, 443], [2049, 111, 445],
    ],
    "Network Printer": [
        [9100, 631], [631, 80], [9100, 80, 443], [9100, 515, 631], [80, 443, 9100, 631],
    ],
    "Web Server": [
        [80], [443], [80, 443], [22, 80, 443], [22, 80], [8080], [8443],
        [22, 80, 443, 3000],
    ],
    "Database Server": [
        [3306], [1433], [1433, 3306], [5432], [27017], [6379], [1521],
        [3306, 22], [1433, 1434],
    ],
    "Mail Server": [
        [25, 587, 993], [143, 993], [110, 995], [25, 465, 587], [993, 995, 587],
    ],
    "DNS Server": [
        [53], [53, 80], [53, 443], [853, 53], [53, 853, 443],
    ],
    "Workstation / Endpoint": [
        [135, 139, 445, 3389], [445, 5357], [135, 445, 3389], [139, 445],
        [135, 139, 445], [5357, 445, 3389],
    ],
    "IoT / Embedded Device": [
        [1883], [1883, 8883], [5683], [1883, 5683, 80], [8883, 443],
        [40711, 1883], [6668, 1883], [10000, 80],
    ],
}

BANNER_TOKENS = {
    "IP Surveillance Camera": "rtsp onvif hikvision axis camera",
    "NVR / DVR Recorder": "nvr dvr dahua recorder rtsp",
    "NAS Storage": "synology diskstation qnap nas samba",
    "Network Printer": "hp jetdirect printer brother",
    "Web Server": "nginx apache lighttpd http server",
    "Database Server": "mysql postgresql mongodb mariadb",
    "Mail Server": "postfix dovecot imap smtp",
    "DNS Server": "bind dns unbound",
    "Router / Firewall": "mikrotik routeros openwrt igd upnp",
    "Switch (Managed)": "cisco snmp managed switch",
    "Workstation / Endpoint": "windows smb netbios",
    "IoT / Embedded Device": "mqtt coap embedded busybox lighttpd",
}


def _perturb(ports: list[int], rng: random.Random) -> list[int]:
    """Realistic noise: drop a port or add one plausible decoy."""
    out = set(ports)
    if len(out) > 1 and rng.random() < 0.30:
        out.discard(rng.choice(sorted(out)))
    if rng.random() < 0.25:
        out.add(rng.choice([80, 443, 22, 8080, 8443]))
    return sorted(out)


def build_device_dataset(n_per_archetype: int = 120):
    rng = random.Random(SEED)
    X, y = [], []
    for label, port_sets in DEVICE_ARCHETYPES.items():
        banner = BANNER_TOKENS.get(label, "")
        for i in range(n_per_archetype):
            base = port_sets[i % len(port_sets)]
            ports = _perturb(base, rng)
            org = ""
            if label == "DNS Server" and rng.random() < 0.4:
                org = rng.choice(["Cloudflare", "Google"])
            X.append(build_device_features(ports, banner_text=banner, org_hint=org))
            y.append(label)
    return np.array(X), np.array(y)


# ---------------------------------------------------------------------------
# OS fingerprint seeds from public stack-signature knowledge
# (p0f signatures, nmap-os-db, long-documented TTL/window conventions).
# ---------------------------------------------------------------------------
OS_SIGNATURES = {
    "Linux": {
        "ttl_init": 64,
        "windows": [5840, 5720, 14600, 29200, 26883, 65535, 14612],
        "df": True, "mss": [1460, 1440, 1430, 1412],
        # Typical SYN-ACK option orders for Linux kernels.
        "opts": ["MSS,SACK,TS,NOP,WS", "MSS,SACK,TS,NOP,WS,NOP,NOP", "MSS,NOP,NOP,SACK,NOP,WS"],
        "ports": [22, 53, 80, 443, 853],
    },
    "Windows": {
        "ttl_init": 128,
        "windows": [8192, 64240, 16384, 65392],
        "df": True, "mss": [1460, 1440],
        # Windows SYN-ACKs: no timestamps, WS+NOP padding + selective ack.
        "opts": ["MSS,NOP,WS,NOP,NOP,SACK", "MSS,NOP,NOP,SACK"],
        "ports": [135, 445, 3389],
    },
    "Network OS (Cisco/Mikrotik)": {
        "ttl_init": [255, 64],
        "windows": [4128, 2144, 2048],
        "df": [True, False], "mss": [1460, 536],
        "opts": ["MSS", ""],
        "ports": [8291, 23, 161, 22],
    },
    "Embedded/IoT RTOS": {
        "ttl_init": [64, 255, 128],
        "windows": [512, 1024, 2048, 4096, 8192],
        "df": [True, False], "mss": [1460, 1400, None],
        "opts": ["MSS", "", "MSS,SACK"],
        "ports": [554, 1883, 8080, 37777],
    },
    "BSD/macOS": {
        "ttl_init": 64,
        "windows": [65535, 33304],
        "df": True, "mss": [1460, 1452],
        "opts": ["MSS,NOP,WS,SACK,TS,NOP,NOP", "MSS,WS,SACK,TS,NOP,NOP"],
        "ports": [22, 88, 548],
    },
}

# CDN/anycast org contexts that correlate with Unix-family edge infra.
CDN_ORGS = ("cloudflare", "google", "amazon", "akamai")

def build_os_dataset(n_per_class: int = 250):
    rng = random.Random(SEED + 1)
    rows, labels = [], []
    for cls, sig in OS_SIGNATURES.items():
        ttls = sig["ttl_init"] if isinstance(sig["ttl_init"], list) else [sig["ttl_init"]]
        dfs = sig["df"] if isinstance(sig["df"], list) else [sig["df"]]
        msss = sig["mss"]
        ports = sig.get("ports", [])
        opts_pool = sig.get("opts", [""])
        for _ in range(n_per_class):
            # Simulate measurement reality: initial TTL minus 0-20 hops.
            reply_ttl = rng.choice(ttls) - rng.randint(0, min(15, rng.choice(ttls) - 1))
            guess = min((64, 128, 255), key=lambda b: abs(b - reply_ttl))
            win = rng.choice(sig["windows"])
            df = rng.choice(dfs)
            mss = rng.choice(msss)
            opts = rng.choice(opts_pool)
            org = ""
            # ~30% of Linux rows sit behind CDN/DNS orgs (anycast reality).
            if cls == "Linux" and rng.random() < 0.30:
                org = rng.choice(CDN_ORGS)
            # ~35% of live captures lack window/MSS/DF (ICMP-only tier).
            if rng.random() < 0.35:
                win = mss = None
                df = None
                opts = ""
            elif rng.random() < 0.15:
                mss = None
            rows.append(build_os_features(
                {"ttl": reply_ttl, "ttlInitialGuess": guess, "windowSize": win,
                 "dfBit": df, "mss": mss},
                rng.sample(ports, k=min(len(ports), rng.randint(1, len(ports)))) if ports else [],
                tcp_options=opts,
                org_hint=org,
            ))
            labels.append(cls)
    return np.array(rows, dtype=float), np.array(labels)


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    metrics: dict = {"trainedAtEpoch": int(np.datetime64("now", "s").astype(int))}

    # --- Device classifier -------------------------------------------------
    X, y = build_device_dataset()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight="balanced", random_state=SEED, n_jobs=-1,
    )
    cal = CalibratedClassifierCV(rf, method="sigmoid", cv=5)
    cal.fit(Xtr, ytr)
    pred = cal.predict(Xte)
    dev_report = classification_report(yte, pred, output_dict=True, zero_division=0)
    metrics["device_classifier"] = {
        "accuracy": round(float(accuracy_score(yte, pred)), 4),
        "classes": DEVICE_CLASSES,
        "perClassF1": {k: round(v["f1-score"], 3) for k, v in dev_report.items()
                       if k in DEVICE_CLASSES},
    }
    import joblib
    joblib.dump({"model": cal, "version": "dev-clf-v1"}, MODELS_DIR / "device_classifier.joblib")

    # --- OS fingerprint model ---------------------------------------------
    Xo, yo = build_os_dataset()
    Xotr, Xote, yotr, yote = train_test_split(Xo, yo, test_size=0.2, random_state=SEED, stratify=yo)
    hgb = HistGradientBoostingClassifier(
        max_iter=250, learning_rate=0.08, max_depth=None,
        l2_regularization=0.5, random_state=SEED,
    )
    hgb.fit(Xotr, yotr)
    opred = hgb.predict(Xote)
    os_report = classification_report(yote, opred, output_dict=True, zero_division=0)
    metrics["os_fingerprint"] = {
        "accuracy": round(float(accuracy_score(yote, opred)), 4),
        "classes": OS_CLASSES,
        "perClassF1": {k: round(v["f1-score"], 3) for k, v in os_report.items()
                       if k in OS_CLASSES},
        "nanTolerantFeatures": ["windowSize", "dfBit", "mss"],
    }
    joblib.dump({"model": hgb, "version": "os-fp-v1"}, MODELS_DIR / "os_fingerprint.joblib")

    (MODELS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
