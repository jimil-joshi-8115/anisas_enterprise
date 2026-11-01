"""Unsupervised anomaly detection across swept subnet hosts.

IsolationForest (primary) + LocalOutlierFactor (secondary vote) over a
per-host feature vector. Requires >= MIN_HOSTS real hosts; below that it
returns an honest INSUFFICIENT_HOSTS state instead of fake outliers.
Every flagged host carries its top diverging features vs subnet median.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np

log = logging.getLogger("anisas.ai.anomaly")

MIN_HOSTS = 6

FEATURE_NAMES = [
    "openPortCount", "p_telnet", "p_ftp", "p_ssh", "p_http", "p_https",
    "p_smb", "p_rdp", "p_rtsp", "p_db", "p_mgmt", "cveCount", "maxCvss",
]

_ANOMALY_PORT_FLAGS = {
    "p_telnet": 23, "p_ftp": 21, "p_ssh": 22, "p_http": 80, "p_https": 443,
    "p_smb": 445, "p_rdp": 3389, "p_rtsp": 554, "p_mgmt": 8291,
}
_DB_PORTS = {3306, 1433, 5432, 6379, 27017}


def _vector(asset: Dict[str, Any], cve_count: int, max_cvss: float) -> Optional[np.ndarray]:
    ip = asset.get("ip") or asset.get("ipAddress")
    if not ip:
        return None
    ports = set(int(p) for p in (asset.get("ports") or asset.get("openPorts") or []))
    vec = [float(len(ports))]
    for name in FEATURE_NAMES[1:11]:
        port = _ANOMALY_PORT_FLAGS.get(name)
        if port is not None:
            vec.append(float(port in ports))
        else:  # db flag
            vec.append(float(bool(ports & _DB_PORTS)))
    vec.append(float(cve_count))
    vec.append(float(max_cvss))
    return np.array(vec)


def detect(assets: List[Dict[str, Any]],
           cve_lookup: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    cve_lookup = cve_lookup or {}
    vectors, ips = [], []
    for a in assets or []:
        ip = a.get("ip") or a.get("ipAddress")
        if not ip:
            continue
        info = cve_lookup.get(ip, {})
        v = _vector(a, int(info.get("cveCount") or 0), float(info.get("maxCvss") or 0.0))
        if v is not None:
            vectors.append(v)
            ips.append(str(ip))

    if len(vectors) < MIN_HOSTS:
        return {
            "state": "INSUFFICIENT_HOSTS",
            "hostCount": len(vectors),
            "requiredHosts": MIN_HOSTS,
            "flaggedHosts": [],
            "note": (f"Only {len(vectors)} host(s) with usable features - "
                     f"clustering needs >= {MIN_HOSTS}. Run a subnet sweep first."),
        }

    X = np.vstack(vectors)

    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import RobustScaler

    Xs = RobustScaler().fit_transform(X)
    iso = IsolationForest(contamination="auto", random_state=42).fit(Xs)
    iso_flags = iso.predict(Xs)          # -1 outlier / 1 inlier
    lof = LocalOutlierFactor(n_neighbors=min(20, max(3, len(Xs) // 3)))
    lof_flags = lof.fit_predict(Xs)

    med = np.median(X, axis=0)
    flagged: List[Dict[str, Any]] = []
    for i, ip in enumerate(ips):
        votes = int(iso_flags[i] == -1) + int(lof_flags[i] == -1)
        if votes == 0:
            continue
        score = float(-iso.score_samples([Xs[i]])[0])
        diffs = [(FEATURE_NAMES[j], float(X[i][j] - med[j])) for j in range(len(FEATURE_NAMES))]
        top_div = [(n, d) for n, d in sorted(diffs, key=lambda t: -abs(t[1]))[:3]
                   if abs(d) > 0.01]
        flagged.append({
            "ip": ip,
            "anomalyScore": round(min(max(score * 50 + 50, 0.0), 100.0), 1),
            "modelVotes": f"{votes}/2",
            "topDivergences": [{"feature": n, "deltaVsMedian": round(d, 2)} for n, d in top_div],
            "interpretation": ", ".join(
                ("more" if d > 0 else "fewer") + f" {n}" for n, d in top_div[:2]),
        })

    flagged.sort(key=lambda f: -f["anomalyScore"])
    return {
        "state": "COMPLETED" if flagged else "NO_OUTLIERS",
        "modelUsed": "IsolationForest+LocalOutlierFactor (RobustScaler)",
        "hostCount": len(vectors),
        "flaggedHostCount": len(flagged),
        "flaggedHosts": flagged,
    }
