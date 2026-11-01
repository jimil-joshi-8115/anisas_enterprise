"""Transparent multi-factor risk scoring engine.

Every point of the final score is attributable: the returned contributions
block is what the UI bars render. Inputs come exclusively from real scan
data (CVEs, open ports, banner-derived firmware versions, WAF, VT score).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Exploitability-weighted port table (curated from common exposure guidance:
# legacy/cleartext mgmt and wormable services weigh more than encrypted web).
PORT_WEIGHTS: Dict[int, int] = {
    21: 8, 23: 10, 25: 5, 53: 3, 80: 3, 110: 4, 135: 7, 139: 7, 161: 6,
    389: 6, 443: 2, 445: 9, 514: 6, 554: 7, 631: 4, 1080: 5, 1433: 8,
    1723: 6, 1883: 5, 1900: 6, 3306: 8, 3389: 8, 5000: 4, 5060: 6,
    5432: 8, 5683: 5, 6379: 8, 7547: 9, 8000: 4, 8080: 4, 8291: 5,
    8443: 3, 8883: 4, 9000: 4, 9100: 6, 27017: 8, 37777: 6, 34567: 6,
}

# Software -> {version-prefix regex: (release date, EOL date)} for firmware-age.
# Dates sourced from public release/EOL records; unknown software => no penalty.
FIRMWARE_RELEASES: List[Dict[str, Any]] = [
    {"name": "nginx", "re": r"nginx/(\d+)\.(\d+)", "dates": {
        "1.18": ("2020-04-21", "2022-05-01"), "1.20": ("2021-04-20", "2023-05-24"),
        "1.22": ("2022-10-19", "2024-06-01"), "1.24": ("2023-04-11", "2025-05-01"),
        "1.26": ("2024-05-14", "2026-06-01"), "1.28": ("2025-04-23", None),
    }},
    {"name": "apache", "re": r"Apache/(\d+)\.(\d+)", "dates": {
        "2.4": ("2012-02-21", "2026-12-31"),
    }},
    {"name": "openssh", "re": r"OpenSSH[_ ](\d+)\.(\d+)", "dates": {
        "8.2": ("2020-02-14", None), "8.4": ("2020-09-27", None),
        "8.9": ("2022-02-23", None), "9.2": ("2023-02-23", None),
        "9.6": ("2023-12-18", None), "9.8": ("2024-07-01", None),
        "10.0": ("2025-04-09", None),
    }},
    {"name": "lighttpd", "re": r"lighttpd/(\d+)\.(\d+)", "dates": {
        "1.4": ("2003-03-01", None),
    }},
    {"name": "busybox", "re": r"BusyBox v(\d+)\.(\d+)", "dates": {
        "1.36": ("2023-01-03", None),
    }},
]

MAX_CVE_COMPONENT = 40
MAX_PORT_COMPONENT = 30
MAX_VT_COMPONENT = 15
MAX_FIRMWARE_COMPONENT = 15


def _parse_version(banner_text: str) -> Optional[tuple]:
    for entry in FIRMWARE_RELEASES:
        m = re.search(entry["re"], banner_text or "", re.IGNORECASE)
        if not m:
            continue
        key = f"{m.group(1)}.{m.group(2)}"
        dates = entry["dates"].get(key)
        if not dates:
            # Unknown minor version: fall back to the nearest known prefix.
            near = [k for k in entry["dates"] if k.split(".")[0] == m.group(1)]
            if not near:
                continue
            key = max(near)
            dates = entry["dates"][key]
        try:
            rel = datetime.strptime(dates[0], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            eol = datetime.strptime(dates[1], "%Y-%m-%d").replace(tzinfo=timezone.utc) if dates[1] else None
            return {"software": entry["name"], "version": key,
                    "releasedAt": rel.isoformat(), "eolAt": eol.isoformat() if eol else None}
        except ValueError:
            continue
    return None


def _firmware_component(info: Optional[Dict[str, Any]]) -> tuple:
    if not info:
        return 0.0, {"reason": "no recognizable versioned banner"}
    now = datetime.now(timezone.utc)
    released = datetime.fromisoformat(info["releasedAt"])
    age_months = max(0, int((now - released).days / 30.44))
    penalty = 0.0
    reason = f"{age_months} months since release"
    if info.get("eolAt"):
        eol = datetime.fromisoformat(info["eolAt"])
        if now > eol:
            penalty += 8.0
            reason += "; past end-of-life"
    if age_months >= 48:
        penalty += 7.0
    elif age_months >= 24:
        penalty += 4.0
    return min(penalty, float(MAX_FIRMWARE_COMPONENT)), {
        "reason": reason, "monthsSinceRelease": age_months,
        "eolPassed": bool(info.get("eolAt") and now > datetime.fromisoformat(info["eolAt"])),
    }


def score_device(cves: List[Dict[str, Any]], open_ports: List[int],
                 banner_text: str = "", waf_vendor: str = "",
                 vt_malicious_score: int = 0) -> Dict[str, Any]:
    cves = cves or []
    ports = sorted({int(p) for p in (open_ports or [])})

    # CVE exposure: CVSS-scaled with KEV amplification.
    cve_pts = 0.0
    kev_count = 0
    max_cvss = 0.0
    for c in cves[:12]:
        cvss = float(c.get("cvss") or c.get("cvssScore") or 5.4)
        max_cvss = max(max_cvss, cvss)
        cve_pts += cvss * 1.6
        if str(c.get("kev", "")).upper() in ("TRUE", "1", "YES") or c.get("inKev"):
            kev_count += 1
            cve_pts += 6.0
    cve_component = round(min(cve_pts, float(MAX_CVE_COMPONENT)), 1)

    port_component = round(min(sum(PORT_WEIGHTS.get(p, 2) * 0.9 for p in ports),
                               float(MAX_PORT_COMPONENT)), 1)

    vt_component = round(min(max(0, int(vt_malicious_score or 0)) * 1.5,
                             float(MAX_VT_COMPONENT)), 1)

    fw_info = _parse_version(banner_text)
    fw_component, fw_detail = _firmware_component(fw_info)

    # WAF presence reduces the reachable-port blast radius slightly.
    waf_relief = -3.0 if (waf_vendor and str(waf_vendor).lower() not in ("none", "unknown")) else 0.0

    total = cve_component + port_component + vt_component + fw_component + waf_relief
    overall = int(round(max(0, min(100, total))))
    rating = ("CRITICAL" if overall >= 75 else "HIGH" if overall >= 45 else
              "MEDIUM" if overall >= 25 else "LOW")

    return {
        "overallRiskScore": overall,
        "postureRating": rating,
        "cveRiskComponent": cve_component,
        "openPortComponent": port_component,
        "vtAbuseComponent": vt_component,
        "firmwareAgePenalty": fw_component,
        "wafRelief": waf_relief,
        "contributionsMax": {
            "cve": MAX_CVE_COMPONENT, "ports": MAX_PORT_COMPONENT,
            "vt": MAX_VT_COMPONENT, "firmware": MAX_FIRMWARE_COMPONENT,
        },
        "detail": {
            "cvesConsidered": len(cves[:12]), "kevCount": kev_count,
            "maxCvss": round(max_cvss, 1), "weightedPorts": ports,
            "firmware": {**(fw_info or {}), **fw_detail},
        },
        "engineVersion": "risk-v2-transparent",
    }
