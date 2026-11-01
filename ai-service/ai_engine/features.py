"""Shared feature construction for Module 5 models.

The exact same functions are used by the training script and the live
inference path so the feature schema can never drift apart.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# Ordered port vocabulary used by the device-type model.
PORT_VOCAB: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445,
    465, 500, 514, 554, 587, 631, 993, 995, 1080, 1433, 1723, 1883, 1900,
    2020, 2222, 2342, 3000, 3306, 3389, 5000, 5001, 5060, 5432, 5683,
    6379, 7547, 8000, 8004, 8006, 8008, 8080, 8081, 8291, 8443, 8883,
    9000, 9100, 27017, 37777, 34567, 49152,
]
_PORT_INDEX = {p: i for i, p in enumerate(PORT_VOCAB)}

SERVICE_HINT_KEYS = [
    "hint_rtsp", "hint_smb", "hint_ssh", "hint_web_server", "hint_nas",
    "hint_nvr", "hint_printer", "hint_mqtt", "hint_database",
    "hint_voip", "hint_mgmt_routeros", "hint_upnp", "hint_tr069",
]

DEVICE_CLASSES = [
    "Router / Firewall", "Switch (Managed)", "IP Surveillance Camera",
    "NVR / DVR Recorder", "NAS Storage", "Network Printer",
    "Web Server", "Database Server", "Mail Server", "DNS Server",
    "Workstation / Endpoint", "IoT / Embedded Device",
]

OS_CLASSES = ["Linux", "Windows", "Network OS (Cisco/Mikrotik)", "Embedded/IoT RTOS", "BSD/macOS"]


def banner_hints(banner_text: str) -> Dict[str, int]:
    """Weak-evidence flags extracted from service banners."""
    t = (banner_text or "").lower()
    return {
        "hint_rtsp": int(any(k in t for k in ("rtsp", "axis", "hikvision", "dahua", "onvif"))),
        "hint_smb": int("samba" in t or "smb" in t),
        "hint_ssh": int("openssh" in t or "dropbear" in t),
        "hint_web_server": int(any(k in t for k in ("nginx", "apache", "lighttpd", "iis", "caddy", "mini_httpd"))),
        "hint_nas": int(any(k in t for k in ("synology", "qnap", "diskstation", "mycloud"))),
        "hint_nvr": int("nvr" in t or "dvr" in t or "hikvision" in t or "dahua" in t),
        "hint_printer": int(any(k in t for k in ("hp ", "jetdirect", "printer", "brother", "epson"))),
        "hint_mqtt": int("mqtt" in t),
        "hint_database": int(any(k in t for k in ("mysql", "postgres", "mongodb", "mariadb"))),
        "hint_voip": int("sip" in t or "voip" in t),
        "hint_mgmt_routeros": int("mikrotik" in t or "routeros" in t),
        "hint_upnp": int("upnp" in t or "igd" in t),
        "hint_tr069": int("tr-069" in t or "tr069" in t or "cwmp" in t),
    }


def _port_multihot(open_ports: Iterable[int]) -> List[int]:
    v = [0] * len(PORT_VOCAB)
    for p in open_ports or []:
        i = _PORT_INDEX.get(int(p))
        if i is not None:
            v[i] = 1
    return v


def build_device_features(
    open_ports: Iterable[int],
    banner_text: str = "",
    org_hint: str = "",
    service_names: str = "",
) -> List[float]:
    """Vector consumed by the device-type RandomForest."""
    vec: List[float] = []
    hot = _port_multihot(open_ports)
    vec.extend(hot)
    vec.append(float(len({int(p) for p in (open_ports or [])})))
    hints = banner_hints(f"{banner_text} {service_names}")
    vec.extend(float(hints[k]) for k in SERVICE_HINT_KEYS)
    o = (org_hint or "").lower()
    vec.extend([
        float(any(k in o for k in ("cloudflare", "google", "amazon", "microsoft", "akamai"))),
        float(any(k in o for k in ("comcast", "telecom", "broadband", "jio", "airtel", "bsnl", "vodafone"))),
    ])
    return vec


def build_os_features(stack: Dict[str, Any], open_ports: Iterable[int] = (),
                      tcp_options: str = "", org_hint: str = "") -> List[float]:
    """Vector consumed by the OS-fingerprint model.

    Missing measurements stay None -> NaN, which HistGradientBoosting handles
    natively. We never substitute invented values.
    """
    ports = set(int(p) for p in (open_ports or []))
    ttl = stack.get("ttl")
    guess = stack.get("ttlInitialGuess")
    win = stack.get("windowSize")
    df = stack.get("dfBit")
    mss = stack.get("mss")

    def num(x: Any) -> Optional[float]:
        try:
            xf = float(x)
            return xf if xf == xf else None  # drop NaN
        except (TypeError, ValueError):
            return None

    ttl_f = num(ttl)
    guess_f = num(guess)
    win_f = num(win)
    mss_f = num(mss)

    opts = (tcp_options or "").upper()
    o = (org_hint or "").lower()
    feats: List[float] = [
        ttl_f if ttl_f is not None else float("nan"),
        guess_f if guess_f is not None else float("nan"),
        win_f if win_f is not None else float("nan"),
        float(df) if df is not None else float("nan"),
        mss_f if mss_f is not None else float("nan"),
        # Weak priors: Windows-family ports, RouterOS mgmt port, telnet-era gear.
        float(bool(ports & {135, 139, 445, 3389})),
        float(8291 in ports),
        float(bool(ports & {23, 500, 161})),
        # Discriminators: DNS/TLS service mix + CDN/anycast org context
        # (public resolvers/CDN edges are overwhelmingly Unix-family kernels).
        float(53 in ports and bool(ports & {443, 853})),
        float(any(k in o for k in ("cloudflare", "google", "amazon", "akamai", "meta"))),
        # TCP option order signature buckets (raw tier only): presence of
        # window-scale / SACK / timestamps ordering typical per family.
        float("WS" in opts and "SACK" in opts),
        float("TS" in opts),
    ]
    return feats


OS_FEATURE_NAMES = ["ttl", "ttlInitialGuess", "windowSize", "dfBit", "mss",
                    "windowsPortFamily", "routerosMgmtPort", "legacyNetPorts",
                    "dnsTlsServiceMix", "cdnOrgContext",
                    "optsWsSack", "optsTimestamp"]

DEVICE_FEATURE_NAMES = ([f"port_{p}" for p in PORT_VOCAB] + ["openPortCount"]
                        + SERVICE_HINT_KEYS + ["cdnOrgHint", "ispOrgHint"])
