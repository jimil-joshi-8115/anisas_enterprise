"""TCP/IP stack probing for OS fingerprinting.

Two tiers, selected automatically:

Tier A (requires admin + Npcap): raw SYN probe via scapy. Captures the real
SYN-ACK and extracts TTL, DF bit, receive window and MSS option.

Tier B (unprivileged): TTL from the OS ping utility reply plus initial-TTL
bucket inference (64/128/255). Window/DF/MSS are unknown -> returned as None
so downstream models impute instead of inventing values.

Every value is either measured or explicitly null. No fabrication.
"""
from __future__ import annotations

import re
import socket
import subprocess
import time
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("anisas.ai.stack_probe")

_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 900


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    ent = _CACHE.get(ip)
    if ent and time.time() - ent.get("_ts", 0) < CACHE_TTL_SECONDS:
        return {k: v for k, v in ent.items() if not k.startswith("_")}
    return None


def _cache_put(ip: str, data: Dict[str, Any]) -> None:
    rec = dict(data)
    rec["_ts"] = time.time()
    _CACHE[ip] = rec


def _ping_ttl(ip: str, timeout_ms: int = 2500) -> Optional[int]:
    """Reply TTL via Windows ping; None when host does not answer ICMP."""
    try:
        out = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=timeout_ms / 1000 + 3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        m = re.search(r"TTL[=:]\s*(\d+)", out.stdout or "")
        return int(m.group(1)) if m else None
    except Exception as exc:  # noqa: BLE001
        log.debug("ping TTL failed for %s: %s", ip, exc)
        return None


INITIAL_TTL_BUCKETS = (64, 128, 255)


def infer_initial_ttl(reply_ttl: int) -> int:
    """Classic nearest-bucket inference of the remote stack's initial TTL."""
    return min(INITIAL_TTL_BUCKETS, key=lambda b: abs(b - reply_ttl))


def estimate_hops(reply_ttl: int) -> Optional[int]:
    init = infer_initial_ttl(reply_ttl)
    hops = init - reply_ttl
    return hops if 0 <= hops <= 30 else None


def probe_scapy(ip: str, port: int, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """Tier A raw SYN probe. Returns measured fields or None on any failure."""
    try:
        from scapy.all import IP, TCP, sr1  # type: ignore
    except Exception as exc:  # noqa: BLE001
        log.debug("scapy unavailable: %s", exc)
        return None
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S", seq=1000)
        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        rtt_ms = round((time.time() - t0) * 1000, 1) if resp else None
        if resp is None or not resp.haslayer("TCP"):
            return None
        mss = None
        opts = []
        for name, val in getattr(resp["TCP"], "options", []) or []:
            if name == "MSS":
                mss = val
                opts.append("MSS")
            elif name == "NOP":
                opts.append("NOP")
            elif name == "WScale":
                opts.append("WS")
            elif name == "SAckOK":
                opts.append("SACK")
            elif name == "Timestamp":
                opts.append("TS")
        return {
            "ttl": int(resp.ttl),
            "dfBit": bool(resp.flags & 0x2) if hasattr(resp, "flags") else None,
            "windowSize": int(resp["TCP"].window),
            "mss": mss,
            "tcpOptions": ",".join(opts),
            "rttMs": rtt_ms,
            "probeTier": "RAW_SOCKET",
        }
    except Exception as exc:  # noqa: BLE001
        log.info("scapy probe failed for %s:%s (%s)", ip, port, exc)
        return None


def probe_stack(ip: str, open_ports: List[int], use_raw: bool = True) -> Dict[str, Any]:
    """Collect stack features with automatic tier selection.

    Result schema (all keys always present):
      ttl, ttlInitialGuess, hopEstimate, dfBit, windowSize, mss, rttMs,
      probeTier  ("RAW_SOCKET" | "ICMP_ONLY"), measuredAtEpoch
    """
    cached = _cache_get(ip)
    if cached:
        return cached

    result: Dict[str, Any] = {
        "ttl": None, "ttlInitialGuess": None, "hopEstimate": None,
        "dfBit": None, "windowSize": None, "mss": None, "rttMs": None,
        "tcpOptions": "", "probeTier": "ICMP_ONLY",
    }

    # Tier A first (only meaningful against an open TCP port).
    if use_raw and open_ports:
        sc = probe_scapy(ip, int(open_ports[0]))
        if sc:
            result.update(sc)

    # Tier B: ping-based TTL works unprivileged and also validates reachability.
    if result["ttl"] is None:
        rt = _ping_ttl(ip)
        if rt is not None:
            result["ttl"] = rt
            result["probeTier"] = "ICMP_ONLY"

    if result["ttl"] is not None:
        result["ttlInitialGuess"] = infer_initial_ttl(result["ttl"])
        result["hopEstimate"] = estimate_hops(result["ttl"])

    # Sanity: reply TTL of a live host cannot exceed the largest bucket.
    if result["ttl"] is not None and result["ttl"] > 255:
        result.update({"ttl": None, "ttlInitialGuess": None, "hopEstimate": None})

    result["measuredAtEpoch"] = int(time.time())
    _cache_put(ip, result)
    return result


def tcp_connect_probe(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Plain connectability check used to confirm 'no open ports' claims."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
