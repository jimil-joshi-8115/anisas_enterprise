"""
Extended IoT/OSINT intelligence sources for Module 4 IoT asset fetching.

Adds 10 additional fingerprinting sources on top of Shodan/Censys/CVEDB:
   1. FOFA            (fofa.info)         - API key required (FOFA_API_KEY)
   2. ZoomEye         (zoomeye.ai)        - API key required (ZOOMEYE_API_KEY)
   3. BinaryEdge      (binaryedge.io)     - API key required (BINARYEDGE_API_KEY)
   4. GreyNoise       (greynoise.io)      - Community endpoint (free); GREYNOISE_API_KEY optional
   5. AlienVault OTX  (otx.alienvault.com)- API key required (OTX_API_KEY)
   6. CVE.org         (cveawg.mitre.org)  - free, no key
   7. EPSS (FIRST)    (api.first.org)     - free, no key
   8. macvendors.com  (api.macvendors.com)- free, no key (rate-limited)
   9. Favicon hash    (mmh3 / Shodan+FOFA compatible) - active HTTP probe
  10. Nmap NSE deep probe (rtsp/onvif/banner) - optional, gated by NMAP_PROBE_ENABLED

EVERY fetcher is read-only, timeout-bounded, and fails silently. Sources that
require an API key activate automatically only when their env var is present.
"""

import os
import re
import json
import base64
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Pure-Python mmh3 (x86, 32-bit) - produces the SAME favicon hash convention
# used by Shodan / FOFA (mmh3 of the base64-encoded favicon bytes), so hashes
# are directly comparable.
# ---------------------------------------------------------------------------
def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    def _rotl(x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    c1, c2 = 0xCC9E2D51, 0x1B873593
    nblocks = len(data) // 4
    h1 = seed & 0xFFFFFFFF
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = _rotl(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= len(data)
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


# ---------------------------------------------------------------------------
# 1. FOFA - host intelligence (Hikvision/Dahua/Huawei centric, great Asia coverage)
#    GET https://fofa.info/api/v1/host/{ip}?key=...&fields=host,ip,port,protocol,product,cpe,banner,title,icon_hash
# ---------------------------------------------------------------------------
def fetch_fofa(clean_ip: str) -> Dict[str, Any]:
    key = os.getenv("FOFA_API_KEY")
    if not key:
        return {}
    try:
        fields = "host,ip,port,protocol,product,cpe,banner,title,icon_hash"
        res = requests.get(
            f"https://fofa.info/api/v1/host/{clean_ip}",
            params={"key": key, "fields": fields, "size": 100},
            timeout=(1.5, 3.0),
        )
        if res.status_code != 200:
            return {}
        body = res.json()
        if body.get("code") != 0:
            return {}
        rows = body.get("results") or []
        products, banners, cpes, ports = [], [], set(), []
        for row in rows:
            row = row if isinstance(row, (list, tuple)) else []
            port = row[2] if len(row) > 2 else None
            product = row[4] if len(row) > 4 and row[4] else None
            cpe = row[5] if len(row) > 5 and row[5] else None
            banner = row[6] if len(row) > 6 and row[6] else None
            title = row[7] if len(row) > 7 and row[7] else None
            if port:
                try:
                    ports.append(int(port))
                except (ValueError, TypeError):
                    pass
            if product:
                products.append({"product": str(product).lower(), "version": None, "port": port, "source": "fofa"})
            if cpe:
                cpes.add(str(cpe))
            text = " ".join([str(banner or ""), str(title or "")]).strip()
            if text:
                banners.append({"port": port, "banner": text[:500], "source": "fofa"})
        return {
            "products": products, "banners": banners, "cpes": sorted(cpes),
            "ports": sorted(set(ports)), "source": "FOFA_HOST_API",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 2. ZoomEye - host intelligence (IoT/surveillance heavy)
# ---------------------------------------------------------------------------
def fetch_zoomeye(clean_ip: str) -> Dict[str, Any]:
    key = os.getenv("ZOOMEYE_API_KEY")
    if not key:
        return {}
    services = []
    try:
        res = requests.get(
            f"https://api.zoomeye.ai/v2/host/{clean_ip}",
            headers={"API-KEY": key, "Accept": "application/json"},
            timeout=(1.5, 3.0),
        )
        if res.status_code in (200, 401, 404):
            pass
        if res.status_code == 200:
            body = res.json() or {}
            resources = ((body.get("data") or {}).get("resources") or [])
            for rsc in resources:
                services.extend(rsc.get("service") or [])
        else:
            # fallback to legacy v1 API
            res1 = requests.get(
                f"https://api.zoomeye.org/host/{clean_ip}?key={key}",
                timeout=(1.5, 3.0),
            )
            if res1.status_code == 200:
                for m in (res1.json() or {}).get("matches") or []:
                    pi = m.get("portinfo") or {}
                    services.append({
                        "port": pi.get("port"), "service": pi.get("service"),
                        "product": pi.get("product"), "version": pi.get("version"),
                        "banner": pi.get("banner"), "cpe": pi.get("cpe"),
                    })
    except Exception:
        return {}

    if not services:
        return {}
    products, banners, cpes, ports = [], [], set(), []
    for s in services:
        if not isinstance(s, dict):
            continue
        port = s.get("port")
        if port:
            try:
                ports.append(int(port))
            except (ValueError, TypeError):
                pass
        prod = s.get("product") or s.get("service")
        if prod:
            products.append({"product": str(prod).lower(), "version": s.get("version"), "port": port, "source": "zoomeye"})
        cpe = s.get("cpe")
        if isinstance(cpe, str) and cpe.strip():
            cpes.add(cpe.strip())
        banner = s.get("banner")
        if banner:
            banners.append({"port": port, "banner": str(banner)[:500], "source": "zoomeye"})
    return {
        "products": products, "banners": banners, "cpes": sorted(cpes),
        "ports": sorted(set(ports)), "source": "ZOOMEYE_HOST_API",
    }


# ---------------------------------------------------------------------------
# 3. BinaryEdge - independent banner/port cross-check
#    GET https://api.binaryedge.io/v2/query/ip/{ip}  (header X-Key)
# ---------------------------------------------------------------------------
def fetch_binaryedge(clean_ip: str) -> Dict[str, Any]:
    key = os.getenv("BINARYEDGE_API_KEY")
    if not key:
        return {}
    try:
        res = requests.get(
            f"https://api.binaryedge.io/v2/query/ip/{clean_ip}",
            headers={"X-Key": key, "Accept": "application/json"},
            timeout=(1.5, 3.0),
        )
        if res.status_code != 200:
            return {}
        events = (res.json() or {}).get("events") or []
        products, banners, ports = [], [], []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            port = ev.get("port")
            if port:
                try:
                    ports.append(int(port))
                except (ValueError, TypeError):
                    pass
            svc = ev.get("service")
            data = (ev.get("result") or {}).get("data") or {}
            d = data.get(svc) or {}
            if isinstance(d, dict):
                prod = d.get("product") or d.get("software")
                if prod:
                    products.append({"product": str(prod).lower(), "version": d.get("version"), "port": port, "source": "binaryedge"})
                banner = d.get("banner") or d.get("response") or d.get("title") or d.get("http")
                if banner and isinstance(banner, str):
                    banners.append({"port": port, "banner": banner[:500], "source": "binaryedge"})
        return {
            "products": products, "banners": banners, "cpes": [],
            "ports": sorted(set(ports)), "source": "BINARYEDGE_QUERY_API",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 4. GreyNoise - internet noise vs real device (reduces false IoT positives)
#    Community endpoint is free / key optional (GREYNOISE_API_KEY).
# ---------------------------------------------------------------------------
def fetch_greynoise(clean_ip: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        headers = {"Accept": "application/json"}
        key = os.getenv("GREYNOISE_API_KEY")
        if key:
            headers["key"] = key
        res = requests.get(f"https://api.greynoise.io/v3/community/{clean_ip}", headers=headers, timeout=(1.5, 3.0))
        # Community endpoint returns HTTP 404 when the IP is NOT observed
        # scanning the internet -- the JSON body still carries noise/riot flags.
        if res.status_code in (200, 404):
            d = res.json() or {}
            if "noise" in d or "riot" in d:
                out = {
                    "noise": bool(d.get("noise")),
                    "riot": bool(d.get("riot")),
                    "classification": d.get("classification"),
                    "name": d.get("name"),
                    "last_seen": d.get("last_seen"),
                    "message": d.get("message"),
                }
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# 5. AlienVault OTX - IoT botnet / threat pulse intelligence
#    GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
# ---------------------------------------------------------------------------
def fetch_otx(clean_ip: str) -> Dict[str, Any]:
    key = os.getenv("OTX_API_KEY")
    if not key:
        return {}
    try:
        res = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{clean_ip}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=(1.5, 3.0),
        )
        if res.status_code != 200:
            return {}
        d = res.json() or {}
        pulses = ((d.get("pulse_info") or {}).get("pulses") or [])
        tags = []
        for p in pulses:
            for t in (p.get("tags") or []):
                if isinstance(t, str) and t.strip():
                    tags.append(t.strip().lower())
        return {
            "pulses": [
                {
                    "name": p.get("name"),
                    "adversary": p.get("adversary"),
                    "description": (p.get("description") or "")[:200],
                    "tags": p.get("tags") or [],
                    "reference": p.get("reference") or [],
                }
                for p in pulses if isinstance(p, dict)
            ][:10],
            "reputation": d.get("reputation"),
            "type": d.get("type"),
            "tags": sorted(set(tags)),
            "source": "ALIENVAULT_OTX",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 6. CVE.org - official CVE metadata (fallback/authoritative layer)
# ---------------------------------------------------------------------------
def fetch_cveorg(cve_id: str) -> Dict[str, Any]:
    try:
        res = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=(1.5, 5.0))
        if res.status_code != 200:
            return {}
        d = res.json() or {}
        cna = (d.get("containers") or {}).get("cna") or {}
        desc = ""
        for x in (cna.get("descriptions") or []):
            if x.get("lang") == "en":
                desc = x.get("value", "")
                break
        score = None
        for m in (cna.get("metrics") or []):
            cvss = m.get("cvssV3_1") or m.get("cvssV3_0")
            if cvss:
                score = cvss.get("baseScore")
                break
        return {
            "cveId": cve_id,
            "summary": desc,
            "cvssScore": score,
            "references": [r.get("url") for r in (cna.get("references") or []) if r.get("url")][:5],
            "source": "CVE.ORG",
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 7. EPSS - Exploit Prediction Scoring (FIRST) probability per CVE
# ---------------------------------------------------------------------------
def fetch_epss(cve_ids: List[str]) -> Dict[str, Any]:
    ids = [c for c in cve_ids if c]
    if not ids:
        return {}
    out: Dict[str, Any] = {}
    try:
        chunk = ",".join(ids[:100])
        res = requests.get("https://api.first.org/data/v1/epss", params={"cve": chunk}, timeout=(1.5, 5.0))
        if res.status_code == 200:
            for item in (res.json() or {}).get("data") or []:
                out[item.get("cve")] = {"epss": item.get("epss"), "percentile": item.get("percentile")}
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# 8. macvendors.com - authoritative MAC vendor lookup
# ---------------------------------------------------------------------------
def fetch_mac_vendor(mac: Optional[str]) -> Dict[str, Any]:
    if not mac or mac in ("N/A", "None", "", None):
        return {}
    normalized = mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if not normalized or len(normalized) < 6:
        return {}
    oui = normalized[:6]
    try:
        res = requests.get(f"https://api.macvendors.com/{oui}", timeout=(1.5, 3.0))
        if res.status_code == 200 and res.text.strip():
            return {"mac": mac, "oui": oui, "vendor": res.text.strip(), "source": "MACVENDORS.COM"}
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# 9. Favicon hash - mmh3(base64(icon)) Shodan/FOFA-compatible fingerprint
# ---------------------------------------------------------------------------
def fetch_favicon_hash(clean_ip: str, open_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    ports = [p for p in (open_ports or []) if p in (80, 443, 8080, 8443, 8888, 5000, 5001, 8000)]
    if not ports:
        ports = [80, 443]
    for port in ports[:3]:
        scheme = "https" if port in (443, 8443) else "http"
        try:
            res = requests.get(
                f"{scheme}://{clean_ip}/favicon.ico",
                timeout=(1.0, 2.5),
                headers={"User-Agent": "Mozilla/5.0 ANISAS-IoT-Intel"},
                verify=False,
            )
            if res.status_code == 200 and res.content:
                b64 = base64.encodebytes(res.content).decode()
                h = mmh3_x86_32(b64.encode())
                return {
                    "hash": h, "size": len(res.content), "port": port,
                    "sha1": __import__("hashlib").sha1(res.content).hexdigest(),
                    "source": "FAVICON_HASH",
                }
        except Exception:
            continue
    return {}


# ---------------------------------------------------------------------------
# 10a. Lightweight Web-Technology fingerprint (Wappalyzer-style, regex based)
# ---------------------------------------------------------------------------
_WEB_TECH_SIGNATURES = [
    # surveillance / camera web UIs
    ("hikvision", r"hikvision"), ("dahua", r"dahua"), ("uniview", r"uniview"),
    ("xiongmai", r"xiongmai|xmeye|雄迈"), ("reolink", r"reolink"),
    ("amcrest", r"amcrest"), ("ezviz", r"ezviz"), ("swann", r"swann"),
    ("lorex", r"lorex"), ("geovision", r"geovision"), ("mobotix", r"mobotix"),
    ("hanwha", r"hanwha|samsung snd|wisenet"), ("axis", r"axis communications|axis-v2"),
    ("vivotek", r"vivotek"), ("avtech", r"avtech"), ("pelco", r"pelco"),
    ("vstarcam", r"vstarcam"), ("netvue", r"netvue"), ("wiseup", r"wiseup"),
    ("hdhdnvr", r"hdhdnvr|hdh"),
    # NAS
    ("synology", r"synology|diskstation|dsm"), ("qnap", r"qnap|qts"),
    ("asustor", r"asustor"), ("terramaster", r"terra.?master"),
    ("wd my cloud", r"mycloud|wd my cloud"),
    # network infra
    ("ubiquiti", r"ubiquiti|unifi|uap"), ("mikrotik", r"mikrotik|routeros"),
    ("tp-link", r"tp-link|tplink"), ("netgear", r"netgear"),
    ("cisco", r"cisco"), ("fortinet", r"fortinet|fortios"),
    ("paloalto", r"paloalto|globalprotect"),
    # generic servers
    ("nginx", r"nginx"), ("apache", r"apache"), ("iis", r"microsoft-iis"),
    ("lighttpd", r"lighttpd"), ("openresty", r"openresty"),
    ("cloudflare", r"cloudflare"), ("gws", r"gws"),
]

_IOT_TECH_BRANDS = {"hikvision", "dahua", "uniview", "xiongmai", "reolink", "amcrest",
                    "ezviz", "swann", "lorex", "geovision", "mobotix", "hanwha", "axis",
                    "vivotek", "avtech", "pelco", "vstarcam", "netvue", "wiseup",
                    "hdhdnvr", "synology", "qnap", "asustor", "terramaster", "wd my cloud",
                    "ubiquiti", "mikrotik", "tp-link", "netgear"}


def detect_web_tech(text_parts: List[str]) -> Dict[str, Any]:
    blob = " ".join(str(t) for t in text_parts).lower()
    found = []
    for brand, pat in _WEB_TECH_SIGNATURES:
        if re.search(pat, blob):
            found.append(brand)
    brands = [b for b in found if b not in ("nginx", "apache", "iis", "lighttpd", "openresty", "cloudflare", "gws")]
    servers = [b for b in found if b in ("nginx", "apache", "iis", "lighttpd", "openresty", "cloudflare", "gws")]
    return {
        "brands": sorted(set(brands)),
        "servers": sorted(set(servers)),
        "iot_brands": sorted(set(brands) & _IOT_TECH_BRANDS),
        "is_iot": bool(set(brands) & _IOT_TECH_BRANDS),
    }


# ---------------------------------------------------------------------------
# 10b. Nmap NSE deep probe (RTSP, ONVIF, banner, http-title). Read-only service
#      fingerprinting. Enabled only when nmap exists AND NMAP_PROBE_ENABLED != "0".
# ---------------------------------------------------------------------------
def _nmap_path() -> Optional[str]:
    for cand in [os.getenv("NMAP_PATH"),
                 r"C:\Program Files (x86)\Nmap\nmap.exe",
                 r"C:\Program Files\Nmap\nmap.exe",
                 "/usr/bin/nmap", "/usr/local/bin/nmap"]:
        if cand and os.path.exists(cand):
            return cand
    return None


def nmap_deep_probe(clean_ip: str, open_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    if os.getenv("NMAP_PROBE_ENABLED", "1").lower() in ("0", "false", "no"):
        return {}
    nmp = _nmap_path()
    if not nmp:
        return {}
    ports = list(set(int(p) for p in (open_ports or []) if str(p).isdigit()))
    candidates = [p for p in ports if p in (22, 23, 80, 443, 554, 8554, 5000, 5001, 8000, 8080, 8443, 8899, 3702, 1900, 37777, 161)]
    if not candidates:
        candidates = [80, 443, 554, 8080, 8443]
    port_str = ",".join(str(p) for p in sorted(set(candidates))[:12])
    cmd = [
        nmp, "-Pn", "-sV", "--version-light",
        "-p", port_str,
        "--script", "banner,http-title,http-server-header,http-headers,http-auth,rtsp-methods,snmp-info,ssh2-enum-algos",
        "--host-timeout", "15s",
        "-oX", "-", clean_ip,
    ]
    try:
        _no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, creationflags=_no_window)
    except Exception:
        return {}
    xml = (proc.stdout or "").strip()
    if not xml:
        return {}
    products, banners, ports_found, scripts_run, hostnames, macs = [], [], [], [], [], []
    try:
        root = ET.fromstring(xml)
        for host in root.iter("host"):
            for addr in host.iter("address"):
                if addr.get("addrtype") == "ipv4":
                    continue
                if addr.get("addrtype") == "mac":
                    macs.append(addr.get("addr"))
            for hn in host.iter("hostname"):
                nm = hn.get("name")
                if nm:
                    hostnames.append(nm)
            for port in host.iter("port"):
                port_id = port.get("portid")
                state = port.find("state")
                if state is not None and state.get("state") == "open" and port_id:
                    try:
                        ports_found.append(int(port_id))
                    except ValueError:
                        pass
                service = port.find("service")
                if service is not None:
                    prod = service.get("product")
                    if prod:
                        products.append({
                            "product": str(prod).lower(),
                            "version": service.get("version"),
                            "port": int(port_id) if port_id else None,
                            "source": "nmap",
                        })
                    b = service.get("banner") or service.get("extrainfo") or service.get("version")
                    if b:
                        banners.append({"port": port_id, "banner": str(b)[:400], "source": "nmap"})
            for script in host.iter("script"):
                sid = script.get("id")
                out = script.get("output") or ""
                if sid:
                    scripts_run.append(sid)
                if out:
                    banners.append({"port": None, "banner": f"{sid}: {out[:350]}", "source": "nmap"})
    except Exception:
        pass
    return {
        "products": products, "banners": banners,
        "ports": sorted(set(ports_found)),
        "scripts": sorted(set(scripts_run)),
        "hostnames": hostnames,
        "mac": macs[0] if macs else None,
        "source": "NMAP_NSE",
        "nmap": True,
    }


# ---------------------------------------------------------------------------
# Master collector - runs all sources in parallel and normalizes into one dict
# ---------------------------------------------------------------------------
def fetch_extended_intel(
    clean_ip: str,
    open_ports: Optional[List[int]] = None,
    mac: Optional[str] = None,
) -> Dict[str, Any]:
    tasks = [
        ("fofa", lambda: fetch_fofa(clean_ip)),
        ("zoomeye", lambda: fetch_zoomeye(clean_ip)),
        ("binaryedge", lambda: fetch_binaryedge(clean_ip)),
        ("greynoise", lambda: fetch_greynoise(clean_ip)),
        ("otx", lambda: fetch_otx(clean_ip)),
        ("macvendors", lambda: fetch_mac_vendor(mac)),
        ("favicon", lambda: fetch_favicon_hash(clean_ip, open_ports)),
        ("nmap", lambda: nmap_deep_probe(clean_ip, open_ports)),
    ]
    results: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks}
        for fut in futures:
            name = futures[fut]
            try:
                r = fut.result()
            except Exception:
                r = {}
            if r:
                results[name] = r

    products: List[Dict[str, Any]] = []
    banners: List[Dict[str, Any]] = []
    cpes: set = set()
    ports: set = set()
    tags: list = []
    active_sources: list = []
    tech_text: List[str] = []

    for name, r in results.items():
        if not isinstance(r, dict):
            continue
        active_sources.append(name)
        products.extend(r.get("products", []) or [])
        banners.extend(r.get("banners", []) or [])
        cpes.update(r.get("cpes", []) or [])
        ports.update(r.get("ports", []) or [])
        if name == "otx":
            tags.extend(r.get("tags", []) or [])
        tech_text.append(json.dumps(r))

    web_tech = detect_web_tech(tech_text)
    for b in web_tech.get("brands", []):
        products.append({"product": b, "version": None, "port": None, "source": "web-tech"})
        tags.append(b)

    nmap_ports = (results.get("nmap") or {}).get("ports", []) or []
    hostnames = []
    for _src in ("nmap", "otx"):
        for h in (results.get(_src) or {}).get("hostnames", []) or []:
            if h and h not in hostnames:
                hostnames.append(h)

    return {
        "active_sources": active_sources,
        "cpes": sorted(cpes),
        "products": products,
        "banners": banners,
        "ports": sorted(set(ports) | set(nmap_ports)),
        "tags": sorted(set(tags)),
        "hostnames": hostnames,
        "mac": (results.get("nmap") or {}).get("mac"),
        "greynoise": results.get("greynoise", {}),
        "otx": results.get("otx", {}),
        "mac_vendor": results.get("macvendors", {}),
        "favicon": results.get("favicon", {}),
        "nmap": results.get("nmap", {}),
        "fofa": {k: results["fofa"][k] for k in ("source",) if k in results.get("fofa", {})} or None,
        "zoomeye": results.get("zoomeye", {}),
        "binaryedge": results.get("binaryedge", {}),
        "web_tech": web_tech,
        "epss": {},
    }


def enrich_epss(cve_ids: List[str]) -> Dict[str, Any]:
    """Expose EPSS enrichment for a batch of CVE IDs (used by CVE sections)."""
    return fetch_epss(cve_ids)


if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "211.20.100.35"
    data = fetch_extended_intel(ip, mac=os.getenv("TEST_MAC"))
    print(json.dumps({k: v for k, v in data.items() if k not in ("products", "banners")}, indent=1, default=str))
    print("products:", len(data["products"]), "banners:", len(data["banners"]), "sources:", data["active_sources"])
