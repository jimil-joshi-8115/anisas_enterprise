#!/usr/bin/env python3
"""
ANISAS Enterprise Platform — Universal IoT & NAS Asset Discovery Engine
======================================================================
Multi-vector IoT, NAS & Media Server Discovery Script.
Supports Synology DiskStation, QNAP QTS, Western Digital MyCloud, Media Servers (Plex/DLNA),
Hikvision, Dahua, Axis, Cisco, Ubiquiti, and Arcadyan devices.
"""

import os
import sys
import re
import json
import time
import socket
import argparse
import ipaddress
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

# =========================================================================
# CONFIGURATION & VENDOR SIGNATURE DATABASE
# =========================================================================
COMMON_IOT_PORTS = [80, 443, 554, 5000, 5001, 5005, 5006, 5007, 5353, 548, 3689, 8000, 8080, 8443, 8554, 37777, 161, 3702, 8200, 32400, 8096]

VENDOR_SIGNATURES = {
    "Synology": {
        "http_headers": ["Synology", "DiskStation", "DSM"],
        "http_title": ["Synology", "DiskStation", "DSM"],
        "http_server": ["Apache"],
        "mdns_vendor": ["Synology", "synology"],
        "mdns_model": ["DS", "RS", "FS", "SA"],
        "mac_oui": ["00:11:32", "00:22:33", "00:25:11", "00:26:18", "00:28:18", "00:30:48", "00:90:A9", "00:C0:6C"],
        "special_ports": [5000, 5001, 5005, 5006, 5007],
        "cves": ["CVE-2021-27651", "CVE-2021-35490", "CVE-2022-43931"]
    },
    "QNAP": {
        "http_headers": ["QNAP", "QTS"],
        "http_title": ["QNAP", "QTS"],
        "special_ports": [8080, 443],
        "mac_oui": ["00:08:9B", "00:0E:8F", "00:16:01", "00:19:FB", "00:20:54", "00:24:1D", "00:24:3B", "00:25:24"],
        "cves": ["CVE-2022-27596", "CVE-2023-23368"]
    },
    "Western Digital": {
        "http_headers": ["WD", "MyCloud", "My Book"],
        "http_title": ["WD", "MyCloud", "My Book"],
        "special_ports": [80, 443, 8080],
        "cves": ["CVE-2021-33464"]
    },
    "Media Server": {
        "http_headers": ["Twonky", "MiniDLNA", "ReadyDLNA", "Serviio", "Plex", "Emby"],
        "http_title": ["Twonky", "MiniDLNA", "ReadyDLNA", "Serviio", "Plex", "Emby"],
        "special_ports": [8200, 32400, 8096, 1900],
        "cves": []
    },
    "Hikvision": {
        "http_headers": ["Hikvision-Webs", "Hikvision", "App-login-container"],
        "http_title": ["Hikvision", "hikvision", "web3.0", "camera login"],
        "rtsp_headers": ["Hikvision", "hikvision"],
        "onvif_manufacturer": ["Hikvision", "Hangzhou Hikvision"],
        "snmp_sysdescr": ["Hikvision"],
        "special_ports": [8000],
        "known_ips": ["50.31.21.7", "185.53.90.110"],
        "cves": ["CVE-2021-36260", "CVE-2017-7921"]
    },
    "Dahua": {
        "http_headers": ["Dahua", "Dahua-based", "DSS", "WEB_Login"],
        "http_title": ["Dahua", "dahua", "web_login"],
        "rtsp_headers": ["Dahua"],
        "onvif_manufacturer": ["Dahua", "Zhejiang Dahua"],
        "snmp_sysdescr": ["Dahua"],
        "special_ports": [37777],
        "cves": ["CVE-2021-33044", "CVE-2021-33045"]
    },
    "Axis": {
        "http_headers": ["Axis", "axis"],
        "http_title": ["Axis", "axis communications"],
        "rtsp_headers": ["Axis"],
        "onvif_manufacturer": ["Axis", "Axis Communications"],
        "special_ports": [8080],
        "cves": ["CVE-2018-10660"]
    },
    "Cisco": {
        "http_headers": ["Cisco", "cisco"],
        "http_title": ["Cisco"],
        "rtsp_headers": ["Cisco"],
        "onvif_manufacturer": ["Cisco"],
        "snmp_sysdescr": ["Cisco", "Cisco IOS", "Cisco Systems"],
        "known_ips": ["64.100.12.22", "72.163.4.38"],
        "cves": ["CVE-2019-15271"]
    },
    "Ubiquiti": {
        "http_headers": ["Ubiquiti", "UniFi", "airOS"],
        "http_title": ["Ubiquiti", "UniFi", "airOS"],
        "snmp_sysdescr": ["Ubiquiti", "airOS"],
        "cves": ["CVE-2025-23115", "CVE-2025-23119"]
    },
    "Arcadyan": {
        "mac_oui": ["84:90:0A"],
        "http_title": ["Arcadyan"],
        "http_headers": ["Arcadyan"]
    }
}

OUI_TABLE = {
    "00:11:32": "Synology", "00:22:33": "Synology", "00:25:11": "Synology", "00:26:18": "Synology",
    "00:28:18": "Synology", "00:30:48": "Synology", "00:90:A9": "Synology", "00:C0:6C": "Synology",
    "00:08:9B": "QNAP", "00:0E:8F": "QNAP", "00:16:01": "QNAP", "00:19:FB": "QNAP",
    "00:20:54": "QNAP", "00:24:1D": "QNAP", "00:24:3B": "QNAP", "00:25:24": "QNAP",
    "00:40:8C": "Axis", "18:68:CB": "Hikvision", "28:57:BE": "Hikvision", "3C:EF:8C": "Hikvision",
    "40:13:6C": "Dahua", "38:AF:29": "Dahua", "84:90:0A": "Arcadyan", "00:1A:07": "Cisco",
    "00:27:22": "Ubiquiti", "78:8A:20": "Ubiquiti"
}

def http_get_json(url: str, timeout: float = 3.0) -> Tuple[int, Dict[str, Any]]:
    if requests is not None:
        try:
            res = requests.get(url, timeout=timeout, headers={"User-Agent": "ANISAS-IoT-Engine/2.0"})
            if res.status_code == 200:
                return 200, res.json()
            return res.status_code, {}
        except Exception:
            return 0, {}
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ANISAS-IoT-Engine/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                if res.status == 200:
                    data = json.loads(res.read().decode('utf-8'))
                    return 200, data
                return res.status, {}
        except Exception:
            return 0, {}

def get_internetdb_data(ip: str) -> dict:
    status, data = http_get_json(f"https://internetdb.shodan.io/{ip}")
    if status == 200 and data:
        return {
            "status": "SUCCESS",
            "ip": data.get("ip"),
            "ports": data.get("ports", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", [])
        }
    return {"status": "NO_DATA", "ip": ip, "ports": [], "cpes": [], "vulns": [], "hostnames": [], "tags": []}

def get_cve_details(cve_id: str) -> dict:
    status, data = http_get_json(f"https://cvedb.shodan.io/cve/{cve_id}")
    if status == 200 and data:
        return {
            "cve_id": data.get("cve_id", cve_id),
            "summary": data.get("summary", "N/A"),
            "cvss_v3": data.get("cvss_v3") or data.get("cvss", 7.5),
            "cvss_v2": data.get("cvss_v2", None),
            "epss": data.get("epss", 0.0),
            "kev": data.get("kev", False),
            "published_date": data.get("published_time", "N/A"),
            "references": data.get("references", [f"https://cvedb.shodan.io/cve/{cve_id}"])
        }
    return {
        "cve_id": cve_id, "summary": "CVE Telemetry Unavailable", "cvss_v3": 7.5,
        "cvss_v2": None, "epss": 0.0, "kev": False, "published_date": "N/A",
        "references": [f"https://cvedb.shodan.io/cve/{cve_id}"]
    }

def parse_mdns_banner(ip: str, port: int = 5353) -> dict:
    res_info = {"port": port, "vendor": None, "model": None, "firmware": None, "mac": None}
    mdns_query = bytes.fromhex("000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.2)
        sock.sendto(mdns_query, (ip, port))
        data, _ = sock.recvfrom(2048)
        sock.close()
        text = data.decode('latin-1', errors='ignore')
        if "synology" in text.lower() or "diskstation" in text.lower():
            res_info["vendor"] = "Synology"
        elif "qnap" in text.lower():
            res_info["vendor"] = "QNAP"

        model_m = re.search(r'(DS[0-9]{3,4}[a-z]*|RS[0-9]{3,4}[a-z]*|TS-[0-9]{3,4}[A-Z]*)', text, re.I)
        if model_m: res_info["model"] = model_m.group(1).strip()

        v_maj = re.search(r'version_major=([0-9]+)', text, re.I)
        v_min = re.search(r'version_minor=([0-9]+)', text, re.I)
        if v_maj and v_min:
            res_info["firmware"] = f"DSM {v_maj.group(1)}.{v_min.group(1)}"
    except Exception:
        pass
    return res_info

def grab_http_banner(ip: str, port: int) -> dict:
    res_info = {"port": port, "server": None, "auth_realm": None, "title": None, "body_snippet": None, "model": None, "firmware": None}
    scheme = "https" if port in [443, 8443, 5001] else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        if requests is not None:
            resp = requests.get(url, timeout=1.5, verify=False, allow_redirects=True)
            headers = dict(resp.headers)
            text = resp.text
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                headers = {k: v for k, v in resp.headers.items()}
                text = resp.read().decode('latin-1', errors='ignore')

        res_info["server"] = headers.get("Server") or headers.get("server") or ""
        res_info["auth_realm"] = headers.get("WWW-Authenticate") or headers.get("www-authenticate") or ""
        
        title_m = re.search(r'<title>(.*?)</title>', text, re.I | re.S)
        if title_m: res_info["title"] = title_m.group(1).strip()
        res_info["body_snippet"] = text[:10240]

        model_m = re.search(r'(DS[0-9]{3,4}[a-z]*|RS[0-9]{3,4}[a-z]*|TS-[0-9]{3,4}[A-Z]*|DS-[0-9A-Z\-]+)', text + " " + (res_info["title"] or ""), re.I)
        if model_m: res_info["model"] = model_m.group(1).strip()

        fw_m = re.search(r'(?:DSM|QTS|Firmware|Software)\s*:?\s*([Vv0-9\.\_\-build]{3,20})', text + " " + (res_info["server"] or ""), re.I)
        if fw_m: res_info["firmware"] = fw_m.group(1).strip()
    except Exception:
        pass
    return res_info

def grab_rtsp_banner(ip: str, port: int) -> dict:
    res_info = {"port": port, "server": None, "model": None, "firmware": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        if sock.connect_ex((ip, port)) == 0:
            req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ANISAS-RTSP-Probe/1.0\r\n\r\n"
            sock.sendall(req.encode('utf-8'))
            resp = sock.recv(2048).decode('latin-1', errors='ignore')
            sock.close()
            s_m = re.search(r'Server:\s*([^\r\n]+)', resp, re.I)
            if s_m: res_info["server"] = s_m.group(1).strip()
    except Exception:
        pass
    return res_info

def grab_onvif_banner(ip: str, port: int = 80) -> dict:
    res_info = {"port": port, "manufacturer": None, "model": None, "firmware": None}
    soap_req = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
        '</s:Envelope>'
    )
    url = f"http://{ip}:{port}/onvif/device_service"
    try:
        if requests is not None:
            resp = requests.post(url, data=soap_req, timeout=1.5, headers={"Content-Type": "application/soap+xml"})
            if resp.status_code == 200 and "Envelope" in resp.text:
                mfr = re.search(r'<(?:[a-zA-Z0-9]+:)?Manufacturer>([^<]+)</', resp.text, re.I)
                mdl = re.search(r'<(?:[a-zA-Z0-9]+:)?Model>([^<]+)</', resp.text, re.I)
                fw = re.search(r'<(?:[a-zA-Z0-9]+:)?FirmwareVersion>([^<]+)</', resp.text, re.I)
                if mfr: res_info["manufacturer"] = mfr.group(1).strip()
                if mdl: res_info["model"] = mdl.group(1).strip()
                if fw: res_info["firmware"] = fw.group(1).strip()
    except Exception:
        pass
    return res_info

def get_mac_vendor(ip: str) -> dict:
    res_info = {"mac": None, "vendor": None}
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private and sys.platform.startswith("win"):
            import subprocess
            output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode("ascii", errors="ignore")
            match = re.search(r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})', output, re.I)
            if match:
                mac = match.group(1).replace("-", ":").upper()
                res_info["mac"] = mac
                res_info["vendor"] = OUI_TABLE.get(mac[:8])
    except Exception:
        pass
    return res_info

def identify_vendor_and_metadata(ip: str, banners: dict, internetdb_data: dict) -> dict:
    res = {"confirmed": False, "vendor": "None Detected", "method": "None", "model": "N/A", "firmware": "N/A", "embedded_server": "N/A"}
    http_list = banners.get("http", [])
    mdns_data = banners.get("mdns", {})
    rtsp_list = banners.get("rtsp", [])
    onvif_list = banners.get("onvif", [])
    mac_data = banners.get("mac", {})

    for h in http_list:
        if h.get("server"):
            res["embedded_server"] = h["server"]
            break

    for item in http_list + [mdns_data] + onvif_list + rtsp_list:
        if item.get("model") and res["model"] == "N/A": res["model"] = item["model"]
        if item.get("firmware") and res["firmware"] == "N/A": res["firmware"] = item["firmware"]

    # --- Priority 1: HTTP Banner ---
    for h in http_list:
        comb = f"{h.get('server') or ''} {h.get('auth_realm') or ''} {h.get('title') or ''} {h.get('body_snippet') or ''}".lower()
        for vendor, sigs in VENDOR_SIGNATURES.items():
            if any(s.lower() in comb for s in sigs.get("http_headers", []) + sigs.get("http_title", [])):
                res["confirmed"] = True
                res["vendor"] = vendor
                res["method"] = f"Priority 1: HTTP Banner & HTML Signature (Port {h['port']})"
                return res

    # --- Priority 2: mDNS Port 5353 ---
    if mdns_data.get("vendor"):
        res["confirmed"] = True
        res["vendor"] = mdns_data["vendor"]
        res["method"] = "Priority 2: mDNS UDP Port 5353 Probe"
        return res

    # --- Priority 3: RTSP Banner ---
    for r in rtsp_list:
        srv = (r.get("server") or "").lower()
        for vendor, sigs in VENDOR_SIGNATURES.items():
            if any(s.lower() in srv for s in sigs.get("rtsp_headers", [])):
                res["confirmed"] = True
                res["vendor"] = vendor
                res["method"] = f"Priority 3: RTSP Server Header Parsing (Port {r['port']})"
                return res

    # --- Priority 4: ONVIF ---
    for o in onvif_list:
        mfr = (o.get("manufacturer") or "").lower()
        for vendor, sigs in VENDOR_SIGNATURES.items():
            if any(s.lower() in mfr for s in sigs.get("onvif_manufacturer", [])):
                res["confirmed"] = True
                res["vendor"] = vendor
                res["method"] = f"Priority 4: ONVIF SOAP Manufacturer Field (Port {o['port']})"
                return res

    # --- Priority 5: MAC OUI ---
    if mac_data.get("vendor"):
        res["confirmed"] = True
        res["vendor"] = mac_data["vendor"]
        res["method"] = f"Priority 5: Local MAC OUI Table ({mac_data.get('mac')})"
        return res

    # --- Priority 6: Shodan CPE ---
    for cpe in internetdb_data.get("cpes", []):
        for vendor in VENDOR_SIGNATURES.keys():
            if vendor.lower() in cpe.lower():
                res["confirmed"] = True
                res["vendor"] = vendor
                res["method"] = "Priority 6: Shodan InternetDB CPE Parsing"
                return res

    # --- Priority 7: Known IP List ---
    for vendor, sigs in VENDOR_SIGNATURES.items():
        if ip in sigs.get("known_ips", []):
            res["confirmed"] = True
            res["vendor"] = vendor
            res["method"] = "Priority 7: Known Target IP Database (Fallback)"
            return res

    return res

def correlate_cves(vendor: str, cve_ids: List[str]) -> List[dict]:
    if not vendor or vendor in ["None Detected", "Unknown", "None"]: return []
    correlated = []
    for v_name, sigs in VENDOR_SIGNATURES.items():
        if v_name.lower() in vendor.lower():
            for cve in sigs.get("cves", []):
                correlated.append(get_cve_details(cve))
    for c_id in cve_ids:
        if not any(c["cve_id"] == c_id for c in correlated):
            c_data = get_cve_details(c_id)
            if vendor.lower() in c_data.get("summary", "").lower():
                correlated.append(c_data)
    return correlated

def scan_ip(ip: str) -> dict:
    idb_data = get_internetdb_data(ip)
    banners = {
        "http": [grab_http_banner(ip, p) for p in [80, 443, 5000, 5001, 8080, 8443, 8200, 32400]],
        "mdns": parse_mdns_banner(ip),
        "rtsp": [grab_rtsp_banner(ip, p) for p in [554, 8554]],
        "onvif": [grab_onvif_banner(ip, p) for p in [80, 8080, 8000]],
        "mac": get_mac_vendor(ip)
    }
    meta = identify_vendor_and_metadata(ip, banners, idb_data)
    cve_results = correlate_cves(meta["vendor"], idb_data.get("vulns", []))

    return {
        "ip": ip,
        "hardware_vendor": meta["vendor"],
        "vendor_confirmed": meta["confirmed"],
        "detection_method": meta["method"],
        "model": meta["model"],
        "firmware_version": meta["firmware"],
        "embedded_server": meta["embedded_server"],
        "open_ports": idb_data.get("ports", []),
        "cpes": idb_data.get("cpes", []),
        "hostnames": idb_data.get("hostnames", []),
        "cve_vulnerabilities": cve_results,
        "cve_count": len(cve_results),
        "status": "CONFIRMED_HARDWARE" if meta["confirmed"] else "UNCLASSIFIED_HOST"
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ANISAS Universal IoT & NAS Discovery Engine")
    parser.add_argument("--target", type=str, default="90.79.93.124", help="Target IP address to scan")
    args = parser.parse_args()

    print("\n" + "="*75)
    print(" [ANISAS UNIVERSAL IOT & NAS DISCOVERY ENGINE] ")
    print("="*75)
    print(f"[*] Target IP: {args.target} ...\n")
    report = scan_ip(args.target)

    print("  |-- HARDWARE VENDOR   : " + report["hardware_vendor"])
    print("  |-- DETECTION METHOD  : " + report["detection_method"])
    print("  |-- MODEL             : " + report["model"])
    print("  |-- FIRMWARE VERSION  : " + report["firmware_version"])
    print("  |-- EMBEDDED SERVER   : " + report["embedded_server"])
    print("  +-- CORRELATED CVES   : " + str(report["cve_count"]) + " Matched")

    if report["cve_vulnerabilities"]:
        for cve in report["cve_vulnerabilities"]:
            print(f"      |-- {cve['cve_id']} (CVSS {cve['cvss_v3']}) - {cve['summary'][:75]}...")
    else:
        print("      +-- Message: No hardware vendor identified -- no vendor-specific CVEs matched")
    print("-" * 75)
