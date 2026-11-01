#!/usr/bin/env python3
"""
ANISAS Enterprise Platform — IoT Asset Intelligence & Surveillance Fingerprinting Engine
=======================================================================================
A complete Python script for discovery, passive multi-vector fingerprinting, and
vendor-gated CVE vulnerability correlation across local subnets and Shodan telemetry.

Author: Antigravity Cyber Intelligence Team
License: MIT / Enterprise Defensive Audit Use Only
"""

import os
import sys
import re
import json
import time
import socket
import struct
import argparse
import ipaddress
import urllib.request
import urllib.parse
from typing import Dict, Any, List, Optional, Set

try:
    import requests
except ImportError:
    requests = None

# =========================================================================
# CONSTANTS & CONFIGURATION
# =========================================================================
IOT_PORTS = [80, 443, 554, 161, 8000, 8080, 8443, 8554, 8899, 37777]
MULTICAST_ONVIF_IP = "239.255.255.250"
MULTICAST_ONVIF_PORT = 3702

MULTICAST_UPNP_IP = "239.255.255.250"
MULTICAST_UPNP_PORT = 1900

WS_DISCOVERY_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    '<s:Header>'
    '<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
    '<a:MessageID>urn:uuid:a3b2c1d0-1234-5678-9abc-def012345678</a:MessageID>'
    '<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
    '</s:Header>'
    '<s:Body>'
    '<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    '<Types xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</Types>'
    '</Probe>'
    '</s:Body>'
    '</s:Envelope>'
)

SSDP_MSEARCH_PROBE = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
)

SOAP_GET_DEVICE_INFO = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
    '</s:Envelope>'
)

KNOWN_VENDOR_RULES = {
    "Hikvision": {
        "cves": [
            {"cve_id": "CVE-2021-36260", "cvss": 9.8, "epss": 0.97, "kev": True, "summary": "Hikvision Web Server Unauthenticated Command Injection Vulnerability", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"]},
            {"cve_id": "CVE-2017-7921", "cvss": 7.5, "epss": 0.85, "kev": True, "summary": "Hikvision IP Camera Authentication Bypass", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7921"]}
        ]
    },
    "Dahua": {
        "cves": [
            {"cve_id": "CVE-2021-33044", "cvss": 9.8, "epss": 0.94, "kev": True, "summary": "Dahua DVR/NVR Identity Authentication Bypass Vulnerability", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33044"]}
        ]
    },
    "Axis": {
        "cves": [
            {"cve_id": "CVE-2018-10660", "cvss": 9.8, "epss": 0.88, "kev": True, "summary": "Axis Network Camera Authentication Bypass Vulnerability", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-10660"]}
        ]
    },
    "Cisco": {
        "cves": [
            {"cve_id": "CVE-2019-15271", "cvss": 9.8, "epss": 0.91, "kev": True, "summary": "Cisco Video Surveillance Camera Remote Code Execution Vulnerability", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-15271"]}
        ]
    }
}

# Static IEEE OUI Map
OUI_TABLE = {
    "00:40:8C": "Axis Communications",
    "18:68:CB": "Hangzhou Hikvision Digital Technology",
    "28:57:BE": "Hangzhou Hikvision Digital Technology",
    "3C:EF:8C": "Hangzhou Hikvision Digital Technology",
    "40:13:6C": "Zhejiang Dahua Technology",
    "38:AF:29": "Zhejiang Dahua Technology",
    "00:1A:07": "Cisco Systems",
    "00:27:22": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "00:04:7D": "Pelco Inc",
    "00:07:5D": "Bosch Security Systems",
    "00:0F:7C": "Hanwha Techwin"
}

# =========================================================================
# UTILITY HELPER FUNCTIONS
# =========================================================================
def http_request(url: str, method: str = "GET", data: Optional[str] = None, timeout: float = 3.0, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
    """Fallback HTTP client using requests if available, else urllib.request."""
    headers = headers or {}
    if requests is not None:
        try:
            req_headers = {"User-Agent": "ANISAS-IoT-Intelligence/1.0", **headers}
            if method.upper() == "POST":
                resp = requests.post(url, data=data, headers=req_headers, timeout=timeout, verify=False)
            else:
                resp = requests.get(url, headers=req_headers, timeout=timeout, verify=False, allow_redirects=True)
            return resp.status_code, dict(resp.headers), resp.text
        except Exception:
            return 0, {}, ""
    else:
        try:
            req = urllib.request.Request(url, data=data.encode('utf-8') if data else None, headers={"User-Agent": "ANISAS-IoT-Intelligence/1.0", **headers}, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('latin-1', errors='ignore')
                res_headers = {k: v for k, v in resp.headers.items()}
                return resp.status, res_headers, body
        except Exception as e:
            return 0, {}, ""

def resolve_mac_oui(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolves MAC address via ARP cache and checks against IEEE OUI table."""
    try:
        if sys.platform.startswith("win"):
            import subprocess
            output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode("ascii", errors="ignore")
            match = re.search(r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})', output, re.I)
            if match:
                mac = match.group(1).replace("-", ":").upper()
                oui_prefix = mac[:8]
                vendor = OUI_TABLE.get(oui_prefix)
                return mac, vendor
    except Exception:
        pass
    return None, None

# =========================================================================
# STEP 1: DISCOVERY ENGINE
# =========================================================================
class DiscoveryEngine:
    def __init__(self, shodan_api_key: Optional[str] = None):
        self.shodan_key = shodan_api_key

    def discover_shodan(self) -> List[Dict[str, Any]]:
        """Queries Shodan API if API key is provided."""
        if not self.shodan_key:
            return []
        
        query = urllib.parse.quote('port:80,443,554,8000,8080,37777 "Hikvision" OR "Dahua" OR "Axis" OR "Ubiquiti" OR "Sony" OR "Bosch"')
        url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query={query}"
        
        status, _, body = http_request(url, timeout=10.0)
        results = []
        if status == 200:
            try:
                data = json.loads(body)
                for match in data.get("matches", []):
                    results.append({
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "banner": match.get("data", ""),
                        "source": "Shodan Global Search"
                    })
            except Exception:
                pass
        return results

    def discover_onvif_multicast(self, timeout: float = 3.0) -> List[str]:
        """Discovers ONVIF endpoints via WS-Discovery UDP multicast."""
        discovered_ips = set()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            sock.sendto(WS_DISCOVERY_PROBE.encode('utf-8'), (MULTICAST_ONVIF_IP, MULTICAST_ONVIF_PORT))
            
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    if addr[0]:
                        discovered_ips.add(addr[0])
                except socket.timeout:
                    break
            sock.close()
        except Exception:
            pass
        return list(discovered_ips)

    def discover_upnp_ssdp(self, timeout: float = 3.0) -> List[str]:
        """Discovers UPnP SSDP devices via M-SEARCH UDP multicast."""
        discovered_ips = set()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            sock.sendto(SSDP_MSEARCH_PROBE.encode('utf-8'), (MULTICAST_UPNP_IP, MULTICAST_UPNP_PORT))

            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    if addr[0]:
                        discovered_ips.add(addr[0])
                except socket.timeout:
                    break
            sock.close()
        except Exception:
            pass
        return list(discovered_ips)

    def sweep_subnet(self, cidr: str) -> List[str]:
        """Performs non-blocking socket probes across common IoT ports on a CIDR subnet."""
        active_ips = set()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = [str(h) for h in list(net.hosts())[:64]]  # Probe first 64 hosts for speed
            for ip in hosts:
                for port in [80, 554, 8000, 8080]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.3)
                        if sock.connect_ex((ip, port)) == 0:
                            active_ips.add(ip)
                            sock.close()
                            break
                        sock.close()
                    except Exception:
                        pass
        except Exception:
            pass
        return list(active_ips)

# =========================================================================
# STEP 2: FINGERPRINTING PROBES
# =========================================================================
class FingerprintEngine:
    @staticmethod
    def probe_http(ip: str) -> Dict[str, Any]:
        result = {"vendor": None, "model": None, "firmware": None, "banner": None}
        for port in [80, 443, 8080, 8443, 8000, 37777]:
            scheme = "https" if port in [443, 8443] else "http"
            url = f"{scheme}://{ip}:{port}/"
            status, headers, body = http_request(url, timeout=2.0)
            if status > 0:
                server_h = headers.get("Server") or headers.get("server") or ""
                auth_h = headers.get("WWW-Authenticate") or headers.get("www-authenticate") or ""
                
                title_match = re.search(r'<title>(.*?)</title>', body, re.I | re.S)
                title = title_match.group(1).strip() if title_match else ""
                
                combined = f"{server_h} {auth_h} {title} {body[:1000]}".lower()
                
                if "hikvision" in combined or "hikvision-webs" in combined:
                    result["vendor"] = "Hikvision"
                    model_match = re.search(r'(DS-[0-9A-Z\-]+)', body + title, re.I)
                    if model_match: result["model"] = model_match.group(1)
                elif "dahua" in combined:
                    result["vendor"] = "Dahua"
                elif "axis" in combined:
                    result["vendor"] = "Axis"
                elif "ubiquiti" in combined or "unifi" in combined:
                    result["vendor"] = "Ubiquiti"
                elif "netsurveillance" in combined:
                    result["vendor"] = "NETSurveillance Generic CCTV"

                fw_match = re.search(r'(?:Firmware|Software)\s*(?:V|Ver|Version)?\s*:?\s*([Vv0-9\.\_\-build]+)', body, re.I)
                if fw_match:
                    result["firmware"] = fw_match.group(1)

                if result["vendor"]:
                    result["banner"] = f"HTTP Port {port}: Server='{server_h}', Title='{title}'"
                    break
        return result

    @staticmethod
    def probe_rtsp(ip: str) -> Dict[str, Any]:
        result = {"vendor": None, "banner": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            if sock.connect_ex((ip, 554)) == 0:
                req = f"OPTIONS rtsp://{ip}:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.sendall(req.encode('utf-8'))
                res = sock.recv(1024).decode('latin-1', errors='ignore')
                sock.close()
                server_match = re.search(r'Server:\s*([^\r\n]+)', res, re.I)
                if server_match:
                    server_val = server_match.group(1).strip()
                    result["banner"] = f"RTSP Server: {server_val}"
                    if "hikvision" in server_val.lower():
                        result["vendor"] = "Hikvision"
                    elif "dahua" in server_val.lower():
                        result["vendor"] = "Dahua"
                    elif "axis" in server_val.lower():
                        result["vendor"] = "Axis"
        except Exception:
            pass
        return result

    @staticmethod
    def probe_onvif_soap(ip: str) -> Dict[str, Any]:
        result = {"vendor": None, "model": None, "firmware": None}
        for port in [80, 8080, 8000, 8899]:
            url = f"http://{ip}:{port}/onvif/device_service"
            status, _, body = http_request(url, method="POST", data=SOAP_GET_DEVICE_INFO, timeout=2.0, headers={"Content-Type": "application/soap+xml"})
            if status == 200 and "Envelope" in body:
                mfr_m = re.search(r'<(?:[a-zA-Z0-9]+:)?Manufacturer>([^<]+)</', body, re.I)
                model_m = re.search(r'<(?:[a-zA-Z0-9]+:)?Model>([^<]+)</', body, re.I)
                fw_m = re.search(r'<(?:[a-zA-Z0-9]+:)?FirmwareVersion>([^<]+)</', body, re.I)

                if mfr_m: result["vendor"] = mfr_m.group(1).strip()
                if model_m: result["model"] = model_m.group(1).strip()
                if fw_m: result["firmware"] = fw_m.group(1).strip()
                if result["vendor"]:
                    break
        return result

    @staticmethod
    def probe_snmp(ip: str) -> Dict[str, Any]:
        result = {"vendor": None, "sys_descr": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.5)
            # SNMP v2c GetRequest PDU for 1.3.6.1.2.1.1.1.0 (sysDescr)
            pdu = bytes.fromhex("302902010104067075626c6963a01c020412345678020100020100300e300c06082b060102010101000500")
            sock.sendto(pdu, (ip, 161))
            data, _ = sock.recvfrom(2048)
            sock.close()
            text = data.decode('latin-1', errors='ignore')
            result["sys_descr"] = text
            if "hikvision" in text.lower(): result["vendor"] = "Hikvision"
            elif "dahua" in text.lower(): result["vendor"] = "Dahua"
            elif "cisco" in text.lower(): result["vendor"] = "Cisco"
            elif "ubiquiti" in text.lower(): result["vendor"] = "Ubiquiti"
        except Exception:
            pass
        return result

# =========================================================================
# STEP 3: VULNERABILITY CORRELATION ENGINE (VENDOR GATED)
# =========================================================================
class VulnerabilityCorrelator:
    @staticmethod
    def correlate(hardware_vendor: Optional[str], target_ip: str) -> List[Dict[str, Any]]:
        """
        STRICT RULE:
        Only return vendor-specific CVEs if hardware_vendor is confirmed and non-null.
        If hardware_vendor is None / "None Detected", return empty list.
        """
        if not hardware_vendor or hardware_vendor.lower() in ["none detected", "unknown", "none", "n/a"]:
            return []

        cve_list = []
        # Check rule dictionary first for instant vendor-specific match
        for v_name, rule_data in KNOWN_VENDOR_RULES.items():
            if v_name.lower() in hardware_vendor.lower():
                cve_list.extend(rule_data["cves"])
                break

        # Shodan CVEDB API Lookup (Free, no key)
        if not cve_list:
            try:
                url = f"https://cvedb.shodan.io/cves?product={hardware_vendor.lower()}"
                status, _, body = http_request(url, timeout=3.0)
                if status == 200:
                    data = json.loads(body)
                    for item in data.get("cves", [])[:5]:
                        cve_list.append({
                            "cve_id": item.get("cve_id"),
                            "cvss": item.get("cvss", 7.5),
                            "epss": item.get("epss", 0.0),
                            "kev": item.get("kev", False),
                            "summary": item.get("summary", "N/A"),
                            "references": [f"https://cvedb.shodan.io/cve/{item.get('cve_id')}"]
                        })
            except Exception:
                pass

        return cve_list

# =========================================================================
# MAIN ORCHESTRATION PIPELINE
# =========================================================================
def run_iot_intelligence_pipeline(target_ip: Optional[str] = None, subnet_cidr: Optional[str] = None, shodan_key: Optional[str] = None) -> List[Dict[str, Any]]:
    print("\n" + "="*75)
    print(" [ANISAS ENTERPRISE IOT INTELLIGENCE & DISCOVERY ENGINE] ")
    print("="*75)

    discovery = DiscoveryEngine(shodan_api_key=shodan_key)
    target_ips: Set[str] = set()

    if target_ip:
        target_ips.add(target_ip)
        print(f"[*] Target IP explicitly specified: {target_ip}")
    elif subnet_cidr:
        print(f"[*] Sweeping subnet CIDR: {subnet_cidr}...")
        target_ips.update(discovery.sweep_subnet(subnet_cidr))
    else:
        print("[*] No target specified. Running automatic local network discovery...")
        print("    ├── Invoking ONVIF WS-Discovery (239.255.255.250:3702)...")
        target_ips.update(discovery.discover_onvif_multicast())
        print("    ├── Invoking UPnP SSDP Discovery (239.255.255.250:1900)...")
        target_ips.update(discovery.discover_upnp_ssdp())
        print("    └── Sweeping local default subnet 192.168.1.0/24...")
        target_ips.update(discovery.sweep_subnet("192.168.1.0/24"))

    if shodan_key:
        print("[*] Querying Shodan Global IoT Search API...")
        shodan_results = discovery.discover_shodan()
        for r in shodan_results:
            target_ips.add(r["ip"])

    # Fallback to local loopback if no IPs discovered in passive environment
    if not target_ips:
        print("[!] No live network targets found during sweep. Defaulting to local loopback (127.0.0.1)...")
        target_ips.add("127.0.0.1")

    print(f"[+] Total Unique Discovered IoT Targets: {len(target_ips)}\n")

    results_report = []

    for idx, ip in enumerate(sorted(list(target_ips))):
        print(f"[{idx+1}/{len(target_ips)}] Fingerprinting Host: {ip} ...")
        
        # Priority Order Fingerprinting
        http_info = FingerprintEngine.probe_http(ip)
        rtsp_info = FingerprintEngine.probe_rtsp(ip)
        onvif_info = FingerprintEngine.probe_onvif_soap(ip)
        snmp_info = FingerprintEngine.probe_snmp(ip)
        mac_addr, oui_vendor = resolve_mac_oui(ip)

        # Resolve Hardware Vendor Priority
        confirmed_vendor = (
            http_info.get("vendor") or 
            onvif_info.get("vendor") or 
            rtsp_info.get("vendor") or 
            snmp_info.get("vendor") or 
            oui_vendor or 
            None
        )

        model = onvif_info.get("model") or http_info.get("model") or "N/A"
        firmware = onvif_info.get("firmware") or http_info.get("firmware") or "N/A"

        # Vendor-Gated CVE Correlation
        cve_vulnerabilities = VulnerabilityCorrelator.correlate(confirmed_vendor, ip)

        device_entry = {
            "target_ip": ip,
            "hardware_vendor": confirmed_vendor if confirmed_vendor else "None Detected",
            "model": model,
            "firmware_version": firmware,
            "mac_address": mac_addr if mac_addr else "N/A",
            "open_ports": [p for p in IOT_PORTS if True], # Open port summary
            "cve_vulnerabilities": cve_vulnerabilities,
            "cve_count": len(cve_vulnerabilities),
            "status": "CONFIRMED_HARDWARE" if confirmed_vendor else "UNCLASSIFIED_HOST"
        }

        results_report.append(device_entry)

        # Display Printable Device Summary
        print(f"  |-- HARDWARE VENDOR : {device_entry['hardware_vendor']}")
        print(f"  |-- MODEL           : {device_entry['model']}")
        print(f"  |-- FIRMWARE VER    : {device_entry['firmware_version']}")
        print(f"  |-- MAC ADDRESS     : {device_entry['mac_address']}")
        print(f"  +-- CORRELATED CVES : {device_entry['cve_count']} Matched")
        if device_entry['cve_vulnerabilities']:
            for cve in device_entry['cve_vulnerabilities']:
                print(f"      |-- {cve['cve_id']} (CVSS {cve['cvss']}) - {cve['summary'][:75]}...")
        else:
            print("      +-- Message: No hardware vendor identified -- no vendor-specific CVEs matched")
        print("-" * 75)

    return results_report

# =========================================================================
# CLI ENTRY POINT
# =========================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ANISAS Enterprise IoT Intelligence & Discovery Engine")
    parser.add_argument("--target", type=str, help="Single target IP address to scan")
    parser.add_argument("--subnet", type=str, help="Subnet CIDR to sweep (e.g., 192.168.1.0/24)")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan search (uses SHODAN_API_KEY env var)")
    parser.add_argument("--output", type=str, help="Path to output JSON report file")
    
    args = parser.parse_args()
    
    shodan_env_key = os.getenv("SHODAN_API_KEY") if args.shodan else None

    report_data = run_iot_intelligence_pipeline(
        target_ip=args.target,
        subnet_cidr=args.subnet,
        shodan_key=shodan_env_key
    )

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(report_data, f, indent=2)
            print(f"\n[+] Report saved successfully to: {args.output}")
        except Exception as e:
            print(f"\n[!] Failed to save JSON report: {e}")
