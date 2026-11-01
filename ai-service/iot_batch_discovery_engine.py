#!/usr/bin/env python3
"""
Automated Real-Time Batch IoT Asset Discovery & CVE Engine
----------------------------------------------------------
Discovers, fingerprints, and correlates vulnerabilities for all reachable
IoT assets (IP Cameras, NVRs, Smart Appliances) in real time.

Zero Hardcoded Test Data:
- Master asset list is built 100% dynamically from live discovery sources.
- CVE correlator processes ONLY actively discovered devices.

Discovery Sources:
 1. Shodan API (port:554,80,443 "RTSP" OR "ONVIF")
 2. Censys v2 API (label: camera)
 3. ONVIF WS-Discovery Multicast (239.255.255.250:3702)
 4. UPnP SSDP M-SEARCH Multicast (239.255.255.250:1900)
 5. Local Subnet ARP / Socket Host Discovery
"""

import os
import sys
import socket
import re
import time
import base64
import subprocess
import ipaddress
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Set, Tuple, Optional
import requests

# Optional Scapy import for Layer 2 discovery
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# IP SUBNET & NETWORK UTILITIES
# ============================================================================

def is_private_ip(ip_str: str) -> bool:
    """Returns True if IPv4 address belongs to RFC1918 / private ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def is_reserved_ip(ip_str: str) -> bool:
    """Checks if an IPv4 address belongs to IANA special-use / reserved ranges (0.0.0.0/8, 127.0.0.0/8, 240.0.0.0/4, etc.)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return (
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_unspecified
        )
    except ValueError:
        return False


def resolve_network_owner(ip_str: str) -> str:
    """Queries RDAP/WHOIS API to resolve network operator / ISP owner without conflating with hardware vendor."""
    clean_ip = ip_str.strip()
    if is_private_ip(clean_ip):
        return "Local Network Subnet"

    try:
        url = f"https://rdap.org/ip/{clean_ip}"
        res = requests.get(url, timeout=4.0)
        if res.status_code == 200:
            data = res.json()
            entities = data.get("entities", [])
            for ent in entities:
                vcard = ent.get("vcardArray", [[]])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            fn_val = item[3].strip()
                            if fn_val and "abuse" not in fn_val.lower() and "noc" not in fn_val.lower():
                                return fn_val

            net_name = data.get("name")
            if net_name and not re.match(r'^(NET|PA|NET6|AS)\d*', net_name):
                return net_name.strip()
    except Exception:
        pass

    try:
        res = requests.get(f"https://internetdb.shodan.io/{clean_ip}", timeout=3.0)
        if res.status_code == 200:
            org = res.json().get("org")
            if org:
                return org
    except Exception:
        pass

    return "Unknown ISP / Operator"


def get_local_subnet_hosts() -> List[str]:
    """Discovers active IPs on local LAN subnet using quick ARP / socket probes."""
    active_ips = []
    try:
        # Get default local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        if is_private_ip(local_ip):
            ip_net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            # Sample subset of hosts for fast discovery
            for host_ip in list(ip_net.hosts())[:30]:
                ip_s = str(host_ip)
                # Quick TCP port check on 80/554/443
                try:
                    s_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_test.settimeout(0.15)
                    if s_test.connect_ex((ip_s, 80)) == 0 or s_test.connect_ex((ip_s, 554)) == 0:
                        active_ips.append(ip_s)
                    s_test.close()
                except Exception:
                    pass
    except Exception:
        pass

    return active_ips


def resolve_mac_and_oui(ip_str: str) -> Tuple[str, str]:
    """
    Layer 2 MAC Address Resolution.
    Strictly Enforced: Public WAN IPs return ("N/A", "N/A").
    Private RFC1918 IPs resolve via Scapy ARP or OS arp table.
    """
    clean_ip = ip_str.strip()
    if not is_private_ip(clean_ip):
        return "N/A", "N/A"

    mac_addr = "Unknown"
    vendor_oui = "Unknown"

    # Scapy ARP Probe
    if SCAPY_AVAILABLE:
        try:
            arp = ARP(pdst=clean_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = srp(ether / arp, timeout=1.0, verbose=False)[0]
            for _, rcv in ans:
                mac_addr = rcv.hwsrc.upper()
                break
        except Exception:
            pass

    # System ARP Table Fallback
    if mac_addr == "Unknown":
        try:
            _nw = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, creationflags=_nw)
            for line in out.splitlines():
                if clean_ip in line:
                    m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if m:
                        mac_addr = m.group(0).upper().replace('-', ':')
                        break
        except Exception:
            pass

    # IEEE Vendor OUI Lookup
    if mac_addr not in ["Unknown", "N/A"]:
        try:
            oui_hex = mac_addr.replace(":", "").replace("-", "")[:6]
            r = requests.get(f"https://api.macvendors.com/{oui_hex}", timeout=1.5)
            if r.status_code == 200:
                vendor_oui = r.text.strip()
        except Exception:
            vendor_oui = f"IEEE OUI ({mac_addr[:8]})"

    return mac_addr, vendor_oui


# ============================================================================
# MASTER BATCH DISCOVERY COLLECTOR
# ============================================================================

class BatchIoTDiscoveryEngine:
    def __init__(self):
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.censys_id = os.getenv("CENSYS_API_ID")
        self.censys_secret = os.getenv("CENSYS_API_SECRET")

    def collect_shodan_assets(self) -> List[str]:
        """Collects reachable camera/IoT IPs from Shodan."""
        ips = []
        if not self.shodan_key:
            print("[Shodan] Warning: SHODAN_API_KEY env variable missing. Skipping Shodan API.")
            return ips

        try:
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=port:554,80,443 \"RTSP\" OR \"ONVIF\""
            res = requests.get(url, timeout=5.0)
            if res.status_code == 200:
                matches = res.json().get("matches", [])
                for m in matches:
                    if m.get("ip_str"):
                        ips.append(m["ip_str"])
            else:
                print(f"[Shodan] Warning HTTP {res.status_code}: {res.text[:100]}")
        except Exception as e:
            print(f"[Shodan Warning]: {e}")

        return ips

    def collect_censys_assets(self) -> List[str]:
        """Collects camera IPs from Censys v2 Search API."""
        ips = []
        if not (self.censys_id and self.censys_secret):
            print("[Censys] Warning: CENSYS_API_ID / CENSYS_API_SECRET missing. Skipping Censys API.")
            return ips

        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            auth = (self.censys_id, self.censys_secret)
            params = {"q": 'labels: "camera" OR services.http.response.html_title: "Camera"', "per_page": 10}
            res = requests.get(url, auth=auth, params=params, timeout=5.0)
            if res.status_code == 200:
                hits = res.json().get("result", {}).get("hits", [])
                for h in hits:
                    if h.get("ip"):
                        ips.append(h["ip"])
            else:
                print(f"[Censys] Warning HTTP {res.status_code}: {res.text[:100]}")
        except Exception as e:
            print(f"[Censys Warning]: {e}")

        return ips

    def collect_onvif_multicast_assets() -> List[str]:
        """Discovers ONVIF cameras via WS-Discovery UDP Multicast (239.255.255.250:3702)."""
        ips = []
        soap_probe = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<e:Header>'
            '<w:MessageID>uuid:84576302-4b67-463d-82d2-8b78345b500e</w:MessageID>'
            '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            '<w:Action>http://schemas.xmlsoap.org/ws/2005:04:discovery/Probe</w:Action>'
            '</e:Header>'
            '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
            '</e:Envelope>'
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(2.0)
        try:
            sock.sendto(soap_probe.encode("utf-8"), ("239.255.255.250", 3702))
            while True:
                try:
                    _, addr = sock.recvfrom(2048)
                    ips.append(addr[0])
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        return ips

    def collect_upnp_multicast_assets() -> List[str]:
        """Discovers UPnP camera/NVR assets via SSDP M-SEARCH Multicast (239.255.255.250:1900)."""
        ips = []
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(2.0)
        try:
            sock.sendto(msearch.encode("utf-8"), ("239.255.255.250", 1900))
            while True:
                try:
                    _, addr = sock.recvfrom(2048)
                    ips.append(addr[0])
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        return ips

    def build_master_asset_list(self) -> List[str]:
        """Combines all 5 discovery sources and deduplicates IPs."""
        master_set: Set[str] = set()

        print("[+] Gathering discovery sources in real-time...")
        
        # 1. Shodan API
        shodan_ips = self.collect_shodan_assets()
        master_set.update(shodan_ips)
        print(f"  -> Shodan API Discovered: {len(shodan_ips)} assets.")

        # 2. Censys v2 API
        censys_ips = self.collect_censys_assets()
        master_set.update(censys_ips)
        print(f"  -> Censys API Discovered: {len(censys_ips)} assets.")

        # 3. ONVIF Multicast
        onvif_ips = BatchIoTDiscoveryEngine.collect_onvif_multicast_assets()
        master_set.update(onvif_ips)
        print(f"  -> ONVIF Multicast Discovered: {len(onvif_ips)} local assets.")

        # 4. UPnP Multicast
        upnp_ips = BatchIoTDiscoveryEngine.collect_upnp_multicast_assets()
        master_set.update(upnp_ips)
        print(f"  -> UPnP Multicast Discovered: {len(upnp_ips)} local assets.")

        # 5. Local Subnet Sweep
        lan_ips = get_local_subnet_hosts()
        master_set.update(lan_ips)
        print(f"  -> Local Subnet Sweep Discovered: {len(lan_ips)} active hosts.")

        sorted_master = sorted(list(master_set))
        print(f"\n[+] Master Unique Discovered Assets: {len(sorted_master)} target IPs.\n")
        return sorted_master


# ============================================================================
# FINGERPRINTING & PROTOCOL PROBING PIPELINE
# ============================================================================

class TargetFingerprinter:
    @staticmethod
    def fingerprint_http_banner(ip: str) -> Dict[str, Any]:
        """
        Enhanced HTTP/HTTPS Router Fingerprinting Engine with Multi-Tier Cascades:
        - Probes ports 80 and 443 with a 5-second timeout (verify=False, SSL errors suppressed).
        - Model Cascade: Title regex -> HTML Body regex ([A-Z]{2,3}[- ]?\d+[A-Z]?) -> 'Model:', 'Product:', 'Device:'.
        - Firmware Cascade: Title version patterns -> HTML Body 'Firmware:', 'Software Version:', 'FW Version:' -> V\d+\.\d+\.\d+ patterns.
        - Embedded Server: Server response header if present -> fallback to 'HTTP/1.1 Server (No Header)'.
        """
        res_info = {
            "server": "Unknown",
            "title": "N/A",
            "vendor": "Unknown",
            "model": "Unknown",
            "firmware": "Unknown",
            "open_http_port": None
        }

        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        for port in [80, 443, 8080, 8443]:
            try:
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{ip}:{port}/"
                r = requests.get(url, timeout=5.0, verify=False, allow_redirects=True)
                res_info["open_http_port"] = port

                # 1. EMBEDDED SERVER EXTRACTION
                server_header = r.headers.get("Server", "").strip()
                if server_header:
                    res_info["server"] = server_header
                else:
                    res_info["server"] = "HTTP/1.1 Server (No Header)"

                auth_hdr = r.headers.get("WWW-Authenticate", "")
                if auth_hdr:
                    realm_m = re.search(r'realm=["\']?([^"\'>\r\n]+)["\']?', auth_hdr, re.IGNORECASE)
                    if realm_m:
                        realm_str = realm_m.group(1).strip()
                        realm_model = re.search(r'([A-Z]{2,4}[- ]?\d+[A-Z0-9]*)\b', realm_str, re.IGNORECASE)
                        if realm_model:
                            res_info["model"] = realm_model.group(1).strip()

                # 2. EXTRACT HTML <title> & HTML BODY
                html_text = r.text
                title_str = ""
                title_match = re.search(r'<title>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title_str = title_match.group(1).strip()
                    res_info["title"] = title_str

                # 3. MODEL EXTRACTION CASCADE
                if title_str and res_info["model"] == "Unknown":
                    title_model = re.search(r'\b([A-Z]{2,4}[- ]?\d+[A-Z0-9]*)\b', title_str)
                    if title_model and title_model.group(1).upper() not in ["HTTP", "HTML", "HOME", "INDEX", "PAGE", "ROUTER"]:
                        res_info["model"] = title_model.group(1).strip()

                if res_info["model"] == "Unknown":
                    body_model = re.search(r'\b([A-Z]{2,3}[- ]?\d+[A-Z]?)\b', html_text)
                    if body_model and body_model.group(1).upper() not in ["HTTP", "HTML", "GET", "POST"]:
                        res_info["model"] = body_model.group(1).strip()

                if res_info["model"] == "Unknown":
                    lbl_model = re.search(r'(?:Model|Product|Device)\s*(?:Name|No\.?|Number)?\s*[:=]\s*["\']?([A-Z0-9_-]{3,15})', html_text, re.IGNORECASE)
                    if lbl_model:
                        res_info["model"] = lbl_model.group(1).strip()

                # 4. FIRMWARE EXTRACTION CASCADE
                if title_str and res_info["firmware"] == "Unknown":
                    title_fw = re.search(r'(?:v|ver|firmware|version)\.?\s*(\d+\.\d+(?:\.\d+)*)', title_str, re.IGNORECASE)
                    if title_fw:
                        res_info["firmware"] = f"v{title_fw.group(1)}"

                if res_info["firmware"] == "Unknown":
                    lbl_fw = re.search(r'(?:Firmware|Software|FW)\s*(?:Version|Ver\.?|Rev\.?)?\s*[:=]\s*["\']?v?(\d+\.\d+(?:\.\d+)*[a-z0-9_-]*)', html_text, re.IGNORECASE)
                    if lbl_fw:
                        res_info["firmware"] = f"v{lbl_fw.group(1)}"

                if res_info["firmware"] == "Unknown":
                    body_fw = re.search(r'\b(?:V|v)(\d+\.\d+\.\d+(?:\.\d+)?)\b', html_text)
                    if body_fw:
                        res_info["firmware"] = f"v{body_fw.group(1)}"

                if res_info["firmware"] == "Unknown" and server_header:
                    srv_fw = re.search(r'(?:/|v\s*)(\d+\.\d+(?:\.\d+)*)', server_header, re.IGNORECASE)
                    if srv_fw:
                        res_info["firmware"] = f"v{srv_fw.group(1)}"

                # 5. VENDOR EXTRACTION FROM HEADERS / TITLE / BODY
                combined_blob = (server_header + " " + auth_hdr + " " + title_str + " " + html_text[:1000]).lower()
                if "arcadyan" in combined_blob:
                    res_info["vendor"] = "Arcadyan Corporation"
                elif "tp-link" in combined_blob or "tplink" in combined_blob:
                    res_info["vendor"] = "TP-Link Technologies"
                elif "asus" in combined_blob:
                    res_info["vendor"] = "ASUSTeK Computer Inc."
                elif "netgear" in combined_blob:
                    res_info["vendor"] = "NETGEAR Inc."
                elif "d-link" in combined_blob or "dlink" in combined_blob:
                    res_info["vendor"] = "D-Link Corporation"
                elif "hikvision" in combined_blob:
                    res_info["vendor"] = "Hikvision Digital Technology"
                elif "dahua" in combined_blob:
                    res_info["vendor"] = "Zhejiang Dahua Technology"

                break
            except Exception:
                pass

        return res_info

    @staticmethod
    def probe_rtsp_describe(ip: str) -> Optional[Dict[str, Any]]:
        """Probes RTSP ports (554, 8554, 8555) with DESCRIBE request."""
        for port in [554, 8554, 8555]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                if s.connect_ex((ip, port)) == 0:
                    req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ANISAS-IoT-Scanner/2.0\r\n\r\n"
                    s.sendall(req.encode("utf-8"))
                    res = s.recv(2048).decode("utf-8", errors="ignore")
                    s.close()

                    server_match = re.search(r'Server:\s*([^\r\n]+)', res, re.IGNORECASE)
                    server_banner = server_match.group(1).strip() if server_match else "RTSP Streaming Service"
                    return {"port": port, "banner": server_banner}
            except Exception:
                pass
        return None

    @staticmethod
    def probe_onvif_unicast(ip: str) -> bool:
        """Sends ONVIF unicast Probe to http://{ip}/onvif/device_service."""
        soap_env = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
            '</s:Envelope>'
        )
        for port in [80, 8080]:
            try:
                url = f"http://{ip}:{port}/onvif/device_service"
                h = {"Content-Type": "application/soap+xml; charset=utf-8"}
                r = requests.post(url, data=soap_env, headers=h, timeout=1.5)
                if r.status_code in [200, 401, 500]:
                    return True
            except Exception:
                pass
        return False


# ============================================================================
# LIVE NVD API V2 CVE CORRELATOR
# ============================================================================

class NvdVulnerabilityCorrelator:
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @classmethod
    def correlate_cves(cls, vendor: str, model: str, firmware: str) -> Tuple[int, List[str]]:
        """
        Queries NVD API v2 for CVSS > 9.0 Critical CVE matches.
        Strict Integrity Rule: If firmware is 'Unknown', 'Latest', or vendor is 'N/A'/'Unknown',
        suppresses version-specific CVEs and returns (0, ["No version-specific CVE matched"]).
        """
        if not firmware or firmware.lower() in ["unknown", "latest", "null", "n/a", "none"]:
            return 0, ["No version-specific CVE matched"]

        if not vendor or vendor.lower() in ["unknown", "n/a"]:
            return 0, ["No version-specific CVE matched"]

        search_term = f"{vendor} {model}".strip()
        cve_details = []
        critical_count = 0

        try:
            params = {
                "keywordSearch": search_term,
                "cvssV3Severity": "CRITICAL",
                "resultsPerPage": 3
            }
            headers = {"User-Agent": "ANISAS-Batch-Scanner/2.0"}
            res = requests.get(cls.NVD_API_URL, params=params, headers=headers, timeout=4.0)
            if res.status_code == 200:
                vulnerabilities = res.json().get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                    cvss_score = metrics.get("cvssData", {}).get("baseScore", 0.0)
                    desc = cve.get("descriptions", [{}])[0].get("value", "N/A")

                    if cvss_score >= 9.0:
                        critical_count += 1

                    cve_details.append(f"{cve_id} (CVSS {cvss_score}): {desc[:80]}...")
            else:
                print(f"[NVD Warning HTTP {res.status_code}] Continuing batch...")
        except Exception as e:
            print(f"[NVD Query Warning]: {e}. Continuing batch...")

        if not cve_details:
            cve_details = ["No version-specific CVE matched"]

        return critical_count, cve_details


# ============================================================================
# EXECUTIVE REPORT RENDERER
# ============================================================================

def process_and_report_asset(ip: str):
    """Executes full discovery & fingerprinting pipeline for a single IP and prints report."""
    clean_ip = ip.strip()

    # Step 1: Reserved / Special-Use IP Check (IANA 240.0.0.0/4, 0.0.0.0/8, 127.0.0.0/8, etc.)
    if is_reserved_ip(clean_ip):
        print("==================================================")
        print("          IOT ASSET RECONNAISSANCE REPORT         ")
        print("==================================================")
        print(f"TARGET IP           : {clean_ip}")
        print(f"ASSET CATEGORY      : Reserved / Unallocated IP")
        print(f"NETWORK OWNER       : Internet Assigned Numbers Authority (IANA)")
        print(f"MAC ADDRESS         : N/A")
        print(f"MAC VENDOR OUI      : N/A")
        print(f"HARDWARE VENDOR     : N/A")
        print(f"HARDWARE MODEL      : N/A")
        print(f"FIRMWARE VERSION    : N/A")
        print(f"EMBEDDED SERVER     : N/A")
        print("--------------------------------------------------")
        print(f"CRITICAL CVE MATCHES: 0")
        print(f"CVE DETAILS         : No version-specific CVE matched")
        print("==================================================\n")
        return

    is_wan = not is_private_ip(clean_ip)

    # 1. Primary Source: RDAP / WHOIS Network Owner
    network_owner = resolve_network_owner(clean_ip)

    # 2. Secondary Source: Layer 2 MAC Address Resolution (RFC1918 Private IPs Only)
    mac_addr, mac_oui = resolve_mac_and_oui(clean_ip) if not is_wan else ("N/A", "N/A")

    # 3. Tertiary Source: HTTP Banner & Protocol Probes
    http_data = TargetFingerprinter.fingerprint_http_banner(clean_ip)
    rtsp_data = TargetFingerprinter.probe_rtsp_describe(clean_ip)
    onvif_active = TargetFingerprinter.probe_onvif_unicast(clean_ip)

    # Trust Hierarchy & Vendor Separation
    if is_wan:
        mac_addr = "N/A"
        mac_oui = "N/A"
        hardware_vendor = http_data["vendor"] if http_data["vendor"] != "Unknown" else "N/A"
        hardware_model = http_data["model"] if http_data["model"] != "Unknown" else "Unknown"
        firmware_ver = http_data["firmware"] if http_data["firmware"] != "Unknown" else "Unknown"
        
        if rtsp_data or onvif_active or "camera" in http_data["title"].lower():
            asset_category = "Surveillance"
        else:
            asset_category = "Unknown WAN Asset"
    else:
        if http_data["vendor"] != "Unknown":
            hardware_vendor = http_data["vendor"]
        elif mac_oui not in ["Unknown", "N/A"]:
            hardware_vendor = mac_oui
        else:
            hardware_vendor = "Unknown"

        hardware_model = http_data["model"]
        firmware_ver = http_data["firmware"]
        asset_category = "Surveillance" if (rtsp_data or onvif_active) else "IoT Device"

    # Embedded Server Identification
    if http_data["server"] != "Unknown":
        embedded_server = http_data["server"]
    elif rtsp_data:
        embedded_server = f"RTSP Daemon ({rtsp_data['banner']})"
    else:
        embedded_server = "HTTP/1.1 Server (No Header)"

    # Live NVD CVE Correlation (Strict vendor matching)
    critical_cve_count, cve_details = NvdVulnerabilityCorrelator.correlate_cves(
        hardware_vendor, hardware_model, firmware_ver
    )

    cve_details_str = "\n              ".join(cve_details)

    # Render Report Block
    print("==================================================")
    print("          IOT ASSET RECONNAISSANCE REPORT         ")
    print("==================================================")
    print(f"TARGET IP           : {ip}")
    print(f"ASSET CATEGORY      : {asset_category}")
    print(f"NETWORK OWNER       : {network_owner}")
    print(f"MAC ADDRESS         : {mac_addr}")
    print(f"MAC VENDOR OUI      : {mac_oui}")
    print(f"HARDWARE VENDOR     : {hardware_vendor}")
    print(f"HARDWARE MODEL      : {hardware_model}")
    print(f"FIRMWARE VERSION    : {firmware_ver}")
    print(f"EMBEDDED SERVER     : {embedded_server}")
    print("--------------------------------------------------")
    print(f"CRITICAL CVE MATCHES: {critical_cve_count}")
    print(f"CVE DETAILS         : {cve_details_str}")
    print("==================================================\n")


# ============================================================================
# MAIN BATCH ENGINE ENTRY POINT
# ============================================================================

def main():
    print("==================================================================")
    print("     AUTOMATED REAL-TIME BATCH IOT ASSET DISCOVERY ENGINE         ")
    print("==================================================================")

    # Build master unique asset list across all discovery sources
    engine = BatchIoTDiscoveryEngine()
    master_asset_ips = engine.build_master_asset_list()

    if not master_asset_ips:
        print("[!] No active IoT assets discovered. Ensure network connectivity or check API keys.")
        return

    print(f"[+] Processing {len(master_asset_ips)} discovered assets sequentially...\n")
    for idx, target_ip in enumerate(master_asset_ips, start=1):
        try:
            process_and_report_asset(target_ip)
        except Exception as e:
            print(f"[!] Error processing target {target_ip}: {e}. Continuing batch...\n")

    print("==================================================================")
    print("           BATCH IOT DISCOVERY PIPELINE COMPLETE                  ")
    print("==================================================================")


if __name__ == "__main__":
    main()
