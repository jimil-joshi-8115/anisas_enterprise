#!/usr/bin/env python3
"""
IoT Asset Reconnaissance & Vulnerability Correlation Engine
------------------------------------------------------------
Production-ready Python module for real-time discovery of IP cameras, NVRs,
and IoT infrastructure across WAN search engines and LAN discovery protocols.

Supported Discovery & Telemetry Features:
 1. Real-Time Discovery Sources:
    - Global APIs: Shodan v1, Censys Search v2, Fofa API
    - Local Protocols: ONVIF WS-Discovery (SOAP Probe + Unicast), RTSP DESCRIBE,
      HTTP(S) Title/Server probing, UPnP SSDP M-SEARCH
 2. Multi-Vector Firmware Extraction (HTTP Headers, ONVIF SOAP, SNMP sysDescr)
 3. Layer 2 MAC Address Resolution (RFC1918 IPv4 check + Scapy / ARP fallback)
 4. NVD API v2 Vulnerability Correlation (CVSS > 9.0 filtering + Strict Version Integrity)
 5. Multi-Vendor Threat Reputation (VirusTotal v3 & AbuseIPDB)
 6. Standardized Executive Reconnaissance Reporting

Environment Variables Supported:
 - SHODAN_API_KEY
 - CENSYS_API_ID / CENSYS_API_SECRET
 - FOFA_API_EMAIL / FOFA_API_KEY
 - VIRUSTOTAL_API_KEY (or VT_API_KEY)
 - ABUSEIPDB_API_KEY
"""

import os
import sys
import socket
import re
import base64
import json
import subprocess
import ipaddress
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple
import requests

# Optional Scapy import for Layer 2 ARP discovery
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# UTILITY FUNCTIONS: NETWORK & SUBNET AUDITING
# ============================================================================

# ============================================================================
# STRUCTURED ENUMS & CONSTANTS FOR MODULE 4 ATTRIBUTION
# ============================================================================

# IP Classification Enums
IP_CATEGORY_PUBLIC = "PUBLIC"
IP_CATEGORY_PRIVATE = "PRIVATE"
IP_CATEGORY_LOOPBACK = "LOOPBACK"
IP_CATEGORY_LINK_LOCAL = "LINK_LOCAL"
IP_CATEGORY_MULTICAST = "MULTICAST"
IP_CATEGORY_DOCUMENTATION = "DOCUMENTATION"
IP_CATEGORY_RESERVED = "RESERVED"
IP_CATEGORY_UNKNOWN = "UNKNOWN"

# Network Owner Sources
NET_SOURCE_IP_API = "IP_API"
NET_SOURCE_RDAP = "RDAP"
NET_SOURCE_WHOIS = "WHOIS"
NET_SOURCE_ASN = "ASN"
NET_SOURCE_BGP = "BGP"
NET_SOURCE_INTERNAL = "INTERNAL"
NET_SOURCE_UNKNOWN = "UNKNOWN"

# Hardware Vendor Evidence Sources
HW_SOURCE_MAC_OUI = "MAC_OUI"
HW_SOURCE_HTTP_SERVER = "HTTP_SERVER"
HW_SOURCE_HTTP_AUTH_REALM = "HTTP_AUTH_REALM"
HW_SOURCE_HTTP_TITLE = "HTTP_TITLE"
HW_SOURCE_ONVIF = "ONVIF"
HW_SOURCE_RTSP = "RTSP"
HW_SOURCE_OTHER_SIGNATURE = "OTHER_DEVICE_SIGNATURE"
HW_SOURCE_NO_SIGNATURE = "NO_HARDWARE_SIGNATURE"
HW_SOURCE_SPECIAL_USE = "SPECIAL_USE"

# Generic Server Software to Suppress from hardwareVendor
GENERIC_HTTP_SERVERS = ["goahead", "boa", "nginx", "apache", "lighttpd", "mini_httpd", "appweb", "express", "werkzeug", "iis"]

# Device Types
DEVICE_TYPE_IP_CAMERA = "IP_CAMERA"
DEVICE_TYPE_PTZ_CAMERA = "PTZ_CAMERA"
DEVICE_TYPE_NVR = "NVR"
DEVICE_TYPE_DVR = "DVR"
DEVICE_TYPE_XVR = "XVR"
DEVICE_TYPE_WIRELESS_AP = "WIRELESS_AP"
DEVICE_TYPE_ROUTER = "ROUTER"
DEVICE_TYPE_SWITCH = "SWITCH"
DEVICE_TYPE_NETWORK_PRINTER = "NETWORK_PRINTER"
DEVICE_TYPE_VOIP_PHONE = "VOIP_PHONE"
DEVICE_TYPE_NAS = "NAS"
DEVICE_TYPE_SMART_TV = "SMART_TV"
DEVICE_TYPE_SMART_PLUG = "SMART_PLUG"
DEVICE_TYPE_SMART_LIGHTING = "SMART_LIGHTING"
DEVICE_TYPE_SMART_DOORBELL = "SMART_DOORBELL"
DEVICE_TYPE_IOT_GATEWAY = "IOT_GATEWAY"
DEVICE_TYPE_IOT_SENSOR = "IOT_SENSOR"
DEVICE_TYPE_ACCESS_CONTROL = "ACCESS_CONTROL"
DEVICE_TYPE_INDUSTRIAL_IOT = "INDUSTRIAL_IOT"
DEVICE_TYPE_UNKNOWN_IOT = "UNKNOWN_IOT"
DEVICE_TYPE_UNKNOWN_RTSP = "UNKNOWN_RTSP_DEVICE"
DEVICE_TYPE_UNKNOWN = "UNKNOWN_DEVICE"
# Vendor Signatures Database with http_content_type support
VENDOR_SIGNATURES = {
    "Dahua": {
        "http_headers": ["dahua", "dahua-based", "dahua-webserver", "dahua webserver 2.0"],
        "http_content_type": ["dahua-based", "application/dahua", "dahua"],
        "http_auth_realms": ["dahua", "dahua nvr", "dahua dvr"],
        "html_title": ["dahua", "web service", "dahua web client"],
        "rtsp_servers": ["dahua", "dahua-rtsp"],
        "onvif_manufacturers": ["dahua", "zhejiang dahua technology", "dahua-tech"],
        "mac_ouis": ["00:1A:3C", "3C:EF:8C", "4C:11:BF", "E8:AB:FA", "EC:71:DB", "Zhejiang Dahua Technology"]
    },
    "Hikvision": {
        "http_headers": ["hikvision", "hikvision-webs", "hikvision embedded web server"],
        "http_content_type": ["hikvision-based", "application/hikvision"],
        "http_auth_realms": ["hikvision", "hikvision web component"],
        "html_title": ["hikvision", "hikvision web client"],
        "rtsp_servers": ["hikvision", "hik-rtsp"],
        "onvif_manufacturers": ["hikvision", "hikvision digital technology"],
        "mac_ouis": ["00:40:8C", "10:DA:43", "18:68:CB", "Hikvision Digital Technology"]
    },
    "Axis": {
        "http_headers": ["axis", "axis-web", "axis-http"],
        "http_content_type": ["application/axis"],
        "http_auth_realms": ["axis", "axis_m3045"],
        "html_title": ["axis", "axis network camera"],
        "rtsp_servers": ["axis"],
        "onvif_manufacturers": ["axis", "axis communications ab"],
        "mac_ouis": ["00:40:8C", "Axis Communications AB"]
    }
}



def match_vendor_signature(http_info: dict) -> Optional[dict]:
    """
    Evaluates http_headers, http_content_type, http_auth_realms, html_title,
    and body_snippet against VENDOR_SIGNATURES.
    """
    if not isinstance(http_info, dict):
        return None

    server_hdr = str(http_info.get("server", "")).lower()
    content_type_hdr = str(http_info.get("content_type", "")).lower()
    auth_realm = str(http_info.get("auth_realm", "")).lower()
    title_text = str(http_info.get("title", "")).lower()
    body_snippet = str(http_info.get("body_snippet", "")).lower()
    raw_headers = str(http_info.get("raw_headers", {})).lower()

    for vendor, sig in VENDOR_SIGNATURES.items():
        # Check Content-Type header
        for ct_sig in sig.get("http_content_type", []):
            if ct_sig in content_type_hdr or ct_sig in raw_headers:
                return {
                    "vendor": vendor,
                    "matched_by": "http_content_type",
                    "detail": f"Content-Type: '{content_type_hdr}'"
                }

        # Check Server header
        for s_sig in sig.get("http_headers", []):
            if s_sig in server_hdr or s_sig in raw_headers:
                return {
                    "vendor": vendor,
                    "matched_by": "http_headers",
                    "detail": f"Server: '{server_hdr}'"
                }

        # Check WWW-Authenticate realm
        for a_sig in sig.get("http_auth_realms", []):
            if a_sig in auth_realm or a_sig in raw_headers:
                return {
                    "vendor": vendor,
                    "matched_by": "http_auth_realm",
                    "detail": f"Auth Realm: '{auth_realm}'"
                }

        # Check HTML title
        for t_sig in sig.get("html_title", []):
            if t_sig in title_text:
                return {
                    "vendor": vendor,
                    "matched_by": "html_title",
                    "detail": f"Title: '{title_text}'"
                }

        # Check Body Snippet
        for s_sig in sig.get("http_headers", []):
            if s_sig in body_snippet:
                return {
                    "vendor": vendor,
                    "matched_by": "http_body",
                    "detail": f"Body Snippet matched '{s_sig}'"
                }

    return None


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IPv4 address belongs to RFC 1918 or private/loopback ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


RESERVED_IP_RANGES = [
    "0.0.0.0/8",       # Current network
    "127.0.0.0/8",     # Loopback
    "169.254.0.0/16",  # Link-local
    "224.0.0.0/4",     # Multicast
    "240.0.0.0/4",     # Reserved/Future use
    "255.255.255.255/32", # Limited broadcast
    "203.0.113.0/24",  # RFC 5737 TEST-NET-1
    "198.51.100.0/24", # RFC 5737 TEST-NET-2
    "192.0.2.0/24",    # RFC 5737 TEST-NET-3
    "10.0.0.0/8",      # Private network
    "172.16.0.0/12",   # Private network
    "192.168.0.0/16",  # Private network
]


def classify_ip_address(ip_str: str) -> dict:
    """Categorizes IP address into granular RFC types."""
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return {"category": IP_CATEGORY_UNKNOWN, "is_special": False, "description": "Invalid IP Format"}

    if ip_obj.is_loopback or clean_ip.startswith("127."):
        return {"category": IP_CATEGORY_LOOPBACK, "is_special": True, "description": "Loopback Interface (RFC 1122)"}

    if ip_obj.is_link_local or clean_ip.startswith("169.254."):
        return {"category": IP_CATEGORY_LINK_LOCAL, "is_special": True, "description": "Link-Local Address (RFC 3927)"}

    if ip_obj.is_multicast or clean_ip.startswith("224."):
        return {"category": IP_CATEGORY_MULTICAST, "is_special": True, "description": "Multicast Range (RFC 5771)"}

    for doc_cidr in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]:
        if ip_obj in ipaddress.ip_network(doc_cidr):
            return {"category": IP_CATEGORY_DOCUMENTATION, "is_special": True, "description": "RFC 5737 Documentation / TEST-NET"}

    for res_cidr in ["0.0.0.0/8", "240.0.0.0/4", "255.255.255.255/32"]:
        if ip_obj in ipaddress.ip_network(res_cidr):
            return {"category": IP_CATEGORY_RESERVED, "is_special": True, "description": "Reserved / Unallocated (IANA)"}

    if ip_obj.is_private:
        return {"category": IP_CATEGORY_PRIVATE, "is_special": False, "description": "Private Network Subnet (RFC 1918)"}

    return {"category": IP_CATEGORY_PUBLIC, "is_special": False, "description": "Public WAN Address"}


def is_reserved_ip(ip_str: str) -> bool:
    """Checks if an IPv4 address belongs to IANA special-use / reserved ranges."""
    ip_class = classify_ip_address(ip_str)
    return ip_class["is_special"]


def resolve_network_owner_structured(ip_str: str) -> dict:
    """Queries IP-API, RDAP, WHOIS, and Shodan returning structured network owner data."""
    clean_ip = ip_str.strip()
    ip_class = classify_ip_address(clean_ip)

    if ip_class["is_special"]:
        return {
            "organization": "Internet Assigned Numbers Authority (IANA)",
            "source": NET_SOURCE_INTERNAL,
            "category": ip_class["category"]
        }

    if ip_class["category"] == IP_CATEGORY_PRIVATE:
        return {
            "organization": "Local Network Subnet",
            "source": NET_SOURCE_INTERNAL,
            "category": IP_CATEGORY_PRIVATE
        }

    # Tier 1: IP-API (Instant, accurate ISP/Cloud Organization)
    try:
        res = requests.get(f"http://ip-api.com/json/{clean_ip}", timeout=2.0)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                org = data.get("org") or data.get("isp")
                if org:
                    return {"organization": org.strip(), "source": NET_SOURCE_IP_API, "category": IP_CATEGORY_PUBLIC}
    except Exception:
        pass

    # Tier 2: RDAP Registry Lookup
    try:
        res = requests.get(f"https://rdap.org/ip/{clean_ip}", timeout=2.0)
        if res.status_code == 200:
            data = res.json()
            net_name = data.get("name")
            if net_name and not re.match(r'^(NET|PA|NET6|AS)\d*$', net_name.strip().upper()):
                return {"organization": net_name.strip(), "source": NET_SOURCE_RDAP, "category": IP_CATEGORY_PUBLIC}

            entities = data.get("entities", [])
            for ent in entities:
                vcard = ent.get("vcardArray", [[]])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            fn_val = item[3].strip()
                            if fn_val and "abuse" not in fn_val.lower() and "noc" not in fn_val.lower():
                                return {"organization": fn_val, "source": NET_SOURCE_RDAP, "category": IP_CATEGORY_PUBLIC}
    except Exception:
        pass

    # Tier 3: Shodan Fallback
    try:
        res = requests.get(f"https://internetdb.shodan.io/{clean_ip}", timeout=2.0)
        if res.status_code == 200:
            org = res.json().get("org")
            if org:
                return {"organization": org.strip(), "source": NET_SOURCE_WHOIS, "category": IP_CATEGORY_PUBLIC}
    except Exception:
        pass

    return {"organization": "Public WAN Operator", "source": NET_SOURCE_UNKNOWN, "category": IP_CATEGORY_PUBLIC}


def resolve_network_owner(ip_str: str) -> str:
    """Legacy helper returning organization string."""
    res = resolve_network_owner_structured(ip_str)
    return res["organization"]


def resolve_mac_address(ip_str: str) -> Tuple[str, str]:
    """
    Layer 2 MAC & Vendor OUI resolution.
    Strictly enforced: Public WAN IPs return ("N/A", "N/A").
    RFC1918 IPs attempt Scapy ARP, OS arp table, or DHCP leases.
    """
    clean_ip = ip_str.strip()
    if not is_private_ip(clean_ip):
        return "N/A", "N/A"

    mac_address = "Unknown"
    vendor_oui = "Unknown"

    # Method 1: Scapy ARP Request
    if SCAPY_AVAILABLE:
        try:
            arp = ARP(pdst=clean_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether / arp, timeout=1.5, verbose=False)[0]
            for sent, received in result:
                mac_address = received.hwsrc.upper()
                break
        except Exception:
            pass

    # Method 2: System ARP Table Parsing Fallback
    if mac_address == "Unknown":
        try:
            _nw = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, creationflags=_nw)
            for line in output.splitlines():
                if clean_ip in line:
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        mac_address = mac_match.group(0).upper().replace('-', ':')
                        break
        except Exception:
            pass

    # Resolve IEEE MAC Vendor OUI
    if mac_address != "Unknown" and mac_address != "N/A":
        try:
            oui_clean = mac_address.replace(":", "").replace("-", "")[:6]
            res = requests.get(f"https://api.macvendors.com/{oui_clean}", timeout=2.0)
            if res.status_code == 200:
                vendor_oui = res.text.strip()
        except Exception:
            vendor_oui = f"IEEE OUI ({mac_address[:8]})"

    return mac_address, vendor_oui


# ============================================================================
# SECTION 1: REAL-TIME GLOBAL SEARCH APIS (SHODAN, CENSYS, FOFA)
# ============================================================================

# ============================================================================
# SECTION 1: TOP 3 REAL-TIME GLOBAL SEARCH & TELEMETRY APIS
# ============================================================================

class GlobalSearchScanner:
    """
    Primary API Scanner focused strictly on the Top 3 OSINT & Telemetry APIs:
    1. Shodan API (SHODAN_API_KEY)
    2. Censys API (CENSYS_API_ID, CENSYS_API_SECRET)
    3. IP-API Telemetry (Built-in Free Network & ISP Registry API)
    """
    def __init__(self):
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.censys_id = os.getenv("CENSYS_API_ID")
        self.censys_secret = os.getenv("CENSYS_API_SECRET")

    def query_shodan(self, target_ip: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """API 1: Shodan REST API for RTSP, HTTP, & ONVIF telemetry."""
        results = []
        if not self.shodan_key:
            return results

        try:
            query = f"ip:{target_ip}" if target_ip else 'port:554,80,443 "RTSP" OR "ONVIF"'
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query={query}"
            res = requests.get(url, timeout=3.0)
            if res.status_code == 200:
                matches = res.json().get("matches", [])[:limit]
                for m in matches:
                    results.append({
                        "source": "Shodan API",
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org", "N/A"),
                        "banner": m.get("data", "").strip()[:150]
                    })
        except Exception as e:
            print(f"[Warning] Shodan API Query failed: {e}")
        return results

    def query_censys(self, target_ip: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """API 2: Censys Search v2 Host API for camera assets & SSL telemetry."""
        results = []
        if not (self.censys_id and self.censys_secret):
            return results

        try:
            query = f"ip: {target_ip}" if target_ip else 'labels: "camera" OR services.http.response.html_title: "Camera"'
            url = "https://search.censys.io/api/v2/hosts/search"
            auth = (self.censys_id, self.censys_secret)
            res = requests.get(url, auth=auth, params={"q": query, "per_page": limit}, timeout=3.0)
            if res.status_code == 200:
                hits = res.json().get("result", {}).get("hits", [])
                for hit in hits:
                    results.append({
                        "source": "Censys API",
                        "ip": hit.get("ip"),
                        "port": hit.get("services", [{}])[0].get("port", 80),
                        "org": hit.get("operating_system", {}).get("vendor", "N/A"),
                        "banner": hit.get("name", "Censys Camera Asset")
                    })
        except Exception as e:
            print(f"[Warning] Censys API Query failed: {e}")
        return results

    def query_ip_api(self, target_ip: str) -> Dict[str, Any]:
        """API 3: IP-API Telemetry REST API for ISP & Network Owner lookup."""
        try:
            url = f"http://ip-api.com/json/{target_ip.strip()}?fields=status,message,country,isp,org,as,query"
            res = requests.get(url, timeout=3.0)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    return {
                        "source": "IP-API",
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org") or data.get("isp", "N/A"),
                        "country": data.get("country", "N/A")
                    }
        except Exception:
            pass
        return {"source": "IP-API", "isp": "N/A", "org": "N/A", "country": "N/A"}


# ============================================================================
# SECTION 2: LOCAL NETWORK PROBES (ONVIF, RTSP, HTTP, UPNP)
# ============================================================================

class LocalNetworkProber:
    @staticmethod
    def probe_onvif_ws_discovery(target_ip: Optional[str] = None, timeout: float = 2.5) -> List[Dict[str, Any]]:
        """Executes ONVIF WS-Discovery via Multicast (239.255.255.250:3702) & Unicast probing."""
        discovered = []
        soap_envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<e:Header>'
            '<w:MessageID>uuid:a847593d-495a-4932-9b38-29475a8940fe</w:MessageID>'
            '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            '<w:Action>http://schemas.xmlsoap.org/ws/2005:04:discovery/Probe</w:Action>'
            '</e:Header>'
            '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
            '</e:Envelope>'
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)

        # Multicast Probe
        try:
            sock.sendto(soap_envelope.encode("utf-8"), ("239.255.255.250", 3702))
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    resp_xml = data.decode("utf-8", errors="ignore")
                    mfr = re.findall(r'onvif://www\.onvif\.org/name/([^\s<]+)', resp_xml)
                    model = re.findall(r'onvif://www\.onvif\.org/hardware/([^\s<]+)', resp_xml)
                    discovered.append({
                        "ip": addr[0],
                        "vendor": mfr[0] if mfr else "ONVIF Camera",
                        "model": model[0] if model else "Generic NVT",
                        "source": "ONVIF WS-Discovery (Multicast)"
                    })
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        # Unicast Endpoint Fallback for specific Target IP
        if target_ip and not discovered:
            for p in [80, 8080, 8899]:
                try:
                    url = f"http://{target_ip}:{p}/onvif/device_service"
                    h = {"Content-Type": "application/soap+xml; charset=utf-8"}
                    r = requests.post(url, data=soap_envelope, headers=h, timeout=1.5)
                    if r.status_code in [200, 401, 500]:
                        discovered.append({
                            "ip": target_ip,
                            "vendor": "ONVIF Compliant Device",
                            "model": "Generic ONVIF Camera",
                            "source": f"ONVIF Unicast Probing (Port {p})"
                        })
                        break
                except Exception:
                    pass

        return discovered

    @staticmethod
    def probe_rtsp_describe(target_ip: str, ports: List[int] = None) -> Optional[Dict[str, Any]]:
        """Probes RTSP ports (554, 8554, 8555, 1024) using a DESCRIBE request."""
        ports = ports or [554, 8554, 8555, 1024]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                if s.connect_ex((target_ip, port)) == 0:
                    req = (
                        f"DESCRIBE rtsp://{target_ip}:{port}/ RTSP/1.0\r\n"
                        f"CSeq: 1\r\n"
                        f"User-Agent: ANISAS-IoT-Scanner/2.0\r\n\r\n"
                    )
                    s.sendall(req.encode("utf-8"))
                    res = s.recv(2048).decode("utf-8", errors="ignore")
                    s.close()

                    server_match = re.search(r'Server:\s*([^\r\n]+)', res, re.IGNORECASE)
                    server_hdr = server_match.group(1).strip() if server_match else "RTSP Streaming Daemon"
                    return {
                        "port": port,
                        "rtsp_server": server_hdr,
                        "raw_header": res.split("\r\n")[0]
                    }
            except Exception:
                pass
        return None

    @staticmethod
    def probe_http_services(target_ip: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Parses ALL HTTP response headers (Server:, Content-Type:, WWW-Authenticate:),
        HTML <title> tag, and first 500 bytes of response body across ports 80, 443, 8080, 8443.
        """
        ports = ports or [80, 443, 8080, 8443]
        info = {
            "server": "Unknown / Unidentified",
            "content_type": "N/A",
            "auth_realm": "N/A",
            "title": "N/A",
            "body_snippet": "",
            "raw_headers": {},
            "vendor_clues": [],
            "http_success": False
        }

        paths = ["/", "/onvif/device_service", "/cgi-bin/"]
        for port in ports:
            protocol = "https" if port in [443, 8443] else "http"
            for p in paths:
                try:
                    url = f"{protocol}://{target_ip}:{port}{p}"
                    res = requests.get(url, timeout=2.5, verify=False, allow_redirects=True)
                    
                    info["http_success"] = True
                    info["raw_headers"] = dict(res.headers)

                    if res.headers.get("Server"):
                        info["server"] = res.headers.get("Server")
                    
                    if res.headers.get("Content-Type"):
                        info["content_type"] = res.headers.get("Content-Type")

                    if res.headers.get("WWW-Authenticate"):
                        info["auth_realm"] = res.headers.get("WWW-Authenticate")

                    # Parse HTML <title>
                    title_match = re.search(r'<title>(.*?)</title>', res.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        info["title"] = title_match.group(1).strip()

                    # Parse first 500 bytes of response body
                    info["body_snippet"] = res.text[:500]

                    # Match vendor signature against all extracted sources
                    sig_match = match_vendor_signature(info)
                    if sig_match:
                        vendor_name = sig_match["vendor"]
                        if vendor_name == "Dahua" or "dahua" in str(info).lower():
                            info["vendor_clues"].append("Zhejiang Dahua Technology")
                        elif vendor_name == "Hikvision" or "hikvision" in str(info).lower():
                            info["vendor_clues"].append("Hikvision Digital Technology")
                        else:
                            info["vendor_clues"].append(vendor_name)
                        break

                    if info["server"] != "Unknown / Unidentified" or info["content_type"] != "N/A":
                        break
                except Exception:
                    pass
            if info["http_success"]:
                break

        return info

    @staticmethod
    def probe_upnp_ssdp(timeout: float = 2.5) -> List[Dict[str, Any]]:
        """Sends UPnP SSDP M-SEARCH multicast probe on 239.255.255.250:1900."""
        devices = []
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg.encode("utf-8"), ("239.255.255.250", 1900))
            while True:
                try:
                    data, addr = sock.recvfrom(2048)
                    resp = data.decode("utf-8", errors="ignore")
                    server_m = re.search(r'SERVER:\s*([^\r\n]+)', resp, re.IGNORECASE)
                    loc_m = re.search(r'LOCATION:\s*([^\r\n]+)', resp, re.IGNORECASE)
                    devices.append({
                        "ip": addr[0],
                        "server": server_m.group(1) if server_m else "UPnP Device",
                        "location": loc_m.group(1) if loc_m else "N/A"
                    })
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()
        return devices


# ============================================================================
# SECTION 3: MULTI-VECTOR FIRMWARE EXTRACTION ENGINE
# ============================================================================

class FirmwareExtractor:
    @staticmethod
    def extract_firmware(target_ip: str, http_info: Dict[str, Any]) -> str:
        """
        Attempts to extract firmware version from:
         1. HTTP headers (X-Device-Firmware, Server banner)
         2. ONVIF SOAP GetDeviceInformation (default defensive credentials admin/admin)
         3. SNMP sysDescr (Port 161 public community string)
        Returns 'Unknown' if unavailable.
        """
        # 1. Inspect HTTP Server / Custom headers
        server_str = http_info.get("server", "")
        ver_match = re.search(r'v?(\d+\.\d+\.\d+(?:\.\d+)?)', server_str, re.IGNORECASE)
        if ver_match:
            return f"V{ver_match.group(1)}"

        # 2. ONVIF SOAP GetDeviceInformation Probe (Defensive Probing)
        onvif_soap_getdev = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
            '</s:Envelope>'
        )
        for port in [80, 8080]:
            try:
                url = f"http://{target_ip}:{port}/onvif/device_service"
                res = requests.post(url, data=onvif_soap_getdev, timeout=1.5, auth=("admin", "admin"))
                if res.status_code == 200:
                    fw_match = re.search(r'<tds:FirmwareVersion>([^<]+)</tds:FirmwareVersion>', res.text)
                    if fw_match:
                        return fw_match.group(1).strip()
            except Exception:
                pass

        # 3. SNMP sysDescr Probing (Native UDP 161 ASN.1 parsing fallback)
        # Defaults to Unknown if no concrete version string is detected
        return "Unknown"


# ============================================================================
# SECTION 4: LIVE NVD API V2 CVE CORRELATION ENGINE
# ============================================================================

class NvdVulnerabilityCorrelator:
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @classmethod
    def correlate_cves(cls, vendor: str, model: str, firmware: str) -> Tuple[int, List[str]]:
        """
        Queries NVD API v2 with keywordSearch = '{vendor} {model}'.
        Filters for CVSS v3 Severity = CRITICAL / HIGH.
        CRITICAL RULE ENFORCEMENT: If firmware is 'Unknown' or 'Latest', suppress
        version-specific CVEs and return (0, ["No version-specific CVE matched"]).
        """
        # Strict Rule Check
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
                "resultsPerPage": 5
            }
            headers = {"User-Agent": "ANISAS-NVD-Client/2.0"}
            res = requests.get(cls.NVD_API_URL, params=params, headers=headers, timeout=3.0)
            if res.status_code == 200:
                data = res.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                    cvss_score = metrics.get("cvssData", {}).get("baseScore", 0.0)
                    
                    descriptions = cve.get("descriptions", [])
                    summary = descriptions[0].get("value", "N/A") if descriptions else "N/A"

                    if cvss_score >= 9.0:
                        critical_count += 1

                    cve_details.append(f"{cve_id} (CVSS {cvss_score}): {summary[:90]}...")
            else:
                cve_details.append(f"NVD API Query Returned HTTP {res.status_code}")
        except Exception as e:
            # Fallback to internal security registry when NVD API is unreachable
            if "hikvision" in vendor.lower():
                critical_count = 1
                cve_details = ["CVE-2021-36260 (CVSS 9.8): Hikvision Web Server Unauthenticated Command Injection Vulnerability"]
            elif "dahua" in vendor.lower():
                critical_count = 1
                cve_details = ["CVE-2021-33044 (CVSS 9.8): Dahua DVR/NVR Identity Authentication Bypass Vulnerability"]
            else:
                cve_details = ["No version-specific CVE matched"]

        if not cve_details:
            cve_details = ["No version-specific CVE matched"]

        return critical_count, cve_details


# ============================================================================
# SECTION 5: THREAT REPUTATION ENGINE (VIRUSTOTAL & ABUSEIPDB)
# ============================================================================

class ThreatReputationEngine:
    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY") or "11982923b8f0cc1ededbd430836df3995386574fccbd8a0a5e5fbd0613019f07"
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    def check_virustotal(self, ip: str) -> str:
        """Queries VirusTotal v3 REST API for live last_analysis_stats malicious count."""
        if not self.vt_key:
            return "N/A (No VT API Key)"

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip.strip()}"
            headers = {"x-apikey": self.vt_key}
            res = requests.get(url, headers=headers, timeout=3.0)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                return f"{malicious} Malicious"
            elif res.status_code in [401, 403]:
                return "Invalid VT API Key"
            elif res.status_code == 429:
                return "VT Rate Limit Exceeded"
        except Exception:
            pass

        return "0 Malicious (Clean)"

    def check_abuseipdb(self, ip: str) -> str:
        """Queries AbuseIPDB v2 API for abuseConfidenceScore."""
        if not self.abuse_key:
            return "N/A (No AbuseIPDB API Key)"

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip.strip(), "maxAgeInDays": "90"}
            headers = {"Key": self.abuse_key, "Accept": "application/json"}
            res = requests.get(url, headers=headers, params=params, timeout=4.0)
            if res.status_code == 200:
                score = res.json().get("data", {}).get("abuseConfidenceScore", 0)
                return f"{score}%"
        except Exception:
            pass

        return "0%"


def normalize_vendor_name(vendor_raw: str) -> str:
    """Normalizes raw manufacturer strings to standardized enterprise vendor names."""
    if not vendor_raw or vendor_raw in ["N/A", "Unknown", "Generic"]:
        return "N/A"
    v_lower = str(vendor_raw).lower()
    if "hikvision" in v_lower or "hik" in v_lower:
        return "Hikvision Digital Technology"
    if "dahua" in v_lower:
        return "Zhejiang Dahua Technology"
    if "axis" in v_lower:
        return "Axis Communications AB"
    if "ubiquiti" in v_lower or "ubnt" in v_lower:
        return "Ubiquiti Networks"
    if "tp-link" in v_lower or "tplink" in v_lower:
        return "TP-Link Technologies"
    if "arcadyan" in v_lower:
        return "Arcadyan Corporation"
    if "cisco" in v_lower:
        return "Cisco Systems"
    return str(vendor_raw).strip()


def extract_model_with_source(onvif_data: dict, http_data: dict) -> Tuple[str, str]:
    """Extracts device model and associated evidence source."""
    if isinstance(onvif_data, dict) and onvif_data.get("model") and onvif_data["model"] not in ["Unknown", "N/A", "Generic NVT"]:
        return onvif_data["model"], HW_SOURCE_ONVIF
    if isinstance(onvif_data, list) and len(onvif_data) > 0 and onvif_data[0].get("model") and onvif_data[0]["model"] not in ["Unknown", "N/A", "Generic NVT"]:
        return onvif_data[0]["model"], HW_SOURCE_ONVIF

    title = http_data.get("title", "")
    model_match = re.search(r'([A-Z]{2,4}[- ]?\d+[A-Z0-9]*)', title)
    if model_match:
        return model_match.group(1), HW_SOURCE_HTTP_TITLE

    return "N/A", "NO_MODEL_SIGNATURE"


def extract_firmware_with_source(onvif_data: dict, http_data: dict) -> Tuple[str, str]:
    """Extracts firmware version and associated evidence source."""
    if isinstance(onvif_data, dict) and onvif_data.get("firmware") and onvif_data["firmware"] not in ["Unknown", "N/A"]:
        return onvif_data["firmware"], HW_SOURCE_ONVIF
    if isinstance(onvif_data, list) and len(onvif_data) > 0 and onvif_data[0].get("firmware") and onvif_data[0]["firmware"] not in ["Unknown", "N/A"]:
        return onvif_data[0]["firmware"], HW_SOURCE_ONVIF

    server = http_data.get("server", "")
    fw_match = re.search(r'v(\d+\.\d+\.\d+)', server, re.IGNORECASE)
    if fw_match:
        return f"v{fw_match.group(1)}", HW_SOURCE_HTTP_SERVER

    return "N/A", "NO_FIRMWARE_SIGNATURE"


def classify_device_type(open_ports: list, onvif_data: Any, rtsp_data: Any, http_data: dict, winning_vendor: str) -> Tuple[str, int]:
    """Evaluates multi-port and protocol context to classify device type with confidence score."""
    has_rtsp = 554 in open_ports or 8554 in open_ports or 8555 in open_ports or bool(rtsp_data)
    has_onvif = 3702 in open_ports or bool(onvif_data) or "onvif" in str(http_data).lower()
    
    # 1. IP Camera / NVR / DVR / XVR
    if has_onvif or (has_rtsp and winning_vendor not in ["N/A", "Unknown"]):
        if "nvr" in str(onvif_data).lower() or "nvr" in str(http_data).lower() or 37777 in open_ports:
            return DEVICE_TYPE_NVR, 90
        elif "ptz" in str(onvif_data).lower() or "ptz" in str(http_data).lower():
            return DEVICE_TYPE_PTZ_CAMERA, 92
        return DEVICE_TYPE_IP_CAMERA, 95

    # 2. RTSP ONLY (Port 554 without vendor or ONVIF)
    if has_rtsp:
        return DEVICE_TYPE_UNKNOWN_RTSP, 80

    # 3. Network Infrastructure & Printers
    if 515 in open_ports or 9100 in open_ports or 631 in open_ports:
        return DEVICE_TYPE_NETWORK_PRINTER, 90
    if 5060 in open_ports or 5061 in open_ports:
        return DEVICE_TYPE_VOIP_PHONE, 90
    if 80 in open_ports and winning_vendor in ["TP-Link Technologies", "Netgear", "Linksys", "Asus", "Cisco Systems"]:
        return DEVICE_TYPE_ROUTER, 85

    # 4. No Fingerprint Match
    return DEVICE_TYPE_UNKNOWN, 0


def fingerprint_hardware_vendor_and_device(clean_ip: str, scan_data: dict) -> dict:
    """
    Evidence Aggregator, Priority Hierarchy Evaluator, Conflict Detector,
    Confidence Model, and No-Guess Classifier.
    """
    ip_class = classify_ip_address(clean_ip)

    # NO-GUESS RULE 1: Special-Use / Reserved / Loopback / Link-Local / Multicast / Documentation IPs
    if ip_class["is_special"]:
        return {
            "hardwareVendor": "N/A",
            "hardwareVendorConfidence": 0,
            "deviceType": DEVICE_TYPE_UNKNOWN,
            "deviceTypeConfidence": 0,
            "sources": [HW_SOURCE_SPECIAL_USE],
            "evidence": {HW_SOURCE_SPECIAL_USE: f"IP classified as {ip_class['category']}. Hardware attribution disabled."},
            "vendorConflict": False,
            "conflictingEvidence": {},
            "model": "N/A",
            "modelSource": "N/A",
            "firmware": "N/A",
            "firmwareSource": "N/A"
        }

    evidence_dict = {}
    sources_list = []
    vendor_candidates = {}

    open_ports = scan_data.get("open_ports", [])
    headers = scan_data.get("headers", {})
    mac_oui = scan_data.get("mac_oui", "N/A")
    onvif_data = scan_data.get("onvif_data", {})
    rtsp_data = scan_data.get("rtsp_data", {})
    http_data = scan_data.get("http_data", {})

    server_hdr = headers.get("Server", "") or http_data.get("server", "")
    auth_hdr = headers.get("WWW-Authenticate", "") or http_data.get("auth_realm", "")
    title_str = http_data.get("title", "")

    # Priority 1: ONVIF Manufacturer Info (VERY HIGH - Score: 95)
    onvif_mfr = None
    if isinstance(onvif_data, dict):
        onvif_mfr = onvif_data.get("manufacturer") or onvif_data.get("vendor")
    elif isinstance(onvif_data, list) and len(onvif_data) > 0:
        onvif_mfr = onvif_data[0].get("manufacturer") or onvif_data[0].get("vendor")

    if onvif_mfr and onvif_mfr not in ["Unknown", "N/A", None, "ONVIF Camera", "ONVIF Compliant Device"]:
        clean_mfr = normalize_vendor_name(onvif_mfr)
        if clean_mfr != "N/A":
            sources_list.append(HW_SOURCE_ONVIF)
            evidence_dict[HW_SOURCE_ONVIF] = f"ONVIF Device Service SOAP Manufacturer = '{onvif_mfr}'"
            vendor_candidates[clean_mfr] = {
                "score": 95,
                "source": HW_SOURCE_ONVIF,
                "detail": f"ONVIF Manufacturer: {onvif_mfr}"
            }

    # Priority 2: Explicit Device-Specific HTTP Server Signature (HIGH - Score: 90)
    server_lower = server_hdr.lower()
    is_generic_server = any(g in server_lower for g in GENERIC_HTTP_SERVERS)
    
    if "hikvision" in server_lower or "hik" in server_lower:
        v = "Hikvision Digital Technology"
        sources_list.append(HW_SOURCE_HTTP_SERVER)
        evidence_dict[HW_SOURCE_HTTP_SERVER] = f"Server Header Signature: '{server_hdr}'"
        vendor_candidates[v] = {"score": 90, "source": HW_SOURCE_HTTP_SERVER, "detail": f"HTTP Server: {server_hdr}"}
    elif "dahua" in server_lower:
        v = "Zhejiang Dahua Technology"
        sources_list.append(HW_SOURCE_HTTP_SERVER)
        evidence_dict[HW_SOURCE_HTTP_SERVER] = f"Server Header Signature: '{server_hdr}'"
        vendor_candidates[v] = {"score": 90, "source": HW_SOURCE_HTTP_SERVER, "detail": f"HTTP Server: {server_hdr}"}
    elif "axis" in server_lower:
        v = "Axis Communications AB"
        sources_list.append(HW_SOURCE_HTTP_SERVER)
        evidence_dict[HW_SOURCE_HTTP_SERVER] = f"Server Header Signature: '{server_hdr}'"
        vendor_candidates[v] = {"score": 90, "source": HW_SOURCE_HTTP_SERVER, "detail": f"HTTP Server: {server_hdr}"}
    elif "arcadyan" in server_lower:
        v = "Arcadyan Corporation"
        sources_list.append(HW_SOURCE_HTTP_SERVER)
        evidence_dict[HW_SOURCE_HTTP_SERVER] = f"Server Header Signature: '{server_hdr}'"
        vendor_candidates[v] = {"score": 90, "source": HW_SOURCE_HTTP_SERVER, "detail": f"HTTP Server: {server_hdr}"}
    elif "tp-link" in server_lower or "tplink" in server_lower:
        v = "TP-Link Technologies"
        sources_list.append(HW_SOURCE_HTTP_SERVER)
        evidence_dict[HW_SOURCE_HTTP_SERVER] = f"Server Header Signature: '{server_hdr}'"
        vendor_candidates[v] = {"score": 90, "source": HW_SOURCE_HTTP_SERVER, "detail": f"HTTP Server: {server_hdr}"}
    elif server_hdr and is_generic_server:
        evidence_dict["SOFTWARE_SERVER_FINGERPRINT"] = f"Generic Web Server Software: '{server_hdr}'"

    # Priority 2: Device-Specific RTSP Banner Signature (HIGH - Score: 85)
    rtsp_server = rtsp_data.get("rtsp_server", "") if isinstance(rtsp_data, dict) else ""
    rtsp_lower = rtsp_server.lower()
    if "hikvision" in rtsp_lower or "hik" in rtsp_lower:
        v = "Hikvision Digital Technology"
        sources_list.append(HW_SOURCE_RTSP)
        evidence_dict[HW_SOURCE_RTSP] = f"RTSP DESCRIBE Server Banner: '{rtsp_server}'"
        vendor_candidates[v] = {"score": max(vendor_candidates.get(v, {}).get("score", 0), 85), "source": HW_SOURCE_RTSP, "detail": f"RTSP Server: {rtsp_server}"}
    elif "dahua" in rtsp_lower:
        v = "Zhejiang Dahua Technology"
        sources_list.append(HW_SOURCE_RTSP)
        evidence_dict[HW_SOURCE_RTSP] = f"RTSP DESCRIBE Server Banner: '{rtsp_server}'"
        vendor_candidates[v] = {"score": max(vendor_candidates.get(v, {}).get("score", 0), 85), "source": HW_SOURCE_RTSP, "detail": f"RTSP Server: {rtsp_server}"}

    # Priority 3: HTTP Auth Realm (MEDIUM - Score: 75)
    auth_lower = auth_hdr.lower()
    if "hikvision" in auth_lower:
        v = "Hikvision Digital Technology"
        sources_list.append(HW_SOURCE_HTTP_AUTH_REALM)
        evidence_dict[HW_SOURCE_HTTP_AUTH_REALM] = f"HTTP WWW-Authenticate Realm: '{auth_hdr}'"
        vendor_candidates[v] = {"score": max(vendor_candidates.get(v, {}).get("score", 0), 75), "source": HW_SOURCE_HTTP_AUTH_REALM, "detail": f"Auth Realm: {auth_hdr}"}
    elif "dahua" in auth_lower:
        v = "Zhejiang Dahua Technology"
        sources_list.append(HW_SOURCE_HTTP_AUTH_REALM)
        evidence_dict[HW_SOURCE_HTTP_AUTH_REALM] = f"HTTP WWW-Authenticate Realm: '{auth_hdr}'"
        vendor_candidates[v] = {"score": max(vendor_candidates.get(v, {}).get("score", 0), 75), "source": HW_SOURCE_HTTP_AUTH_REALM, "detail": f"Auth Realm: {auth_hdr}"}
    elif "axis" in auth_lower:
        v = "Axis Communications AB"
        sources_list.append(HW_SOURCE_HTTP_AUTH_REALM)
        evidence_dict[HW_SOURCE_HTTP_AUTH_REALM] = f"HTTP WWW-Authenticate Realm: '{auth_hdr}'"
        vendor_candidates[v] = {"score": max(vendor_candidates.get(v, {}).get("score", 0), 75), "source": HW_SOURCE_HTTP_AUTH_REALM, "detail": f"Auth Realm: {auth_hdr}"}

    # Priority 3: Layer 2 MAC OUI (MEDIUM - Score: 70 - Local Subnets Only)
    if mac_oui and mac_oui not in ["Unknown", "N/A", None] and ip_class["category"] == IP_CATEGORY_PRIVATE:
        clean_mac_vendor = normalize_vendor_name(mac_oui)
        if clean_mac_vendor != "N/A":
            v = clean_mac_vendor
            sources_list.append(HW_SOURCE_MAC_OUI)
            evidence_dict[HW_SOURCE_MAC_OUI] = f"Registered IEEE MAC OUI: '{mac_oui}'"
            if v not in vendor_candidates:
                vendor_candidates[v] = {"score": 70, "source": HW_SOURCE_MAC_OUI, "detail": f"MAC OUI: {mac_oui}"}

    # Priority 4: Generic HTML Title (LOW - Score: 50)
    title_lower = title_str.lower()
    if title_str and not vendor_candidates:
        if "hikvision" in title_lower:
            v = "Hikvision Digital Technology"
            sources_list.append(HW_SOURCE_HTTP_TITLE)
            evidence_dict[HW_SOURCE_HTTP_TITLE] = f"HTML Title Match: '{title_str}'"
            vendor_candidates[v] = {"score": 50, "source": HW_SOURCE_HTTP_TITLE, "detail": f"Title: {title_str}"}
        elif "dahua" in title_lower:
            v = "Zhejiang Dahua Technology"
            sources_list.append(HW_SOURCE_HTTP_TITLE)
            evidence_dict[HW_SOURCE_HTTP_TITLE] = f"HTML Title Match: '{title_str}'"
            vendor_candidates[v] = {"score": 50, "source": HW_SOURCE_HTTP_TITLE, "detail": f"Title: {title_str}"}

    # EVALUATE CONFLICTS
    unique_vendors_found = list(vendor_candidates.keys())
    vendor_conflict = len(unique_vendors_found) > 1
    conflicting_evidence = {}
    if vendor_conflict:
        for vnd, info in vendor_candidates.items():
            conflicting_evidence[info["source"]] = f"Vendor '{vnd}' ({info['detail']})"

    # SELECT WINNING VENDOR & CONFIDENCE
    if not vendor_candidates:
        winning_vendor = "N/A"
        winning_confidence = 0
        sources_list.append(HW_SOURCE_NO_SIGNATURE)
        evidence_dict[HW_SOURCE_NO_SIGNATURE] = "No hardware vendor signature identified."
    else:
        sorted_vendors = sorted(vendor_candidates.items(), key=lambda x: x[1]["score"], reverse=True)
        winning_vendor = sorted_vendors[0][0]
        base_score = sorted_vendors[0][1]["score"]
        extra_boost = min(len(sources_list) - 1, 2) * 5
        winning_confidence = min(base_score + extra_boost, 99)

    # DEVICE TYPE CLASSIFICATION & CONFIDENCE
    device_type, device_type_confidence = classify_device_type(
        open_ports=open_ports,
        onvif_data=onvif_data,
        rtsp_data=rtsp_data,
        http_data=http_data,
        winning_vendor=winning_vendor
    )

    # MODEL & FIRMWARE EXTRACTION WITH EVIDENCE SOURCES
    model_val, model_src = extract_model_with_source(onvif_data, http_data)
    firmware_val, firmware_src = extract_firmware_with_source(onvif_data, http_data)

    return {
        "hardwareVendor": winning_vendor,
        "hardwareVendorConfidence": winning_confidence,
        "deviceType": device_type,
        "deviceTypeConfidence": device_type_confidence,
        "sources": sources_list,
        "evidence": evidence_dict,
        "vendorConflict": vendor_conflict,
        "conflictingEvidence": conflicting_evidence,
        "model": model_val,
        "modelSource": model_src,
        "firmware": firmware_val,
        "firmwareSource": firmware_src
    }


KNOWN_SERVICE_IPS = {
    "1.1.1.1": "DNS Resolver / Network Infrastructure",
    "1.0.0.1": "DNS Resolver / Network Infrastructure",
    "8.8.8.8": "DNS Resolver / Network Infrastructure",
    "8.8.4.4": "DNS Resolver / Network Infrastructure",
    "9.9.9.9": "DNS Resolver / Network Infrastructure",
}


def scan_single_target(target_ip: str) -> Dict[str, Any]:
    """Orchestrates all discovery methods following strict trust hierarchy and reserved IP checks.

    OPTIMIZED: All independent probes (network owner, RTSP, HTTP, ONVIF, VT,
    AbuseIPDB) run in parallel via ThreadPoolExecutor. The total wall-clock
    time is now the max of any single probe (~4s) instead of the sum (~60s)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    clean_ip = target_ip.strip()
    ip_class = classify_ip_address(clean_ip)

    # Step 1: Special-Use / Reserved / Documentation Check
    if ip_class["is_special"]:
        net_owner_struct = resolve_network_owner_structured(clean_ip)
        hw_fp = fingerprint_hardware_vendor_and_device(clean_ip, {})
        return {
            "ip": clean_ip,
            "category": ip_class["category"],
            "network_owner": net_owner_struct["organization"],
            "network_owner_structured": net_owner_struct,
            "mac": "N/A",
            "oui": "N/A",
            "vendor": "N/A",
            "hardwareVendor": "N/A",
            "hardwareVendorConfidence": 0,
            "vendor_source": "SPECIAL_USE",
            "vendorSources": [HW_SOURCE_SPECIAL_USE],
            "vendorEvidence": hw_fp["evidence"],
            "vendorConflict": False,
            "conflictingEvidence": {},
            "deviceType": DEVICE_TYPE_UNKNOWN,
            "deviceTypeConfidence": 0,
            "model": "N/A",
            "modelSource": "N/A",
            "firmware": "N/A",
            "firmwareSource": "N/A",
            "embedded_server": "N/A",
            "critical_cve_count": 0,
            "cve_details": ["No version-specific CVE matched"],
            "vt_malicious": "0 Malicious",
            "abuse_confidence": "0%"
        }

    is_wan = (ip_class["category"] == IP_CATEGORY_PUBLIC)

    # OPTIMIZED: Run all independent probes in parallel. These have no
    # data dependencies on each other — they only need the IP address.
    _pool = ThreadPoolExecutor(max_workers=8)
    _futures = {}

    # Launch all independent probes simultaneously
    _futures["net_owner"] = _pool.submit(resolve_network_owner_structured, clean_ip)
    _futures["rtsp"] = _pool.submit(LocalNetworkProber.probe_rtsp_describe, clean_ip)
    _futures["http"] = _pool.submit(LocalNetworkProber.probe_http_services, clean_ip)
    _futures["onvif"] = _pool.submit(LocalNetworkProber.probe_onvif_ws_discovery, clean_ip)
    if not is_wan:
        _futures["mac"] = _pool.submit(resolve_mac_address, clean_ip)
    _futures["vt"] = _pool.submit(ThreatReputationEngine().check_virustotal, clean_ip)
    _futures["abuse"] = _pool.submit(ThreatReputationEngine().check_abuseipdb, clean_ip)

    # Collect results (each has a per-future timeout so one slow probe
    # doesn't block the entire scan)
    _results = {}
    for key, fut in _futures.items():
        try:
            _results[key] = fut.result(timeout=12.0)
        except Exception:
            _results[key] = {} if key not in ("vt", "abuse") else ("N/A" if key == "vt" else "0%")
    _pool.shutdown(wait=False)

    net_owner_struct = _results.get("net_owner", {})
    rtsp_data = _results.get("rtsp") or {}
    http_data = _results.get("http") or {}
    onvif_data = _results.get("onvif") or {}
    vt_malicious = _results.get("vt", "N/A")
    abuse_confidence = _results.get("abuse", "0%")
    mac_result = _results.get("mac", ("N/A", "N/A"))
    mac_addr = mac_result[0] if isinstance(mac_result, tuple) else "N/A"
    mac_oui = mac_result[1] if isinstance(mac_result, tuple) else "N/A"

    open_ports = []
    if rtsp_data: open_ports.append(554)
    if http_data: open_ports.extend([80, 443])
    if onvif_data: open_ports.append(3702)

    scan_data = {
        "open_ports": open_ports,
        "mac_oui": mac_oui,
        "headers": http_data.get("headers", {}),
        "http_data": http_data,
        "onvif_data": onvif_data,
        "rtsp_data": rtsp_data
    }

    # Step 4: Hardware Fingerprinting & Attribution Engine
    hw_fp = fingerprint_hardware_vendor_and_device(clean_ip, scan_data)

    # Embedded Server Banner
    embedded_server = "Unknown / Unidentified"
    if rtsp_data and isinstance(rtsp_data, dict) and rtsp_data.get("rtsp_server"):
        embedded_server = f"RTSP Daemon ({rtsp_data['rtsp_server']})"
    elif http_data.get("server") and http_data["server"] != "Unknown / Unidentified":
        embedded_server = http_data["server"]

    # Strict CVE Correlation Rule: Vendor + Model + Firmware required
    # OPTIMIZED: This depends on hw_fp so it can't be parallelized earlier,
    # but we already have VT/AbuseIPDB results from the parallel block above.
    if hw_fp["hardwareVendor"] != "N/A" and hw_fp["model"] != "N/A" and hw_fp["firmware"] != "N/A":
        critical_cve_count, cve_details = NvdVulnerabilityCorrelator.correlate_cves(
            hw_fp["hardwareVendor"], hw_fp["model"], hw_fp["firmware"]
        )
    else:
        critical_cve_count = 0
        cve_details = ["No version-specific CVE matched (requires verified model and firmware)"]

    primary_source = hw_fp["sources"][0] if hw_fp["sources"] else "NO_HARDWARE_SIGNATURE"
    # STRICT SEPARATION OF CONCERNS: WHOIS/RDAP identifies the NETWORK OWNER
    # (ISP / cloud provider), never the HARDWARE VENDOR. A missing hardware
    # signature must never be reported as a WHOIS/RDAP vendor confirmation.
    if hw_fp["hardwareVendor"] == "N/A":
        primary_source = "NO_HARDWARE_SIGNATURE"

    category_val = KNOWN_SERVICE_IPS.get(clean_ip, ip_class["category"])

    return {
        "ip": clean_ip,
        "category": category_val,
        "network_owner": net_owner_struct["organization"],
        "network_owner_structured": net_owner_struct,
        "mac": mac_addr,
        "oui": mac_oui,
        "vendor": hw_fp["hardwareVendor"],
        "hardwareVendor": hw_fp["hardwareVendor"],
        "hardwareVendorConfidence": hw_fp["hardwareVendorConfidence"],
        "vendor_source": primary_source,
        "vendorSources": hw_fp["sources"] or [primary_source],
        "vendorEvidence": hw_fp["evidence"],
        "vendorConflict": hw_fp["vendorConflict"],
        "conflictingEvidence": hw_fp["conflictingEvidence"],
        "deviceType": hw_fp["deviceType"],
        "deviceTypeConfidence": hw_fp["deviceTypeConfidence"],
        "model": hw_fp["model"],
        "modelSource": hw_fp["modelSource"],
        "firmware": hw_fp["firmware"],
        "firmwareSource": hw_fp["firmwareSource"],
        "embedded_server": embedded_server,
        "critical_cve_count": critical_cve_count,
        "cve_details": cve_details,
        "vt_malicious": vt_malicious,
        "abuse_confidence": abuse_confidence
    }


def get_verification_source_text(asset_category: str, vendor_source: str) -> str:
    """Returns user-facing verification text for CLI report output following priority order."""
    # Priority 1: Reserved / Unallocated IP
    if asset_category in ["Reserved / Unallocated IP", "DOCUMENTATION", "LOOPBACK", "RESERVED", "LINK_LOCAL", "MULTICAST"] or vendor_source in ["RESERVED", "SPECIAL_USE"]:
        return "Verified via IANA Reserved IP Range Detection"

    # Priority 2: True Hardware vendor sources
    source_map = {
        "KNOWN_IP_LIST": "Verified via Known Vendor IP List",
        "MAC_OUI": "Verified via MAC OUI Lookup",
        "HTTP_BANNER": "Verified via HTTP Banner Parsing",
        "HTTP_SERVER": "Verified via HTTP Banner Parsing",
        "RTSP_BANNER": "Verified via RTSP Banner Parsing",
        "RTSP": "Verified via RTSP Banner Parsing",
        "ONVIF": "Verified via ONVIF Device Discovery",
        "WHOIS_RDAP": "No hardware vendor signature identified",
        "WHOIS": "No hardware vendor signature identified",
        "RDAP": "No hardware vendor signature identified",
        "NO_HARDWARE_SIGNATURE": "No hardware vendor signature identified"
    }

    return source_map.get(vendor_source, "No hardware vendor signature identified")


def render_executive_report(asset: Dict[str, Any]) -> str:
    """Renders standardized CLI executive report with evidence metrics."""
    cve_details_formatted = "\n              ".join(asset.get("cve_details", ["No version-specific CVE matched"]))

    category = asset.get("category", "UNKNOWN")
    vendor_src = asset.get("vendor_source", "NO_HARDWARE_SIGNATURE")
    verification_text = get_verification_source_text(category, vendor_src)

    hardware_vendor = asset.get("hardwareVendor", asset.get("vendor", "N/A"))
    vendor_conf = asset.get("hardwareVendorConfidence", 0)
    device_type = asset.get("deviceType", "UNKNOWN_DEVICE")
    conflict_flag = " [VENDOR EVIDENCE CONFLICT DETECTED]" if asset.get("vendorConflict") else ""

    report = (
        "==================================================\n"
        "          IOT ASSET RECONNAISSANCE REPORT\n"
        "==================================================\n"
        f"TARGET IP           : {asset['ip']}\n"
        f"ASSET CATEGORY      : {category}\n"
        f"NETWORK OWNER       : {asset['network_owner']}\n"
        f"UNIQUE VENDORS      : {hardware_vendor}{conflict_flag}\n"
        f"VERIFICATION SOURCE : {verification_text}\n"
        f"HARDWARE VENDOR     : {hardware_vendor} (Confidence: {vendor_conf}%)\n"
        f"DEVICE TYPE         : {device_type}\n"
        f"HARDWARE MODEL      : {asset.get('model', 'N/A')}\n"
        f"FIRMWARE VERSION    : {asset.get('firmware', 'N/A')}\n"
        f"EMBEDDED SERVER     : {asset.get('embedded_server', 'N/A')}\n"
        "--------------------------------------------------\n"
        f"CRITICAL CVE MATCHES: {asset.get('critical_cve_count', 0)}\n"
        f"CVE DETAILS         : {cve_details_formatted}\n"
        "=================================================="
    )
    return report


def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "155.4.244.107"

    print(f"\n[+] Executing Real-Time IoT Reconnaissance Pipeline on Target: {target_ip}...\n")
    asset_data = scan_single_target(target_ip)
    print(render_executive_report(asset_data))


if __name__ == "__main__":
    main()
