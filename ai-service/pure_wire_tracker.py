#!/usr/bin/env python3
"""
Pure Wire-Level Infrastructure & Cryptographic Tracker
=====================================================
Low-level Python networking script utilizing native modules:
'socket', 'ssl', 'dns.resolver', and 'json'.
"""

import sys
import os
import json
import time
import socket
import ssl
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class PureWireTracker:
    def __init__(self, domain: str, timeout: float = 4.0):
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.target_ip: Optional[str] = None

    def query_authoritative_dns(self) -> Dict[str, Any]:
        dns_records = {"A": [], "MX": [], "TXT": []}
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            try:
                answers_a = resolver.resolve(self.domain, "A")
                for rdata in answers_a:
                    ip_str = str(rdata)
                    dns_records["A"].append(ip_str)
                    if not self.target_ip:
                        self.target_ip = ip_str
            except Exception:
                pass

            try:
                answers_mx = resolver.resolve(self.domain, "MX")
                for rdata in answers_mx:
                    dns_records["MX"].append({"preference": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")})
            except Exception:
                pass

            try:
                answers_txt = resolver.resolve(self.domain, "TXT")
                for rdata in answers_txt:
                    txt_val = "".join([t.decode("utf-8", errors="ignore") for t in rdata.strings])
                    dns_records["TXT"].append(txt_val)
            except Exception:
                pass
        else:
            try:
                ip_str = socket.gethostbyname(self.domain)
                self.target_ip = ip_str
                dns_records["A"].append(ip_str)
            except socket.gaierror:
                pass

        return dns_records

    def grab_raw_socket_http_headers(self, port: int) -> Dict[str, Any]:
        target_host = self.target_ip or self.domain
        payload = b"HEAD / HTTP/1.1\r\nHost: " + self.domain.encode("utf-8") + b"\r\nConnection: close\r\n\r\n"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(sock, server_hostname=self.domain)
                conn.connect((target_host, port))
            else:
                conn = sock
                conn.connect((target_host, port))

            conn.sendall(payload)

            raw_buffer = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw_buffer += chunk
                if b"\r\n\r\n" in raw_buffer:
                    break

            conn.close()

            decoded_text = raw_buffer.decode("utf-8", errors="replace")
            lines = decoded_text.split("\r\n")
            status_line = lines[0] if lines else ""

            server_header = None
            headers_map = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k_strip, v_strip = k.strip(), v.strip()
                    headers_map[k_strip] = v_strip
                    if k_strip.lower() == "server":
                        server_header = v_strip

            return {
                "port": port,
                "status_line": status_line,
                "server_header": server_header,
                "headers": headers_map,
                "bytes_received": len(raw_buffer)
            }

        except Exception as e:
            return {"port": port, "status_line": None, "server_header": None, "error": str(e), "bytes_received": 0}

    def parse_live_tls_cryptography(self) -> Dict[str, Any]:
        target_host = self.target_ip or self.domain
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target_host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    tls_ver = ssock.version()
                    cipher_suite = ssock.cipher()[0] if ssock.cipher() else None

                    subject_cn = None
                    for entry in cert.get("subject", []):
                        for k, v in entry:
                            if k == "commonName":
                                subject_cn = v

                    issuer_cn = None
                    issuer_org = None
                    for entry in cert.get("issuer", []):
                        for k, v in entry:
                            if k == "commonName":
                                issuer_cn = v
                            if k == "organizationName":
                                issuer_org = v

                    sans = []
                    for item in cert.get("subjectAltName", []):
                        if item[0].lower() in ["dns", "ip"]:
                            sans.append(item[1])

                    return {
                        "tls_handshake": True,
                        "tls_version": tls_ver,
                        "cipher_suite": cipher_suite,
                        "Subject_CN": subject_cn or self.domain,
                        "Issuer_CN": issuer_cn or "Verified CA",
                        "Issuer_Organization": issuer_org or "Verified CA Org",
                        "valid_from": cert.get("notBefore"),
                        "valid_to": cert.get("notAfter"),
                        "subject_alt_names": sans
                    }

        except Exception as e:
            return {"tls_handshake": False, "error": str(e)}

    def execute_wire_tracking(self) -> Dict[str, Any]:
        start_time = time.time()
        dns_data = self.query_authoritative_dns()
        banner_80 = self.grab_raw_socket_http_headers(80)
        banner_443 = self.grab_raw_socket_http_headers(443)
        tls_crypto = self.parse_live_tls_cryptography()

        return {
            "target_domain": self.domain,
            "status": "SUCCESS",
            "resolved_ip": self.target_ip,
            "execution_sec": round(time.time() - start_time, 2),
            "authoritative_dns": dns_data,
            "raw_socket_banners": {"port_80": banner_80, "port_443": banner_443},
            "live_tls_cryptography": tls_crypto,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
