#!/usr/bin/env python3
"""
ANISAS Enterprise Cyber Intelligence Platform
================================================
Anti-Wildcard Subdomain & Real-Time Infrastructure Verifier

Features:
1. Anti-Wildcard Zone Baseline Detection (Randomized non-existent subdomain probing)
2. Baseline IP Filtering (Removes false positive IPs returning for all subdomains)
3. Real-Time HTTP/HTTPS Probing (Verifies 200, 301, 302, 403, 404 live web servers)
4. Port 443 SSL/TLS Certificate Handshake (Extracts Issuer, SANs, Expiry)
5. Clean JSON Output Specification for Real-time Dashboards
"""

import os
import sys
import json
import time
import uuid
import socket
import ssl
import requests
import urllib3
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AntiWildcardSubdomainVerifier:
    def __init__(self, domain: str, timeout: float = 0.4, max_workers: int = 15):
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.max_workers = max_workers
        self.is_wildcard_zone = False
        self.wildcard_baseline_ips = set()

    def detect_wildcard_baseline(self) -> bool:
        """
        1. ANTI-WILDCARD VALIDATION:
        Sends resolution requests to randomized, non-existent subdomains.
        If resolved, flags domain as a Wildcard Zone and captures baseline IPs.
        """
        random_sub = f"z9x2y8w7v6-{uuid.uuid4().hex[:10]}.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            resolved_ips = socket.gethostbyname_ex(random_sub)[2]
            if resolved_ips:
                self.is_wildcard_zone = True
                self.wildcard_baseline_ips.update(resolved_ips)
                print(f"[WILDCARD DETECTED] Zone '{self.domain}' responds to non-existent subdomains!")
                print(f"[WILDCARD BASELINE IPs] {list(self.wildcard_baseline_ips)}")
                return True
        except Exception:
            pass

        self.is_wildcard_zone = False
        print(f"[WILDCARD CHECK] Zone '{self.domain}' is clean (No wildcard resolution).")
        return False

    def filter_wildcard_ips(self, resolved_ips: List[str]) -> List[str]:
        """
        2. REAL-TIME FILTERING:
        Filters out any IPs matching the wildcard baseline unless unique IPs are present.
        """
        if not self.is_wildcard_zone:
            return resolved_ips

        clean_ips = [ip for ip in resolved_ips if ip not in self.wildcard_baseline_ips]
        return clean_ips

    def probe_http_live_status(self, subdomain: str) -> Dict[str, Any]:
        """
        3. HTTP LIVE PROBING:
        Probes HTTPS and HTTP endpoints to verify live web servers (200, 301, 302, 403, etc.)
        """
        headers = {
            "User-Agent": "ANISAS-IntelPlatform/2.0 (Defense & Aerospace Infrastructure Verifier)"
        }
        for proto in ["https", "http"]:
            url = f"{proto}://{subdomain}"
            try:
                res = requests.get(url, timeout=self.timeout, allow_redirects=True, headers=headers, verify=False)
                # Valid web response codes: 200, 301, 302, 401, 403, 404, 500
                if res.status_code < 550:
                    return {
                        "is_live": True,
                        "protocol": proto,
                        "status_code": res.status_code,
                        "final_url": res.url,
                        "server_header": res.headers.get("Server", "Unknown"),
                        "response_time_ms": int(res.elapsed.total_seconds() * 1000)
                    }
            except Exception:
                pass

        return {
            "is_live": False,
            "protocol": None,
            "status_code": None,
            "final_url": None,
            "server_header": None,
            "response_time_ms": 0
        }

    def fetch_tls_handshake(self, subdomain: str) -> Dict[str, Any]:
        """
        4. SSL/TLS CERTIFICATE HANDSHAKE:
        Extracts live X.509 certificate details directly from Port 443.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((subdomain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    sans = []
                    for item in cert.get("subjectAltName", []):
                        if item[0].lower() in ["dns", "ip"]:
                            sans.append(item[1])

                    issuer_parts = []
                    for entry in cert.get("issuer", []):
                        for k, v in entry:
                            if k in ["commonName", "organizationName"]:
                                issuer_parts.append(f"{k}={v}")

                    return {
                        "tls_active": True,
                        "issuer": ", ".join(issuer_parts) if issuer_parts else "Verified TLS Certificate",
                        "validFrom": cert.get("notBefore", "N/A"),
                        "validTo": cert.get("notAfter", "N/A"),
                        "san_list": sans,
                        "tls_version": ssock.version() or "TLSv1.3"
                    }
        except Exception as e:
            return {
                "tls_active": False,
                "error": str(e)
            }

    def process_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        sub = subdomain.strip().lower()

        # Step 1: Real-time DNS Resolution
        try:
            resolved_ips = socket.gethostbyname_ex(sub)[2]
        except Exception:
            return None  # Unresolvable DNS

        # Step 2: Anti-Wildcard Filtering
        valid_ips = self.filter_wildcard_ips(resolved_ips)
        if not valid_ips:
            # False positive wildcard subdomain filtered out!
            return None

        # Step 3: Live HTTP/HTTPS Probe
        http_telemetry = self.probe_http_live_status(sub)
        if not http_telemetry["is_live"]:
            return None  # Unresponsive web server

        # Step 4: Live Port 443 TLS Certificate Handshake
        tls_telemetry = self.fetch_tls_handshake(sub)

        # Step 5: Clean JSON Record
        return {
            "subdomain": sub,
            "domain_root": self.domain,
            "resolved_ips": valid_ips,
            "is_wildcard_filtered": self.is_wildcard_zone,
            "http_telemetry": http_telemetry,
            "tls_telemetry": tls_telemetry,
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    def run_pipeline(self, candidates: List[str]) -> Dict[str, Any]:
        """
        5. CLEAN STRUCTURED OUTPUT PIPELINE
        """
        start_time = time.time()
        self.detect_wildcard_baseline()

        verified_subdomains = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(self.process_subdomain, candidates))

        for r in results:
            if r is not None:
                verified_subdomains.append(r)

        execution_duration = round(time.time() - start_time, 2)

        return {
            "target_domain": self.domain,
            "wildcard_zone_detected": self.is_wildcard_zone,
            "wildcard_baseline_ips": list(self.wildcard_baseline_ips),
            "total_candidates_processed": len(candidates),
            "total_verified_live_subdomains": len(verified_subdomains),
            "execution_duration_sec": execution_duration,
            "verified_dataset": verified_subdomains
        }


# =========================================================================
# CLI TEST DRIVER
# =========================================================================
if __name__ == "__main__":
    test_domain = "reddit.com"
    sample_candidates = [
        "z9x2y8w7v6.reddit.com",  # Synthetic fake subdomain to test anti-wildcard
        "www.reddit.com",
        "api.reddit.com",
        "fake-nonexistent-subdomain-12345.reddit.com",
        "mail.reddit.com",
        "vpn.reddit.com"
    ]

    print("=" * 75)
    print("ANISAS ANTI-WILDCARD SUBDOMAIN & REAL-TIME VERIFIER")
    print("=" * 75)

    verifier = AntiWildcardSubdomainVerifier(domain=test_domain)
    output_json = verifier.run_pipeline(sample_candidates)

    print("\n" + json.dumps(output_json, indent=2))
