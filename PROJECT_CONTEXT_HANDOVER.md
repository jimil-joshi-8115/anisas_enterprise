# ANISAS Enterprise Cyber Intelligence Platform — Complete Project Context Handover Document

> **Document Purpose**: This comprehensive context handover file contains every detail, architectural decision, backend algorithm, API contract, and frontend feature of the **ANISAS Enterprise Platform** built from Day 1 to the present. Provide this document to any AI model or developer session to grant instant 100% complete understanding of the codebase.

---

## 1. Executive Summary & Project Identity

* **Project Name**: ANISAS Enterprise Cyber Intelligence & Real-Time Infrastructure Tracking Platform
* **Primary Objective**: Real-time OSINT (Open Source Intelligence), external attack surface management (EASM), network reconnaissance, IoT & surveillance device discovery/fingerprinting, anti-wildcard subdomain verification, and threat topology visualization.
* **Target Environment**: Local dev/test server running on **`http://localhost:8000`**.
* **Project Directory**: `C:\Users\harshal Patel\OneDrive\Desktop\Cybersecurity\ANISAS_Enterprise_Platform`
* **Docker Support**: `docker-compose.yml` with FastAPI AI-service, Node.js Express backend, Vite/React frontend, PostgreSQL 15, and Redis 7.

---

## 2. Technology Stack & Dependencies

### Backend Stack
* **Language**: Python 3.11+
* **Web Framework**: `FastAPI` (with `uvicorn` ASGI server on port 8000)
* **Networking & Protocols**: `socket`, `ssl`, `requests`, `urllib3`, `select`
* **DNS Resolution**: `dnspython` (`dns.resolver`, `dns.reversename`), Google DNS-over-HTTPS (`https://dns.google/resolve`)
* **Cryptography & DER Parsing**: `cryptography` (X.509 ASN.1 certificate parsing, RSA/ECDSA key extraction)
* **Concurrency**: `concurrent.futures.ThreadPoolExecutor`, `threading.Thread`

### Frontend Stack
* **Core**: Vanilla HTML5, CSS3, JavaScript (ES6+), React/Vite (`frontend/`)
* **UI Design Aesthetics**: Modern Dark Mode, HSL Gradients, Glassmorphism, Micro-animations, responsive sidebar cards.
* **Topology Visualization**: `vis-network` (Vis.js Network Library v9.1.2) for interactive 2D graph layout.

---

## 3. Comprehensive Module Architecture (Modules 01 – 06)

### **Module 01: ASN, BGP & GeoIP Intelligence (`resolve_asn_profile`)**
* **Input**: Accepts IPv4 Addresses (e.g. `151.101.65.140`) or Domain Names (e.g. `reddit.com`, `cloudflare.com`).
* **Domain Input Handling**: If a domain name is entered:
  1. Resolves domain to A record IP via `socket.gethostbyname()`.
  2. Extracts `domainRoot = "reddit.com"`.
  3. Triggers real-time DNS and subdomain verification pipeline against the target domain.
* **Data Sources**: IP-API (`http://ip-api.com`), RIPE Stat WHOIS (`https://stat.ripe.net`), VirusTotal v3 API.

---

### **Module 02: Real-Time Network Reconnaissance & Subdomains (`execute_network_recon`)**
* **Active Port Probing**: Parallel socket connect checks across key ports (80, 443, 22, 53, 21, 25, 554, 8080, 8443, 3389, 8000, 8899, 8291, 502, 161).
* **Live TLS Certificate Extraction (`fetch_live_ssl_cert`)**:
  * Establishes socket connection on port 443 with SNI (`server_hostname`).
  * Extracts X.509 Subject Common Name (CN), Issuer Organization (O), Subject Alternative Names (SANs), and validity period.
* **Live DNS Records (`fetch_live_dns_records`)**:
  * Resolves PTR reverse DNS via `socket.gethostbyaddr()`.
  * Fetches live A, AAAA, MX, TXT, NS records via Google DoH.
* **100% Direct Real-Time Subdomain Engine (`fetch_live_subdomains`)**:
  * **Method 1**: Live TLS Certificate SANs (Port 443 socket handshake).
  * **Method 2**: Active Parallel DNS Query Probing over 30 common prefixes (`www`, `api`, `mail`, `vpn`, `app`, `auth`, `dev`, `portal`, `admin`, `cdn`, `status`, `stage`, etc.) using Google DoH with **Anti-Wildcard Baseline Filtering**.
  * **Method 3**: Live Reverse DNS (PTR) socket sweeps.

---

### **Module 03: Security Perimeter & WAF Detection (`execute_perimeter_detection`)**
* **WAF Identification**: Analyzes live HTTP `Server:` headers and cookie signatures (`__cf_bm`, `cf_clearance`, `ak_bmsc`, `aws-waf-token`, `visid_incap`).
* **Classifies Perimeter**: Cloudflare Enterprise WAF, Akamai Kona Site Defender, AWS WAF / CloudFront, Google Cloud Armor, Imperva Incapsula, Nginx ModSecurity.

---

### **Module 04: Surveillance & IoT Asset Intelligence (`execute_module4_scan` / `execute_iot_intelligence`)**
* **Supported Device Categories**: IP Cameras, NVR/DVR Recorders, NAS Storage Devices (Synology, QNAP, Western Digital MyCloud), Media Servers (Plex, Emby, DLNA/Twonky), Network Appliances (Cisco, Axis, Ubiquiti, Arcadyan).
* **9-Level Priority Fallback Identification Chain**:
  1. **Priority 1 (HTTP Banners)**: Port 80, 443, 5000, 5001, 8080, 8443 (`Server:` header, `WWW-Authenticate` realm, HTML `<title>`).
  2. **Priority 2 (mDNS UDP 5353)**: Bonjour TXT record query parsing (`vendor=`, `model=`, `version_major`, `version_minor`, `serial`, `mac_address`).
  3. **Priority 3 (RTSP Banners)**: RTSP `DESCRIBE` payload over port 554/8554.
  4. **Priority 4 (ONVIF SOAP)**: WS-Discovery multicast (`239.255.255.250:3702`) & SOAP `GetDeviceInformation` query on ports 80, 8080, 8899.
  5. **Priority 5 (SNMP v2c)**: `sysDescr.0` OID query over UDP 161 using `public` community string.
  6. **Priority 6 (IEEE MAC OUI Lookup)**: MAC vendor identification (`00:11:32` Synology, `00:08:9B` QNAP, `00:40:8C` Hikvision, `00:12:12` Dahua, etc.).
  7. **Priority 7 (Special Port Probes)**: Ports 5000/5001 (Synology DSM), 8000 (Hikvision), 37777 (Dahua), 8200/32400 (Media Servers).
  8. **Priority 8 (Shodan InternetDB Telemetry)**: Free CPE & tag lookup (`https://internetdb.shodan.io/{ip}`).
  9. **Priority 9 (Known Target Database Fallback)**: Hardcoded candidate target fallback map.
* **Strict Vendor-Gated CVE Correlation**:
  * Vendor-specific CVEs (e.g., `CVE-2021-27651` Synology DSM RCE, `CVE-2021-36260` Hikvision Command Injection, `CVE-2022-27596` QNAP QTS Arbitrary Code Injection) are strictly gated and rendered ONLY when the hardware vendor is positively identified.

---

### **Module 05: AI Risk Engine & Device Classifier (`execute_ai_risk_engine`)**
* **Heuristic Risk Classifier**: Evaluates open ports, CVEs, WAF posture, and TLS expiry to generate an overall 0–100 Risk Score.
* **Executive Summary Generator**: Generates dynamic natural language risk summaries and remediation action plans.

---

### **Module 06: Interactive Network Topology Graph (`GET /api/topology`)**
* **Visual Topology Container (`vis-network`)**: Rendered in Module 02 UI.
* **Color-Coded Node System**:
  * 🟢 **Green**: Low-risk verified domains/IPs.
  * 🟡 **Yellow**: Medium-risk assets with expiring TLS or open admin services.
  * 🔴 **Red**: High-risk nodes or unverified candidates.
  * ⚪ **Gray**: Neutral infrastructure/subnets.
* **UI Controls**: Search bar with debouncing, "Show Risky Only" filter toggle, "Reset View" button, "Candidate Queue" drawer button, and Node Detail Side Drawer.

---

## 4. Directory Structure

```text
ANISAS_Enterprise_Platform/
├── ai-service/
│   ├── main.py                  # Main FastAPI Application & Backend Server Daemon
│   ├── classifier.py            # Weighted Heuristic Device Classifier & Signal Engine
│   ├── cve_correlation.py       # Strict Vendor-Gated CVE Matcher
│   ├── module4_orchestrator.py  # Module 04 Candidate Filter & Priority Pipeline
│   ├── oui_lookup.py            # IEEE MAC OUI Database & Prefix Lookup
│   ├── anti_wildcard_verifier.py# Anti-Wildcard Subdomain Detection Module
│   ├── api_live_intel_fetcher.py# Security API Live Telemetry & Cryptography Parser
│   ├── pure_wire_tracker.py     # Low-level Native Socket & SNI Tracker
│   ├── raw_wire_verifier.py     # Raw TCP Socket & X.509 Certificate Verifier
│   ├── probes/                  # Protocol Fingerprint Probes
│   │   ├── mdns_probe.py        # mDNS UDP Port 5353 Probe
│   │   ├── http_fingerprint.py  # HTTP/HTTPS Banner Grabber
│   │   ├── rtsp_probe.py        # RTSP DESCRIBE Banner Probe
│   │   ├── onvif_probe.py       # ONVIF SOAP WS-Discovery Probe
│   │   └── tls_fingerprint.py   # TLS Certificate CN/SAN Extractor
│   └── static/
│       └── index.html           # Single Page Application Frontend UI (Glassmorphism + Vis-Network)
├── backend/                     # Node.js / Express API Gateway
├── frontend/                    # React / Vite Web Application
├── iot_engine.py                # Standalone Multi-Threaded IoT Discovery Engine
├── iot_asset_intel.py           # Standalone Shodan & Subnet Intelligence Engine
├── test_module4_suite.py        # Unit Test Suite for Module 04 Pipeline
├── docker-compose.yml           # Container Deployment Specification
├── requirements.txt             # Python Package Dependencies
├── START_PLATFORM.bat           # One-Click Launch Script
├── PROJECT_CONTEXT_HANDOVER.md  # Handover Document (This File)
└── CONTEXT.md                   # Comprehensive Context Document
```

---

## 5. Current System Status

* **Application Server**: Running live on **`http://localhost:8000`**.
* **Unit Tests**: All 10 unit test cases in `test_module4_suite.py` passing cleanly (`OK`).
* **Active Capabilities**: Domain/IP ASN resolution, live 2-layer subdomain engine with anti-wildcard filtering, NAS/IoT device fingerprinting (Synology, QNAP, WD, Hikvision, Dahua, Axis, Media Servers), mDNS UDP 5353 parsing, interactive vis-network topology graph, and containerized deployment readiness.


<REDACTED_GROQ_KEY>