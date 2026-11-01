# ANISAS Enterprise Cybersecurity Platform — Agent Architecture & Handover (`AGENT.md`)

This document provides a comprehensive technical overview of all architecture upgrades, threat intelligence methodologies, hard enforcement rules, and production scripts developed across this session for the **ANISAS Enterprise Cyber Intelligence Platform**.

---

## 1. Executive Overview

The platform's **Module 4 (Surveillance & IoT Asset Intelligence)** was upgraded from static/mock data to **100% real-time dynamic telemetry and protocol fingerprinting**. All fake models, unverified CVE matches, and misattributed network owner assignments have been eliminated.

---

## 2. Global Enforcement Rules & Trust Hierarchy

### **Rule 1: IANA Reserved / Unallocated IP Interception**
- **Trigger:** IPv4 address falls into IANA special-use or reserved ranges (`0.0.0.0/8`, `127.0.0.0/8`, `240.0.0.0/4`, `255.255.255.255/32`, `169.254.0.0/16`, `224.0.0.0/4`).
- **Behavior:** Immediately intercepts the IP before any network socket probes, ARP lookups, or WHOIS queries are initiated.
- **Assigned Values:**
  - `NETWORK_OWNER`: `"Internet Assigned Numbers Authority (IANA)"`
  - `HARDWARE_VENDOR`: `"N/A"`
  - `ASSET_CATEGORY`: `"Reserved / Unallocated IP"`
  - `MAC_ADDRESS` / `MAC_VENDOR_OUI` / `HARDWARE_MODEL` / `FIRMWARE_VERSION` / `EMBEDDED_SERVER`: `"N/A"`
  - `CRITICAL CVE MATCHES`: `0`

### **Rule 2: Vendor vs. ISP Trust Hierarchy Separation**
- **`NETWORK_OWNER` (Primary Source):** Resolved via live RDAP/WHOIS (`https://rdap.org/ip/{ip}`) for public WAN IPs (e.g. `Comcast Cable Communications`, `Telekom Malaysia`).
- **`HARDWARE_VENDOR` (Secondary/Tertiary Source):**
  - **Private RFC1918 IPs:** Resolved via Layer 2 MAC OUI (Scapy ARP / system ARP table) or explicit HTTP header signatures.
  - **Public WAN IPs:** Explicitly set to `"N/A"` unless HTTP banner/ONVIF probing explicitly identifies a real hardware manufacturer (e.g., Hikvision, Dahua, Axis, TP-Link, Arcadyan). ISP names are **never** copied to `HARDWARE_VENDOR`.

### **Rule 3: Firmware Integrity & CVE Correlation Rule**
- **Trigger:** `FIRMWARE_VERSION` is `"Unknown"`, `"Latest"`, `null`, or `hardware_vendor` is `"N/A"`.
- **Behavior:** Suppresses all version-specific CVE matches (e.g. Hikvision `CVE-2021-36260`, Dahua `CVE-2021-33044`).
- **Output:** Outputs `CRITICAL CVE MATCHES: 0` and `CVE DETAILS: No version-specific CVE matched`.

### **Rule 4: Layer 2 WAN MAC Rule**
- **Behavior:** Layer 2 ARP requests (`scapy.all.ARP`) are executed **only** for RFC1918 private IPv4 addresses (`10.x`, `172.16.x-172.31.x`, `192.168.x`).
- **Public WAN IPs:** Automatically set `MAC_ADDRESS = "N/A"` and `MAC_VENDOR_OUI = "N/A"`.

---

## 3. Real-Time Telemetry & Fingerprinting Cascades

### **A. Global Search Engine APIs**
- **Shodan InternetDB API:** `https://internetdb.shodan.io/{ip}` (Queries live open ports, hostnames, and CPE signatures).
- **Shodan REST API v1:** `https://api.shodan.io/shodan/host/search` (Search query: `port:554,80,443 "RTSP" OR "ONVIF"`).
- **Censys Search v2 API:** `https://search.censys.io/api/v2/hosts/search` (Query label: `camera`).
- **Fofa Search API:** `https://fofa.info/api/v1/search/all` (Query base64: `body="onvif"`).

### **B. Local & Network Protocol Fingerprinting**
- **ONVIF WS-Discovery:** Multicast SOAP probe to `239.255.255.250:3702` + Unicast POST to `http://{ip}:{port}/onvif/device_service`.
- **RTSP DESCRIBE Probe:** Probes ports `554`, `8554`, `8555`, `1024` with RTSP `DESCRIBE` requests to extract the `Server:` response header.
- **HTTP/HTTPS Fingerprinting Cascade:**
  - Probes ports `80`, `443`, `8080`, `8443` (`verify=False`, 5-second timeout).
  - **Server Header Parsing:** Extracts `Server:` software version banners.
  - **WWW-Authenticate Header Parsing:** Extracts `realm` model and authentication clues.
  - **HTML `<title>` Regex Extraction:** Parses model numbers (`[A-Z]{2,4}[- ]?\d+[A-Z0-9]*`) and firmware versions (`v\d+\.\d+\.\d+`).
  - **HTML Body Text Regex Cascades:** Cascades through body text for `"Model:"`, `"Product:"`, `"Device:"`, `"Firmware:"`, `"FW Version:"`.
- **Threat Reputation Integration:** Live VirusTotal v3 REST API (`https://www.virustotal.com/api/v3/ip_addresses/{ip}`) + AbuseIPDB v2 REST API.

---

## 4. Key Production Modules & Scripts

| File Path | Description |
| :--- | :--- |
| [`ai-service/main.py`](file:///C:/Users/harshal%20Patel/OneDrive/Desktop/Cybersecurity/ANISAS_Enterprise_Platform/ai-service/main.py) | **Enterprise Platform FastAPI Backend** running daemon on `http://localhost:8000`. Houses Module 4 (`execute_iot_intelligence`) with strict vendor separation and `vendorSource` API contract. |
| [`ai-service/iot_recon_engine.py`](file:///C:/Users/harshal%20Patel/OneDrive/Desktop/Cybersecurity/ANISAS_Enterprise_Platform/ai-service/iot_recon_engine.py) | **Single-Target Standalone Recon Engine** with live VirusTotal v3, NVD API v2 correlation, RDAP WHOIS, and executive report formatting. |
| [`ai-service/iot_batch_discovery_engine.py`](file:///C:/Users/harshal%20Patel/OneDrive/Desktop/Cybersecurity/ANISAS_Enterprise_Platform/ai-service/iot_batch_discovery_engine.py) | **Automated Real-Time Batch Discovery Engine** combining Shodan, Censys, ONVIF Multicast, UPnP Multicast, and Subnet Host Sweeping with unique IP deduplication. |
| [`ai-service/iot_asset_discovery.py`](file:///C:/Users/harshal%20Patel/OneDrive/Desktop/Cybersecurity/ANISAS_Enterprise_Platform/ai-service/iot_asset_discovery.py) | **Multi-Protocol Probe & CVE Correlation Script**. |

---

## 5. UI Verification Source Mapping (`vendorSource`)

To prevent the UI from displaying hardcoded or unexecuted verification methods, the UI maps `vendorSource` dynamically:

```javascript
function getVerificationSourceText(assetCategory, vendorSource) {
  if (assetCategory === "Reserved / Unallocated IP") {
    return "Verified via IANA Reserved IP Range Detection";
  }

  switch (vendorSource) {
    case "MAC_OUI":
      return "Verified via MAC OUI Lookup";
    case "HTTP_BANNER":
      return "Verified via HTTP Banner Parsing";
    case "WHOIS_RDAP":
    case "WHOIS":
    case "RDAP":
      return "Verified via WHOIS/RDAP Registry Lookup";
    default:
      return "Verification Source Unknown";
  }
}
```

---

## 6. Standardized Executive Reconnaissance Report Format

```text
==================================================
          IOT ASSET RECONNAISSANCE REPORT
==================================================
TARGET IP           : 240.0.0.1
ASSET CATEGORY      : Reserved / Unallocated IP
NETWORK OWNER       : Internet Assigned Numbers Authority (IANA)
MAC ADDRESS         : N/A
MAC VENDOR OUI      : N/A
HARDWARE VENDOR     : N/A
HARDWARE MODEL      : N/A
FIRMWARE VERSION    : N/A
EMBEDDED SERVER     : N/A
--------------------------------------------------
CRITICAL CVE MATCHES: 0
CVE DETAILS         : No version-specific CVE matched
--------------------------------------------------
VIRUSTOTAL MALICIOUS: 0 Malicious
ABUSEIPDB CONFIDENCE: 0%
==================================================
```

---

## 7. Execution Quick Reference

```powershell
# 1. Start Platform Web App & FastAPI Daemon Server
python main.py

# 2. Run Single Target IoT Reconnaissance Engine
python iot_recon_engine.py <TARGET_IP>

# 3. Run Automated Batch Discovery Engine
python iot_batch_discovery_engine.py
```
