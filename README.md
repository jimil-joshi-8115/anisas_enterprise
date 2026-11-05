# ANISAS: Autonomous Network Intelligence & Security Assessment System

> One public IP in, a full security assessment out.

![Python](https://img.shields.io/badge/Python-3.10--3.14-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-uvicorn-009688)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Educational%20%2F%20Research-orange)

ANISAS is a self-contained "SOC in a box": one FastAPI service and one browser UI. Give it an IP address or domain and it enriches the target with public threat intelligence, fingerprints the exposed network and IoT estate, scores the risk, draws the topology and exports a SOC report.

Everything runs locally on port 9000. No database, message broker or cloud account is needed to start.

Built for the **GTU Cyber Bootcamp**, whose challenge was: *build an AI-augmented system that accepts a single public IP and autonomously maps the network behind it, from ASN down to device fingerprints, open services and security controls, with no manual steps after launch.*

```
Target (IP / domain)
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│  ai-service/main.py  -  FastAPI + uvicorn  (http://:9000)     │
│                                                               │
│  M01 ASN & ISP ──► M02 Network Recon ──┬──► M03 Perimeter     │
│                                        └──► M04 IoT / Sweep   │
│                                                   │           │
│                                        M05 AI Risk Engine     │
│                                                   │           │
│                                        M06 Dashboard + Export │
└───────────────────────────────────────────────────────────────┘
        │                                   ▲
        ▼                                   │
  ~30 public OSINT / threat APIs      static/index.html
  (RDAP, BGP, VT, Shodan, Censys,     (vanilla JS + d3 + Tailwind)
   AbuseIPDB, crt.sh, NVD, KEV, EPSS)
```

---

## Table of Contents

1. [What it does](#what-it-does)
2. [Design principles](#design-principles)
3. [The six modules](#the-six-modules)
4. [Architecture](#architecture)
5. [Tech stack](#tech-stack)
6. [Repository layout](#repository-layout)
7. [Getting started](#getting-started)
8. [Configuration and API keys](#configuration-and-api-keys)
9. [Using the platform](#using-the-platform)
10. [API reference](#api-reference)
11. [Data model](#data-model)
12. [AI engine](#ai-engine)
13. [Report export](#report-export)
14. [Troubleshooting](#troubleshooting)
15. [Known limitations](#known-limitations)
16. [Roadmap](#roadmap)
17. [Security and legal notice](#security-and-legal-notice)
18. [Credits](#credits)

---

## What it does

Given a target, ANISAS answers six questions:

| Question | What ANISAS reports |
|---|---|
| **Who owns it?** | ASN, ISP, RIR, allocated prefix, country, reverse DNS, WHOIS/RDAP, BGP announcements |
| **What is exposed?** | Open TCP ports, service banners, TLS certificates, HTTP headers, DNS records, subdomains |
| **How is it defended?** | CDN / WAF / firewall / IDS inference, DMZ segmentation, posture score |
| **What devices are there?** | Routers, cameras, NVRs, printers, NAS, servers, embedded IoT, plus CVEs, KEV hits and firmware age |
| **How bad is it?** | A factor-by-factor risk score, an OS and device prediction, a topology graph, a plain-English report |
| **Can I hand this to someone?** | A multi-page PDF and a complete JSON telemetry export |

---

## Design principles

- **Collect evidence in the same order every time.** The pipeline is a layered DAG: each module consumes the evidence of the ones before it, so results are repeatable and human error is removed.
- **Total scan time is the slowest call, not the sum.** Independent lookups run in parallel (thread pools), so latency follows the slowest source.
- **Honest output.** Results carry an evidence status (OBSERVED, CORRELATED, INFERRED, PREDICTED, UNKNOWN). Missing data is reported as `N/A`, `NOT AVAILABLE` or `INSUFFICIENT_HOSTS`, never invented.
- **A port is a hint, not an identity.** Device identification needs corroborating probes (RTSP, ONVIF, HTTP, TLS, mDNS, OUI), not just an open port.
- **"Zero" is not "clean".** When a free API is rate-limited or blind, the UI says so instead of showing a verified-clean host.
- **Zero-setup start.** One process, in-memory state, no external services required.

---

## The six modules

| # | Module | What it does | Primary output |
|---|---|---|---|
| 01 | ASN & ISP Real Intelligence | Resolves the target, then pulls ASN, ISP, RIR, geo, reverse DNS, WHOIS/RDAP, BGP prefixes and abuse / VirusTotal reputation | ASN profile, prefixes, threat score |
| 02 | Network Reconnaissance | TCP connect scan of a curated port list, banner and service detection, TLS certificate inspection, HTTP headers, DNS records, subdomain discovery | Port map, DNS records, certificates |
| 03 | Security Perimeter Detection | Classifies the IP's purpose (CDN, cloud, carrier, residential, unmapped) and infers firewall / WAF / IDS posture with hardening guidance | Posture score, perimeter recommendations |
| 04 | Surveillance & IoT Asset Intelligence | Fingerprints devices via RTSP, ONVIF, SNMP, HTTP and TLS; maps OUI vendors; correlates NVD CVEs, CISA KEV and EPSS; runs a threaded subnet sweep with live progress | Asset inventory, CVE list, firmware and risk findings |
| 05 | AI Risk Engine | Builds a feature vector, runs the device-type and OS classifiers, infers topology with networkx, flags subnet anomalies, produces a weighted risk score and a narrative (real LLM or deterministic template) | Risk score, posture rating, AI narrative |
| 06 | Unified SOC Dashboard | Consolidates every module into one KPI dashboard, a network topology graph, a DNS attack-surface map and a force-directed graph; exports PDF and JSON | Dashboard and PDF/JSON report |

### Module 01: ASN & ISP Intelligence

Who owns the target, how it is routed, and whether it is flagged.

- **Sources, queried in parallel:** ip-api, RIPEstat, VirusTotal v3.
- **Threat-intel fallback:** if VirusTotal fails, ANISAS checks 7 DNS blocklists (Spamhaus ZEN, CBL, UCEPROTECT, s5h, Barracuda, SpamCop, SORBS), then AlienVault OTX, and reshapes the result into the same schema so the rest of the pipeline is unchanged.
- **Output:** ASN, organization, registry (RIR), CIDR, geo, BGP origin and prefixes, threat score, and the hand-off payload for Module 02.

### Module 02: Network Reconnaissance

What the target actually exposes.

- **Port sweep:** TCP connect scan over a curated port list using a 60-thread pool. It needs no root rights.
- **Banners and services:** protocol-aware banner grabbing (HTTP, DNS, SSH, FTP, SMTP, IMAP/POP3), with exposure categories for admin and database ports.
- **TLS:** live certificate parse (subject, issuer, validity, SANs, grade, trust).
- **DNS:** PTR via the OS resolver, A / MX / NS via Google DNS-over-HTTPS.
- **Subdomains:** discovered through crt.sh, AlienVault OTX and HackerTarget, then each one is resolved and probed live with real status codes.
- **Enrichment:** Shodan InternetDB and Censys, behind a rate gate and a circuit breaker so free-tier APIs are not hammered.

### Module 03: Security Perimeter Detection

What kind of perimeter the target sits behind.

- A rule-based 5-branch classifier: **anycast CDN edge, cloud VPC origin, carrier backbone, residential CPE, unmapped**.
- Maps the branch to WAF / firewall / IDS attribution, DMZ segment type, a posture score and a purpose-filtered hardening plan (for example, RPKI and BCP 38 advice for carrier infrastructure, CSP and HSTS advice only for web servers).
- WAF is reported as `N/A` for non-web infrastructure instead of forcing a guess.

### Module 04: Surveillance & IoT Asset Intelligence

Is that "camera" really a camera?

- **Single target:** parallel probes (RTSP OPTIONS, ONVIF SOAP, HTTP title and server, TLS certificate, mDNS, MAC/OUI) feed a weighted evidence classifier with a 0.50 threshold. One weak signal can never declare a "CCTV camera".
- **Vendor trust hierarchy:** device-reported evidence (mDNS, ONVIF) outranks spoofable or weak evidence (OUI, banners).
- **Strict CVE separation:** hardware-specific CVEs only apply once a vendor is confirmed. Service-level CVEs from InternetDB, CVEDB and NVD are reported separately, with CISA KEV and EPSS enrichment.
- **Subnet sweep:** two-phase TCP-connect sweep (liveness gate, then full port scan on live hosts) on a background thread with live progress. Port-based guesses are labelled `Assumed`.
- **Endpoint verification:** the `probe-endpoints` call checks ONVIF and RTSP live, so a guess can be confirmed or disproved.

### Module 05: AI Risk Engine

Turns evidence into decisions: a risk number, an OS guess, a device class, a graph, anomalies and a written report. See [AI engine](#ai-engine).

### Module 06: Unified SOC Dashboard

A read-only aggregation layer. Every number comes from another module.

- **Dashboard:** KPI cards with LIVE / LIMITED / EMPTY pills, so a green pill never sits on degraded data.
- **Three topology views:** network graph, DNS attack-surface map (domain, subdomain, IP, subnet), and a force-directed graph with OBSERVED / CORRELATED / INFERRED node provenance.
- **Export:** PDF and JSON.

---

## Architecture

### Runtime topology

```
Browser
  └─ GET /                      → static/index.html (single page)
  └─ fetch('/api/v1/...')       → JSON envelope:
                                   { success, data, error, timestamp }

FastAPI (ai-service/main.py)
  ├─ Module handlers            → resolve_asn_profile, execute_network_recon,
  │                               execute_perimeter_detection,
  │                               execute_iot_intelligence,
  │                               execute_subnet_iot_intelligence,
  │                               execute_ai_risk_engine
  ├─ Module 06 builders         → topology-graph, /api/v1/topology[/dns|/force]
  ├─ Export                     → /module6/export/json, /module6/export/pdf
  └─ Static mount               → /static
```

### Data flow

1. The UI fires the module requests. Each handler stores its result in an in-memory dict keyed by scan ID.
2. Module 06 reads those stores. It never re-scans on the dashboard or export path.
3. The PDF/JSON export resolves the requested scan ID, prefers the subnet sweep profile when one covers the target, and reports `NOT AVAILABLE` for anything missing (it never invents numbers).

### Concurrency

Four long-lived `ThreadPoolExecutor` pools are shared across scans, so a subnet sweep cannot exhaust the uvicorn thread pool:

| Pool | Workers | Used for |
|---|---|---|
| `_SWEEP_POOL` | 128 | Host liveness sweep |
| `_DEEP_POOL` | 16 | Per-host deep fingerprint |
| `_GRAB_POOL` | 8 | Banner and certificate grabbing |
| `_CVE_POOL` | 32 | CVE enrichment |

### Caches

| Cache | TTL |
|---|---|
| ASN | 5 s |
| Network recon | 300 s |
| Telemetry (Shodan / Censys) | 300 s |
| Stack probe | 15 min |
| CVE | 24 h |

### External services

About 30 public APIs, including ip-api, RIPEstat, VirusTotal, Shodan (Host API and InternetDB), Censys, AbuseIPDB, GreyNoise, AlienVault OTX, crt.sh, HackerTarget, Google DoH, RDAP, NVD, CVEDB, CISA KEV, FIRST EPSS, and optional LLM providers (OpenAI, Groq, Anthropic, Gemini).

---

## Tech stack

| Layer | Technology |
|---|---|
| UI | Single-page `static/index.html`: vanilla JS, Tailwind (CDN), d3 v7 (CDN), Font Awesome |
| API | Python 3.10+ (tested on 3.14.5), FastAPI, Pydantic, uvicorn |
| Concurrency | `ThreadPoolExecutor`, `threading` |
| ML and graph | scikit-learn (RandomForest, IsolationForest, LocalOutlierFactor), numpy, joblib, networkx |
| Reporting | ReportLab |
| Networking | requests, socket, ssl, ipaddress; optional scapy, cryptography, dnspython |
| Legacy scaffold | Node 20 + Express + Prisma + Redis + BullMQ; React 18 + Vite + Tailwind (not used by the served UI) |

---

## Repository layout

```
ANISAS FINAL PROJECT/
├─ README.md                      ← this file
├─ START_ANISAS_GUI.bat           ← recommended: GUI launcher
├─ START_ANISAS.bat               ← console launcher
├─ Start-ANISAS.ps1               ← launcher logic (Python/port/dependency checks)
├─ README_LAUNCHER.txt
├─ ANISAS_Keys/
│  └─ .env                        ← API keys (never commit this)
└─ ANISAS_Enterprise_Platform/
   ├─ ai-service/                 ← the live platform
   │  ├─ main.py                  ← FastAPI app, all six modules
   │  ├─ pdf_report.py            ← ReportLab PDF report
   │  ├─ ai_engine/               ← Module 05 package
   │  │  ├─ stack_probe.py        ← TCP/ICMP stack probes
   │  │  ├─ features.py           ← feature vector
   │  │  ├─ device_classifier.py  ← device-type model
   │  │  ├─ os_fingerprint.py     ← OS classifier
   │  │  ├─ topology.py           ← networkx graph inference
   │  │  ├─ anomaly.py            ← IsolationForest + LOF
   │  │  ├─ risk_scorer.py        ← weighted risk engine
   │  │  ├─ nl_reporter.py        ← LLM / template narrative
   │  │  └─ train.py              ← model training
   │  ├─ probes/                  ← RTSP, ONVIF, SNMP, mDNS, TLS, HTTP probes
   │  ├─ models/                  ← device_classifier.joblib, os_fingerprint.joblib, metrics.json
   │  ├─ static/index.html        ← the SOC UI
   │  ├─ iot_recon_engine.py      ← Module 04 reconnaissance engine
   │  ├─ iot_extended_intel.py    ← CVE / KEV / EPSS enrichment
   │  ├─ module4_orchestrator.py  ← Module 04 evidence contract + classifier
   │  ├─ subnet_sweep.py          ← liveness sweep
   │  ├─ classifier.py, oui_lookup.py, cve_correlation.py, ip_range_prediction.py
   │  └─ requirements.txt
   ├─ backend/                    ← legacy Express/Prisma scaffold
   ├─ frontend/                   ← legacy React/Vite scaffold
   ├─ docker-compose.yml          ← provided, but no Dockerfiles are included
   └─ run.bat / START_PLATFORM.bat
```

Several Python files in `ai-service/` are not wired into the live request path (`iot_batch_discovery_engine.py`, `iot_asset_discovery.py`, `anti_wildcard_verifier.py`, `pure_wire_tracker.py`, `api_live_intel_fetcher.py`). They are kept for reference.

---

## Getting started

### Prerequisites

| Requirement | Version |
|---|---|
| Windows | 10 or 11 (the launchers are PowerShell/WPF) |
| Python | 3.10 to 3.14 (tested on 3.14.5) |
| pip | bundled with Python |
| Browser | Chrome, Edge or Firefox |
| Node.js | not required for the served UI (only for the legacy scaffold) |

### Option 1: GUI launcher (recommended)

Double-click `START_ANISAS_GUI.bat`. It will:

1. Locate a working Python interpreter.
2. Verify (and install) the Python requirements.
3. Check that port 9000 is free.
4. Start `ai-service/main.py` in the background.
5. Wait for an HTTP 200 and open <http://localhost:9000>.
6. Stream logs and offer Stop / Restart.

Server logs: `%TEMP%\anisas_server_out.log` and `%TEMP%\anisas_server_err.log`.

### Option 2: console launcher

```bat
START_ANISAS.bat
```

### Option 3: manual

```bash
cd "ANISAS_Enterprise_Platform\ai-service"
python -m pip install -r requirements.txt
python main.py
# open http://localhost:9000
```

Optional extras that unlock the deeper probes:

```bash
python -m pip install scapy cryptography dnspython
```

| Package | Enables |
|---|---|
| `scapy` | Raw TCP stack fingerprinting (`dfBit`, `windowSize`, `mss`) |
| `cryptography` | Deeper TLS certificate parsing |
| `dnspython` | Direct DNS record queries |

### Option 4: the platform's own script

```bat
cd "ANISAS_Enterprise_Platform"
run.bat
```

> Do not start more than one instance on port 9000. The launcher detects an existing server and reuses it.

---

## Configuration and API keys

ANISAS works without any key, with reduced intelligence. Keys unlock the live external APIs and the real LLM narrative.

| Variable | Used by | Effect |
|---|---|---|
| `PORT` | server | Listen port (default 9000) |
| `VIRUSTOTAL_API_KEY` | M01 / M05 | VirusTotal reputation, malicious score |
| `SHODAN_API_KEY` | M02 | Shodan host tags and CPEs |
| `CENSYS_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET` | M02 | Censys host data |
| `GROQ_API_KEY` / `OPENAI_API_KEY` | M05 | Real LLM narrative |
| `CENSYS_MIN_INTERVAL`, `INTERNETDB_MIN_INTERVAL` | throttling | Minimum seconds between calls |

Keys live in `ANISAS_Keys\.env`. The service reads **environment variables only** and does not auto-load `.env`. Load the file into the shell before starting, for example:

```powershell
Get-Content ".\ANISAS_Keys\.env" | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim('"').Trim("'"), 'Process')
  }
}
cd ".\ANISAS_Enterprise_Platform\ai-service"
python main.py
```

Without keys:

- Module 05 still runs; the narrative uses the deterministic TemplateEngine fallback.
- VirusTotal, Shodan and Censys sections show reduced or empty data.

> A fallback VirusTotal key is embedded in `main.py` for the demo. Remove it and rotate the key before any real deployment. Never commit `ANISAS_Keys/.env`.

---

## Using the platform

1. Enter an IP address or domain in the target field.
2. Click **EXECUTE**. Modules 01 to 05 run and populate their tabs, then Module 06 builds the dashboard, topology graph and DNS map.
3. Optional: click **SWEEP SUBNET**. The /24 is swept with live progress, and the discovered devices replace the single-target Module 04 view.
4. Review the tabs:
   - **Module 01**: ASN, ISP, prefixes, threat intel
   - **Module 02**: ports, services, DNS records, certificates
   - **Module 03**: perimeter posture and hardening advice
   - **Module 04**: device inventory, CVEs, firmware, recommendations
   - **Module 05**: risk score, OS and device prediction, AI narrative
   - **Module 06**: all-module dashboard and topology
   - **DNS MAP**: domain, subdomain, IP and subnet graph
5. Click **EXPORT PDF REPORT** or **EXPORT TELEMETRY JSON**.

The export uses the stored scan data for the current scan, so it is fast and always matches the screen. Missing modules are printed as `NOT AVAILABLE` instead of being re-scanned or invented.

---

## API reference

All JSON responses use the same envelope:

```json
{ "success": true, "data": { }, "error": null, "timestamp": "2026-11-05T10:00:00Z" }
```

### Module 01: ASN & ISP

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/asn/scan` | Run an ASN/ISP scan |
| GET | `/api/v1/asn/history` | Scan history |
| GET | `/api/v1/asn/{scan_id}` | Stored profile |
| DELETE | `/api/v1/asn/{scan_id}` | Remove a profile |

### Module 02: Network Reconnaissance

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/network/scan` | Full recon |
| POST | `/api/v1/network/recon` | Alias |
| GET | `/api/v1/network/{scan_id}` | Stored result |

### Module 03: Security Perimeter

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/perimeter/scan` | Perimeter assessment |
| GET | `/api/v1/perimeter/{scan_id}` | Stored result |

### Module 04: IoT & Surveillance

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/iot/scan` | Single target, or `mode=subnet` |
| GET | `/api/v1/iot/subnet/progress` | Live sweep progress |
| GET | `/api/v1/iot/{scan_id}` | Stored profile |
| GET | `/module4/summary` | Aggregated summary |
| GET | `/module4/devices` | Device list |
| GET | `/module4/vendors` | Vendor distribution |
| GET | `/module4/firmware` | Firmware distribution |
| GET | `/module4/cves` | CVE matches |
| GET | `/module4/recommendations` | Recommendations |
| POST | `/api/v1/iot/probe-endpoints` | Targeted ONVIF / RTSP endpoint probe |

### Module 05: AI Risk Engine

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/ai/eval` | Run the AI engine |
| GET | `/api/v1/ai/{scan_id}` | Stored profile |
| GET | `/module5/summary` | Summary |
| GET | `/module5/risk-scores` | Risk breakdown |
| GET | `/module5/os-fingerprints` | OS predictions |
| GET | `/module5/ai-summary` | Narrative |

### Module 06: Dashboard, Topology & Export

| Method | Path | Purpose |
|---|---|---|
| GET | `/module6/topology-graph` | Topology used by the UI |
| GET | `/api/topology` | Topology (legacy schema) |
| GET | `/api/v1/topology` | Topology (v1) |
| GET | `/api/v1/topology/dns` | DNS attack-surface graph |
| GET | `/api/v1/topology/force` | Force-directed graph payload |
| GET | `/api/topology/candidates` | Monitored subdomain candidates |
| POST | `/api/topology/verify` | Verify a candidate |
| POST | `/api/v1/validate` | Cross-module validation |
| GET | `/module6/export/json` | Full JSON telemetry (`?scanId=`) |
| GET | `/module6/export/pdf` | PDF report (`?scanId=`) |

### UI

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Serves `static/index.html` |

---

## Data model

All state is held in in-memory dictionaries inside `main.py`. There is no database and no persistence, so a restart clears everything.

| Store | Written by | Contents |
|---|---|---|
| `scan_store` | M01 | ASN / ISP profiles |
| `network_store` | M02 | Recon results |
| `perimeter_store` | M03 | Perimeter assessments |
| `history_store` | M01 | Scan history |
| `iot_store` | M04 | Single-target and subnet-sweep profiles |
| `ai_engine_store` | M05 | Risk / AI profiles |
| `_subnet_progress` | M04 | Live sweep progress |

**Scan IDs**

- M01 creates its own `scan-<epoch_ms>`.
- The UI uses `scan-<target>-<epoch_ms>` for M02 to M05.
- A subnet sweep uses `scan-subnet-auto-<ip>-<ts>` (or `scan-subnet-<cidr>-<ts>`).
- The export resolver matches by scan ID, then by target IP, then prefers the subnet profile covering the target.

---

## AI engine

Module 05 is a seven-stage fusion pipeline.

| Stage | Component | Notes |
|---|---|---|
| 1 | Stack probe | TTL, window, DF bit and MSS. Raw-socket tier needs scapy and admin rights; falls back to ICMP TTL only |
| 2 | Device classifier | RandomForest, 12 device classes, 98.61% on the synthetic test split |
| 3 | OS fingerprint | Tree-based classifier, 5 OS families, 91.6% on the synthetic test split. Missing measurements stay missing; confidence shrinks with less evidence |
| 4 | Topology | networkx graph. Nodes only from discovered facts, no phantom devices |
| 5 | Anomaly detection | IsolationForest + LOF vote. Needs at least 6 real hosts, otherwise `INSUFFICIENT_HOSTS` |
| 6 | Risk scoring | Weighted, attributable factors: CVEs, ports, VirusTotal abuse, firmware age, WAF relief |
| 7 | NL report | OpenAI / Groq / Anthropic / Gemini, else a deterministic template. `llmModelUsed` says which path ran |

Model files:

- `ai-service/models/device_classifier.joblib` (~18 MB)
- `ai-service/models/os_fingerprint.joblib` (~1.9 MB)
- `ai-service/models/metrics.json`

Retrain:

```bash
cd "ANISAS_Enterprise_Platform\ai-service"
python -m ai_engine.train
```

> **Important:** the published accuracy figures come from synthetic archetype data generated by `train.py`, not from a labelled real-world corpus. Treat predictions as heuristic, not as ground truth.

---

## Report export

### PDF: `GET /module6/export/pdf?scanId=...`

A multi-page A4 report containing:

- Cover and executive KPI strip (risk score, risk level, IoT assets, open ports)
- Data-availability banner (any module that had no stored data)
- Module 01: ASN, ISP, prefixes, threat intel
- Module 02: host, ports, services, TLS certificate, DNS records table
- Module 03: perimeter posture and recommendations
- Module 04: scan mode, subnet scope, top 20 devices ranked by risk, with a note stating the total and how many were omitted
- Module 05: device and OS predictions, risk breakdown, AI narrative
- Module 06: consolidated dashboard KPIs, module availability, DNS inventory, topology inference, subnet sweep summary

### JSON: `GET /module6/export/json?scanId=...`

The same bundle as a machine-readable object, including the full Module 06 block and every discovered device (not just the top 20).

Both endpoints read stored data only. They never re-run a scan, so exports are fast and reproducible.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Port 9000 is busy | Another instance or program | Stop it, or set `PORT=9001` |
| `NOT AVAILABLE` in the PDF | That module had no stored data for the scan | Re-run EXECUTE for the target, then export |
| PDF shows 0 devices but the UI shows many | The subnet sweep had not finished, or was for a different CIDR | Finish the sweep, then export |
| LLM report says `TEMPLATE_FALLBACK` | No LLM key loaded | Set `GROQ_API_KEY` or `OPENAI_API_KEY` |
| `No module named joblib` | Optional model dependency missing | `python -m pip install joblib` |
| `probeTier` is always `ICMP_ONLY` | scapy not installed | `python -m pip install scapy` |
| Topology graphs are blank | d3 loads from a CDN and the machine is offline | Restore connectivity |
| Module 05 anomaly stage never runs | Sweep results are stored under a separate scan ID | Known limitation, see below |

---

## Known limitations

This is a demonstration and research platform, not a hardened production SOC product.

- **No persistence.** Every store is in memory; a restart wipes all scans.
- **No authentication.** Every route is open and CORS is permissive.
- **Synthetic ML training data.** Classifier accuracy is measured on generated archetypes.
- **Module 05 topology is single-target.** The subnet inventory is reported separately in Module 04 and the Module 06 summary.
- **Anomaly detection rarely triggers on a single target.** It needs at least six real hosts from a sweep.
- **Optional probes are optional.** Without scapy, cryptography and dnspython, the matching measurements are reported as unavailable, not faked.
- **Scores are partly rule-based.** The Module 03 posture score and scan-detection chance come from the network class, not from probing the target.
- **`docker-compose.yml` is incomplete.** It references Dockerfiles that are not included, and no `/health` route exists yet.
- **The Node/React stack is a legacy scaffold.** It does not implement Modules 04 to 06 and is not required to run ANISAS.
- **Some files are unused.** See the note in [Repository layout](#repository-layout).

---

## Roadmap

- Auto-load `ANISAS_Keys/.env` at startup
- Persistent storage (SQLite or Redis) and result expiry
- Authentication, restricted CORS and rate limiting
- Evidence-driven posture scoring in Module 03
- Pass the subnet sweep into Module 05 so anomaly detection and topology see all hosts
- Train classifiers on labelled real-world captures
- Complete Dockerfiles and a `/health` route

---

## Security and legal notice

ANISAS actively connects to the target you enter (TCP port probes, HTTP/TLS requests, subnet sweeps). **Only scan systems you own or have explicit written permission to test.** Unauthorised scanning may be illegal in your jurisdiction. This is an educational project.

Before exposing ANISAS beyond localhost:

- Add authentication and authorisation.
- Restrict CORS to trusted origins.
- Put it behind TLS and a reverse proxy.
- Move API keys into a secrets manager and remove the embedded fallback key.
- Add rate limiting and request logging.
- Replace `innerHTML` rendering with safe DOM APIs (scan banners are untrusted input).

---

## Credits

Built as the **ANISAS Enterprise Cyber Intelligence Platform** (Modules 01 to 06) for the GTU Cyber Bootcamp, with FastAPI, scikit-learn, networkx, ReportLab and d3.

**Team:** Joshi Jimil and Harshal Patel

## License

Add a license of your choice (for example MIT) before publishing the repository.
