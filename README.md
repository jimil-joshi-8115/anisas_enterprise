# ANISAS — Enterprise Cyber Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.95%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A self-hosted cyber-intelligence and IoT reconnaissance platform. It correlates
ASN/IP intelligence, network perimeters, exposed services and IoT devices into a
single SOC-style dashboard, with ML-based device/OS fingerprinting, CVE
correlation, risk scoring, topology visualisation and PDF reporting.

> **Runs in a single Python process.** `ai-service/main.py` serves both the REST
> API and the web UI — no database or message broker required.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Deployment](#deployment)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Legal & ethics](#legal--ethics)
- [License](#license)

---

## Features

| Area | Capability |
|---|---|
| **ASN / IP intelligence** | Lookups across Shodan, VirusTotal, Censys, AlienVault OTX, AbuseIPDB and IPInfo, with graceful fallbacks |
| **Network recon** | Subnet sweep, port and service discovery, anti-wildcard verification |
| **IoT discovery** | ONVIF, RTSP, mDNS, HTTP and TLS fingerprinting probes |
| **Machine learning** | Device-classification and OS-fingerprint models (scikit-learn joblib bundles shipped in-repo) |
| **Risk analysis** | CVE correlation, anomaly detection and weighted risk scoring |
| **Topology** | Force-directed network graph, DNS resolution and host correlation |
| **Reporting** | Downloadable JSON and PDF assessments, optional AI-written executive summaries (Groq) |
| **Interface** | Dark SOC dashboard, live scan progress, module views 01–06 |

## Architecture

```
                        ┌──────────────────────────────────────────┐
   Browser  ───────────▶│  FastAPI  (ai-service/main.py)            │
   (dashboard)          │                                           │
                        │  ├── /api/v1/asn|iot|network|perimeter    │──▶ Shodan / VirusTotal /
                        │  ├── /api/v1/topology, /api/topology      │    Censys / OTX / AbuseIPDB /
                        │  ├── /module4–6 (CVE, AI, exports)        │    IPInfo / Groq
                        │  └── static/  (served by the same app)    │
                        └──────────────────────────────────────────┘
                                        ▲
                                        │ HTTP (optional)
                        ┌───────────────┴──────────────────────────┐
                        │  Node/TypeScript API + React client       │
                        │  (reference stack — backend/ frontend/)   │
                        └──────────────────────────────────────────┘
```

## Repository layout

```
ai-service/          ✅ The application — FastAPI backend, web UI, ML models, probes
├── main.py            API routes + serves static/index.html
├── ai_engine/         ML models, anomaly detection, risk scoring, topology
├── probes/            ONVIF / RTSP / mDNS / HTTP / TLS fingerprinting
├── static/            Browser dashboard (HTML + JS + vendored graph libraries)
└── models/            Pre-trained .joblib models (required at runtime)

backend/             🔧 Reference Node/TypeScript API (Express + Prisma + Postgres/Redis)
frontend/            🔧 Reference React/Vite client (Vite + Tailwind, mock dashboard)

docker-compose.yml   Full stack (Postgres + Redis + FastAPI + Node API + UI)
render.yaml          Render Blueprint for the Python service
run.bat              One-click Windows launcher for the Python app
start_server.py      uvicorn entrypoint (used by hosting platforms)
```

Only `ai-service/` is needed to run the product. `backend/` and `frontend/` are
kept as the original full-stack reference and are **not** started by `run.bat`.

## Quick start

### Windows — one click

```bat
run.bat
```

Installs the Python requirements, starts the server and opens
<http://localhost:9000>.

### Manual (any OS)

```bash
git clone https://github.com/jimil-joshi-8115/anisas_enterprise.git
cd anisas_enterprise/ai-service
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Open <http://localhost:9000>.

### Docker

```bash
docker build -t anisas ./ai-service
docker run --rm -p 9000:9000 --env-file .env anisas
```

Full stack, including the Node reference API and React client:

```bash
docker compose up --build
# UI on http://localhost:3000 · FastAPI on http://localhost:9000
```

## Configuration

Copy `.env.example` to `.env` and fill in what you have — **every key is
optional**, a missing key only disables that one provider.

| Variable | Purpose |
|---|---|
| `PORT` | Port for the FastAPI service (default `9000`) |
| `DEBUG` | Verbose logging |
| `SHODAN_API_KEY` | Shodan host intelligence |
| `VIRUSTOTAL_API_KEY` | VirusTotal reputation |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys search |
| `OTX_API_KEY` | AlienVault OTX threat pulses |
| `ABUSEIPDB_API_KEY` | Abuse confidence scores |
| `IPINFO_TOKEN` | ASN / geo enrichment |
| `GREYNOISE_API_KEY`, `SECURITYTRAILS_API_KEY`, `BINARYEDGE_API_KEY`, `FOFA_API_KEY`, `ZOOMEYE_API_KEY` | Optional extra sources |
| `GROQ_API_KEY` | AI-written summaries |
| `ENABLE_*_SCANS` | Toggle individual data sources |

`.env` is git-ignored. Never commit real keys — if one leaks, rotate it with the
provider immediately.

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard |
| `POST` | `/api/v1/asn/scan` | ASN / IP intelligence scan (`{"targetIp": "1.1.1.1"}`) |
| `GET` | `/api/v1/asn/history` | Scan history |
| `GET` | `/api/v1/asn/{scan_id}` | Single ASN result |
| `DELETE` | `/api/v1/asn/{scan_id}` | Delete a scan |
| `POST` | `/api/v1/network/scan` | Network reconnaissance |
| `POST` | `/api/v1/perimeter/scan` | Perimeter scan |
| `POST` | `/api/v1/iot/scan` | IoT discovery |
| `GET` | `/api/v1/topology`, `/api/v1/topology/force` | Topology graphs |
| `POST` | `/api/v1/validate` | Input validation |
| `GET` | `/module4/*` | CVE, device, firmware and risk views |
| `GET` | `/module6/export/pdf` | PDF report |

Interactive docs: <http://localhost:9000/docs>.

## Deployment

### Render (free tier, recommended)

1. Fork or push this repository to GitHub.
2. In Render: **New → Blueprint**, pick the repo — `render.yaml` is detected.
3. Add your API keys under **Environment** (they are never stored in git).
4. Deploy. Health check is `GET /`.

> Free instances sleep after ~15 minutes idle; the first request then takes
> 30–60 s to wake.

### Any Docker host (VPS, Fly.io, Railway, Koyeb)

```bash
docker build -t anisas ./ai-service
docker run -d -p 9000:9000 --env-file .env --restart unless-stopped anisas
```

### Local / home server with a public URL

Expose the local service without opening ports:

```bash
cloudflared tunnel --url http://localhost:9000
```

## Security notes

⚠️ **This build ships without authentication.** Anyone who can reach the port
can run scans and consume your API quota.

Before exposing it publicly:

- put it behind a reverse proxy with HTTP Basic Auth, an SSO gateway, or a
  private tunnel restricted to known users;
- use dedicated, rate-limited API keys rather than production keys;
- keep `.env` out of the image and out of version control;
- terminate TLS at the proxy;
- review the provider terms for each intelligence API you enable.

## Limitations

- Results depend on third-party APIs; providers rate-limit or change schemas.
- ML models are pre-trained snapshots — retrain with `ai-service/ai_engine/train.py`.
- Scans are intended for single targets/subnets, not internet-scale sweeps.
- The Node `backend/` + `frontend/` stack is a reference implementation and is
  not required by the Python application.

## Legal & ethics

Use this software **only** against systems you own or have explicit written
permission to test. Unauthorised scanning, enumeration or probing is illegal in
most jurisdictions. The authors accept no liability for misuse or damage.

## License

Released under the [MIT License](LICENSE).
