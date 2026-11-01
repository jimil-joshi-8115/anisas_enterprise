ANISAS Enterprise Cyber Intelligence Platform
============================================

A local FastAPI application that performs cyber-intelligence and IoT/network
reconnaissance and renders the results in a browser dashboard (SOC-style UI).
The backend also serves the frontend, so a single Python process is all you need.


REPOSITORY LAYOUT
-----------------
ai-service/     The working application (Python / FastAPI + the browser UI).
                This is what you run. Everything below is optional reference code.
backend/        Reference Node/TypeScript API (Express + Prisma + Postgres/Redis).
frontend/       Reference React/Vite client for that Node API.
docker-compose.yml  Brings up Postgres + Redis + backend + frontend together.
run.bat         One-click launcher for the Python app (Windows).
start_server.py Starts the Python app with uvicorn (used for deployment).

Note: the Python app in ai-service/ is self-contained and does not require
Node.js, Postgres or Redis. The backend/ and frontend/ folders are kept as the
original full-stack reference and are run separately (see their package.json).


WHAT IT DOES
------------
- ASN / IP intelligence (Shodan, VirusTotal, Censys, OTX, AbuseIPDB, IPInfo)
- IoT / device discovery with ML-based device and OS fingerprinting
- CVE correlation and risk scoring
- Topology graph visualisation and PDF reporting
- Optional AI-written summaries via Groq


REQUIREMENTS
------------
- Python 3.10+ (3.12/3.13/3.14 also work)
- Internet access for the live-intel lookups


QUICK START (WINDOWS - 1 CLICK)
-------------------------------
1. Double-click "run.bat".
2. It installs the Python requirements, starts the server and opens
   http://localhost:9000 in your browser.


QUICK START (MANUAL / ANY OS)
-----------------------------
1. cd ai-service
2. pip install -r requirements.txt
3. python main.py
4. Open http://localhost:9000


CONFIGURATION (API KEYS)
------------------------
All keys are optional - the app degrades gracefully when one is missing.
Copy the example file and fill in your own keys:

    copy .env.example .env      (Windows)
    cp .env.example .env        (macOS / Linux)

Then edit .env, or set the same names as environment variables:

    SHODAN_API_KEY
    VIRUSTOTAL_API_KEY
    CENSYS_API_ID / CENSYS_API_SECRET
    OTX_API_KEY
    ABUSEIPDB_API_KEY
    IPINFO_TOKEN
    GROQ_API_KEY
    JWT_SECRET

Never commit your real .env - it is already listed in .gitignore.


MAIN ENDPOINT
-------------
POST /api/v1/asn/scan
    body: {"targetIp": "1.1.1.1"}


DEPLOYMENT
----------
The app is a plain FastAPI service:

    uvicorn main:app --host 0.0.0.0 --port $PORT

Run that from the ai-service directory on any Python host (Render, Railway,
Fly.io, a VPS, or behind a Cloudflare Tunnel) and set the keys above as
environment variables in the host dashboard.

Note: there is no built-in authentication. If you expose it publicly, put it
behind a password gate (or a private tunnel) so strangers cannot spend your
API quota.


LEGAL
-----
Only scan systems you own or have explicit written permission to test.
Unauthorised scanning may be illegal in your jurisdiction.
