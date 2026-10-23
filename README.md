# Spork-IDS: Python-Based Intrusion Detection System & Modern Security Operations UI

<p align="center">
  <img src="https://img.shields.io/badge/Backend-Python%203.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+" />
  <img src="https://img.shields.io/badge/Framework-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React TypeScript" />
  <img src="https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/Database-SQLite%203-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="Apache 2.0" />
</p>

---

## 1. Project Overview

**Spork-IDS** is a customized, professional Intrusion Detection System (IDS) and Security Operations Center (SOC) dashboard. Inspired by the open-source [CrowdSec](https://github.com/crowdsecurity/crowdsec) project, Spork-IDS replaces external Go daemons with a **100% Python-native detection backend** paired with a modern, responsive dark-navy cybersecurity web dashboard.

The platform continuously parses incoming logs, normalizes security events, evaluates threat patterns via a multi-paradigm bucket engine (Leaky Bucket, Trigger, Uniq), records alerts, enforces time-to-live (TTL) IP bans/decisions, and provides real-time telemetry.

> **Attribution & Licensing:** Spork-IDS is an independent customized derivative work inspired by CrowdSec. Upstream CrowdSec is developed and maintained by CrowdSec under the Apache License 2.0. See [LICENSE](LICENSE) for full licensing terms. Spork-IDS is not an official CrowdSec product.

---

## 2. Architecture & CrowdSec Relationship (Transparent Disclosure)

CrowdSec's upstream security engine is implemented in Go. In strict adherence to the project's **Python-only backend requirement**, Spork-IDS does **not** rely on a hidden Go binary or simulate backend detection:

1. **Python-Native Security Engine (`app/detection/`)**:
   - Implements CrowdSec's core bucket algorithms in pure Python:
     - **Leaky Bucket:** Discretely leaks events over configurable intervals; overflows when capacity is reached.
     - **Trigger Bucket:** Immediate overflow (capacity = 0) for zero-tolerance critical exploits (SQLi, Directory Traversal).
     - **Uniq Bucket:** Measures cardinality across a sliding time window (used for horizontal port scans and credential stuffing).
   - Operates completely self-contained on Windows and Linux without requiring Go compilers or root daemons.
2. **FastAPI REST API Server (`app/api/`)**:
   - High-throughput asynchronous REST API exposing health, dashboard summaries, alerts, raw log ingestion, decisions, and scenario telemetry.
   - Built-in OpenAPI Swagger documentation (`/docs`).
3. **Optional CrowdSec Interoperability Adapter (`app/integrations/crowdsec_client.py`)**:
   - If an external upstream CrowdSec Local API (LAPI) instance is running on the network (e.g., `http://localhost:8080`), Spork-IDS can connect in **Hybrid Mode** to query LAPI heartbeats and sync decisions.
   - When disconnected (default standalone mode), Spork-IDS operates autonomously using its native Python detection engine.

### Architectural Comparison

| Dimension | CrowdSec Reference | Spork-IDS Implementation |
| :--- | :--- | :--- |
| **Backend Language** | Go (1.23+) | **Python (3.9+)** |
| **API Framework** | Custom Go HTTP router | **FastAPI + Uvicorn ASGI** |
| **Detection Mechanics** | Leakybucket Go routines (`pkg/leakybucket`) | **Python Leaky, Trigger & Uniq Bucket Engine (`app/detection/`)** |
| **Log Parsing** | Grok + YAML configs | **Regex/Grok Normalization Pipeline (`app/services/parser.py`)** |
| **Enrichment** | MaxMind GeoIP + CAPI | **Local Subnet/RFC1918 & GeoIP Classifier (`app/services/enrichment.py`)** |
| **Data Persistence** | SQLite / Postgres | **SQLite 3 via SQLAlchemy 2.0 ORM (`data/spork.db`)** |
| **User Interface** | Upstream has no native UI (SaaS console) | **Custom React 18 + TypeScript + Tailwind CSS UI (`frontend/`)** |
| **Windows Support** | Requires daemon service & Go runtime | **Zero external dependencies, runs out of the box in VS Code** |

---

## 3. Repository Structure

```
spork-IDS/
├── app/
│   ├── api/                     # REST API route controllers
│   │   ├── alerts.py            # Alert filtering, retrieval, and status management
│   │   ├── dashboard.py         # Aggregated SOC overview metrics & trends
│   │   ├── decisions.py         # Remediation policies (bans, throttles, unbans)
│   │   ├── events.py            # Event stream and raw log ingestion
│   │   ├── health.py            # Service health & uptime indicator
│   │   ├── metrics.py           # Granular bucket and engine telemetry
│   │   ├── router.py            # Top-level API router mounting all modules
│   │   ├── scenarios.py         # Scenario catalog & live evaluation sandbox
│   │   └── settings.py          # Configuration & CrowdSec LAPI connection tester
│   ├── core/                    # Settings, security & structured logging
│   │   ├── config.py            # Pydantic Settings (.env, defaults)
│   │   ├── logging.py           # Structured logger setup
│   │   └── security.py          # API key header authorization (X-Api-Key)
│   ├── db/                      # Persistence layer
│   │   ├── base.py              # Declarative base
│   │   ├── seed.py              # Realistic sample attack & event seeder
│   │   └── session.py           # SQLAlchemy SQLite connection & sessionmaker
│   ├── detection/               # Pure Python Detection Engine
│   │   ├── buckets.py           # LeakyBucket, TriggerBucket, and UniqBucket primitives
│   │   ├── engine.py            # Central coordinator, bucket instances & sandbox
│   │   └── scenarios.py         # Built-in scenarios and filter predicates
│   ├── integrations/            # External security integrations
│   │   └── crowdsec_client.py   # CrowdSec Local API (LAPI) client adapter
│   ├── models/                  # Database tables & validation schemas
│   │   ├── db_models.py         # SQLAlchemy models (Events, Alerts, Decisions, Stats)
│   │   └── schemas.py           # Pydantic request/response schemas
│   ├── services/                # Business logic & pipeline
│   │   ├── decision_manager.py  # TTL ban calculation, expiration & unban
│   │   ├── enrichment.py        # Subnet/RFC1918/GeoIP classifier & risk scoring
│   │   ├── metrics_service.py   # Trend & telemetry calculator
│   │   ├── parser.py            # Log parsing (SSH, Nginx, Syslog, Windows, Firewall)
│   │   └── pipeline.py          # Ingestion coordinator (Parse -> Enrich -> Save -> Detect)
│   └── main.py                  # FastAPI application entry point & static SPA mounting
├── frontend/                    # Modern React + TypeScript + Tailwind CSS UI
│   ├── src/
│   │   ├── components/          # Sidebar, Navbar, status badges
│   │   ├── pages/               # Overview, Alerts, Events, Detection, Decisions, Metrics, Settings
│   │   ├── services/            # api.ts (REST client targeting /api)
│   │   ├── types/               # TypeScript interfaces matching backend models
│   │   ├── App.tsx              # Main layout, router & attack simulator
│   │   └── main.tsx             # React entry point
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── tests/                       # Automated Pytest suite (24 tests)
│   ├── conftest.py              # Test database (in-memory SQLite with StaticPool)
│   ├── test_api.py              # REST API endpoint integration tests
│   ├── test_detection.py        # Leaky bucket, trigger, and uniq unit tests
│   ├── test_integrations.py     # CrowdSec client offline/fallback tests
│   └── test_parser.py           # SSH, Nginx, SQLi, and Windows parser tests
├── data/                        # Persistent SQLite database storage (git-ignored)
├── requirements.txt             # Python runtime dependencies
├── requirements-dev.txt         # Dev & test dependencies (pytest, pytest-asyncio)
├── .env.example                 # Example configuration
├── run.py                       # Root launcher script
└── README.md                    # Project documentation
```

---

## 4. Built-in Detection Scenarios

Spork-IDS includes 6 pre-configured detection scenarios implemented in Python:

1. **`spork/ssh-bf` (SSH Brute Force)**:
   - *Type:* Leaky Bucket
   - *Threshold:* Capacity 5 events, Leak speed 20 seconds.
   - *Matching:* Detects repeated failed logins from the same source IP.
   - *Action:* Automatic 4-hour IP ban.
2. **`spork/http-crawl-bf` (Web Route Enumeration)**:
   - *Type:* Leaky Bucket
   - *Threshold:* Capacity 8 events, Leak speed 15 seconds.
   - *Matching:* Detects aggressive HTTP 404/403 status probing across paths (`/.env`, `/wp-login.php`, `/admin`).
   - *Action:* Automatic 2-hour IP ban.
3. **`spork/http-sqli` (SQL Injection Exploit)**:
   - *Type:* Trigger Bucket
   - *Threshold:* Capacity 0 (immediate overflow on first sight).
   - *Matching:* Identifies SQL injection keywords (`UNION SELECT`, `1=1`, `information_schema`, `--`) in request URLs.
   - *Action:* Critical severity alert + 24-hour IP ban.
4. **`spork/http-path-traversal` (Directory Traversal)**:
   - *Type:* Trigger Bucket
   - *Threshold:* Capacity 0 (immediate overflow).
   - *Matching:* Detects traversal payloads (`../`, `..%2f`, `/etc/passwd`, `win.ini`).
   - *Action:* Critical severity alert + 24-hour IP ban.
5. **`spork/port-scan` (Horizontal/Vertical Port Probe)**:
   - *Type:* Uniq Bucket
   - *Threshold:* Capacity 5 distinct destination ports within a 45-second window.
   - *Matching:* Tracks unique ports targeted in firewall logs (`DPT=...`).
   - *Action:* 6-hour IP ban.
6. **`spork/auth-credential-stuffing` (Multi-Account Stuffing)**:
   - *Type:* Uniq Bucket
   - *Threshold:* Capacity 4 distinct usernames from a single source IP within 60 seconds.
   - *Matching:* Detects automated credential spray attempts targeting diverse accounts.
   - *Action:* 12-hour IP ban.

---

## 5. REST API Documentation

The FastAPI backend exposes fully documented endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Returns service health, uptime, engine status, and decision counts |
| `GET` | `/api/dashboard/summary` | Aggregated statistics, 12-hour activity trend, and top attacking IPs |
| `GET` | `/api/alerts` | Paginated alerts with filters: `severity`, `scenario`, `ip`, `status` |
| `GET` | `/api/alerts/{id}` | Detailed alert record including contributing raw logs and attached bans |
| `PATCH` | `/api/alerts/{id}/status` | Update alert status (`resolved`, `dismissed`, `active`) |
| `DELETE` | `/api/alerts/{id}` | Permanently delete an alert record |
| `GET` | `/api/events` | Paginated security log events with filters: `service`, `is_suspicious`, `ip` |
| `POST` | `/api/events/raw` | Ingest a batch of raw log lines through the parsing & detection pipeline |
| `GET` | `/api/decisions` | Active or historical remediation decisions (banned IPs/ranges) |
| `POST` | `/api/decisions` | Manually ban or throttle an IP, range, or username |
| `DELETE` | `/api/decisions/{id}` | Revoke / unban an active decision |
| `GET` | `/api/scenarios` | Catalog of detection scenarios and live in-memory bucket metrics |
| `POST` | `/api/scenarios/evaluate` | Interactive sandbox to evaluate a test log line against a scenario |
| `GET` | `/api/metrics` | Granular operational telemetry, bucket states, and uptime counters |
| `GET` | `/api/settings` | Server environment configuration and CrowdSec connection status |
| `POST` | `/api/settings/test-crowdsec` | Actively probe an external CrowdSec LAPI URL with latency test |

Interactive OpenAPI documentation is available in any browser at `http://localhost:8000/docs`.

---

## 6. Frontend Operations Dashboard

Built with **React 18**, **TypeScript**, and **Tailwind CSS**, the Spork-IDS web interface adopts a dark-navy cybersecurity operations center theme:

1. **Overview Page**: High-level SOC view with 4 top stat cards, a 12-hour threat trend bar chart, top attacking IPs with country tags, recent alert feed, and quick attack simulation controls.
2. **Alerts Page**: Comprehensive alert triage center with multi-attribute filtering (Severity, Status, Scenario), expandable modals showing raw contributing log events, and one-click resolution.
3. **Events & Logs Page**: Searchable log viewer displaying normalized events and parsed JSON attributes. Features a **Real-Time Log Ingestion Box** to test arbitrary log strings with pre-configured attack presets.
4. **Detection Page**: Scenario catalog showing capacity, leak speed, and active bucket instances. Features an **Interactive Sandbox Evaluator** allowing operators to test rule matching and bucket math in isolation.
5. **Decisions Page**: Remediation enforcement center displaying active IP bans, countdown timers, and expiration dates, with a modal to create manual bans or immediately unban an IP.
6. **Metrics Page**: Real-time performance indicators (suspicious event ratio, live in-memory bucket instances, continuous uptime).
7. **Settings Page**: Configuration management, browser API key settings, and a **CrowdSec LAPI Connection Tester** with live latency measurement.

---

## 7. Setup & Run Instructions (VS Code on Windows)

### Prerequisites

- **Python 3.9+**
- **Node.js 18+** and **npm**
- **Git**

### Step 1: Clone and Navigate to the Repository

```powershell
git clone https://github.com/21-kdg/spork-IDS.git
cd spork-IDS
git checkout feature/spork-ui-redesign
```

### Step 2: Set Up Python Backend Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

### Step 3: Build the Modern Frontend Bundle

```powershell
cd frontend
npm install
npm run build
cd ..
```

*(Note: The built frontend is automatically served by FastAPI at `http://localhost:8000`. You do not need to run a second terminal during demonstration.)*

### Step 4: Run the Application

```powershell
python run.py
```

Open your browser and navigate to:
- **Web Dashboard:** [http://localhost:8000](http://localhost:8000)
- **Interactive API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

### (Optional) Frontend Development Server with Hot-Reload

If actively modifying React components:
```powershell
cd frontend
npm run dev
```
*(Runs on `http://localhost:5173` with automated API proxy to port 8000)*

---

## 8. Automated Testing & Verification

Spork-IDS includes an automated test suite verifying all detection rules, edge cases, parser regexes, REST endpoints, and integration fallbacks:

```powershell
.\.venv\Scripts\pytest -v
```

### Test Results Summary

```
tests/test_api.py::test_api_health PASSED
tests/test_api.py::test_api_dashboard_summary PASSED
tests/test_api.py::test_api_events_ingest_and_list PASSED
tests/test_api.py::test_api_alerts_lifecycle PASSED
tests/test_api.py::test_api_scenarios_list_and_evaluate PASSED
tests/test_api.py::test_api_decisions_crud PASSED
tests/test_api.py::test_api_metrics PASSED
tests/test_api.py::test_api_settings PASSED
tests/test_detection.py::test_leaky_bucket_overflow PASSED
tests/test_detection.py::test_leaky_bucket_draining PASSED
tests/test_detection.py::test_trigger_bucket_immediate_overflow PASSED
tests/test_detection.py::test_uniq_bucket_cardinality PASSED
tests/test_detection.py::test_detection_engine_ssh_bruteforce PASSED
tests/test_detection.py::test_detection_engine_sqli_trigger PASSED
tests/test_detection.py::test_detection_engine_false_positive_normal_traffic PASSED
tests/test_integrations.py::test_crowdsec_offline_fallback PASSED
tests/test_integrations.py::test_crowdsec_online_success PASSED
tests/test_integrations.py::test_crowdsec_status_standalone PASSED
tests/test_parser.py::test_parse_ssh_failed_password PASSED
tests/test_parser.py::test_parse_ssh_accepted PASSED
tests/test_parser.py::test_parse_http_sqli_signature PASSED
tests/test_parser.py::test_parse_http_path_traversal PASSED
tests/test_parser.py::test_parse_windows_event PASSED
tests/test_parser.py::test_parse_firewall_drop PASSED

============================= 24 passed in 0.22s =============================
```

---

## 9. Git Commands for Review & Pushing to GitHub

All work has been developed cleanly on the feature branch `feature/spork-ui-redesign`.

To review git status, commit your changes, and push to GitHub:

```bash
# 1. Review status of modified and untracked files
git status

# 2. Stage the new Python backend, frontend source, and tests
git add .

# 3. Commit with a structured message
git commit -m "feat: implement Python-based detection engine and modern UI for Spork-IDS"

# 4. Push the feature branch to your GitHub repository
git push -u origin feature/spork-ui-redesign
```

---

## 10. License & Attributions

- **Spork-IDS** source code and extensions are licensed under the [Apache License 2.0](LICENSE).
- Based on concepts and functional foundations from [CrowdSec](https://github.com/crowdsecurity/crowdsec), copyright (c) CrowdSec SAS.
