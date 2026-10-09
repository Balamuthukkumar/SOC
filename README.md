# SOC Platform

Backend for an OT/ICS-aware security operations platform: asset inventory, vulnerability alerts (NVD + CISA KEV),
security-event ingestion (Suricata / Zeek / generic), AI-assisted detect → triage → case → response workflow,
MITRE ATT&CK mapping, threat hunting, purple-team validation, compliance, SBOMs, OT device discovery and topology.

A clean rewrite of the original OneAlert project: FastAPI + SQLAlchemy 2.0 (async), same `/api/v1` URLs.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env
.venv/bin/python -m uvicorn app.main:app --reload      # http://localhost:8000/docs
```

Demo login (when `SEED_DEMO=true`): `admin@example.com` / `password123` — a water-treatment plant with a
multi-stage intrusion already investigated. **Turn `SEED_DEMO` off outside local use.**

```bash
.venv/bin/python -m pytest          # 59 tests, isolated SQLite database
docker compose up --build           # Postgres + app; needs SECRET_KEY and POSTGRES_PASSWORD
```

## Layout

```
app/
  main.py            app wiring, middleware, health/metrics, serves frontend/dist at /app when present
  config.py db.py security.py deps.py limiter.py middleware.py scheduler.py seed.py
  models/            SQLAlchemy 2.0 typed models, one module per domain
  schemas/           Pydantic request/response models
  routers/           one module per API area (auth, assets, alerts, events, cases, mitre, hunt,
                     response_plans, validation, ot, topology, compliance, sbom, orgs, integrations, billing)
  services/
    ai.py            Anthropic / OpenAI-compatible client; get_ai() is None without credentials
    agents/          base (run ledger) · detect · triage · hunt · response · purple · orchestrator
    feeds.py         NVD + CISA KEV fetch/parse        matching.py   advisory ↔ asset (CPE + version ranges)
    alert_checker.py feed → alerts → notifications     notify.py     Slack / webhook / Mailgun
    ot_risk.py topology.py compliance.py sbom.py similarity.py remediation.py epss.py
    policy.py executor.py   response autonomy levels / action execution (SIMULATED)
    integrations.py  Splunk, Sentinel, ServiceNow, PagerDuty (SSRF-guarded)    stripe_client.py
migrations/          Alembic (async); `alembic upgrade head`
tests/               pytest, one file per phase
```

## How it works

1. **Ingest** — assets are entered or promoted from sensor-discovered devices; events arrive via `/events/ingest`,
   `/events/upload`, or OT sensors via `/ot/ingest/batch`. The scheduler pulls NVD and CISA KEV every
   `FEED_INTERVAL_HOURS`; `alert_checker` matches advisories to assets and creates deduplicated alerts.
2. **Detect → Triage** — `POST /cases/pipeline` runs the detect agent (rules + optional LLM) then the triage agent,
   which clusters alerts/events by shared IPs and asset, and opens cases with MITRE tactics/techniques.
3. **Respond** — `POST /response-plans/generate?case_id=` drafts an action plan. `services/policy.py` decides per
   action whether a human must approve (OT control/field/safety zones and destructive actions always do).
4. **Validate** — purple-team runs check whether your own telemetry contains evidence of each ATT&CK technique.

Every agent run is recorded (`/cases/agents/runs`). With no AI key configured, every agent has a deterministic
rule-based fallback, so the whole pipeline works offline.

## Deliberate behaviours worth knowing

- **Response actions are simulated.** `services/executor.py` logs and reports success; nothing touches a firewall,
  EDR or IdP. Replace an entry in `HANDLERS` to wire a real integration.
- **Hunt never executes LLM-written SQL.** The model returns structured filters validated against a column
  whitelist and always scoped to the caller's `user_id`.
- **Purple-team validation is evidence-based**, not random: *detected* means a matching event exists in your data.
  Only `dry_run` mode exists; live attack execution is intentionally not implemented.
- **Integration credentials** are Fernet-encrypted at rest (key derived from `SECRET_KEY`) and masked in API
  responses. Changing `SECRET_KEY` makes stored credentials unreadable.
- **Matching is conservative on version**: an asset with no recorded version is treated as possibly affected.
  Matching is by vendor/product *name*; a CVE for "FortiOS" will not match an asset named "FortiGate 200F".
- Multi-worker deployments: the GitHub OAuth state store and rate limiter are per-process (use Redis for both).

## Frontend

React 18 + TypeScript + Vite + Tailwind 4 in `frontend/` (dashboard, alerts, assets, events, cases, hunt lab, MITRE map,
response plans, validation, OT discovery, compliance, settings).

```bash
cd frontend && npm install
npm run build        # -> frontend/dist, served by the backend at http://localhost:8000/app/
npm run dev          # hot-reload UI on :3000, proxies /api to :8000
```

## Not included

- Role management endpoints (users self-register as `viewer`; creating an org makes you `admin`).
