# ZeroTrust AI — Real-Time SOC Dashboard

A live operations dashboard for the threat-ai pipeline. It reads from the **same
Redis** the pipeline writes to, so everything updates in real time (auto-refresh
every 5s). No changes to `config.yml`.

## What it shows
- **KPIs** — endpoints (online/offline), active threats, critical incidents, blocked users, average risk.
- **Infrastructure global view** — every host: OS, Windows version, primary user, status, threat count, risk.
- **User risk & deviation** — each user's risk score vs their personal *baseline* (normal), how far they deviate (σ and points), trend, top technique, status.
- **User behavior variation** — score-over-time curve per user with the normal baseline overlaid.
- **Top 10 ATT&CK techniques** across the domain.
- **Threat severity / OS / tactics** breakdowns.
- **Live incident & action feed** — what fired, on whom, and what action was taken.
- **Block / Unblock** any user directly from the table (enforced in Entra ID when reachable).

## Run it

```bash
# 1. install (Redis must be running; the pipeline deps too)
pip install -r dashboard/requirements.txt

# 2. (optional) populate Redis with demo data so the UI is full immediately
python -m dashboard.seed_demo

# 3. start the dashboard
python -m dashboard.server
#   -> http://127.0.0.1:8080
```

Run it alongside `python main.py` in production — as the pipeline detects threats
and dispatches reports, incidents flow into Redis and appear on the dashboard live.

Override host/port with env vars: `DASHBOARD_HOST`, `DASHBOARD_PORT`.

## How "live" vs "demo" works
- If Redis has user profiles, the dashboard shows **LIVE** data.
- If Redis is empty, it serves a realistic **DEMO** snapshot so the UI is never blank.
- `static/demo-data.js` lets `static/index.html` render fully **offline** as a static
  preview (used when `/api/snapshot` isn't reachable). Regenerate it with:
  ```bash
  python -c "import json,dashboard.demo as d; open('dashboard/static/demo-data.js','w').write('window.DEMO_SNAPSHOT='+json.dumps(d.build_demo_snapshot())+';')"
  ```

## Machine OS inventory
The pipeline doesn't collect OS/version, so enrich it in **`dashboard/machines.yml`**
(separate from `config.yml`). Each entry maps a host name to its OS, version,
primary user and status. Hosts without an entry show up as `Windows / unknown`.

## Where the data comes from (Redis keys)
| Key                          | Written by            | Used for                         |
|------------------------------|-----------------------|----------------------------------|
| `profile:<user>`             | profile_updater       | score, baseline, trend, curve    |
| `incidents:log`              | report_dispatcher     | live feed                        |
| `incidents:tech_counts`      | report_dispatcher     | top-10 ATT&CK                    |
| `incidents:machine_counts`   | report_dispatcher     | per-host threat counts           |
| `incident:last:<user>`       | report_dispatcher     | user's current technique/action  |
| `status:<user>`              | dashboard block/unblock | active / blocked state         |
