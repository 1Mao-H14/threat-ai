#!/usr/bin/env python3
"""
tests/test_hourly_job.py

Integration test for the REAL processing/hourly_job.py run_pipeline()
function — this is the actual code path APScheduler calls every minute
in production. NOT a reimplementation.

What's MOCKED (safe to run on your laptop):
  - ActionEngine        -> MockActionEngine (no real Azure AD calls)
  - ReportNotifier.send -> captured in memory (no real email/Slack/etc. sent)

What's REAL:
  - Redis (must be running)
  - parser.py, aggregator.py, scorer.py, mitre_engine.py
  - report_builder.py   (push notification text)
  - report_html_builder.py (full HTML report pages)
  - report_dispatcher.py (writes real .html files to reports/<user>/)

Requires: Redis on localhost:6379

Run:
    python tests/test_hourly_job.py --scenario ransomware
    python tests/test_hourly_job.py --all
"""

import sys, os, json, argparse, time
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG = {
    "redis":  {"host": "localhost", "port": 6379},
    "buffer": {"max_size": 1000},
    "identity_map": {"alicevm": "alice", "charliem": "charlie"},
    "scoring": {
        "warmup_hours":         0,     # disabled for testing — act immediately
        "action_after_mins":    0,
        "alert_threshold":      0.50,
        "mfa_threshold":        0.70,
        "block_threshold":      0.85,
        "report_cooldown_mins": 0,     # no cooldown during tests
    },
    "actions": {
        "noc_webhook": "",
        "block_users": False,
        "force_mfa":   False,
    },
    "entra_id": {
        "tenant_id":     "test-tenant",
        "client_id":     "test-client",
        "client_secret": "test-secret",
        "domain":        "marwanhamdaoui2020gmail.onmicrosoft.com",
        "poll_interval": 60,
    },
    "vms": [],
    "business_impact": {
        "company_size":               "smb",
        "currency":                   "EUR",
        "annual_revenue":             1_500_000,
        "employee_count":             45,
        "avg_employee_hourly_cost":   38,
        "productivity_loss_pct":      0.65,
        "downtime_hours":             8,
        "estimated_data_exposed_gb":  120,
        "estimated_records_at_risk":  2500,
        "data_type_at_risk":          "pii",
        "critical_systems_impacted":  True,
        "users_impacted":             15,
    },
}

SEP = "═" * 72


# ── MOCK ACTION ENGINE (no real Azure AD calls) ──────────────────────────

class MockActionEngine:
    def __init__(self, config):
        self.config        = config
        self.calls         = []
        s = config["scoring"]
        self.alert_thresh  = s["alert_threshold"]
        self.mfa_thresh    = s["mfa_threshold"]
        self.block_thresh  = s["block_threshold"]

    def handle(self, user, score, row, breakdown):
        if score >= self.block_thresh:
            result = {"action": "block", "success": True,
                      "detail": "Compte bloqué (SIMULÉ — Azure AD non appelé en mode test)"}
        elif score >= self.mfa_thresh:
            result = {"action": "mfa", "success": True,
                      "detail": "Sessions révoquées (SIMULÉ)"}
        elif score >= self.alert_thresh:
            result = {"action": "alert", "success": True,
                      "detail": "Alerte NOC envoyée (SIMULÉ)"}
        else:
            result = {"action": "none", "success": True, "detail": "Aucune action"}

        self.calls.append({"user": user, "score": score, **result})
        print(f"    🎯 [MockAction] {user} → {result['action']} | {result['detail']}")
        return result


# ── MOCK NOTIFIER (captures sends instead of hitting real channels) ──────

_captured_sends = []

def _mock_send(self, audience, severity, title, body, body_format="text"):
    _captured_sends.append({
        "audience": audience, "severity": severity,
        "title": title, "body": body,
    })
    print(f"    📨 [MockNotifier] {audience}/{severity} → \"{title}\" "
          f"(would send to channels matching this audience+severity)")
    return 1


# ── EVENT INJECTION (same fixtures as test_attack_simulation.py) ─────────

def _load_scenarios():
    from tests.fixtures.sysmon_messages import (
        SCENARIO_RANSOMWARE, SCENARIO_CREDENTIAL_DUMP, SCENARIO_LATERAL_MOVEMENT,
    )
    from tests.fixtures.entra_events import (
        SCENARIO_BRUTE_FORCE_TAKEOVER, SCENARIO_PRIVILEGE_ESCALATION, SCENARIO_FULL_APT,
    )
    return {
        "ransomware":       {"sysmon": SCENARIO_RANSOMWARE,      "entra": SCENARIO_BRUTE_FORCE_TAKEOVER},
        "credential_dump":  {"sysmon": SCENARIO_CREDENTIAL_DUMP, "entra": []},
        "lateral_movement": {"sysmon": SCENARIO_LATERAL_MOVEMENT,"entra": SCENARIO_PRIVILEGE_ESCALATION},
        "full_apt":         {"sysmon": SCENARIO_RANSOMWARE + SCENARIO_CREDENTIAL_DUMP, "entra": SCENARIO_FULL_APT},
    }


def inject_events(scenario: dict, user: str = "alice"):
    from processing.parser import parse_sysmon_raw
    from collectors.entraid_collector import EntraIDCollector
    from collectors.smart_buffer import SmartBuffer

    buffer = SmartBuffer(CONFIG)
    pushed_sysmon = 0
    for event_id, message, timestamp, machine in scenario["sysmon"]:
        parsed = parse_sysmon_raw(event_id=event_id, message=message,
                                   timestamp=timestamp, machine=machine)
        if parsed:
            parsed["user"] = user
            buffer.push(parsed)
            pushed_sysmon += 1

    collector = EntraIDCollector.__new__(EntraIDCollector)
    collector.config = CONFIG
    collector.buffer = buffer
    pushed_entra = 0
    for raw in scenario["entra"]:
        parsed = collector._parse_signin(raw) if "createdDateTime" in raw else collector._parse_audit(raw)
        parsed["user"] = user
        buffer.push(parsed)
        pushed_entra += 1

    print(f"    ✅ Injected {pushed_sysmon} Sysmon + {pushed_entra} Entra events for '{user}'")


# ── RUN ─────────────────────────────────────────────────────────────────

def run_scenario(name: str):
    global _captured_sends
    _captured_sends = []

    scenarios = _load_scenarios()
    if name not in scenarios:
        print(f"Unknown scenario '{name}'. Available: {list(scenarios.keys())}")
        return False

    print(f"\n{SEP}\n  HOURLY_JOB INTEGRATION TEST: {name.upper()}\n{SEP}")

    import redis as redispy
    r = redispy.Redis(host="localhost", port=6379)
    r.delete("buffer:alice"); r.delete("profile:alice"); r.delete("model:alice")
    print("  🧹 Redis cleaned for 'alice'")

    print("\n  STEP 1 — Injecting events into Redis...")
    inject_events(scenarios[name])
    time.sleep(0.3)

    print("\n  STEP 2 — Running the REAL run_pipeline(config)...")
    print("           (ActionEngine + ReportNotifier mocked, everything else real)\n")

    from processing.hourly_job import run_pipeline

    with patch("actions.action_engine.ActionEngine", MockActionEngine), \
         patch("reporting.notifier.ReportNotifier.send", _mock_send):
        run_pipeline(CONFIG)

    print(f"\n{SEP}\n  RESULTS\n{SEP}")

    if not _captured_sends:
        print("  ❌ No reports were dispatched — check detection thresholds / fixtures")
        return False

    for s in _captured_sends:
        print(f"\n  [{s['audience'].upper()} / {s['severity'].upper()}] {s['title']}")
        print("  " + "-"*68)
        # Print first 12 lines so the terminal isn't flooded
        for line in s["body"].splitlines()[:12]:
            print(f"  {line}")
        print("  ... (truncated — full HTML report saved to disk, see below)")

    # Locate the HTML files written by the real ReportDispatcher
    user_dir = os.path.join("reports", "alice")
    if os.path.isdir(user_dir):
        files = sorted(os.listdir(user_dir))[-2:]
        print(f"\n  📄 HTML report pages written to: {os.path.abspath(user_dir)}/")
        for f in files:
            full = os.path.abspath(os.path.join(user_dir, f))
            print(f"     - {full}")
        print(f"\n  ➜ Open these in a browser to see the rendered report:")
        for f in files:
            print(f"     file://{os.path.abspath(os.path.join(user_dir, f))}")
    else:
        print(f"\n  ⚠  Expected HTML output dir not found: {user_dir}")

    print(f"\n{SEP}\n  {name.upper()} — PASSED ({len(_captured_sends)} push notifications, "
          f"{len(files) if os.path.isdir(user_dir) else 0} HTML files)\n{SEP}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", choices=["ransomware","credential_dump","lateral_movement","full_apt"])
    group.add_argument("--all", action="store_true")
    args = parser.parse_args()

    try:
        import redis as redispy
        redispy.Redis(host="localhost", port=6379).ping()
        print("✅ Redis connection OK")
    except Exception as e:
        print(f"❌ Redis not available: {e}")
        print("   Start it with: docker run -d -p 6379:6379 redis:alpine")
        sys.exit(1)

    if args.all:
        results = {n: run_scenario(n) for n in
                   ["ransomware", "credential_dump", "lateral_movement", "full_apt"]}
        print(f"\n{SEP}\n  FINAL RESULTS\n{SEP}")
        for n, ok in results.items():
            print(f"  {'✅' if ok else '❌'}  {n}")
    else:
        run_scenario(args.scenario)
