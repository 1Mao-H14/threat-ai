#!/usr/bin/env python3
"""
tests/test_attack_simulation.py

Full end-to-end pipeline test.
Requires: Redis running on localhost:6379
Does NOT require: Azure AD, WinRM, real VMs

What this does:
  1. Parses realistic Sysmon + Entra event fixtures
  2. Pushes them into Redis (SmartBuffer) exactly as collectors would
  3. Runs the pipeline (aggregator → scorer → MITRE engine)
  4. Generates + prints both executive and technical reports
  5. Verifies the action taken is included in the report

Run from repo root:
    python tests/test_attack_simulation.py
    python tests/test_attack_simulation.py --scenario ransomware
    python tests/test_attack_simulation.py --scenario credential_dump
    python tests/test_attack_simulation.py --scenario lateral_movement
    python tests/test_attack_simulation.py --scenario full_apt
    python tests/test_attack_simulation.py --all
"""

import sys, os, json, argparse, time
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.makedirs("tests/output", exist_ok=True)

# ── CONFIG ────────────────────────────────────────────────────────────────
CONFIG = {
    "redis":  {"host": "localhost", "port": 6379},
    "buffer": {"max_size": 1000},
    "identity_map": {"alicevm": "alice", "charliem": "charlie"},
    "scoring": {
        "warmup_hours":      0,      # disabled for testing
        "action_after_mins": 0,      # act immediately
        "alert_threshold":   0.50,
        "mfa_threshold":     0.70,
        "block_threshold":   0.85,
        "report_cooldown_mins": 0,   # no cooldown during tests
    },
    # Simulated actions (no real Azure AD calls during tests)
    "actions": {
        "noc_webhook": "",
        "block_users": False,   # ← set True to test real Azure AD blocking
        "force_mfa":   False,
    },
    "entra_id": {
        "tenant_id":     os.environ.get("TENANT_ID", "test-tenant"),
        "client_id":     os.environ.get("CLIENT_ID", "test-client"),
        "client_secret": os.environ.get("CLIENT_SECRET", "test-secret"),
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
        "vms_touched_this_incident":  2,
        "estimated_data_exposed_gb":  120,
        "estimated_records_at_risk":  2500,
        "data_type_at_risk":          "pii",
        "critical_systems_impacted":  True,
        "users_impacted":             12,
    },
}

SEP  = "═" * 72
SEP2 = "─" * 72

# ── SCENARIO DEFINITIONS ─────────────────────────────────────────────────

def _load_scenarios():
    """Import fixtures lazily so import errors are clear."""
    from tests.fixtures.sysmon_messages import (
        SCENARIO_RANSOMWARE,
        SCENARIO_CREDENTIAL_DUMP,
        SCENARIO_LATERAL_MOVEMENT,
    )
    from tests.fixtures.entra_events import (
        SCENARIO_BRUTE_FORCE_TAKEOVER,
        SCENARIO_DEFENSE_EVASION,
        SCENARIO_PRIVILEGE_ESCALATION,
        SCENARIO_FULL_APT,
    )
    return {
        "ransomware":      {"sysmon": SCENARIO_RANSOMWARE,         "entra": SCENARIO_BRUTE_FORCE_TAKEOVER},
        "credential_dump": {"sysmon": SCENARIO_CREDENTIAL_DUMP,    "entra": []},
        "lateral_movement":{"sysmon": SCENARIO_LATERAL_MOVEMENT,   "entra": SCENARIO_PRIVILEGE_ESCALATION},
        "full_apt":        {"sysmon": SCENARIO_RANSOMWARE
                                    + SCENARIO_CREDENTIAL_DUMP,    "entra": SCENARIO_FULL_APT},
    }


# ── STEP 1: INJECT EVENTS INTO REDIS ─────────────────────────────────────

def inject_sysmon_events(scenario_sysmon: list, user_override: str = "alice"):
    from processing.parser import parse_sysmon_raw
    from collectors.smart_buffer import SmartBuffer

    buffer = SmartBuffer(CONFIG)
    pushed = 0

    for event_id, message, timestamp, machine in scenario_sysmon:
        parsed = parse_sysmon_raw(
            event_id  = event_id,
            message   = message,
            timestamp = timestamp,
            machine   = machine,
        )
        if parsed:
            # Force the user so all events land on one profile
            parsed["user"] = user_override
            buffer.push(parsed)
            pushed += 1
        else:
            print(f"    ⚠  parse_sysmon_raw returned None for EventID={event_id}")

    print(f"    ✅ Sysmon: {pushed}/{len(scenario_sysmon)} events pushed to Redis")
    return pushed


def inject_entra_events(scenario_entra: list, user_override: str = "alice"):
    """
    Directly parses Entra dicts (bypasses live Graph API call)
    and pushes parsed events into SmartBuffer.
    """
    from collectors.entraid_collector import EntraIDCollector
    from collectors.smart_buffer import SmartBuffer

    # Build a minimal collector just to use its _parse_signin / _parse_audit methods
    collector = EntraIDCollector.__new__(EntraIDCollector)
    collector.config   = CONFIG
    collector.buffer   = SmartBuffer(CONFIG)

    pushed = 0
    for raw in scenario_entra:
        try:
            # Determine if it's a sign-in or audit log by key presence
            if "createdDateTime" in raw:
                parsed = collector._parse_signin(raw)
            else:
                parsed = collector._parse_audit(raw)
            parsed["user"] = user_override
            collector.buffer.push(parsed)
            pushed += 1
        except Exception as e:
            print(f"    ⚠  Entra parse error: {e}")

    print(f"    ✅ Entra:  {pushed}/{len(scenario_entra)} events pushed to Redis")
    return pushed


# ── STEP 2: RUN PIPELINE ─────────────────────────────────────────────────

class MockActionEngine:
    """
    Replaces ActionEngine during tests so we don't call real Azure AD.
    Records what action WOULD have been taken and makes it available
    for the report's 'action confirmed' section.
    """
    def __init__(self, config):
        self.config       = config
        self.calls        = []
        self.alert_thresh = config["scoring"]["alert_threshold"]
        self.mfa_thresh   = config["scoring"]["mfa_threshold"]
        self.block_thresh = config["scoring"]["block_threshold"]

    def handle(self, user, score, row, breakdown):
        if score >= self.block_thresh:
            action_taken = "COMPTE BLOQUÉ (simulé — Azure AD non appelé en mode test)"
            level        = "CRITICAL"
        elif score >= self.mfa_thresh:
            action_taken = "SESSIONS RÉVOQUÉES + MFA FORCÉ (simulé)"
            level        = "HIGH"
        else:
            action_taken = "ALERTE NOC ENVOYÉE (simulé)"
            level        = "MEDIUM"

        self.calls.append({
            "user":         user,
            "score":        score,
            "action_taken": action_taken,
            "level":        level,
            "technique":    breakdown.get("technique", "unknown"),
        })
        print(f"    🎯 [MockAction] {user} → {action_taken}")
        return action_taken


def run_pipeline_for_user(user: str, mock_actions: MockActionEngine):
    """
    Runs the same logic as hourly_job.run_pipeline() but for one user,
    using MockActionEngine and wiring in the ReportDispatcher.
    """
    import redis as redispy
    from processing.aggregator    import aggregate_to_row
    from profiles.profile_updater import update_user_profile
    from detection.mitre_engine   import MitreDetectionEngine
    from reporting.report_dispatcher import ReportDispatcher

    r = redispy.Redis(host="localhost", port=6379)

    # Pull events from Redis
    key    = f"buffer:{user}"
    raw    = r.lrange(key, 0, -1)
    events = [json.loads(e.decode()) for e in raw]
    r.delete(key)

    if not events:
        print(f"    ⚠  No events in buffer for user '{user}'")
        return None

    print(f"    📦 {len(events)} events pulled from buffer for '{user}'")

    window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    row          = aggregate_to_row(events, user, window_start)

    profile, score, breakdown, action = update_user_profile(user, row, CONFIG)

    engine     = MitreDetectionEngine()
    detections = engine.analyze(features=row, user=user, machine="AliceVm.harmonytech.local")

    print(f"    📊 Score: {score:.4f}  |  Detections: {len(detections)}")
    for d in detections:
        print(f"       [{d.technique.id}] {d.technique.name}  conf={d.confidence:.0%}")

    # Action (mock)
    action_confirmed = "none"
    if detections:
        top         = detections[0]
        final_score = max(score, top.confidence)
        mock_actions.handle(
            user      = user,
            score     = final_score,
            row       = row,
            breakdown = {
                "technique": top.technique.id,
                "name":      top.technique.name,
                "tactic":    top.technique.tactic,
                "evidence":  top.evidence,
            }
        )
        if mock_actions.calls:
            action_confirmed = mock_actions.calls[-1]["action_taken"]

    # Dispatch reports — action_confirmed goes into report
    dispatcher = ReportDispatcher(CONFIG, channels_path="reporting/channels.yml")

    # Override: inject what was actually executed into config for the report
    incident_overrides = {
        "action_confirmed":          action_confirmed,
        "vms_touched_this_incident": 2,
        "downtime_hours":            8,
    }

    # Determine action label for report_builder
    s = CONFIG["scoring"]
    if score >= s["block_threshold"]:
        action_label = "block"
    elif score >= s["mfa_threshold"]:
        action_label = "mfa"
    else:
        action_label = "alert"

    # Build and print reports directly (no real channel send during tests)
    from reporting.report_builder import (
        build_executive_report, build_technical_report, severity_from_score
    )
    severity = severity_from_score(score, CONFIG)

    exec_title, exec_body = build_executive_report(
        user=user, row=row, score=score, severity=severity,
        detections=detections, action=action_label,
        config={**CONFIG, "business_impact": {
            **CONFIG["business_impact"], **incident_overrides
        }},
    )

    tech_title, tech_body = build_technical_report(
        user=user, machine="AliceVm.harmonytech.local",
        row=row, score=score, severity=severity,
        detections=detections, feature_breakdown=breakdown,
        config=CONFIG,
    )

    return {
        "user":         user,
        "score":        score,
        "severity":     severity,
        "detections":   detections,
        "row":          row,
        "exec_title":   exec_title,
        "exec_body":    exec_body,
        "tech_title":   tech_title,
        "tech_body":    tech_body,
        "action_taken": action_confirmed,
    }


# ── STEP 3: VERIFY ACTION IN REPORT ──────────────────────────────────────

def verify_action_in_report(result: dict) -> bool:
    """
    Verifies that the action the system took is mentioned in the report.
    This is the check for your question: "Does the action appear in the report?"
    """
    body          = result["exec_body"]
    action_taken  = result["action_taken"]
    checks_passed = []

    # Check 1: action section present
    if "ACTION AUTOMATIQUE PRISE" in body:
        checks_passed.append("✅ Section 'ACTION AUTOMATIQUE PRISE' présente")
    else:
        checks_passed.append("❌ Section ACTION manquante dans le rapport exécutif")

    # Check 2: block / mfa / alert keyword present
    severity = result["severity"]
    if severity == "critical" and ("bloqué" in body.lower() or "block" in body.lower()):
        checks_passed.append("✅ Action BLOCK mentionnée pour sévérité CRITICAL")
    elif severity == "high" and ("mfa" in body.lower() or "révoqué" in body.lower()):
        checks_passed.append("✅ Action MFA mentionnée pour sévérité HIGH")
    elif severity in ("medium", "info") and "supervision" in body.lower():
        checks_passed.append("✅ Action ALERT (supervision) mentionnée pour sévérité MEDIUM")

    # Check 3: MITRE technique in technical report
    tech_body = result["tech_body"]
    if result["detections"] and result["detections"][0].technique.id in tech_body:
        checks_passed.append(f"✅ Technique {result['detections'][0].technique.id} présente dans rapport technique")

    # Check 4: financial section present
    if "IMPACT FINANCIER" in body:
        checks_passed.append("✅ Section IMPACT FINANCIER présente")
    else:
        checks_passed.append("⚠  Section IMPACT FINANCIER absente (vérifier business_impact config)")

    for c in checks_passed:
        print(f"    {c}")

    return all("✅" in c for c in checks_passed)


# ── MAIN ──────────────────────────────────────────────────────────────────

def run_scenario(name: str):
    scenarios = _load_scenarios()
    if name not in scenarios:
        print(f"Unknown scenario '{name}'. Available: {list(scenarios.keys())}")
        return

    sc = scenarios[name]
    print(f"\n{SEP}")
    print(f"  ATTACK SIMULATION: {name.upper()}")
    print(SEP)

    # Clean up previous test data for this user
    import redis as redispy
    r = redispy.Redis(host="localhost", port=6379)
    r.delete("buffer:alice")
    r.delete("profile:alice")
    r.delete("model:alice")
    print("  🧹 Redis cleaned for user 'alice'")

    print(f"\n  STEP 1 — Injecting events into Redis...")
    inject_sysmon_events(sc["sysmon"])
    inject_entra_events(sc["entra"])

    time.sleep(0.3)   # let Redis settle

    print(f"\n  STEP 2 — Running pipeline...")
    mock_actions = MockActionEngine(CONFIG)
    result = run_pipeline_for_user("alice", mock_actions)

    if result is None:
        print("  ❌ Pipeline returned no result")
        return

    print(f"\n  STEP 3 — Verifying action appears in report...")
    passed = verify_action_in_report(result)

    print(f"\n{SEP2}")
    print(f"  EXECUTIVE REPORT")
    print(SEP2)
    print(f"Subject: {result['exec_title']}")
    print()
    print(result["exec_body"])

    print(f"\n{SEP2}")
    print(f"  TECHNICAL REPORT")
    print(SEP2)
    print(f"Subject: {result['tech_title']}")
    print()
    print(result["tech_body"])

    # Save
    for kind, title, body in [
        ("executive", result["exec_title"], result["exec_body"]),
        ("technical", result["tech_title"], result["tech_body"]),
    ]:
        path = f"tests/output/{name}_{kind}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Subject: {title}\n\n{body}")
        print(f"\n  ✅ {kind.capitalize()} report saved → {path}")

    status = "PASSED" if passed else "FAILED"
    print(f"\n{SEP}")
    print(f"  SCENARIO {name.upper()} — {status}")
    print(SEP)
    return passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroTrust AI Attack Simulation Test")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", choices=["ransomware","credential_dump","lateral_movement","full_apt"])
    group.add_argument("--all", action="store_true")
    args = parser.parse_args()

    print("\nZeroTrust AI — Full Pipeline Attack Simulation")
    print("Requires: Redis on localhost:6379")

    try:
        import redis as redispy
        redispy.Redis(host="localhost", port=6379).ping()
        print("✅ Redis connection OK\n")
    except Exception as e:
        print(f"❌ Redis not available: {e}")
        print("   Start Redis: docker run -p 6379:6379 redis:alpine")
        sys.exit(1)

    if args.all:
        results = {}
        for name in ["ransomware", "credential_dump", "lateral_movement", "full_apt"]:
            results[name] = run_scenario(name)
        print(f"\n{SEP}")
        print("  FINAL RESULTS")
        print(SEP)
        for name, passed in results.items():
            icon = "✅" if passed else "❌"
            print(f"  {icon}  {name}")
    else:
        run_scenario(args.scenario)
