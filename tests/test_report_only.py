#!/usr/bin/env python3
"""
tests/test_report_only.py

Standalone test for the reporting module.
NO Redis, NO Azure AD, NO WinRM required.
Just imports and runs the report builders directly.

Run from repo root:
    python tests/test_report_only.py

Output: printed reports + saved to tests/output/
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.makedirs("tests/output", exist_ok=True)

from reporting.report_builder import (
    build_executive_report,
    build_technical_report,
    severity_from_score,
)
from reporting.report_html_builder import build_executive_html, build_technical_html
from reporting.financial_estimator import estimate as financial_estimate
from detection.mitre_engine import MitreDetectionEngine, Detection, TECHNIQUES

# ── MINIMAL CONFIG ────────────────────────────────────────────────────────
CONFIG = {
    "scoring": {
        "alert_threshold": 0.50,
        "mfa_threshold":   0.70,
        "block_threshold": 0.85,
    },
    "business_impact": {
        "company_size":               "smb",
        "currency":                   "EUR",
        "annual_revenue":             1_500_000,
        "employee_count":             45,
        "avg_employee_hourly_cost":   38,
        "productivity_loss_pct":      0.65,
        "downtime_hours":             8,
        "vms_touched_this_incident":  3,
        "estimated_data_exposed_gb":  120,
        "estimated_records_at_risk":  2500,
        "data_type_at_risk":          "pii",
        "critical_systems_impacted":  True,
        "users_impacted":             15,
    },
}

# ── SYNTHETIC ATTACK SCENARIOS ────────────────────────────────────────────
SCENARIOS = {

    "ransomware_full_chain": {
        "description": "Ransomware — encoded PS + shadow copy deletion + file encryption",
        "user": "alice",
        "machine": "AliceVm.harmonytech.local",
        "score": 0.94,
        "action": "block",
        "row": {
            "user": "alice",
            "window_start": "2026-06-18T02:00:00+00:00",
            "total_events": 47,
            # Entra
            "signin_count": 3,
            "failed_logins": 11,
            "mfa_used": 0,
            "is_legacy_auth": 1,
            "risk_level_max": 3,
            "is_off_hours_login": 1,
            # Audit
            "group_change": 1,
            "mfa_changed": 1,
            "policy_changed": 0,
            # Process
            "process_count": 12,
            "suspicious_pairs": 2,
            "encoded_cmds": 1,
            "download_cmds": 1,
            "elevated_procs": 3,
            "backup_deletion": 1,
            # Network
            "net_count": 18,
            "external_conns": 14,
            "suspicious_ports": 1,
            # LSASS
            "lsass_access": 1,
            "lsass_dump_score": 1,
            # Files
            "file_writes": 89,
            "suspicious_writes": 1,
            "extension_changes": 1,
            # Registry
            "registry_writes": 3,
            "persistence_keys": 1,
            # Time
            "hour_of_day": 2,
            "is_off_hours": 1,
            "is_weekend": 0,
        },
        "detections": [
            Detection(
                technique  = TECHNIQUES["T1486"],
                confidence = 1.0,
                evidence   = ["File extensions changed", "Shadow copy deletion"],
                timestamp  = "2026-06-18T02:40:00+00:00",
                user       = "alice",
                action     = "block",
            ),
            Detection(
                technique  = TECHNIQUES["T1003"],
                confidence = 1.0,
                evidence   = ["lsass.exe accessed", "Credential dump access mask"],
                timestamp  = "2026-06-18T02:39:00+00:00",
                user       = "alice",
                action     = "block",
            ),
            Detection(
                technique  = TECHNIQUES["T1059.001"],
                confidence = 0.90,
                evidence   = ["Encoded PowerShell detected", "Download command detected"],
                timestamp  = "2026-06-18T02:34:00+00:00",
                user       = "alice",
                action     = "mfa",
            ),
            Detection(
                technique  = TECHNIQUES["T1547"],
                confidence = 0.85,
                evidence   = ["Registry Run key modified", "Executable in suspicious path"],
                timestamp  = "2026-06-18T02:37:00+00:00",
                user       = "alice",
                action     = "block",
            ),
        ],
        "breakdown": {
            "extension_changes": 0.70,
            "backup_deletion":   0.95,
            "lsass_dump_score":  1.00,
            "encoded_cmds":      0.85,
            "persistence_keys":  0.65,
            "suspicious_pairs":  0.85,
            "failed_logins":     0.46,
            "is_off_hours_login":0.60,
            "suspicious_ports":  0.60,
            "external_conns":    0.40,
        },
    },

    "credential_dump_only": {
        "description": "Credential dump — lsass access, no ransomware indicators",
        "user": "alice",
        "machine": "AliceVm.harmonytech.local",
        "score": 0.76,
        "action": "mfa",
        "row": {
            "user": "alice",
            "window_start": "2026-06-18T03:00:00+00:00",
            "total_events": 9,
            "signin_count": 1,
            "failed_logins": 0,
            "mfa_used": 0,
            "is_legacy_auth": 0,
            "risk_level_max": 0,
            "is_off_hours_login": 1,
            "group_change": 0,
            "mfa_changed": 0,
            "policy_changed": 0,
            "process_count": 4,
            "suspicious_pairs": 0,
            "encoded_cmds": 1,
            "download_cmds": 0,
            "elevated_procs": 1,
            "backup_deletion": 0,
            "net_count": 3,
            "external_conns": 1,
            "suspicious_ports": 0,
            "lsass_access": 1,
            "lsass_dump_score": 1,
            "file_writes": 2,
            "suspicious_writes": 0,
            "extension_changes": 0,
            "registry_writes": 0,
            "persistence_keys": 0,
            "hour_of_day": 3,
            "is_off_hours": 1,
            "is_weekend": 0,
        },
        "detections": [
            Detection(
                technique  = TECHNIQUES["T1003"],
                confidence = 1.0,
                evidence   = ["lsass.exe accessed", "Credential dump access mask"],
                timestamp  = "2026-06-18T03:05:00+00:00",
                user       = "alice",
                action     = "block",
            ),
        ],
        "breakdown": {
            "lsass_access":      0.70,
            "lsass_dump_score":  1.00,
            "encoded_cmds":      0.85,
            "is_off_hours_login":0.60,
            "external_conns":    0.40,
        },
    },

    "brute_force_medium": {
        "description": "Brute force — medium severity, MFA action only",
        "user": "alice",
        "machine": "unknown",
        "score": 0.58,
        "action": "alert",
        "row": {
            "user": "alice",
            "window_start": "2026-06-18T04:00:00+00:00",
            "total_events": 14,
            "signin_count": 1,
            "failed_logins": 7,
            "mfa_used": 0,
            "is_legacy_auth": 1,
            "risk_level_max": 2,
            "is_off_hours_login": 1,
            "group_change": 0,
            "mfa_changed": 0,
            "policy_changed": 0,
            "process_count": 0,
            "suspicious_pairs": 0,
            "encoded_cmds": 0,
            "download_cmds": 0,
            "elevated_procs": 0,
            "backup_deletion": 0,
            "net_count": 0,
            "external_conns": 0,
            "suspicious_ports": 0,
            "lsass_access": 0,
            "lsass_dump_score": 0,
            "file_writes": 0,
            "suspicious_writes": 0,
            "extension_changes": 0,
            "registry_writes": 0,
            "persistence_keys": 0,
            "hour_of_day": 4,
            "is_off_hours": 1,
            "is_weekend": 0,
        },
        "detections": [
            Detection(
                technique  = TECHNIQUES["T1110"],
                confidence = 0.60,
                evidence   = ["7 failed logins"],
                timestamp  = "2026-06-18T04:01:00+00:00",
                user       = "alice",
                action     = "mfa",
            ),
            Detection(
                technique  = TECHNIQUES["T1078"],
                confidence = 0.40,
                evidence   = ["Login outside normal hours", "High risk login detected"],
                timestamp  = "2026-06-18T04:01:00+00:00",
                user       = "alice",
                action     = "mfa",
            ),
        ],
        "breakdown": {
            "failed_logins":     0.46,
            "is_off_hours_login":0.60,
            "is_legacy_auth":    0.30,
        },
    },
}


# ── TEST RUNNER ───────────────────────────────────────────────────────────

SEP = "═" * 70

def run_scenario(name: str, sc: dict):
    print(f"\n{SEP}")
    print(f"  SCENARIO: {name.upper()}")
    print(f"  {sc['description']}")
    print(SEP)

    severity = severity_from_score(sc["score"], CONFIG)

    # ── Executive report ──────────────────────────────────────────────────
    exec_title, exec_body = build_executive_report(
        user       = sc["user"],
        row        = sc["row"],
        score      = sc["score"],
        severity   = severity,
        detections = sc["detections"],
        action     = sc["action"],
        config     = CONFIG,
    )

    print(f"\n{'─'*70}")
    print(f"  EXECUTIVE REPORT  (managers / non-technical)")
    print(f"{'─'*70}")
    print(f"Subject: {exec_title}")
    print()
    print(exec_body)

    # ── Technical report ─────────────────────────────────────────────────
    tech_title, tech_body = build_technical_report(
        user              = sc["user"],
        machine           = sc["machine"],
        row               = sc["row"],
        score             = sc["score"],
        severity          = severity,
        detections        = sc["detections"],
        feature_breakdown = sc["breakdown"],
        config            = CONFIG,
    )

    print(f"\n{'─'*70}")
    print(f"  TECHNICAL REPORT  (SOC analysts / security engineers)")
    print(f"{'─'*70}")
    print(f"Subject: {tech_title}")
    print()
    print(tech_body)

    # ── Financial estimate standalone check ───────────────────────────────
    est = financial_estimate(sc["row"], sc["detections"], CONFIG)
    if est:
        print(f"\n{'─'*70}")
        print(f"  FINANCIAL ESTIMATOR — raw output (for unit-test verification)")
        print(f"{'─'*70}")
        print(f"  Vector      : {est.vector}")
        print(f"  Low         : {est.currency} {est.low:,}")
        print(f"  Mid         : {est.currency} {est.mid:,}")
        print(f"  High        : {est.currency} {est.high:,}")
        print(f"  Multipliers : {len(est.multipliers)}")
        for m in est.multipliers:
            print(f"    ×{m.value:.1f}  {m.label}")
        if est.downtime:
            print(f"  Downtime    : {est.currency} {est.downtime['total']:,}  ({est.downtime['hours']}h)")
        if est.regulatory:
            print(f"  GDPR max    : {est.currency} {est.regulatory['gdpr_worst_case_fine']:,}")

    # ── Save to file ──────────────────────────────────────────────────────
    out_path = f"tests/output/{name}_executive.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"Subject: {exec_title}\n\n{exec_body}")
    print(f"\n  ✅ Executive report saved → {out_path}")

    out_path = f"tests/output/{name}_technical.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"Subject: {tech_title}\n\n{tech_body}")
    print(f"  ✅ Technical report saved → {out_path}")


def assert_financial_range(name, est, expected_vector):
    """Simple assertions so this doubles as a regression test."""
    assert est is not None,                 f"[{name}] estimate returned None"
    assert est.vector == expected_vector,   f"[{name}] wrong vector: {est.vector}"
    assert est.low   > 0,                  f"[{name}] low cost is 0"
    assert est.mid   > est.low,            f"[{name}] mid ≤ low"
    assert est.high  > est.mid,            f"[{name}] high ≤ mid"
    assert len(est.multipliers) > 0,       f"[{name}] no multipliers applied"
    print(f"  ✅ Assertions passed for {name}")


if __name__ == "__main__":
    print("\nZeroTrust AI — Report Generation Test Suite")
    print("No Redis / Azure AD / WinRM required")

    for scenario_name, scenario_data in SCENARIOS.items():
        run_scenario(scenario_name, scenario_data)

    # Regression assertions
    print(f"\n{SEP}")
    print("  REGRESSION ASSERTIONS")
    print(SEP)

    est_rw = financial_estimate(
        SCENARIOS["ransomware_full_chain"]["row"],
        SCENARIOS["ransomware_full_chain"]["detections"],
        CONFIG,
    )
    assert_financial_range("ransomware_full_chain", est_rw, "ransomware")

    est_cd = financial_estimate(
        SCENARIOS["credential_dump_only"]["row"],
        SCENARIOS["credential_dump_only"]["detections"],
        CONFIG,
    )
    assert_financial_range("credential_dump_only", est_cd, "credential_dump")

    est_bf = financial_estimate(
        SCENARIOS["brute_force_medium"]["row"],
        SCENARIOS["brute_force_medium"]["detections"],
        CONFIG,
    )
    assert_financial_range("brute_force_medium", est_bf, "brute_force")

    print(f"\n{'═'*70}")
    print("  ALL TESTS PASSED")
    print(f"  Reports saved in tests/output/")
    print(f"{'═'*70}\n")
