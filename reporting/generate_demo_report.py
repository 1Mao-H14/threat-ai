#!/usr/bin/env python3
"""
reporting/generate_demo_report.py

Builds rapport_technique_incident.html for the example incident
(alice@AliceVm.harmonytech.local, ransomware, score 0.94) using the
exact figures from the incident brief.

This is a DEMO populated with the synthetic test scenario used
throughout this project's test suite (see tests/fixtures/). Wire your
real incident data through reporting/incident_data.py's IncidentData
contract to use this for live incidents.

Requires:
    pip install plotly kaleido

Run:
    python3 reporting/generate_demo_report.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from detection.mitre_engine import Technique, Detection
except ImportError:
    from dataclasses import dataclass

    @dataclass
    class Technique:
        id: str; name: str; tactic: str; severity: float; description: str

    @dataclass
    class Detection:
        technique: Technique; confidence: float; evidence: list
        timestamp: str; user: str; action: str

from reporting.incident_data import (
    IncidentData, EventTypeBreakdown, ScorePoint, KillChainPhase,
    IOC, ChainOfCustody, IRContact, CyberInsurance,
)
from reporting.financial_estimator import estimate as financial_estimate
from reporting.charts import build_all_charts
from reporting.technical_report_v2 import build_report


def main():
    TECHNIQUES = {
        "T1486": Technique("T1486", "Data Encrypted for Impact", "Impact", 0.99, "Ransomware pattern"),
        "T1003": Technique("T1003", "OS Credential Dumping", "Credential Access", 0.95, "lsass.exe access"),
        "T1059.001": Technique("T1059.001", "PowerShell", "Execution", 0.80, "Encoded PowerShell"),
        "T1547": Technique("T1547", "Boot Autostart Execution", "Persistence", 0.80, "Registry Run key"),
    }

    row = {
        "user": "alice", "window_start": "2026-06-20T02:00:00+00:00",
        "total_events": 47, "signin_count": 3, "failed_logins": 11,
        "file_writes": 89, "lsass_access": 1, "lsass_dump_score": 1,
        "backup_deletion": 1, "extension_changes": 1, "encoded_cmds": 1,
        "suspicious_pairs": 2, "persistence_keys": 1, "external_conns": 14,
    }

    detections = [
        Detection(TECHNIQUES["T1486"], 1.00, ["File extensions changed", "Shadow copy deletion"], "2026-06-20T02:45:00+00:00", "alice", "block"),
        Detection(TECHNIQUES["T1003"], 1.00, ["lsass.exe accessed", "Credential dump access mask"], "2026-06-20T02:20:00+00:00", "alice", "block"),
        Detection(TECHNIQUES["T1059.001"], 0.90, ["Encoded PowerShell detected", "Download command detected"], "2026-06-20T02:08:00+00:00", "alice", "mfa"),
        Detection(TECHNIQUES["T1547"], 0.85, ["Registry Run key modified", "Executable in suspicious path"], "2026-06-20T02:32:00+00:00", "alice", "block"),
    ]

    feature_breakdown = {
        "backup_deletion": 0.95, "lsass_dump_score": 1.00, "encoded_cmds": 0.85,
        "suspicious_pairs": 0.85, "persistence_keys": 0.65,
    }

    config = {
        "scoring": {"alert_threshold": 0.50, "mfa_threshold": 0.70, "block_threshold": 0.85},
        "business_impact": {
            "company_size": "smb", "currency": "EUR", "annual_revenue": 1_500_000,
            "employee_count": 45, "avg_employee_hourly_cost": 38, "productivity_loss_pct": 0.65,
            "downtime_hours": 4, "vms_touched_this_incident": 1, "estimated_data_exposed_gb": 0,
            "estimated_records_at_risk": 2500, "data_type_at_risk": "pii",
            "critical_systems_impacted": False, "users_impacted": 1,
        },
    }

    financial = financial_estimate(row, detections, config)

    incident = IncidentData(
        user="alice",
        machine="AliceVm.harmonytech.local",
        reference="ZTA-20260620-0243-ALIC-CRI",
        severity="critical",
        score=0.94,
        window_start="2026-06-20T02:00:00+00:00",
        window_end="2026-06-20T04:00:00+00:00",
        detection_delay_minutes=163,
        row=row,
        detections=detections,
        feature_breakdown=feature_breakdown,
        action_confirmed="Compte bloque et sessions revoquees (Azure AD HTTP 204)",
        action_success=True,
        financial=financial,
        mfa_active=True,

        event_breakdown=[
            EventTypeBreakdown("Credential Dump", 25),
            EventTypeBreakdown("PowerShell", 8),
            EventTypeBreakdown("Backup", 6),
            EventTypeBreakdown("Persistence", 4),
            EventTypeBreakdown("Autres", 4),
        ],
        score_timeline=[
            ScorePoint("02:00", 0.10), ScorePoint("02:30", 0.30),
            ScorePoint("03:00", 0.60), ScorePoint("03:23", 0.94),
            ScorePoint("04:00", 0.94),
        ],
        kill_chain_phases=[
            KillChainPhase("Execution", "02:05", "02:15"),
            KillChainPhase("Credential Access", "02:15", "02:30"),
            KillChainPhase("Persistence", "02:30", "02:45"),
            KillChainPhase("Impact", "02:45", "03:00"),
        ],

        # Annex data: left empty/honest where no real forensic pipeline
        # currently surfaces it. Fill these from real IR tooling for
        # live incidents, never with invented values.
        iocs=[],
        chain_of_custody=ChainOfCustody(
            collected_by="Equipe IR",
            tool="Sysmon v10.2 + Microsoft Graph API",
            collected_at="2026-06-20T03:30:00+00:00",
        ),
        ir_contact=IRContact(
            team_name="Equipe IR Harmony Technology",
            email="ir@harmonytech.com",
            note="Validation humaine requise avant cloture de l'incident",
        ),
        insurance=CyberInsurance(
            insurer=None, policy_ref=None, limit=None, deductible=None,
            coverage=None,
        ),
        rgpd_template_ref=None,
    )

    charts = build_all_charts(incident)
    title, html = build_report(incident, charts)

    out_dir = "reports/alice"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "rapport_technique_incident.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Generated: {out_path}")
    print(f"Title: {title}")


if __name__ == "__main__":
    main()
