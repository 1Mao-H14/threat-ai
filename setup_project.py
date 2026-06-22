#!/usr/bin/env python3
"""
setup_project.py
Run once from the repo root to create every directory and __init__.py.

Usage:
    python setup_project.py
"""

import os
import textwrap

# ── FULL PROJECT STRUCTURE ────────────────────────────────────────────────
#
# threat-ai/
# ├── main.py                        ← entry point, starts all threads
# ├── config.yml                     ← all configuration (secrets → env vars)
# ├── requirements.txt
# ├── setup_project.py               ← this file
# │
# ├── collectors/
# │   ├── __init__.py
# │   ├── sysmon_collector.py        ← WinRM → Sysmon events → SmartBuffer
# │   ├── entraid_collector.py       ← Graph API → sign-in + audit → SmartBuffer
# │   └── smart_buffer.py            ← priority Redis ring-buffer
# │
# ├── processing/
# │   ├── __init__.py
# │   ├── parser.py                  ← raw Sysmon message → structured dict
# │   ├── aggregator.py              ← list[events] → one feature row per user
# │   └── hourly_job.py              ← scheduled pipeline: buffer → row → score → action
# │
# ├── profiles/
# │   ├── __init__.py
# │   ├── profile_store.py           ← Redis: user profiles + model persistence
# │   ├── profile_updater.py         ← updates score history, warmup, trend
# │   └── scorer.py                  ← rule-based → z-score → isolation forest
# │
# ├── detection/
# │   ├── __init__.py
# │   └── mitre_engine.py            ← maps feature row → MITRE ATT&CK detections
# │
# ├── actions/
# │   ├── __init__.py
# │   └── action_engine.py           ← Graph API: block user, revoke sessions, NOC webhook
# │
# ├── reporting/                     ← NEW MODULE
# │   ├── __init__.py
# │   ├── channels.yml               ← one entry per notification destination
# │   ├── financial_estimator.py     ← telemetry signals → cost range (low/mid/high)
# │   ├── report_builder.py          ← builds executive + technical report text
# │   ├── report_dispatcher.py       ← cooldown + send via notifier
# │   └── notifier.py                ← Apprise wrapper: routes by audience + severity
# │
# └── tests/
#     ├── __init__.py
#     ├── fixtures/
#     │   ├── sysmon_messages.py     ← realistic raw Sysmon event message strings
#     │   └── entra_events.py        ← realistic raw Entra ID log dicts
#     ├── test_attack_simulation.py  ← injects events → Redis → full pipeline → report
#     ├── test_report_only.py        ← standalone report test (no Redis needed)
#     └── test_parser.py             ← unit tests for parser.py

DIRS = [
    "collectors",
    "processing",
    "profiles",
    "detection",
    "actions",
    "reporting",
    "tests",
    "tests/fixtures",
]

def main():
    print("Creating project structure...\n")
    for d in DIRS:
        os.makedirs(d, exist_ok=True)
        init = os.path.join(d, "__init__.py")
        if not os.path.exists(init):
            open(init, "w").close()
            print(f"  created  {init}")
        else:
            print(f"  exists   {init}")

    # Create tests/fixtures/__init__.py too
    fix_init = "tests/fixtures/__init__.py"
    if not os.path.exists(fix_init):
        open(fix_init, "w").close()
        print(f"  created  {fix_init}")

    print("\nDone. Run:  pip install -r requirements.txt")
    print("Then:       python tests/test_report_only.py   (no Redis needed)")
    print("Then:       python tests/test_attack_simulation.py  (Redis needed)")

if __name__ == "__main__":
    main()
