# dashboard/demo.py
"""
Builds a realistic, self-contained demo snapshot for the dashboard.

Used in two places:
  1. dashboard/server.py  -> served when Redis has no live data yet, so the
     dashboard is never empty on first run.
  2. dashboard/static/demo-data.js is generated from this (see build script in
     README) so the dashboard renders fully offline as a static preview.

The shape returned here is the EXACT contract the frontend expects from
GET /api/snapshot. Keep build_demo_snapshot() and ThreatDataProvider in sync.
"""

import math
import random
from datetime import datetime, timezone, timedelta

# ── MITRE catalogue (mirrors detection/mitre_engine.py) ───────────────────────
TECHNIQUES = {
    "T1003":     ("OS Credential Dumping",        "Credential Access",     0.95),
    "T1110":     ("Brute Force",                  "Initial Access",        0.75),
    "T1059":     ("Command and Scripting",        "Execution",             0.75),
    "T1059.001": ("PowerShell",                   "Execution",             0.80),
    "T1547":     ("Boot/Logon Autostart",         "Persistence",           0.80),
    "T1078":     ("Valid Accounts",               "Initial Access",        0.70),
    "T1078.002": ("Domain Accounts",              "Privilege Escalation",  0.90),
    "T1562":     ("Impair Defenses",              "Defense Evasion",       0.90),
    "T1021":     ("Remote Services",              "Lateral Movement",      0.85),
    "T1486":     ("Data Encrypted for Impact",    "Impact",                0.99),
    "T1071":     ("Application Layer Protocol",   "Command and Control",   0.85),
    "T1041":     ("Exfiltration Over C2",         "Exfiltration",          0.90),
}

# ── Demo fleet ────────────────────────────────────────────────────────────────
_MACHINES = [
    # name,           ip,           os,                 version,        user,     status,   risk
    ("AliceVm",       "10.0.0.5",   "Windows 11 Pro",   "23H2 (22631)", "alice",   "online",  0.94),
    ("BobWS",         "10.0.0.6",   "Windows 10 Pro",   "22H2 (19045)", "bob",     "online",  0.18),
    ("CharlieVm",     "10.0.0.7",   "Windows 11 Ent",   "23H2 (22631)", "charlie", "online",  0.72),
    ("DianaLap",      "10.0.0.8",   "Windows 10 Ent",   "21H2 (19044)", "diana",   "online",  0.07),
    ("FileServer01",  "10.0.1.10",  "Windows Server",   "2022 (20348)", "svc_file","online",  0.41),
    ("DC01",          "10.0.1.2",   "Windows Server",   "2019 (17763)", "svc_dc",  "online",  0.12),
    ("EveVm",         "10.0.0.9",   "Windows 11 Pro",   "23H2 (22631)", "eve",     "offline", 0.55),
    ("FrankWS",       "10.0.0.11",  "Windows 10 Pro",   "22H2 (19045)", "frank",   "online",  0.31),
]

_USER_PROFILE = {
    # user:   (machine,        trend,    status,   last_action, top_tech,    baseline)
    "alice":   ("AliceVm",      "rising",  "blocked","block",    "T1486",     0.21),
    "bob":     ("BobWS",        "stable",  "active", "none",     None,        0.15),
    "charlie": ("CharlieVm",    "rising",  "active", "mfa",      "T1003",     0.19),
    "diana":   ("DianaLap",     "falling", "active", "none",     None,        0.10),
    "svc_file":("FileServer01", "stable",  "active", "alert",    "T1071",     0.28),
    "svc_dc":  ("DC01",         "stable",  "active", "none",     None,        0.09),
    "eve":     ("EveVm",        "rising",  "active", "mfa",      "T1078.002", 0.22),
    "frank":   ("FrankWS",      "stable",  "active", "alert",    "T1110",     0.20),
}


def _severity_from_score(s):
    if s >= 0.85: return "critical"
    if s >= 0.70: return "high"
    if s >= 0.50: return "medium"
    return "info"


def _behavior_curve(baseline, current, points=48, seed=0):
    """Hourly score history: noisy baseline that ramps to `current` at the end."""
    rnd = random.Random(seed)
    labels, scores, base = [], [], []
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    ramp_start = int(points * 0.78)
    for i in range(points):
        ts = now - timedelta(hours=(points - 1 - i))
        noise = rnd.uniform(-0.05, 0.06)
        if i < ramp_start:
            val = max(0.0, min(1.0, baseline + noise))
        else:
            prog = (i - ramp_start) / max(1, (points - 1 - ramp_start))
            val = max(0.0, min(1.0, baseline + (current - baseline) * (prog ** 1.6) + noise * 0.5))
        labels.append(ts.strftime("%H:%M"))
        scores.append(round(val * 100, 1))
        base.append(round(baseline * 100, 1))
    return {"labels": labels, "scores": scores, "baseline": base}


def build_demo_snapshot():
    now = datetime.now(timezone.utc)

    machines, users, behavior = [], [], {}
    sev_dist = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    os_dist, tactic_dist, tech_counts = {}, {}, {}

    for idx, (name, ip, osr, ver, user, status, risk) in enumerate(_MACHINES):
        threats = 0
        prof = _USER_PROFILE.get(user)
        top = prof[4] if prof else None
        if risk >= 0.50 and top:
            threats = 1 + (1 if risk >= 0.85 else 0)
        machines.append({
            "name": name, "ip": ip, "os": osr, "os_version": ver,
            "primary_user": user, "status": status,
            "risk": round(risk * 100, 1), "active_threats": threats,
            "last_seen": (now - timedelta(minutes=(idx * 3 if status == "online" else 240))).isoformat(),
        })
        os_key = osr.split(" (")[0]
        os_dist[os_key] = os_dist.get(os_key, 0) + 1

    for seed, (user, (machine, trend, status, last_action, top, baseline)) in enumerate(_USER_PROFILE.items()):
        m = next((mm for mm in _MACHINES if mm[0] == machine), None)
        current = m[6] if m else baseline
        sev = _severity_from_score(current)
        sev_dist[sev] += 1
        std = 0.06
        deviation_sigma = round((current - baseline) / std, 1)
        users.append({
            "user": user, "machine": machine,
            "score": round(current * 100, 1),
            "baseline": round(baseline * 100, 1),
            "deviation_pct": round((current - baseline) * 100, 1),
            "deviation_sigma": deviation_sigma,
            "trend": trend, "status": status,
            "last_action": last_action,
            "top_technique": top,
            "severity": sev,
        })
        behavior[user] = _behavior_curve(baseline, current, seed=seed + 1)
        if top:
            t = TECHNIQUES[top]
            tactic_dist[t[1]] = tactic_dist.get(t[1], 0) + 1

    # Synthetic incident log (newest first)
    incidents = []
    incident_specs = [
        ("alice",   "AliceVm",      "T1486",     "critical", 0.94, "block", True),
        ("alice",   "AliceVm",      "T1003",     "critical", 0.91, "block", True),
        ("charlie", "CharlieVm",    "T1003",     "high",     0.76, "mfa",   True),
        ("eve",     "EveVm",        "T1078.002", "medium",   0.55, "mfa",   True),
        ("svc_file","FileServer01", "T1071",     "info",     0.41, "alert", True),
        ("frank",   "FrankWS",      "T1110",     "medium",   0.52, "alert", True),
        ("charlie", "CharlieVm",    "T1059.001", "high",     0.71, "mfa",   False),
        ("alice",   "AliceVm",      "T1547",     "critical", 0.88, "block", True),
        ("eve",     "EveVm",        "T1021",     "medium",   0.58, "mfa",   True),
        ("svc_file","FileServer01", "T1041",     "info",     0.44, "alert", True),
    ]
    for i, (user, machine, tid, sev, score, action, ok) in enumerate(incident_specs):
        name, tactic, _ = TECHNIQUES[tid]
        incidents.append({
            "ts": (now - timedelta(minutes=4 * i + 2)).isoformat(),
            "user": user, "machine": machine, "severity": sev,
            "score": round(score, 4), "action": action, "action_success": ok,
            "technique_id": tid, "technique_name": name, "tactic": tactic,
            "evidence": [],
        })
        tech_counts[tid] = tech_counts.get(tid, 0) + 1

    # Pad technique counts to make a fuller top-10
    extra = {"T1059": 4, "T1078": 6, "T1562": 2, "T1071": 5, "T1110": 7, "T1003": 5,
             "T1486": 3, "T1547": 2, "T1021": 4, "T1041": 3, "T1078.002": 3, "T1059.001": 2}
    for k, v in extra.items():
        tech_counts[k] = tech_counts.get(k, 0) + v

    top_techniques = []
    for tid, count in sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]:
        name, tactic, sev = TECHNIQUES[tid]
        top_techniques.append({"id": tid, "name": name, "tactic": tactic,
                               "count": count, "severity": round(sev * 100)})

    online = sum(1 for m in machines if m["status"] == "online")
    blocked = sum(1 for u in users if u["status"] == "blocked")
    active_threats = sum(m["active_threats"] for m in machines)
    crit = sev_dist["critical"]
    avg_risk = round(sum(u["score"] for u in users) / max(1, len(users)), 1)

    return {
        "generated_at": now.isoformat(),
        "live": False,
        "kpis": {
            "endpoints": len(machines), "online": online, "offline": len(machines) - online,
            "total_users": len(users), "active_threats": active_threats,
            "blocked_users": blocked, "critical_incidents": crit,
            "avg_risk": avg_risk, "incidents_24h": len(incidents),
        },
        "machines": machines,
        "users": sorted(users, key=lambda u: u["score"], reverse=True),
        "severity_distribution": sev_dist,
        "os_distribution": os_dist,
        "tactic_distribution": tactic_dist,
        "top_techniques": top_techniques,
        "incidents": incidents,
        "behavior": behavior,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(build_demo_snapshot(), indent=2)[:2000])
