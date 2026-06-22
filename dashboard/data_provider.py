# dashboard/data_provider.py
"""
Builds the live dashboard snapshot from the SAME Redis the pipeline writes to.

Sources:
  profile:<user>            -> score, trend, history, status      (ProfileStore)
  incidents:log             -> rolling alert feed                 (ReportDispatcher)
  incidents:tech_counts     -> per-technique counters             (ReportDispatcher)
  incidents:machine_counts  -> per-machine threat counters        (ReportDispatcher)
  status:<user>             -> active | blocked                   (this dashboard)
  config.yml  (read-only)   -> VM inventory (name/ip/user)
  dashboard/machines.yml    -> optional OS / version enrichment

If Redis has no user profiles yet, falls back to demo.build_demo_snapshot()
so the dashboard is never blank on first launch.
"""

import os
import json
import math
import statistics
from datetime import datetime, timezone

import yaml

from dashboard.demo import build_demo_snapshot, TECHNIQUES

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _severity_from_score(s, scoring):
    if s >= scoring.get("block_threshold", 0.85): return "critical"
    if s >= scoring.get("mfa_threshold", 0.70):   return "high"
    if s >= scoring.get("alert_threshold", 0.50): return "medium"
    return "info"


class ThreatDataProvider:
    def __init__(self, config: dict):
        self.config = config
        self.scoring = config.get("scoring", {})
        import redis
        self.r = redis.Redis(
            host=config["redis"]["host"],
            port=config["redis"]["port"],
        )
        self._machines_meta = self._load_machine_inventory()

    # ── inventory: config.yml VMs + optional machines.yml OS metadata ─────────
    def _load_machine_inventory(self):
        meta = {}
        for vm in self.config.get("vms", []):
            name = vm.get("name")
            if name:
                meta[name] = {
                    "ip": vm.get("ip", "—"),
                    "primary_user": vm.get("username", "—"),
                    "os": "Windows", "os_version": "unknown",
                }
        path = os.path.join(_HERE, "machines.yml")
        if os.path.exists(path):
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            for m in data.get("machines", []):
                name = m.get("name")
                if not name:
                    continue
                meta.setdefault(name, {"ip": "—", "primary_user": "—"})
                meta[name].update({k: v for k, v in m.items() if k != "name"})
        return meta

    # ── helpers ───────────────────────────────────────────────────────────────
    def _users(self):
        keys = self.r.keys("profile:*")
        return [k.decode().split(":", 1)[1] for k in keys]

    def _get(self, key):
        v = self.r.get(key)
        return v.decode() if isinstance(v, bytes) else v

    def _status(self, user):
        return self._get(f"status:{user}") or "active"

    # ── public API ──────────────────────────────────────────────────────────--
    def set_status(self, user: str, status: str):
        """status in {'active','blocked'} — drives the UI + block/unblock."""
        self.r.set(f"status:{user}", status)
        return self._status(user)

    def get_snapshot(self):
        users = self._users()
        if not users:
            return build_demo_snapshot()  # nothing live yet → demo

        now = datetime.now(timezone.utc)
        user_rows, behavior = [], {}
        sev_dist = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        machine_index = {}

        for user in users:
            prof = self.r.get(f"profile:{user}")
            if not prof:
                continue
            prof = json.loads(prof)
            hist = prof.get("score_history", [])
            scores = [h["score"] for h in hist if "score" in h]
            current = float(prof.get("current_score", 0.0))
            baseline = float(statistics.mean(scores)) if scores else current
            std = float(statistics.pstdev(scores)) if len(scores) > 1 else 0.06
            std = max(std, 0.02)
            sev = _severity_from_score(current, self.scoring)
            sev_dist[sev] += 1

            last_inc = self.r.get(f"incident:last:{user}")
            last_inc = json.loads(last_inc) if last_inc else {}
            machine = last_inc.get("machine") or self._machine_for(user)
            top_tech = last_inc.get("technique_id")

            status = "warmup" if prof.get("warmup") else self._status(user)

            user_rows.append({
                "user": user, "machine": machine,
                "score": round(current * 100, 1),
                "baseline": round(baseline * 100, 1),
                "deviation_pct": round((current - baseline) * 100, 1),
                "deviation_sigma": round((current - baseline) / std, 1),
                "trend": prof.get("score_trend", "stable"),
                "status": status,
                "last_action": last_inc.get("action", prof.get("last_action", "none")),
                "top_technique": top_tech,
                "severity": sev,
            })

            # behaviour curve (last 48 points)
            pts = hist[-48:]
            behavior[user] = {
                "labels":   [self._hhmm(h.get("ts")) for h in pts],
                "scores":   [round(h.get("score", 0) * 100, 1) for h in pts],
                "baseline": [round(baseline * 100, 1)] * len(pts),
            }

            machine_index.setdefault(machine, {"risk": 0.0, "threats": 0, "user": user})
            machine_index[machine]["risk"] = max(machine_index[machine]["risk"], current)
            if sev in ("critical", "high"):
                machine_index[machine]["threats"] += 1

        # machines: union of inventory + observed
        machines, os_dist = [], {}
        names = set(self._machines_meta) | set(machine_index)
        for name in sorted(names):
            meta = self._machines_meta.get(name, {})
            mi = machine_index.get(name, {})
            osr = meta.get("os", "Windows")
            ver = meta.get("os_version", "unknown")
            machines.append({
                "name": name, "ip": meta.get("ip", "—"),
                "os": osr, "os_version": ver,
                "primary_user": meta.get("primary_user", mi.get("user", "—")),
                "status": meta.get("status", "online"),
                "risk": round(mi.get("risk", 0.0) * 100, 1),
                "active_threats": mi.get("threats", 0),
                "last_seen": now.isoformat(),
            })
            os_dist[osr] = os_dist.get(osr, 0) + 1

        # incidents + counters
        incidents = self._incident_log(limit=60)
        top_techniques = self._top_techniques(limit=10)
        tactic_dist = {}
        for t in top_techniques:
            tactic_dist[t["tactic"]] = tactic_dist.get(t["tactic"], 0) + t["count"]

        online = sum(1 for m in machines if m["status"] == "online")
        blocked = sum(1 for u in user_rows if u["status"] == "blocked")
        active_threats = sum(m["active_threats"] for m in machines)
        avg_risk = round(sum(u["score"] for u in user_rows) / max(1, len(user_rows)), 1)

        return {
            "generated_at": now.isoformat(),
            "live": True,
            "kpis": {
                "endpoints": len(machines), "online": online,
                "offline": len(machines) - online, "total_users": len(user_rows),
                "active_threats": active_threats, "blocked_users": blocked,
                "critical_incidents": sev_dist["critical"], "avg_risk": avg_risk,
                "incidents_24h": len(incidents),
            },
            "machines": machines,
            "users": sorted(user_rows, key=lambda u: u["score"], reverse=True),
            "severity_distribution": sev_dist,
            "os_distribution": os_dist,
            "tactic_distribution": tactic_dist,
            "top_techniques": top_techniques,
            "incidents": incidents,
            "behavior": behavior,
        }

    # ── internals ──────────────────────────────────────────────────────────────
    def _machine_for(self, user):
        for name, meta in self._machines_meta.items():
            if meta.get("primary_user") == user:
                return name
        return "unknown"

    def _hhmm(self, ts):
        try:
            return datetime.fromisoformat(ts).strftime("%H:%M")
        except Exception:
            return ""

    def _incident_log(self, limit=60):
        raw = self.r.lrange("incidents:log", 0, limit - 1)
        out = []
        for item in raw:
            try:
                out.append(json.loads(item.decode() if isinstance(item, bytes) else item))
            except Exception:
                pass
        return out

    def _top_techniques(self, limit=10):
        counts = self.r.hgetall("incidents:tech_counts") or {}
        rows = []
        for tid, c in counts.items():
            tid = tid.decode() if isinstance(tid, bytes) else tid
            c = int(c)
            meta = TECHNIQUES.get(tid)
            if not meta:
                continue
            name, tactic, sev = meta
            rows.append({"id": tid, "name": name, "tactic": tactic,
                         "count": c, "severity": round(sev * 100)})
        rows.sort(key=lambda r: r["count"], reverse=True)
        return rows[:limit]
