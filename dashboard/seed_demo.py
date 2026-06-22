# dashboard/seed_demo.py
"""
Populate Redis with realistic demo data so the LIVE dashboard
(GET /api/snapshot reading real Redis) is fully populated without
having to run the whole collector/pipeline stack.

Usage (from repo root, Redis must be running):
    python -m dashboard.seed_demo

Writes profile:<user>, score_history, incidents:log, incidents:tech_counts,
incidents:machine_counts, incident:last:<user> and status:<user>.
Re-runnable: it overwrites the demo keys each time.
"""

import os
import json
import yaml
import redis

from dashboard.demo import build_demo_snapshot, TECHNIQUES

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    with open(os.path.join(_ROOT, "config.yml")) as f:
        config = yaml.safe_load(f)
    r = redis.Redis(host=config["redis"]["host"], port=config["redis"]["port"])

    snap = build_demo_snapshot()

    # profiles + behaviour curves
    for u in snap["users"]:
        user = u["user"]
        curve = snap["behavior"].get(user, {"labels": [], "scores": []})
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        n = len(curve["scores"])
        score_history = []
        for i, s in enumerate(curve["scores"]):
            ts = (now - timedelta(hours=(n - 1 - i))).isoformat()
            score_history.append({"ts": ts, "score": round(s / 100.0, 4)})
        profile = {
            "user": user,
            "created_at": (now - timedelta(days=10)).isoformat(),
            "last_updated": now.isoformat(),
            "warmup": (u["status"] == "warmup"),
            "total_hours": n,
            "current_score": round(u["score"] / 100.0, 4),
            "score_trend": u["trend"],
            "last_action": u["last_action"],
            "feature_history": [],
            "score_history": score_history,
            "incidents": [],
        }
        r.set(f"profile:{user}", json.dumps(profile))
        r.set(f"status:{user}", "blocked" if u["status"] == "blocked" else "active")

    # incident log + counters
    r.delete("incidents:log", "incidents:tech_counts", "incidents:machine_counts")
    for inc in reversed(snap["incidents"]):           # oldest first -> lpush => newest first
        r.lpush("incidents:log", json.dumps(inc))
        r.hincrby("incidents:tech_counts", inc["technique_id"], 1)
        r.hincrby("incidents:machine_counts", inc["machine"], 1)
        r.set(f"incident:last:{inc['user']}", json.dumps(inc))
    r.ltrim("incidents:log", 0, 499)

    # pad technique counts for a fuller top-10
    for t in snap["top_techniques"]:
        existing = int(r.hget("incidents:tech_counts", t["id"]) or 0)
        if t["count"] > existing:
            r.hincrby("incidents:tech_counts", t["id"], t["count"] - existing)

    print(f"Seeded {len(snap['users'])} profiles and {len(snap['incidents'])} incidents into Redis "
          f"({config['redis']['host']}:{config['redis']['port']}).")
    print("Start the dashboard:  python -m dashboard.server")


if __name__ == "__main__":
    main()
