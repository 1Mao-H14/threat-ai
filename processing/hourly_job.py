# processing/hourly_job.py
"""
Scheduled pipeline: buffered events -> aggregated row -> score ->
MITRE detections -> action execution -> report dispatch (push + HTML).

Run every minute by APScheduler (see main.py).

Key change vs. the original version: the action engine's result is
CAPTURED and passed into the report, so the report shows what was
ACTUALLY executed (e.g. "Azure AD HTTP 204 — compte bloqué") rather
than only the intended action label.
"""

import json
import logging
import redis
from datetime import datetime, timezone

logger = logging.getLogger("Pipeline")


def get_active_users(r) -> list:
    keys = r.keys("buffer:*")
    return [k.decode().split(":", 1)[1] for k in keys]


def get_and_clear_buffer(r, user: str) -> list:
    key    = f"buffer:{user}"
    raw    = r.lrange(key, 0, -1)
    events = [json.loads(e.decode()) for e in raw]
    r.delete(key)
    return events


def should_act(profile, config):
    """Check if enough time passed to start acting."""
    try:
        created_at   = datetime.fromisoformat(profile["created_at"])
        now          = datetime.now(timezone.utc)
        minutes_seen = (now - created_at).total_seconds() / 60
        hours_seen   = minutes_seen / 60

        action_after = config["scoring"]["action_after_mins"]
        warmup_hours = config["scoring"]["warmup_hours"]

        return (minutes_seen >= action_after and
                hours_seen   >= warmup_hours)
    except Exception:
        return False


def _distinct_machines(events: list) -> int:
    """
    Counts distinct machines touched in this window directly from
    telemetry — feeds the financial estimator's 'systems affected'
    multiplier automatically, no manual config entry required.
    """
    machines = {e.get("machine") for e in events if e.get("machine")}
    return len(machines) or 1


def run_pipeline(config: dict):
    from processing.aggregator       import aggregate_to_row
    from profiles.profile_updater    import update_user_profile
    from detection.mitre_engine      import MitreDetectionEngine
    from actions.action_engine       import ActionEngine
    from reporting.report_dispatcher import ReportDispatcher

    r          = redis.Redis(
        host=config["redis"]["host"],
        port=config["redis"]["port"]
    )
    engine     = MitreDetectionEngine()
    actions    = ActionEngine(config)
    dispatcher = ReportDispatcher(config)

    window_start = datetime.now(timezone.utc).replace(
        second=0, microsecond=0
    )
    users = get_active_users(r)
    logger.info(
        f"━━━ Pipeline | {window_start} | "
        f"{len(users)} active users ━━━"
    )

    for user in users:
        try:
            # Get buffered events
            events = get_and_clear_buffer(r, user)
            if not events:
                continue

            logger.info(f"[{user}] {len(events)} events")

            # Aggregate into one row
            row = aggregate_to_row(events, user, window_start)

            # Update profile + get score
            profile, score, breakdown, _ = \
                update_user_profile(user, row, config)

            # MITRE detection
            detections = engine.analyze(
                features = row,
                user     = user,
                machine  = row.get("machine", "unknown")
            )

            # Log detections
            for d in detections:
                logger.warning(
                    f"[{user}] {d.technique.id} — "
                    f"{d.technique.name} | "
                    f"confidence={d.confidence:.0%} | "
                    f"evidence={', '.join(d.evidence)}"
                )

            if not should_act(profile, config):
                logger.info(f"[{user}] Still in warmup — no action")
                continue

            if not detections:
                continue

            top         = detections[0]
            final_score = max(score, top.confidence)

            # ── EXECUTE ACTION + CAPTURE WHAT ACTUALLY HAPPENED ───────────
            action_result = actions.handle(
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

            logger.info(
                f"[{user}] action={action_result['action']} "
                f"success={action_result['success']} — "
                f"{action_result['detail']}"
            )

            # ── DISPATCH REPORTS — confirmed action included ──────────────
            result = dispatcher.dispatch(
                user               = user,
                machine            = row.get("machine", "unknown"),
                row                = row,
                score              = final_score,
                detections         = detections,
                feature_breakdown  = breakdown,
                action             = action_result["action"],
                incident_overrides = {
                    "action_confirmed":          action_result["detail"],
                    "action_success":            action_result["success"],
                    "vms_touched_this_incident": _distinct_machines(events),
                },
            )

            if result:
                logger.info(
                    f"[{user}] HTML reports → "
                    f"{result.get('executive_html')} | "
                    f"{result.get('technical_html')}"
                )

        except Exception as e:
            logger.error(f"[{user}] Pipeline error: {e}")
