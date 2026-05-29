# processing/hourly_job.py
import json
import logging
import redis
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("Pipeline")


def get_active_users(r) -> list:
    keys  = r.keys("buffer:*")
    return [k.decode().split(":",1)[1] for k in keys]


def get_and_clear_buffer(r, user: str) -> list:
    key    = f"buffer:{user}"
    raw    = r.lrange(key, 0, -1)
    events = [json.loads(e.decode()) for e in raw]
    r.delete(key)
    return events


def should_act(profile: dict, config: dict) -> bool:
    """Check if enough time passed to start acting."""
    try:
        created_at   = datetime.fromisoformat(
                           profile["created_at"]
                       )
        now          = datetime.now(timezone.utc)
        minutes_seen = (now - created_at).total_seconds() / 60
        hours_seen   = minutes_seen / 60

        action_after = config["scoring"]["action_after_mins"]
        warmup_hours = config["scoring"]["warmup_hours"]

        return (minutes_seen >= action_after and
                hours_seen   >= warmup_hours)
    except:
        return False


def run_pipeline(config: dict):
    from processing.aggregator    import aggregate_to_row
    from profiles.profile_updater import update_user_profile
    from detection.mitre_engine   import MitreDetectionEngine
    from actions.action_engine    import ActionEngine

    r       = redis.Redis(
        host=config["redis"]["host"],
        port=config["redis"]["port"]
    )
    engine  = MitreDetectionEngine()
    actions = ActionEngine(config)

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
            profile, score, breakdown, action = \
                update_user_profile(user, row, config)

            # MITRE detection
            detections = engine.analyze(
                features = row,
                user     = user,
                machine  = row.get("machine","unknown")
            )

            # Log detections
            for d in detections:
                logger.warning(
                    f"[{user}] {d.technique.id} — "
                    f"{d.technique.name} | "
                    f"confidence={d.confidence:.0%} | "
                    f"evidence={', '.join(d.evidence)}"
                )

            # Take action if ready
            if should_act(profile.__dict__, config):
                if detections:
                    top          = detections[0]
                    final_score  = max(score, top.confidence)
                    actions.handle(
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
            else:
                logger.info(
                    f"[{user}] Still in warmup — no action"
                )

        except Exception as e:
            logger.error(f"[{user}] Pipeline error: {e}")
