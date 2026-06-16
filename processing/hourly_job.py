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


def should_act(profile, config):
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
            if should_act(profile, config):
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


def log_user_status(user: str, row: dict, score: float,
                    detections: list, action: str):
    """
    Prints full visible status of user to terminal.
    Will be used for dashboard later.
    """
    print("\n" + "="*60)
    print(f"  USER REPORT: {user.upper()}")
    print("="*60)

    # Score with visual bar
    bar_length = 30
    filled     = int(score * bar_length)
    bar        = "█" * filled + "░" * (bar_length - filled)
    color      = (
        "\033[31m" if score >= 0.85 else
        "\033[33m" if score >= 0.70 else
        "\033[32m" if score >= 0.50 else
        "\033[36m"
    )
    print(f"\n  THREAT SCORE: {color}{bar} {score:.2f}\033[0m")

    # Status
    status = (
        "🔴 CRITICAL" if score >= 0.85 else
        "🟠 HIGH"     if score >= 0.70 else
        "🟡 MEDIUM"   if score >= 0.50 else
        "🟢 NORMAL"
    )
    print(f"  STATUS: {status}")
    print(f"  ACTION: {action.upper()}")

    # Key features
    print("\n  KEY SIGNALS:")
    signals = {
        "Failed Logins":       row.get("failed_logins", 0),
        "Suspicious Pairs":    row.get("suspicious_pairs", 0),
        "Encoded Commands":    row.get("encoded_cmds", 0),
        "LSASS Access":        row.get("lsass_access", 0),
        "Persistence Keys":    row.get("persistence_keys", 0),
        "External Conns":      row.get("external_conns", 0),
        "Suspicious Ports":    row.get("suspicious_ports", 0),
        "Extension Changes":   row.get("extension_changes", 0),
        "Off Hours Login":     row.get("is_off_hours_login", 0),
        "Group Changes":       row.get("group_change", 0),
    }
    for signal, value in signals.items():
        if value:
            print(f"    ⚠️  {signal}: {value}")

    # MITRE detections
    if detections:
        print("\n  MITRE ATT&CK DETECTIONS:")
        for d in detections:
            conf_bar = "█" * int(d.confidence * 10)
            print(f"    [{d.technique.id}] {d.technique.name}")
            print(f"      Tactic:     {d.technique.tactic}")
            print(f"      Confidence: {conf_bar} {d.confidence:.0%}")
            print(f"      Evidence:   {', '.join(d.evidence)}")
    else:
        print("\n  MITRE ATT&CK: No techniques detected")

    # Entra ID info
    print("\n  ENTRA ID ACTIVITY:")
    print(f"    Logins this window:  {row.get('signin_count', 0)}")
    print(f"    Failed logins:       {row.get('failed_logins', 0)}")
    print(f"    MFA used:            {bool(row.get('mfa_used', 0))}")
    print(f"    Off hours login:     {bool(row.get('is_off_hours_login', 0))}")
    print(f"    Risk level:          {row.get('risk_level_max', 0)}")

    # Sysmon info
    print("\n  ENDPOINT ACTIVITY:")
    print(f"    Processes started:   {row.get('process_count', 0)}")
    print(f"    Network connections: {row.get('net_count', 0)}")
    print(f"    File writes:         {row.get('file_writes', 0)}")
    print(f"    Registry writes:     {row.get('registry_writes', 0)}")

    print("="*60 + "\n")
