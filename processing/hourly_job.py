# processing/hourly_job.py
"""
Scheduled pipeline: buffered events -> aggregated row -> score ->
MITRE detections -> action execution -> report dispatch (push + HTML).

Run every minute by APScheduler (see main.py).

MFA escalation watch (new):
  When ActionEngine forces MFA (session revoke), a watch is recorded
  in Redis. On every following pipeline run, regardless of whether
  that user has any new buffered events:
    - a successful MFA sign-in -> watch resolved silently, no report
      (expected good outcome).
    - scoring.mfa_failed_attempts_threshold (default 3) failed sign-in
      attempts accumulate -> ESCALATE immediately: force a real
      account block and dispatch a CRITICAL report.
    - if neither happens before scoring.mfa_reauth_window_mins elapses
      (default 15) -> ESCALATE as a backstop, covering a user who goes
      silent entirely rather than one who keeps actively failing.

Action cooldown vs report cooldown:
  action_cooldown_mins (in this file) gates whether the SAME user +
  technique re-triggers actions.handle() again at all. It is checked
  BEFORE acting, so a persistent low-grade detection does not
  re-execute MFA-force / block every single cycle.
  report_cooldown_mins (in reporting/report_dispatcher.py) separately
  gates duplicate report sends for the same user + technique. The
  first occurrence of any technique always produces a report; only
  repeats within the cooldown window are suppressed.
"""

import json
import logging
import redis
from datetime import datetime, timezone, timedelta

from detection.mitre_engine import Technique

logger = logging.getLogger("Pipeline")

MFA_FAILURE_TECHNIQUE = Technique(
    id="ZTA-MFA-FAIL",
    name="Echec de reauthentification apres MFA force",
    tactic="Credential Access",
    severity=0.95,
    description=(
        "L'utilisateur n'a pas complete une reauthentification MFA "
        "reussie dans le delai imparti apres la revocation forcee "
        "de ses sessions."
    ),
)


def get_active_users(r) -> list:
    keys = r.keys("buffer:*")
    return [k.decode().split(":", 1)[1] for k in keys]


def get_pending_mfa_users(r) -> list:
    keys = r.keys("mfa_pending:*")
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
    machines = {e.get("machine") for e in events if e.get("machine")}
    return len(machines) or 1


# ── ACTION COOLDOWN (gates re-running the same action) ───────────────

def _action_cooldown_key(user: str, technique_id: str) -> str:
    return f"action_cooldown:{user}:{technique_id}"


def _on_action_cooldown(r, user: str, technique_id: str) -> bool:
    return bool(r.exists(_action_cooldown_key(user, technique_id)))


def _set_action_cooldown(r, user: str, technique_id: str, minutes: int):
    r.set(_action_cooldown_key(user, technique_id), "1", ex=minutes * 60)


# ── MFA ESCALATION WATCH ──────────────────────────────────────────────

def _mfa_pending_key(user: str) -> str:
    return f"mfa_pending:{user}"


def _set_mfa_pending(r, user: str, technique_id: str, technique_name: str,
                      row: dict, breakdown: dict, window_minutes: int):
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=window_minutes)).isoformat()
    payload = {
        "set_at":         datetime.now(timezone.utc).isoformat(),
        "deadline":       deadline,
        "technique_id":   technique_id,
        "technique_name": technique_name,
        "row":            row,
        "breakdown":      breakdown,
        "failed_attempts": 0,
    }
    # No TTL here on purpose: expiry is checked explicitly against the
    # stored deadline so the escalation logic can still see and act on
    # it at the moment it expires, instead of the key silently vanishing.
    r.set(_mfa_pending_key(user), json.dumps(payload))


def _save_mfa_pending(r, user: str, pending: dict):
    r.set(_mfa_pending_key(user), json.dumps(pending))


def _get_mfa_pending(r, user: str) -> dict | None:
    raw = r.get(_mfa_pending_key(user))
    if not raw:
        return None
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


def _clear_mfa_pending(r, user: str):
    r.delete(_mfa_pending_key(user))


def _mfa_reauth_succeeded(row: dict) -> bool:
    """A successful, MFA-backed sign-in in this window counts as resolution."""
    return row.get("signin_count", 0) > 0 and row.get("mfa_used", 0) > 0


def _handle_mfa_watch(r, user: str, row: dict | None, config: dict,
                       actions, dispatcher) -> None:
    """
    Called once per user per cycle, for EVERY user with a pending MFA
    watch, regardless of whether they have new buffered events this
    cycle (a user who has gone silent and never reauthenticates would
    never appear in get_active_users() again otherwise).

    Escalation triggers (either one fires a real block + report):
      1. COUNT: scoring.mfa_failed_attempts_threshold (default 3) failed
         sign-in attempts accumulate while the watch is active. This is
         the primary trigger, an actively repeated failure is the
         strongest signal.
      2. TIME (backstop only): the watch deadline passes with zero
         signal either way, no successes, but also no failed attempts
         building toward the count. Covers a user who simply never
         shows up again rather than one who keeps actively failing.
    """
    pending = _get_mfa_pending(r, user)
    if not pending:
        return

    threshold = config["scoring"].get("mfa_failed_attempts_threshold", 3)

    if row is not None:
        if _mfa_reauth_succeeded(row):
            logger.info(f"[{user}] MFA reauthentication succeeded — watch resolved")
            _clear_mfa_pending(r, user)
            return

        new_failed = row.get("failed_logins", 0)
        if new_failed > 0:
            pending["failed_attempts"] = pending.get("failed_attempts", 0) + new_failed
            _save_mfa_pending(r, user, pending)
            logger.info(
                f"[{user}] failed reauth attempt(s) +{new_failed} "
                f"(total {pending['failed_attempts']}/{threshold})"
            )

        if pending["failed_attempts"] >= threshold:
            _escalate_mfa_failure(
                r, user, pending, config, actions, dispatcher,
                reason=f"{pending['failed_attempts']} tentatives de connexion "
                       f"echouees apres la revocation de session MFA",
            )
            return

    deadline = datetime.fromisoformat(pending["deadline"])
    if datetime.now(timezone.utc) < deadline:
        return  # still within the grace window, keep waiting

    _escalate_mfa_failure(
        r, user, pending, config, actions, dispatcher,
        reason="Delai de reauthentification MFA expire sans succes "
               f"({pending.get('failed_attempts', 0)} echec(s) observe(s))",
    )


def _escalate_mfa_failure(r, user: str, pending: dict, config: dict,
                           actions, dispatcher, reason: str) -> None:
    logger.warning(
        f"[{user}] MFA escalation triggered ({reason}) "
        f"original technique: {pending['technique_id']} — forcing BLOCK"
    )

    action_result = actions.handle(
        user      = user,
        score     = 1.0,  # force the block branch regardless of configured thresholds
        row       = pending["row"],
        breakdown = {
            "technique": MFA_FAILURE_TECHNIQUE.id,
            "name":      MFA_FAILURE_TECHNIQUE.name,
            "tactic":    MFA_FAILURE_TECHNIQUE.tactic,
            "evidence":  [reason],
        },
    )
    logger.info(
        f"[{user}] escalation action={action_result['action']} "
        f"success={action_result['success']} — {action_result['detail']}"
    )

    from detection.mitre_engine import Detection
    escalation_detection = Detection(
        technique  = MFA_FAILURE_TECHNIQUE,
        confidence = 1.0,
        evidence   = [
            f"Technique d'origine: {pending['technique_id']} ({pending['technique_name']})",
            reason,
        ],
        timestamp  = datetime.now(timezone.utc).isoformat(),
        user       = user,
        action     = "block",
    )

    dispatcher.dispatch(
        user               = user,
        machine            = pending["row"].get("machine", "unknown"),
        row                = pending["row"],
        score              = 1.0,
        detections         = [escalation_detection],
        feature_breakdown  = pending.get("breakdown", {}),
        action             = action_result["action"],
        incident_overrides = {
            "action_confirmed":          action_result["detail"],
            "action_success":            action_result["success"],
            "vms_touched_this_incident": 1,
        },
    )

    _clear_mfa_pending(r, user)


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

    mfa_reauth_window_mins = config["scoring"].get("mfa_reauth_window_mins", 15)
    action_cooldown_mins   = config["scoring"].get("action_cooldown_mins", 30)

    window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    active_users  = set(get_active_users(r))
    pending_users = set(get_pending_mfa_users(r))
    all_users     = active_users | pending_users

    logger.info(
        f"━━━ Pipeline | {window_start} | "
        f"{len(active_users)} active, {len(pending_users)} awaiting MFA reauth ━━━"
    )

    for user in all_users:
        try:
            row = None

            if user in active_users:
                events = get_and_clear_buffer(r, user)
                if events:
                    logger.info(f"[{user}] {len(events)} events")
                    row = aggregate_to_row(events, user, window_start)

            # ── MFA WATCH: check resolution / escalation first, every cycle ──
            _handle_mfa_watch(r, user, row, config, actions, dispatcher)

            if row is None:
                continue  # pending-only user with no new events this cycle, done

            # Update profile + get score
            profile, score, breakdown, _ = update_user_profile(user, row, config)

            # MITRE detection
            detections = engine.analyze(
                features = row,
                user     = user,
                machine  = row.get("machine", "unknown")
            )

            for d in detections:
                logger.warning(
                    f"[{user}] {d.technique.id} - {d.technique.name} | "
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

            if _on_action_cooldown(r, user, top.technique.id):
                logger.info(
                    f"[{user}] {top.technique.id} action on cooldown "
                    f"({action_cooldown_mins}min) — action skipped"
                )
                continue

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
                f"success={action_result['success']} - "
                f"{action_result['detail']}"
            )

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
                    f"[{user}] HTML reports -> "
                    f"{result.get('executive_html')} | "
                    f"{result.get('technical_html')}"
                )

            _set_action_cooldown(r, user, top.technique.id, action_cooldown_mins)

            # If this action was an MFA force, start watching for reauth.
            if action_result["action"] == "mfa" and action_result["success"]:
                _set_mfa_pending(
                    r, user, top.technique.id, top.technique.name,
                    row, breakdown, mfa_reauth_window_mins,
                )
                logger.info(
                    f"[{user}] MFA reauth watch started, {mfa_reauth_window_mins}min window"
                )

            # If a real block just happened for any reason, any pending
            # MFA watch for this user is now moot.
            if action_result["action"] == "block":
                _clear_mfa_pending(r, user)

        except Exception as e:
            logger.error(f"[{user}] Pipeline error: {e}")
