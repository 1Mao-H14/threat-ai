# profiles/profile_updater.py
import logging
from datetime import datetime, timezone
from profiles.profile_store import ProfileStore
from profiles.scorer        import Scorer

logger = logging.getLogger("ProfileUpdater")

MAX_HISTORY  = 720    # 30 days hourly rows
MAX_SCORES   = 720


def update_user_profile(
    user:    str,
    row:     dict,
    config:  dict
):
    store   = ProfileStore(config)
    scorer  = Scorer(config)
    profile = store.load_or_create(user)
    now_ts  = datetime.now(timezone.utc).isoformat()

    # ── COMPUTE SCORE ─────────────────────────
    hour_score, breakdown = scorer.compute(row, profile)

    # ── UPDATE RUNNING SCORE ──────────────────
    previous           = profile["current_score"]
    running_score      = scorer.apply_decay(previous, hour_score)
    profile["current_score"] = round(running_score, 4)

    # ── SCORE TREND ───────────────────────────
    if   running_score > previous + 0.05:
        profile["score_trend"] = "rising"
    elif running_score < previous - 0.05:
        profile["score_trend"] = "falling"
    else:
        profile["score_trend"] = "stable"

    # ── UPDATE HISTORY ────────────────────────
    profile["total_hours"] += 1
    profile["score_history"].append({
        "ts":    now_ts,
        "score": hour_score
    })
    profile["score_history"] = profile["score_history"][-MAX_SCORES:]

    # Only add clean rows to feature history
    if hour_score < 0.5:
        profile["feature_history"].append(row)
        profile["feature_history"] = \
            profile["feature_history"][-MAX_HISTORY:]

    # ── CHECK WARMUP ──────────────────────────
    warmup_hours = config["scoring"]["warmup_hours"]
    if profile["warmup"] and profile["total_hours"] >= warmup_hours:
        profile["warmup"] = False
        logger.info(f"[{user}] Warmup complete — monitoring ON")

    profile["last_updated"] = now_ts

    # ── SAVE ──────────────────────────────────
    store.save_profile(user, profile)
    store.push_score(user, hour_score, now_ts)

    logger.info(
        f"[{user}] "
        f"score={hour_score:.3f} | "
        f"running={running_score:.3f} | "
        f"trend={profile['score_trend']} | "
        f"warmup={profile['warmup']} | "
        f"history={len(profile['feature_history'])}h"
    )

    return profile, hour_score, breakdown, profile["last_action"]
