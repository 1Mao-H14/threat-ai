# profiles/profile_store.py
import redis
import json
import pickle
import logging
from datetime import datetime, timezone

logger = logging.getLogger("ProfileStore")


class ProfileStore:

    def __init__(self, config: dict):
        self.r = redis.Redis(
            host=config["redis"]["host"],
            port=config["redis"]["port"]
        )

    # ── USER PROFILE ──────────────────────────
    def save_profile(self, user: str, profile: dict):
        self.r.set(f"profile:{user}", json.dumps(profile))

    def load_profile(self, user: str) -> dict | None:
        data = self.r.get(f"profile:{user}")
        return json.loads(data) if data else None

    def create_profile(self, user: str) -> dict:
        profile = {
            "user":            user,
            "created_at":      datetime.now(timezone.utc).isoformat(),
            "last_updated":    datetime.now(timezone.utc).isoformat(),
            "warmup":          True,
            "total_hours":     0,
            "current_score":   0.0,
            "score_trend":     "stable",
            "last_action":     "none",
            "feature_history": [],
            "score_history":   [],
            "incidents":       [],
        }
        self.save_profile(user, profile)
        logger.info(f"[{user}] Profile created")
        return profile

    def load_or_create(self, user: str) -> dict:
        profile = self.load_profile(user)
        if not profile:
            profile = self.create_profile(user)
        return profile

    # ── SCORE HISTORY ─────────────────────────
    def push_score(self, user: str, score: float, ts: str):
        profile = self.load_profile(user)
        if not profile:
            return
        profile["score_history"].append({
            "score": score,
            "ts":    ts
        })
        # Keep last 720 scores (30 days)
        profile["score_history"] = profile["score_history"][-720:]
        self.save_profile(user, profile)

    # ── MODEL ─────────────────────────────────
    def save_model(self, user: str, model):
        self.r.set(f"model:{user}", pickle.dumps(model))

    def load_model(self, user: str):
        data = self.r.get(f"model:{user}")
        return pickle.loads(data) if data else None

    # ── ALL USERS ─────────────────────────────
    def get_all_users(self) -> list:
        keys = self.r.keys("profile:*")
        return [k.decode().split(":",1)[1] for k in keys]
