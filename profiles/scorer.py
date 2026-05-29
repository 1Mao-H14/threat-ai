# profiles/scorer.py
import numpy as np
import logging
from profiles.profile_store import ProfileStore

logger = logging.getLogger("Scorer")

MIN_ZSCORE   = 10    # rows needed for z-score
MIN_ISO      = 72    # rows needed for isolation forest

WEIGHTS = {
    # CRITICAL
    "lsass_access":      1.0,
    "lsass_dump_score":  1.0,
    "policy_changed":    0.95,
    "backup_deletion":   0.95,

    # HIGH
    "suspicious_pairs":  0.85,
    "encoded_cmds":      0.85,
    "role_assigned":     0.85,
    "group_change":      0.80,
    "download_cmds":     0.75,

    # MEDIUM
    "failed_logins":     0.65,
    "is_off_hours_login":0.60,
    "suspicious_ports":  0.60,
    "persistence_keys":  0.65,
    "extension_changes": 0.70,
    "suspicious_writes": 0.65,

    # LOW
    "external_conns":    0.40,
    "elevated_procs":    0.35,
    "registry_writes":   0.25,
    "process_count":     0.20,
}

DECAY_PER_CLEAN = 0.05


class Scorer:

    def __init__(self, config: dict):
        self.config = config
        self.store  = ProfileStore(config)

    def compute(
        self,
        row:     dict,
        profile: dict
    ) -> tuple[float, dict]:
        history = profile.get("feature_history", [])
        n       = len(history)

        if n < MIN_ZSCORE:
            return self._rule_based(row)
        elif n < MIN_ISO:
            return self._zscore(row, history)
        else:
            return self._isolation_forest(
                row, history, profile["user"]
            )

    # ── METHOD 1: RULE BASED ──────────────────
    def _rule_based(
        self, row: dict
    ) -> tuple[float, dict]:
        breakdown = {}
        total     = 0.0

        for feature, weight in WEIGHTS.items():
            val = float(row.get(feature, 0))
            if val > 0:
                contribution         = min(val, 1.0) * weight
                breakdown[feature]   = round(contribution, 4)
                total               += contribution

        score = min(total / sum(WEIGHTS.values()), 1.0)
        return round(score, 4), breakdown

    # ── METHOD 2: Z-SCORE ─────────────────────
    def _zscore(
        self,
        row:     dict,
        history: list
    ) -> tuple[float, dict]:
        breakdown = {}
        scores    = []

        for feature, weight in WEIGHTS.items():
            vals = [float(h.get(feature, 0)) for h in history]
            mean = np.mean(vals)
            std  = max(np.std(vals), 0.1)
            curr = float(row.get(feature, 0))
            z    = (curr - mean) / std

            if z > 1.5:
                contribution       = min(z / 5.0, 1.0) * weight
                breakdown[feature] = round(contribution, 4)
                scores.append(contribution)

        score = min(
            sum(scores) / sum(WEIGHTS.values()), 1.0
        ) if scores else 0.0
        return round(score, 4), breakdown

    # ── METHOD 3: ISOLATION FOREST ────────────
    def _isolation_forest(
        self,
        row:     dict,
        history: list,
        user:    str
    ) -> tuple[float, dict]:
        from sklearn.ensemble import IsolationForest

        model = self.store.load_model(user)

        if model is None or len(history) % 24 == 0:
            X     = np.array([
                [float(h.get(f, 0)) for f in WEIGHTS.keys()]
                for h in history
            ])
            model = IsolationForest(
                n_estimators=100,
                contamination=0.02,
                random_state=42
            )
            model.fit(X)
            self.store.save_model(user, model)
            logger.info(
                f"[{user}] Model retrained "
                f"on {len(history)} samples"
            )

        vec   = np.array([
            [float(row.get(f, 0)) for f in WEIGHTS.keys()]
        ])
        raw   = model.decision_function(vec)[0]
        score = float(1.0 / (1.0 + np.exp(5 * raw)))

        _, breakdown = self._zscore(row, history)
        return round(score, 4), breakdown

    # ── DECAY ─────────────────────────────────
    def apply_decay(
        self,
        current_score: float,
        new_score:     float
    ) -> float:
        if new_score < 0.3:
            decayed = current_score - DECAY_PER_CLEAN
            return max(decayed, new_score)
        else:
            return max(
                current_score * 0.85 + new_score * 0.15,
                new_score
            )
