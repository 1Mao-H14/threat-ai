# actions/action_engine.py
import msal
import requests
import logging
from datetime import datetime, timezone

logger = logging.getLogger("ActionEngine")


class ActionEngine:

    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, config: dict):
        self.config        = config
        self.tenant_id     = config["entra_id"]["tenant_id"]
        self.client_id     = config["entra_id"]["client_id"]
        self.client_secret = config["entra_id"]["client_secret"]
        self.domain        = config["entra_id"]["domain"]
        self.webhook       = config["actions"]["noc_webhook"]
        self.alert_thresh  = config["scoring"]["alert_threshold"]
        self.mfa_thresh    = config["scoring"]["mfa_threshold"]
        self.block_thresh  = config["scoring"]["block_threshold"]

    def handle(
        self,
        user:      str,
        score:     float,
        row:       dict,
        breakdown: dict
    ) -> dict:
        """
        Executes the action AND returns a confirmation dict describing
        what actually happened — not just what was intended. This is
        what the report shows under "Confirmation", distinct from the
        generic "Action prévue" label.

        Returns:
            {
                "action":  "block" | "mfa" | "alert" | "none",
                "success": bool,   # did the underlying API call succeed?
                "detail":  str,    # human-readable confirmation or failure
            }
        """
        logger.info(
            f"[{user}] score={score:.3f} "
            f"technique={breakdown.get('technique','unknown')}"
        )

        if score >= self.block_thresh:
            blocked = self._block(user, score, breakdown)
            revoked = self._revoke_sessions(user)
            self._alert_noc(user, score, breakdown, "CRITICAL")
            return {
                "action":  "block",
                "success": blocked,
                "detail": (
                    "Compte bloqué et sessions révoquées (Azure AD HTTP 204)"
                    if blocked and revoked else
                    f"Échec partiel — blocage={blocked}, révocation={revoked}. Voir logs ActionEngine."
                ),
            }

        elif score >= self.mfa_thresh:
            revoked = self._revoke_sessions(user)
            self._alert_noc(user, score, breakdown, "HIGH")
            return {
                "action":  "mfa",
                "success": revoked,
                "detail": (
                    "Sessions révoquées — réauthentification MFA forcée (Azure AD HTTP 200)"
                    if revoked else
                    "Échec de révocation des sessions. Voir logs ActionEngine."
                ),
            }

        elif score >= self.alert_thresh:
            self._alert_noc(user, score, breakdown, "MEDIUM")
            return {
                "action":  "alert",
                "success": True,
                "detail":  "Alerte envoyée au NOC — aucune action automatique sur le compte",
            }

        return {
            "action":  "none",
            "success": True,
            "detail":  "Aucune action requise — score sous le seuil d'alerte",
        }

    # ── GET TOKEN ─────────────────────────────
    def _get_token(self) -> str:
        app    = msal.ConfidentialClientApplication(
            self.client_id,
            authority         = f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential = self.client_secret
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        return result["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # ── GET USER ID ───────────────────────────
    def _get_user_id(self, user: str) -> str | None:
        upn = f"{user}@{self.domain}"
        try:
            r = requests.get(
                f"{self.GRAPH}/users/{upn}",
                headers=self._headers()
            )
            if r.status_code == 200:
                return r.json()["id"]
            else:
                logger.error(
                    f"Get user ID failed for '{upn}': "
                    f"HTTP {r.status_code} — {r.text}"
                )
        except Exception as e:
            logger.error(f"Get user ID error for '{upn}': {e}")
        return None

    # ── BLOCK USER — now returns bool ─────────
    def _block(self, user: str, score: float, breakdown: dict) -> bool:
        if not self.config["actions"].get("block_users", True):
            logger.info(f"[{user}] block_users disabled in config — skipped")
            return False

        uid = self._get_user_id(user)
        if not uid:
            return False

        try:
            r = requests.patch(
                f"{self.GRAPH}/users/{uid}",
                headers = {**self._headers(),
                           "Content-Type": "application/json"},
                json    = {"accountEnabled": False}
            )
            if r.status_code == 204:
                logger.warning(
                    f"[{user}] ACCOUNT BLOCKED "
                    f"score={score:.3f}"
                )
                return True
            else:
                logger.error(f"Block failed: {r.text}")
                return False
        except Exception as e:
            logger.error(f"Block error: {e}")
            return False

    # ── REVOKE SESSIONS — now returns bool ────
    def _revoke_sessions(self, user: str) -> bool:
        if not self.config["actions"].get("force_mfa", True):
            logger.info(f"[{user}] force_mfa disabled in config — skipped")
            return False

        uid = self._get_user_id(user)
        if not uid:
            return False

        try:
            r = requests.post(
                f"{self.GRAPH}/users/{uid}/revokeSignInSessions",
                headers=self._headers()
            )
            if r.status_code == 200:
                logger.warning(
                    f"[{user}] SESSIONS REVOKED — MFA forced"
                )
                return True
            else:
                logger.error(f"Revoke failed: {r.text}")
                return False
        except Exception as e:
            logger.error(f"Revoke error: {e}")
            return False

    # ── ALERT NOC ─────────────────────────────
    def _alert_noc(
        self,
        user:      str,
        score:     float,
        breakdown: dict,
        level:     str
    ):
        if not self.webhook:
            logger.info(f"[{user}] NOC webhook not configured — skipped")
            return

        payload = {
            "alert_level":   level,
            "user":          user,
            "threat_score":  round(score, 3),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "technique":     breakdown.get("technique","unknown"),
            "tactic":        breakdown.get("tactic","unknown"),
            "evidence":      breakdown.get("evidence",[]),
            "action_taken":  (
                "BLOCKED"        if score >= self.block_thresh else
                "MFA FORCED"     if score >= self.mfa_thresh   else
                "ALERT ONLY"
            )
        }

        try:
            r = requests.post(
                self.webhook,
                json    = payload,
                timeout = 10
            )
            logger.info(
                f"[{user}] NOC alerted — "
                f"{level} (HTTP {r.status_code})"
            )
        except Exception as e:
            logger.error(f"NOC alert error: {e}")
