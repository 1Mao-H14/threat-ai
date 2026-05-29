# collectors/entraid_collector.py
import msal
import requests
import time
import logging
from datetime import datetime, timezone, timedelta
from collectors.smart_buffer import SmartBuffer

logger = logging.getLogger("EntraIDCollector")


class EntraIDCollector:

    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, config: dict):
        self.config        = config
        self.tenant_id     = config["entra_id"]["tenant_id"]
        self.client_id     = config["entra_id"]["client_id"]
        self.client_secret = config["entra_id"]["client_secret"]
        self.poll_interval = config["entra_id"]["poll_interval"]
        self.buffer        = SmartBuffer(config)
        self.last_poll     = datetime.now(timezone.utc) - timedelta(minutes=2)
        self._token        = None
        self._token_expiry = None

    # ── AUTH ──────────────────────────────────
    def _get_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._token and now < self._token_expiry:
            return self._token

        app    = msal.ConfidentialClientApplication(
            self.client_id,
            authority      = f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential = self.client_secret
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        self._token        = result["access_token"]
        self._token_expiry = now + timedelta(
            seconds=result["expires_in"] - 60
        )
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # ── FETCH USERS (auto-discovery) ──────────
    def fetch_users(self) -> list:
        """
        Reads all users from Entra ID automatically.
        No manual configuration needed.
        """
        r = requests.get(
            f"{self.GRAPH}/users"
            f"?$select=id,displayName,userPrincipalName,department,jobTitle",
            headers=self._headers()
        )
        return r.json().get("value", [])

    # ── FETCH SIGNIN LOGS ─────────────────────
    def _fetch_signins(self, since: str) -> list:
        r = requests.get(
            f"{self.GRAPH}/auditLogs/signIns"
            f"?$filter=createdDateTime ge {since}"
            f"&$top=100",
            headers=self._headers()
        )
        return r.json().get("value", [])

    # ── FETCH AUDIT LOGS ──────────────────────
    def _fetch_audits(self, since: str) -> list:
        r = requests.get(
            f"{self.GRAPH}/auditLogs/directoryAudits"
            f"?$filter=activityDateTime ge {since}"
            f"&$top=100",
            headers=self._headers()
        )
        return r.json().get("value", [])

    # ── PARSE SIGNIN ──────────────────────────
    def _parse_signin(self, log: dict) -> dict:
        ts  = log.get("createdDateTime", "")
        dt  = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        loc = log.get("location", {})
        dev = log.get("deviceDetail", {})

        RISK_MAP = {"none":0,"low":1,"medium":2,"high":3}

        return {
            "source":        "entra_id",
            "log_type":      "entra_signin",
            "timestamp":     ts,
            "user":          log.get("userPrincipalName","").split("@")[0].lower(),
            "features": {
                "login_success":    int(log.get("status",{}).get("errorCode",1) == 0),
                "failed_login":     int(log.get("status",{}).get("errorCode",1) != 0),
                "mfa_used":         int(log.get("authenticationRequirement","") == "multiFactorAuthentication"),
                "is_legacy_auth":   int(log.get("clientAppUsed","").lower() in ["smtp","imap","pop3"]),
                "risk_level":       RISK_MAP.get(log.get("riskLevelAggregated","none").lower(), 0),
                "is_off_hours":     int(dt.hour < 7 or dt.hour > 20),
                "is_weekend":       int(dt.weekday() >= 5),
                "country":          loc.get("countryOrRegion","unknown"),
                "device_compliant": int(dev.get("isCompliant", False)),
                "hour_of_day":      dt.hour,
            }
        }

    # ── PARSE AUDIT ───────────────────────────
    def _parse_audit(self, log: dict) -> dict:
        ts       = log.get("activityDateTime", "")
        activity = log.get("activityDisplayName","").lower()
        targets  = log.get("targetResources", [])
        actor    = log.get("initiatedBy",{}).get("user",{})

        try:
            dt   = datetime.fromisoformat(ts.replace("Z","+00:00"))
            hour = dt.hour
        except:
            hour = 0

        return {
            "source":    "entra_id",
            "log_type":  "entra_audit",
            "timestamp": ts,
            "user":      actor.get("userPrincipalName","").split("@")[0].lower(),
            "features": {
                "is_group_change":   int("member" in activity),
                "is_role_assigned":  int("role" in activity),
                "is_password_reset": int("password" in activity),
                "is_policy_changed": int("policy" in activity),
                "is_mfa_changed":    int("authentication method" in activity),
                "is_user_created":   int("add user" in activity),
                "is_user_deleted":   int("delete user" in activity),
                "is_off_hours":      int(hour < 7 or hour > 20),
                "hour_of_day":       hour,
            }
        }

    # ── MAIN LOOP ─────────────────────────────
    def run(self):
        logger.info("Entra ID Collector started")

        # Auto discover users at startup
        users = self.fetch_users()
        logger.info(f"Entra ID: {len(users)} users discovered")
        for u in users:
            logger.info(
                f"  → {u.get('userPrincipalName','')} "
                f"dept={u.get('department','unknown')}"
            )

        while True:
            try:
                since = self.last_poll.strftime("%Y-%m-%dT%H:%M:%SZ")
                now   = datetime.now(timezone.utc)

                # Signins
                signins = self._fetch_signins(since)
                logger.info(f"EntraID: {len(signins)} signins")
                for log in signins:
                    self.buffer.push(self._parse_signin(log))

                # Audits
                audits = self._fetch_audits(since)
                logger.info(f"EntraID: {len(audits)} audits")
                for log in audits:
                    self.buffer.push(self._parse_audit(log))

                self.last_poll = now

            except Exception as e:
                logger.error(f"EntraID error: {e}")

            time.sleep(self.poll_interval)
