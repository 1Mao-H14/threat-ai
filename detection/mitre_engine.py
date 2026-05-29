# detection/mitre_engine.py
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging

logger = logging.getLogger("MitreEngine")


@dataclass
class Technique:
    id:          str
    name:        str
    tactic:      str
    severity:    float
    description: str


@dataclass
class Detection:
    technique:  Technique
    confidence: float
    evidence:   list
    timestamp:  str
    user:       str
    action:     str


TECHNIQUES = {
    "T1003": Technique(
        id="T1003", name="OS Credential Dumping",
        tactic="Credential Access",
        severity=0.95,
        description="lsass.exe access detected"
    ),
    "T1110": Technique(
        id="T1110", name="Brute Force",
        tactic="Initial Access",
        severity=0.75,
        description="Multiple failed login attempts"
    ),
    "T1059": Technique(
        id="T1059", name="Command and Scripting",
        tactic="Execution",
        severity=0.75,
        description="Suspicious command execution"
    ),
    "T1059.001": Technique(
        id="T1059.001", name="PowerShell",
        tactic="Execution",
        severity=0.80,
        description="Encoded PowerShell command detected"
    ),
    "T1547": Technique(
        id="T1547", name="Boot Autostart Execution",
        tactic="Persistence",
        severity=0.80,
        description="Registry Run key modified"
    ),
    "T1078": Technique(
        id="T1078", name="Valid Accounts",
        tactic="Initial Access",
        severity=0.70,
        description="Suspicious use of valid credentials"
    ),
    "T1078.002": Technique(
        id="T1078.002", name="Domain Accounts",
        tactic="Privilege Escalation",
        severity=0.90,
        description="User added to privileged group"
    ),
    "T1562": Technique(
        id="T1562", name="Impair Defenses",
        tactic="Defense Evasion",
        severity=0.90,
        description="Security policy changed"
    ),
    "T1021": Technique(
        id="T1021", name="Remote Services",
        tactic="Lateral Movement",
        severity=0.85,
        description="Access to multiple machines detected"
    ),
    "T1486": Technique(
        id="T1486", name="Data Encrypted for Impact",
        tactic="Impact",
        severity=0.99,
        description="Ransomware pattern detected"
    ),
    "T1071": Technique(
        id="T1071", name="Application Layer Protocol",
        tactic="Command and Control",
        severity=0.85,
        description="C2 communication pattern detected"
    ),
    "T1041": Technique(
        id="T1041", name="Exfiltration Over C2",
        tactic="Exfiltration",
        severity=0.90,
        description="Large data transfer to external IP"
    ),
}


class MitreDetectionEngine:

    def analyze(
        self,
        features: dict,
        user:     str,
        machine:  str
    ) -> list[Detection]:

        ts         = datetime.now(timezone.utc).isoformat()
        detections = []

        checks = [
            self._check_credential_dump,
            self._check_brute_force,
            self._check_execution,
            self._check_persistence,
            self._check_privilege_escalation,
            self._check_defense_evasion,
            self._check_lateral_movement,
            self._check_ransomware,
            self._check_c2,
            self._check_valid_accounts,
        ]

        for check in checks:
            result = check(features, user, machine, ts)
            if result:
                detections.append(result)

        detections.sort(
            key=lambda x: x.confidence,
            reverse=True
        )
        return detections

    # ── T1003 — Credential Dumping ────────────
    def _check_credential_dump(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("lsass_access", 0) > 0:
            confidence += 0.7
            evidence.append("lsass.exe accessed")

        if f.get("lsass_dump_score", 0) > 0:
            confidence += 0.3
            evidence.append("Credential dump access mask")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1003"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "block"
            )

    # ── T1110 — Brute Force ───────────────────
    def _check_brute_force(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0
        failed     = f.get("failed_logins", 0)

        if failed >= 10:
            confidence += 0.8
            evidence.append(f"{failed} failed logins")
        elif failed >= 5:
            confidence += 0.5
            evidence.append(f"{failed} failed logins")

        if f.get("signin_count", 0) > 0 and failed > 0:
            confidence += 0.1
            evidence.append("Success after failures")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1110"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "mfa" if confidence < 0.8 else "block"
            )

    # ── T1059 — Command Execution ─────────────
    def _check_execution(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("encoded_cmds", 0) > 0:
            confidence += 0.6
            evidence.append("Encoded PowerShell detected")

        if f.get("has_download_cmd", 0) > 0:
            confidence += 0.4
            evidence.append("Download command detected")

        if f.get("suspicious_pairs", 0) > 0:
            confidence += 0.3
            evidence.append("Suspicious process pair")

        if confidence > 0:
            technique = TECHNIQUES["T1059.001"] \
                if f.get("encoded_cmds") \
                else TECHNIQUES["T1059"]
            return Detection(
                technique  = technique,
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "alert" if confidence < 0.7 else "mfa"
            )

    # ── T1547 — Persistence ───────────────────
    def _check_persistence(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("persistence_keys", 0) > 0:
            confidence += 0.7
            evidence.append("Registry Run key modified")

        if f.get("suspicious_writes", 0) > 0:
            confidence += 0.3
            evidence.append("Executable in suspicious path")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1547"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "alert" if confidence < 0.8 else "block"
            )

    # ── T1078.002 — Privilege Escalation ──────
    def _check_privilege_escalation(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("group_change", 0) > 0:
            confidence += 0.6
            evidence.append("Added to privileged group")

        if f.get("role_assigned", 0) > 0:
            confidence += 0.5
            evidence.append("New role assigned")

        if f.get("elevated_procs", 0) > 3:
            confidence += 0.2
            evidence.append("Multiple elevated processes")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1078.002"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "alert" if confidence < 0.7 else "block"
            )

    # ── T1562 — Defense Evasion ───────────────
    def _check_defense_evasion(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("policy_changed", 0) > 0:
            confidence += 0.8
            evidence.append("Audit policy changed")

        if f.get("mfa_changed", 0) > 0:
            confidence += 0.6
            evidence.append("MFA method changed")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1562"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "block"
            )

    # ── T1021 — Lateral Movement ──────────────
    def _check_lateral_movement(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("signin_count", 0) > 3:
            confidence += 0.4
            evidence.append("Multiple machine logins")

        if f.get("is_off_hours_login") and \
           f.get("signin_count", 0) > 1:
            confidence += 0.3
            evidence.append("Off hours multi-machine access")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1021"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "mfa" if confidence < 0.8 else "block"
            )

    # ── T1486 — Ransomware ────────────────────
    def _check_ransomware(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("extension_changes", 0) > 0:
            confidence += 0.6
            evidence.append("File extensions changed")

        if f.get("backup_deletion", 0) > 0:
            confidence += 0.4
            evidence.append("Shadow copy deletion")

        if f.get("persistence_keys", 0) > 0 and \
           f.get("extension_changes", 0) > 0:
            confidence += 0.2
            evidence.append("Persistence + file encryption")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1486"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "block"
            )

    # ── T1071 — C2 Communication ──────────────
    def _check_c2(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("suspicious_ports", 0) > 0:
            confidence += 0.5
            evidence.append("Connection on suspicious port")

        if f.get("external_conns", 0) > 10 and \
           f.get("is_off_hours"):
            confidence += 0.3
            evidence.append("High external traffic off hours")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1071"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "alert" if confidence < 0.7 else "block"
            )

    # ── T1078 — Valid Accounts ────────────────
    def _check_valid_accounts(self, f, user, machine, ts):
        evidence   = []
        confidence = 0.0

        if f.get("is_off_hours_login") and \
           f.get("signin_count", 0) > 0:
            confidence += 0.4
            evidence.append("Login outside normal hours")

        if f.get("risk_level_max", 0) >= 2:
            confidence += 0.4
            evidence.append("High risk login detected")

        if confidence > 0:
            return Detection(
                technique  = TECHNIQUES["T1078"],
                confidence = min(confidence, 1.0),
                evidence   = evidence,
                timestamp  = ts,
                user       = user,
                action     = "mfa" if confidence < 0.7 else "alert"
            )
