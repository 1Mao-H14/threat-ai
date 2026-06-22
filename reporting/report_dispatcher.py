# reporting/report_dispatcher.py
"""
Glue layer: builds both report variants, applies per-user per-technique
cooldown, sends a push notification through configured channels, AND
saves full HTML/CSS report pages to disk (the polished version a SOC
analyst or manager opens in a browser).

Architecture:
  - Push notification (email/Slack/Teams/WhatsApp/SMS) = short, plain-text,
    designed to fit a phone screen / chat bubble — built by report_builder.py
  - HTML report file = the full rendered page with charts, severity colours,
    financial breakdown — built by report_html_builder.py, saved under
    reports/<user>/<timestamp>_<severity>_<executive|technical>.html

Per-incident business context override:
  Pass incident_overrides={'vms_touched_this_incident': 3, 'downtime_hours': 6}
  to inject incident-specific numbers without editing config.yml.
  The override dict is merged into config['business_impact'] for this
  dispatch only — the stored config is not mutated.
"""

import os
import json
import copy
import redis
import logging
from datetime import datetime, timezone

from reporting.report_builder import (
    build_executive_report,
    build_technical_report,
    severity_from_score,
)
from reporting.report_html_builder import (
    build_executive_html,
    build_technical_html,
)
from reporting.notifier import ReportNotifier

logger = logging.getLogger("ReportDispatcher")


class ReportDispatcher:

    def __init__(
        self,
        config:         dict,
        channels_path:  str = "reporting/channels.yml",
        html_output_dir:str = "reports",
    ):
        self.config          = config
        self.notifier        = ReportNotifier(channels_path)
        self.cooldown_min    = config.get("scoring", {}).get("report_cooldown_mins", 15)
        # Edge-triggered de-duplication: an alert fires ONCE when a threat
        # first appears, stays silent while the same threat persists, and only
        # re-arms after the threat clears (see clear_incident) or after a long
        # safety window. report_cooldown_mins == 0 disables dedup entirely
        # (used by the test suite so every dispatch sends).
        self.dedup_enabled   = self.cooldown_min > 0
        renotify_hours       = config.get("scoring", {}).get("report_renotify_hours", 6)
        self.renotify_secs   = int(renotify_hours * 3600)
        self.html_output_dir = html_output_dir
        self.r               = redis.Redis(
            host=config["redis"]["host"],
            port=config["redis"]["port"]
        )

    # ── COOLDOWN ──────────────────────────────────────────────────────────

    def _incident_key(self, user: str) -> str:
        return f"incident:active:{user}"

    @staticmethod
    def _fingerprint(detections: list) -> str:
        """Stable identifier for the current threat = top technique id."""
        return detections[0].technique.id if detections else ""

    def _already_alerted(self, user: str, fingerprint: str) -> bool:
        """True if this exact threat is already an active, alerted incident."""
        if not self.dedup_enabled:
            return False
        active = self.r.get(self._incident_key(user))
        active = active.decode() if isinstance(active, bytes) else active
        return active == fingerprint

    def _mark_alerted(self, user: str, fingerprint: str):
        """Record the active incident so repeats of the SAME threat stay silent."""
        if not self.dedup_enabled:
            return
        self.r.set(self._incident_key(user), fingerprint, ex=self.renotify_secs)

    def clear_incident(self, user: str):
        """
        Called by the pipeline when a user shows NO active threat in a window.
        Clears the active-incident marker so a genuinely new occurrence of the
        same threat later will alert again (edge-triggered, not continuous).
        """
        self.r.delete(self._incident_key(user))

    # ── INCIDENT LOG (feeds the live dashboard) ────────────────────────

    def _record_incident(self, user, machine, severity, score, detections,
                         action, action_success, exec_path, tech_path):
        """
        Persist a compact record of every dispatched alert to Redis so the
        dashboard can show recent incidents, per-technique counts, per-machine
        threats and per-user last action — all in real time. Best-effort:
        a logging failure here must never break alerting.
        """
        try:
            top = detections[0]
            rec = {
                "ts":             datetime.now(timezone.utc).isoformat(),
                "user":           user,
                "machine":        machine,
                "severity":       severity,
                "score":          round(float(score), 4),
                "action":         action,
                "action_success": bool(action_success),
                "technique_id":   top.technique.id,
                "technique_name": top.technique.name,
                "tactic":         top.technique.tactic,
                "evidence":       list(top.evidence),
                "techniques":     [d.technique.id for d in detections],
                "exec_html":      exec_path,
                "tech_html":      tech_path,
            }
            # Domain-wide rolling incident log (newest first, keep last 500)
            self.r.lpush("incidents:log", json.dumps(rec))
            self.r.ltrim("incidents:log", 0, 499)
            # Per-technique counters (top-10 attacks across the domain)
            for d in detections:
                self.r.hincrby("incidents:tech_counts", d.technique.id, 1)
            # Per-machine threat counter
            if machine:
                self.r.hincrby("incidents:machine_counts", machine, 1)
            # Per-user latest incident snapshot
            self.r.set(f"incident:last:{user}", json.dumps(rec))
        except Exception as e:
            logger.error(f"[{user}] incident logging failed: {e}")

    # ── CONFIG MERGE ──────────────────────────────────────────────────────

    def _merged_config(self, incident_overrides: dict) -> dict:
        """Returns a config copy with business_impact keys overridden for this incident."""
        if not incident_overrides:
            return self.config
        cfg = copy.deepcopy(self.config)
        cfg.setdefault("business_impact", {}).update(incident_overrides)
        return cfg

    # ── HTML FILE OUTPUT ──────────────────────────────────────────────────

    def _save_html(self, user: str, severity: str, kind: str, html: str) -> str:
        user_dir = os.path.join(self.html_output_dir, user)
        os.makedirs(user_dir, exist_ok=True)

        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{ts}_{severity}_{kind}.html"
        path     = os.path.join(user_dir, filename)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"[{user}] {kind} HTML report saved → {path}")
        return path

    # ── MAIN ENTRY POINT ─────────────────────────────────────────────────

    def dispatch(
        self,
        user:               str,
        machine:            str,
        row:                dict,
        score:              float,
        detections:         list,
        feature_breakdown:  dict,
        action:             str = "alert",
        incident_overrides: dict = None,   # e.g. {'action_confirmed': '...', 'action_success': True}
    ) -> dict:
        """
        Returns a dict of file paths + send counts so callers (or tests)
        can verify what was produced:
            {
              "executive_html": "reports/alice/..._executive.html",
              "technical_html": "reports/alice/..._technical.html",
              "sent_executive": 1,
              "sent_technical": 1,
            }
        Returns {} if skipped (no detections or on cooldown).
        """
        if not detections:
            return {}

        cfg          = self._merged_config(incident_overrides or {})
        severity     = severity_from_score(score, cfg)
        technique_id = detections[0].technique.id
        fingerprint  = self._fingerprint(detections)

        # Alert ONCE per threat occurrence. Same active threat -> stay silent.
        if self._already_alerted(user, fingerprint):
            logger.info(
                f"[{user}] {technique_id} already alerted (active incident) — report skipped"
            )
            return {}

        # ── HTML REPORT FILES (full rendered pages) ─────────────────────────
        # Built FIRST so each saved file can be attached to the email alert.
        _, exec_html = build_executive_html(
            user=user, row=row, score=score, severity=severity,
            detections=detections, action=action, config=cfg,
        )
        exec_path = self._save_html(user, severity, "executive", exec_html)

        _, tech_html = build_technical_html(
            user=user, machine=machine, row=row, score=score,
            severity=severity, detections=detections,
            feature_breakdown=feature_breakdown, config=cfg,
        )
        tech_path = self._save_html(user, severity, "technical", tech_html)

        # ── PUSH NOTIFICATIONS (short text + full HTML report attached) ─────
        # The rendered HTML page is attached to the alert so email recipients
        # receive the polished report as a file. Apprise services that do not
        # support attachments (SMS, some chat apps) simply ignore it.
        exec_title, exec_body = build_executive_report(
            user=user, row=row, score=score, severity=severity,
            detections=detections, action=action, config=cfg,
        )
        sent_exec = self.notifier.send(
            "executive", severity, exec_title, exec_body, attach=exec_path,
        )

        tech_title, tech_body = build_technical_report(
            user=user, machine=machine, row=row, score=score,
            severity=severity, detections=detections,
            feature_breakdown=feature_breakdown, config=cfg,
        )
        sent_tech = self.notifier.send(
            "technical", severity, tech_title, tech_body, attach=tech_path,
        )

        logger.info(
            f"[{user}] reports dispatched — "
            f"push(executive={sent_exec}, technical={sent_tech}) "
            f"html(executive={exec_path}, technical={tech_path})"
        )
        self._mark_alerted(user, fingerprint)
        self._record_incident(
            user, machine, severity, score, detections, action,
            cfg.get("business_impact", {}).get("action_success"),
            exec_path, tech_path,
        )

        return {
            "executive_html": exec_path,
            "technical_html": tech_path,
            "sent_executive":  sent_exec,
            "sent_technical":  sent_tech,
        }
