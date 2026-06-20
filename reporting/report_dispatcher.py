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
        self.html_output_dir = html_output_dir
        self.r               = redis.Redis(
            host=config["redis"]["host"],
            port=config["redis"]["port"]
        )

    # ── COOLDOWN ──────────────────────────────────────────────────────────

    def _cooldown_key(self, user: str, technique_id: str) -> str:
        return f"report_cooldown:{user}:{technique_id}"

    def _on_cooldown(self, user: str, technique_id: str) -> bool:
        return bool(self.r.exists(self._cooldown_key(user, technique_id)))

    def _set_cooldown(self, user: str, technique_id: str):
        self.r.set(
            self._cooldown_key(user, technique_id),
            "1",
            ex=self.cooldown_min * 60
        )

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

        if self._on_cooldown(user, technique_id):
            logger.info(f"[{user}] {technique_id} on cooldown — report skipped")
            return {}

        # ── PUSH NOTIFICATIONS (short, plain text) ─────────────────────────
        exec_title, exec_body = build_executive_report(
            user=user, row=row, score=score, severity=severity,
            detections=detections, action=action, config=cfg,
        )
        sent_exec = self.notifier.send("executive", severity, exec_title, exec_body)

        tech_title, tech_body = build_technical_report(
            user=user, machine=machine, row=row, score=score,
            severity=severity, detections=detections,
            feature_breakdown=feature_breakdown, config=cfg,
        )
        sent_tech = self.notifier.send("technical", severity, tech_title, tech_body)

        # ── HTML REPORT FILES (full rendered pages) ─────────────────────────
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

        logger.info(
            f"[{user}] reports dispatched — "
            f"push(executive={sent_exec}, technical={sent_tech}) "
            f"html(executive={exec_path}, technical={tech_path})"
        )
        self._set_cooldown(user, technique_id)

        return {
            "executive_html": exec_path,
            "technical_html": tech_path,
            "sent_executive":  sent_exec,
            "sent_technical":  sent_tech,
        }
