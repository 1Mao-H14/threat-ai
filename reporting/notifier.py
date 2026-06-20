# reporting/notifier.py
"""
Reads reporting/channels.yml and dispatches a report to every channel
that matches its audience + severity.

Adding a new destination = adding one YAML entry to channels.yml.
No code change. Call reload() to hot-reload without restarting the process.

Secrets: never paste raw tokens into channels.yml — use ${ENV_VAR}
placeholders (see channels.yml). They're substituted from the process
environment at load time, same pattern you'd want for config.yml too.
"""

import os
import re
import logging
import yaml
import apprise

logger = logging.getLogger("ReportNotifier")

SEVERITY_ORDER  = ["info", "medium", "high", "critical"]
ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _interpolate_env(value: str) -> str:
    return ENV_VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)


class ReportNotifier:

    def __init__(self, config_path: str = "reporting/channels.yml"):
        self.config_path = config_path
        self._channels    = self._load_channels()

    def _load_channels(self) -> list:
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        channels = data.get("channels", [])
        for c in channels:
            c["url"] = _interpolate_env(c["url"])
        return channels

    def reload(self):
        """Hot-reload channels.yml without restarting the process."""
        self._channels = self._load_channels()
        logger.info(f"Reloaded {len(self._channels)} channel(s)")

    def _matches(self, channel: dict, audience: str, severity: str) -> bool:
        if not channel.get("enabled", True):
            return False

        chan_audience = channel.get("audience", "both")
        if chan_audience not in (audience, "both"):
            return False

        min_sev = channel.get("min_severity", "info")
        try:
            return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(min_sev)
        except ValueError:
            logger.warning(f"[{channel.get('name')}] unknown severity '{min_sev}'")
            return False

    def send(
        self,
        audience:    str,
        severity:    str,
        title:       str,
        body:        str,
        body_format: str = "text",
    ) -> int:
        targets = [c for c in self._channels if self._matches(c, audience, severity)]
        if not targets:
            logger.info(f"No '{audience}' channel matched severity={severity}")
            return 0

        sent = 0
        for chan in targets:
            try:
                a  = apprise.Apprise()
                a.add(chan["url"])
                ok = a.notify(title=title, body=body, body_format=body_format)
                logger.info(f"[{chan['name']}] notify={'OK' if ok else 'FAILED'}")
                sent += int(ok)
            except Exception as e:
                logger.error(f"[{chan['name']}] error: {e}")
        return sent
