# dashboard/server.py
"""
ZeroTrust AI — real-time SOC dashboard backend (Flask).

Run from the repo root:
    pip install -r dashboard/requirements.txt
    python -m dashboard.server                # http://127.0.0.1:8080

Endpoints
    GET  /                          -> dashboard UI
    GET  /api/snapshot              -> full live snapshot (polled by the UI)
    GET  /api/health                -> liveness probe
    POST /api/users/<user>/block    -> block a user (Entra ID + local state)
    POST /api/users/<user>/unblock  -> unblock a user

Data comes from the SAME Redis the pipeline writes to. If Redis has no data
yet, the snapshot falls back to a realistic demo so the UI is never empty.
"""

import os
import logging

import yaml
from flask import Flask, jsonify, send_from_directory, request

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s")
logger = logging.getLogger("Dashboard")

_HERE   = os.path.dirname(os.path.abspath(__file__))
_ROOT   = os.path.dirname(_HERE)
_STATIC = os.path.join(_HERE, "static")


def load_config():
    with open(os.path.join(_ROOT, "config.yml")) as f:
        return yaml.safe_load(f)


def create_app():
    app = Flask(__name__, static_folder=None)
    config = load_config()

    from dashboard.data_provider import ThreatDataProvider
    provider = ThreatDataProvider(config)

    # Lazy ActionEngine — only constructed when a block/unblock is requested,
    # so the dashboard still serves data even if Entra ID creds are absent.
    def _action_engine():
        try:
            from actions.action_engine import ActionEngine
            return ActionEngine(config)
        except Exception as e:
            logger.warning(f"ActionEngine unavailable: {e}")
            return None

    # ── UI ────────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(_STATIC, "index.html")

    @app.route("/<path:path>")
    def static_files(path):
        return send_from_directory(_STATIC, path)

    # ── API ────────────────────────────────────────────────────────────────────
    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/snapshot")
    def snapshot():
        try:
            return jsonify(provider.get_snapshot())
        except Exception as e:
            logger.error(f"snapshot error: {e}")
            from dashboard.demo import build_demo_snapshot
            snap = build_demo_snapshot()
            snap["error"] = str(e)
            return jsonify(snap)

    def _set_blocked(user, blocked):
        provider.set_status(user, "blocked" if blocked else "active")
        eng = _action_engine()
        enforcement = {"success": False, "detail": "enforcement skipped (no ActionEngine)"}
        if eng:
            enforcement = eng.set_account_enabled(user, enabled=not blocked)
        return jsonify({
            "user": user,
            "status": "blocked" if blocked else "active",
            "enforcement": enforcement,
        })

    @app.route("/api/users/<user>/block", methods=["POST"])
    def block(user):
        logger.warning(f"[{user}] BLOCK requested via dashboard")
        return _set_blocked(user, True)

    @app.route("/api/users/<user>/unblock", methods=["POST"])
    def unblock(user):
        logger.warning(f"[{user}] UNBLOCK requested via dashboard")
        return _set_blocked(user, False)

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "8080"))
    logger.info(f"ZeroTrust AI dashboard → http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
