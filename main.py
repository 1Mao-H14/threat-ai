# main.py
import logging
import time
import threading
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
# ==========================
# Enhanced formatter
formatter = logging.Formatter(
    "\n%(asctime)s"
    "\n[%(name)s] %(levelname)s"
    "\n%(message)s"
    "\n" + "─"*60
)

# Console handler with colors
class ColorHandler(logging.StreamHandler):
    COLORS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    RESET = "\033[0m"

    def emit(self, record):
        color = self.COLORS.get(record.levelname, "")
        record.msg = f"{color}{record.msg}{self.RESET}"
        super().emit(record)

handler = ColorHandler()
handler.setFormatter(formatter)
logging.basicConfig(
    level    = logging.INFO,
    handlers = [handler]
)

# =======================================
def load_config() -> dict:
    with open("config.yml", "r") as f:
        return yaml.safe_load(f)


logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(name)s] %(levelname)s — %(message)s"
)
logger = logging.getLogger("Main")


def main():
    logger.info("=== ZeroTrust AI Starting ===")

    config = load_config()
    logger.info(
        f"Config loaded — "
        f"{len(config['vms'])} VMs configured"
    )

    from collectors.sysmon_collector  import SysmonCollector
    from collectors.entraid_collector import EntraIDCollector
    from processing.hourly_job        import run_pipeline

    sysmon = SysmonCollector(config)
    t1     = threading.Thread(target=sysmon.run, daemon=True)
    t1.start()
    logger.info("✅ Sysmon Collector started")

    entraid = EntraIDCollector(config)
    t2      = threading.Thread(target=entraid.run, daemon=True)
    t2.start()
    logger.info("✅ Entra ID Collector started")

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func     = lambda: run_pipeline(config),
        trigger  = "interval",
        minutes  = 1          # ← run every 1 minute
    )
    scheduler.start()
    logger.info("✅ Pipeline scheduled every 1 minute")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.shutdown()


if __name__ == "__main__":
    main()
