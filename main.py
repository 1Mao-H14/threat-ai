# main.py
import logging
import time
import threading
import yaml
from apscheduler.schedulers.background import BackgroundScheduler


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

    # Load config
    config = load_config()
    logger.info(
        f"Config loaded — "
        f"{len(config['vms'])} VMs configured"
    )

    # Import collectors
    from collectors.sysmon_collector  import SysmonCollector
    from collectors.entraid_collector import EntraIDCollector
    from processing.hourly_job        import run_pipeline

    # Start Sysmon collector
    sysmon = SysmonCollector(config)
    t1     = threading.Thread(
                 target=sysmon.run,
                 daemon=True
             )
    t1.start()
    logger.info("✅ Sysmon Collector started")

    # Start Entra ID collector
    entraid = EntraIDCollector(config)
    t2      = threading.Thread(
                  target=entraid.run,
                  daemon=True
              )
    t2.start()
    logger.info("✅ Entra ID Collector started")

    # Schedule pipeline every 30 minutes
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func     = lambda: run_pipeline(config),
        trigger  = "interval",
        minutes  = 30        # runs every 30 minutes
    )
    scheduler.start()
    logger.info("✅ Pipeline scheduled every 30 minutes")

    # Keep running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.shutdown()


if __name__ == "__main__":
    main()
