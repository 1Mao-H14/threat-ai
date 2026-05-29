# collectors/sysmon_collector.py
import winrm
import json
import time
import logging
from processing.parser    import parse_sysmon_raw
from collectors.smart_buffer import SmartBuffer

logger = logging.getLogger("SysmonCollector")

WATCHED_EVENT_IDS = [1, 3, 10, 11, 13]


class SysmonCollector:

    def __init__(self, config: dict):
        self.config   = config
        self.vms      = config["vms"]
        self.buffer   = SmartBuffer(config)
        self.sessions = {}

    def _get_session(self, vm: dict):
        name = vm["name"]
        if name not in self.sessions:
            self.sessions[name] = winrm.Session(
                vm["ip"],
                auth=(vm["username"], vm["password"]),
                transport="ntlm"
            )
        return self.sessions[name]

    def _read_events(self, session, last_minutes=2) -> list:
        ids    = ",".join(str(i) for i in WATCHED_EVENT_IDS)
        script = f"""
$events = Get-WinEvent -FilterHashtable @{{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = (Get-Date).AddMinutes(-{last_minutes})
    Id        = {ids}
}} -ErrorAction SilentlyContinue

foreach ($e in $events) {{
    @{{
        EventID     = $e.Id
        TimeCreated = $e.TimeCreated.ToString("o")
        Message     = $e.Message
        MachineName = $e.MachineName
    }} | ConvertTo-Json -Compress
}}
"""
        result = session.run_ps(script)
        if result.status_code != 0:
            return []

        events = []
        for line in result.std_out.decode().strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except:
                continue
        return events

    def _collect_vm(self, vm: dict):
        name = vm["name"]
        try:
            session = self._get_session(vm)
            events  = self._read_events(session)
            logger.info(f"{name}: {len(events)} Sysmon events")

            for raw in events:
                parsed = parse_sysmon_raw(
                    event_id  = raw["EventID"],
                    message   = raw["Message"],
                    timestamp = raw["TimeCreated"],
                    machine   = raw["MachineName"]
                )
                if parsed:
                    self.buffer.push(parsed)

        except Exception as e:
            logger.error(f"{name} error: {e}")
            self.sessions.pop(name, None)

    def run(self):
        logger.info("Sysmon Collector started")
        while True:
            for vm in self.vms:
                self._collect_vm(vm)
            time.sleep(
                self.config["entra_id"]["poll_interval"]
            )
