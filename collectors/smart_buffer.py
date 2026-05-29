# collectors/smart_buffer.py
import redis
import json
import logging

logger = logging.getLogger("SmartBuffer")


class SmartBuffer:

    EVENT_PRIORITY = {
        "lsass_access":    10,
        "entra_audit":     9,
        "entra_signin":    9,
        "registry_set":    8,
        "process_create":  7,
        "file_create":     6,
        "network_connect": 3,
        "dns_query":       1,
    }

    IMPORTANT_FEATURES = [
        "is_lsass_access",
        "is_suspicious_pair",
        "has_encoded_cmd",
        "is_persistence_key",
        "office_writing_exe",
        "extension_changes",
        "backup_deletion_cmd",
        "is_policy_changed",
        "is_group_change",
        "is_role_assigned",
        "lsass_dump_score",
    ]

    def __init__(self, config: dict):
        self.max_size = config["buffer"]["max_size"]
        self.r        = redis.Redis(
            host = config["redis"]["host"],
            port = config["redis"]["port"]
        )

    def get_priority(self, event: dict) -> int:
        features = event.get("features", {})
        log_type = event.get("log_type", "unknown")

        # Important feature present → max priority
        for feat in self.IMPORTANT_FEATURES:
            if features.get(feat, 0):
                return 10

        return self.EVENT_PRIORITY.get(log_type, 3)

    def push(self, event: dict):
        user = event.get("user", "unknown")
        if not user or user == "unknown":
            return

        key           = f"buffer:{user}"
        priority      = self.get_priority(event)
        event["priority"] = priority
        current_size  = self.r.llen(key)

        if current_size < self.max_size:
            # Space available → store it
            self.r.rpush(key, json.dumps(event).encode())
            self.r.expire(key, 7200)
            logger.debug(f"[{user}] STORED priority={priority}")
        else:
            # Buffer full → smart decision
            self._smart_insert(key, event, priority)

    def _smart_insert(self, key: str, new_event: dict, new_priority: int):
        all_raw    = self.r.lrange(key, 0, -1)
        all_events = []

        for raw in all_raw:
            try:
                all_events.append(json.loads(raw.decode()))
            except:
                continue

        # Find lowest priority event
        lowest_priority = 999
        lowest_index    = -1

        for i, evt in enumerate(all_events):
            evt_priority = evt.get("priority", 3)
            if evt_priority < lowest_priority:
                lowest_priority = evt_priority
                lowest_index    = i

        if new_priority > lowest_priority:
            # Replace lowest with new important event
            all_events.pop(lowest_index)
            all_events.append(new_event)

            self.r.delete(key)
            for evt in all_events:
                self.r.rpush(key, json.dumps(evt).encode())
            self.r.expire(key, 7200)

            logger.debug(
                f"REPLACED priority={lowest_priority} "
                f"with priority={new_priority}"
            )
        else:
            logger.debug(
                f"DROPPED priority={new_priority} "
                f"buffer full"
            )
