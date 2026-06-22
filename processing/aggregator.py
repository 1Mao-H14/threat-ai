# processing/aggregator.py
from datetime import datetime


MODEL_FEATURES = [
    "signin_count", "failed_logins", "mfa_used",
    "is_legacy_auth", "risk_level_max", "is_off_hours_login",
    "group_change", "role_assigned", "password_reset",
    "policy_changed", "mfa_changed",
    "process_count", "suspicious_pairs", "encoded_cmds",
    "download_cmds", "elevated_procs", "backup_deletion",
    "net_count", "external_conns", "suspicious_ports",
    "lsass_access", "lsass_dump_score",
    "file_writes", "suspicious_writes", "extension_changes",
    "registry_writes", "persistence_keys",
    "hour_of_day", "is_off_hours", "is_weekend",
]


def aggregate_to_row(
    events:       list,
    user:         str,
    window_start: datetime
) -> dict:

    # Group by log type
    by_type = {}
    for e in events:
        lt = e.get("log_type","unknown")
        if lt not in by_type:
            by_type[lt] = []
        by_type[lt].append(e)

    def feat(log_type, feature):
        return sum(
            e["features"].get(feature, 0)
            for e in by_type.get(log_type, [])
        )

    def present(log_type):
        return int(len(by_type.get(log_type, [])) > 0)

    signins = by_type.get("entra_signin", [])
    audits  = by_type.get("entra_audit",  [])

    return {
        # METADATA
        "user":         user,
        "window_start": window_start.isoformat(),
        "total_events": len(events),

        # ── ENTRA ID SIGNIN ───────────────────
        "signin_count":      len(signins),
        "entra_present":     present("entra_signin"),
        "failed_logins":     feat("entra_signin", "failed_login"),
        "mfa_used":          int(feat("entra_signin", "mfa_used") > 0),
        "is_legacy_auth":    int(feat("entra_signin", "is_legacy_auth") > 0),
        "risk_level_max":    max(
                                 (e["features"].get("risk_level", 0)
                                  for e in signins),
                                 default=0
                             ),
        "is_off_hours_login":int(feat("entra_signin", "is_off_hours") > 0),

        # ── ENTRA ID AUDIT ────────────────────
        "audit_present":  present("entra_audit"),
        "group_change":   feat("entra_audit", "is_group_change"),
        "role_assigned":  feat("entra_audit", "is_role_assigned"),
        "password_reset": feat("entra_audit", "is_password_reset"),
        "policy_changed": feat("entra_audit", "is_policy_changed"),
        "mfa_changed":    feat("entra_audit", "is_mfa_changed"),

        # ── SYSMON PROCESS ────────────────────
        "process_count":  len(by_type.get("process_create", [])),
        "proc_present":   present("process_create"),
        "suspicious_pairs":feat("process_create", "is_suspicious_pair"),
        "encoded_cmds":   feat("process_create", "has_encoded_cmd"),
        "download_cmds":  feat("process_create", "has_download_cmd"),
        "elevated_procs": feat("process_create", "is_elevated"),
        "backup_deletion":feat("process_create", "backup_deletion_cmd"),

        # ── SYSMON NETWORK ────────────────────
        "net_count":      len(by_type.get("network_connect", [])),
        "net_present":    present("network_connect"),
        "external_conns": feat("network_connect", "is_external_conn"),
        "suspicious_ports":feat("network_connect","is_suspicious_port"),

        # ── SYSMON LSASS ──────────────────────
        "lsass_access":    feat("lsass_access", "is_lsass_access"),
        "lsass_dump_score":feat("lsass_access", "lsass_dump_score"),

        # ── SYSMON FILE ───────────────────────
        "file_writes":     len(by_type.get("file_create", [])),
        "file_present":    present("file_create"),
        "suspicious_writes":feat("file_create","office_writing_exe"),
        "extension_changes":feat("file_create","extension_changes"),

        # ── SYSMON REGISTRY ───────────────────
        "registry_writes": len(by_type.get("registry_set", [])),
        "reg_present":     present("registry_set"),
        "persistence_keys":feat("registry_set","is_persistence_key"),

        # ── TIME ──────────────────────────────
        "hour_of_day":    window_start.hour,
        "is_off_hours":   int(
                              window_start.hour < 7 or
                              window_start.hour > 20
                          ),
        "is_weekend":     int(window_start.weekday() >= 5),
    }
