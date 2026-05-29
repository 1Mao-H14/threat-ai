# processing/parser.py
import re
from datetime import datetime


def extract_field(message: str, field: str) -> str:
    for line in message.splitlines():
        if f"{field}:" in line:
            val = line.split(":", 1)[-1].strip()
            if val and val != "-":
                return val
    return ""


def parse_timestamp(ts: str) -> dict:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return {
            "hour_of_day": dt.hour,
            "day_of_week": dt.weekday(),
            "is_off_hours": int(dt.hour < 7 or dt.hour > 20),
            "is_weekend":   int(dt.weekday() >= 5),
        }
    except:
        return {
            "hour_of_day": 0,
            "day_of_week": 0,
            "is_off_hours": 0,
            "is_weekend":   0,
        }


def parse_event_id_1(message: str) -> dict:
    """Process Create."""
    image        = extract_field(message, "Image").lower()
    parent_image = extract_field(message, "ParentImage").lower()
    cmdline      = extract_field(message, "CommandLine").lower()
    integrity    = extract_field(message, "IntegrityLevel").lower()
    user         = extract_field(message, "User").lower()

    image_name   = image.split("\\")[-1]
    parent_name  = parent_image.split("\\")[-1]

    BAD_PAIRS = {
        ("winword.exe",  "cmd.exe"),
        ("winword.exe",  "powershell.exe"),
        ("winword.exe",  "wscript.exe"),
        ("excel.exe",    "cmd.exe"),
        ("excel.exe",    "powershell.exe"),
        ("outlook.exe",  "powershell.exe"),
        ("mshta.exe",    "powershell.exe"),
        ("wscript.exe",  "powershell.exe"),
        ("chrome.exe",   "cmd.exe"),
    }

    SUSPICIOUS_PATTERNS = [
        r"-enc\s+[a-zA-Z0-9+/=]{20,}",
        r"iex\s*\(",
        r"downloadstring",
        r"downloadfile",
        r"-nop.*bypass",
        r"webclient",
        r"net user.*/add",
        r"vssadmin.*delete",
    ]

    suspicious_score = sum(
        1 for p in SUSPICIOUS_PATTERNS
        if re.search(p, cmdline)
    )

    return {
        "user":                 user.split("\\")[-1],
        "process_name":         image_name,
        "parent_process":       parent_name,
        "is_suspicious_pair":   int((parent_name, image_name) in BAD_PAIRS),
        "has_encoded_cmd":      int(bool(re.search(
                                    r"-enc\s+[a-zA-Z0-9+/=]{20,}", cmdline))),
        "has_download_cmd":     int("downloadstring" in cmdline
                                    or "downloadfile" in cmdline),
        "suspicious_cmd_score": suspicious_score,
        "is_elevated":          int(integrity in ["high","system"]),
        "backup_deletion_cmd":  int("vssadmin" in cmdline
                                    and "delete" in cmdline),
    }


def parse_event_id_3(message: str) -> dict:
    """Network Connection."""
    dst_ip   = extract_field(message, "DestinationIp")
    dst_port = extract_field(message, "DestinationPort")
    image    = extract_field(message, "Image").lower()

    try:
        dst_port = int(dst_port)
    except:
        dst_port = 0

    def is_private(ip):
        return (ip.startswith("10.") or
                ip.startswith("192.168.") or
                ip.startswith("172.") or
                ip == "127.0.0.1")

    SUSPICIOUS_PROCS = {
        "lsass.exe","winlogon.exe",
        "csrss.exe","smss.exe"
    }
    SUSPICIOUS_PORTS = {4444,1337,8080,9001,6666,31337}

    return {
        "dst_ip":              dst_ip,
        "dst_port":            dst_port,
        "is_external_conn":    int(not is_private(dst_ip)),
        "is_suspicious_port":  int(dst_port in SUSPICIOUS_PORTS),
        "is_suspicious_proc":  int(image.split("\\")[-1] in SUSPICIOUS_PROCS),
    }


def parse_event_id_10(message: str) -> dict:
    """Process Access — lsass."""
    target      = extract_field(message, "TargetImage").lower()
    source      = extract_field(message, "SourceImage").lower()
    access_mask = extract_field(message, "GrantedAccess").lower()

    DUMP_MASKS    = {"0x1010","0x1410","0x1fffff","0x1f3fff"}
    LEGIT_CALLERS = {"csrss.exe","wininit.exe","services.exe","lsm.exe"}

    is_lsass     = int("lsass.exe" in target)
    is_dump_mask = int(access_mask in DUMP_MASKS)
    is_legit     = int(source.split("\\")[-1] in LEGIT_CALLERS)

    return {
        "is_lsass_access":  is_lsass,
        "is_dump_mask":     is_dump_mask,
        "is_legit_caller":  is_legit,
        "lsass_dump_score": is_lsass * is_dump_mask * (1 - is_legit),
    }


def parse_event_id_11(message: str) -> dict:
    """File Create."""
    path    = extract_field(message, "TargetFilename").lower()
    process = extract_field(message, "Image").lower()

    SUSPICIOUS_PATHS = [
        "\\appdata\\roaming",
        "\\appdata\\local\\temp",
        "\\users\\public",
        "\\windows\\temp",
        "\\programdata",
    ]
    OFFICE_APPS = {
        "winword.exe","excel.exe","outlook.exe",
        "powerpnt.exe","chrome.exe","firefox.exe"
    }
    EXE_EXTS    = {".exe",".dll",".bat",".ps1",".vbs",".hta"}
    file_ext    = "." + path.split(".")[-1] if "." in path else ""

    return {
        "file_path":          path,
        "file_extension":     file_ext,
        "is_suspicious_path": int(any(p in path for p in SUSPICIOUS_PATHS)),
        "is_executable":      int(file_ext in EXE_EXTS),
        "office_writing_exe": int(process.split("\\")[-1] in OFFICE_APPS
                                  and file_ext in EXE_EXTS),
        "extension_changes":  int(file_ext in {
                                  ".locked",".encrypted",".enc",".crypto"
                              }),
    }


def parse_event_id_13(message: str) -> dict:
    """Registry Set."""
    key = extract_field(message, "TargetObject").lower()

    RUN_KEYS = ["\\run\\","\\runonce\\","\\winlogon","\\services\\"]

    return {
        "registry_key":       key,
        "is_persistence_key": int(any(k in key for k in RUN_KEYS)),
    }


EVENT_PARSERS = {
    1:  parse_event_id_1,
    3:  parse_event_id_3,
    10: parse_event_id_10,
    11: parse_event_id_11,
    13: parse_event_id_13,
}

LOG_TYPE_MAP = {
    1:  "process_create",
    3:  "network_connect",
    10: "lsass_access",
    11: "file_create",
    13: "registry_set",
}


def parse_sysmon_raw(
    event_id:  int,
    message:   str,
    timestamp: str,
    machine:   str
) -> dict | None:

    parser = EVENT_PARSERS.get(event_id)
    if not parser:
        return None

    fields   = parser(message)
    user     = fields.pop("user", "unknown")
    log_type = LOG_TYPE_MAP.get(event_id, f"sysmon_{event_id}")

    if not user or user == "unknown":
        return None

    return {
        "source":    "sysmon",
        "log_type":  log_type,
        "timestamp": timestamp,
        "user":      user,
        "machine":   machine,
        "features":  {
            **fields,
            **parse_timestamp(timestamp),
        }
    }
