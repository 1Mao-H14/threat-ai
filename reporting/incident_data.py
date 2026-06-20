# reporting/incident_data.py
"""
Single input contract for the full technical incident report.

Existing pipeline fields (user, row, detections, financial estimate) map
directly from what processing/hourly_job.py already produces. The new
annex fields below (IOCs, chain of custody, IR contact, insurance,
RGPD template) are NOT auto-derivable from the current Sysmon/Entra
telemetry. They default to None/empty and the report renders an honest
"Non disponible" instead of inventing values.

Do not populate iocs with fabricated hashes or IP addresses. If real
forensic artifacts are not available, leave the list empty. A security
report that contains invented evidence is worse than one with a gap
clearly marked.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EventTypeBreakdown:
    """Used for the event-distribution pie chart. Label -> count."""
    label: str
    count: int


@dataclass
class ScorePoint:
    """One point on the score evolution line chart."""
    timestamp: str   # e.g. "02:00", or full ISO string
    score: float      # 0.0-1.0


@dataclass
class KillChainPhase:
    """One bar on the chronology Gantt chart."""
    tactic:      str   # e.g. "Execution"
    start:       str   # ISO timestamp or "HH:MM"
    end:         str   # ISO timestamp or "HH:MM"


@dataclass
class IOC:
    """One indicator of compromise. Leave fields empty rather than inventing them."""
    ioc_type:    str             # filename | hash_sha256 | domain | ip | url
    value:       str
    sha256:      Optional[str] = None
    first_seen:  Optional[str] = None
    last_seen:   Optional[str] = None


@dataclass
class ChainOfCustody:
    collected_by:   str = "Non renseigné"
    tool:           str = "Sysmon + Microsoft Graph API"
    tool_version:   str = "Non renseigné"
    collected_at:   str = ""
    integrity_hash: Optional[str] = None  # hash of the raw log export, if computed


@dataclass
class IRContact:
    team_name: str = "Équipe Sécurité"
    email:     str = ""
    phone:     str = ""
    note:      str = "Validation humaine requise avant clôture de l'incident"


@dataclass
class CyberInsurance:
    insurer:    Optional[str] = None
    policy_ref: Optional[str] = None
    limit:      Optional[int] = None
    deductible: Optional[int] = None
    currency:   str = "EUR"
    coverage:   Optional[str] = None  # e.g. "IR, Forensics, Legal, Notification"


@dataclass
class IncidentData:
    # ── Core identifiers ──────────────────────────────────────────────
    user:       str
    machine:    str
    reference:  str           # e.g. ZTA-20260620-0243-ALIC-CRI
    severity:   str           # critical | high | medium | info
    score:      float
    window_start: str
    window_end:   str
    detection_delay_minutes: Optional[int] = None

    # ── Pipeline outputs (reuse existing objects) ─────────────────────
    row:                dict = field(default_factory=dict)
    detections:         list = field(default_factory=list)   # list[Detection]
    feature_breakdown:  dict = field(default_factory=dict)
    action_confirmed:   Optional[str] = None
    action_success:     Optional[bool] = None

    # ── Financial (from financial_estimator.estimate()) ──────────────
    financial: Optional[object] = None   # FinancialEstimate instance, or None

    # ── Chart input data ──────────────────────────────────────────────
    event_breakdown: list = field(default_factory=list)   # list[EventTypeBreakdown]
    score_timeline:  list = field(default_factory=list)   # list[ScorePoint]
    kill_chain_phases: list = field(default_factory=list) # list[KillChainPhase]

    # ── Annex data (optional, honest fallback if absent) ──────────────
    iocs:            list = field(default_factory=list)   # list[IOC]
    chain_of_custody: Optional[ChainOfCustody] = None
    ir_contact:       Optional[IRContact] = None
    insurance:        Optional[CyberInsurance] = None
    rgpd_template_ref: Optional[str] = None

    # ── Misc ────────────────────────────────────────────────────────
    mfa_active: Optional[bool] = None
    generated_at: str = ""
