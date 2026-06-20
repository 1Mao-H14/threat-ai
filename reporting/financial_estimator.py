# reporting/financial_estimator.py
"""
Worst-case financial impact estimator for executive reports.

Every number traces back to a citable source OR a formula the reader
can verify. The report always distinguishes between:
  (A) Our estimate — derived from YOUR telemetry signals + config values
  (B) Industry benchmark — external survey average shown only as context

Signal mapping (aggregator row ──→ financial indicator):
  row field             indicator used
  ─────────────────────────────────────────────────────────────
  file_writes           data volume proxy (GB = file_writes × 0.5 if not configured)
  extension_changes     encryption confirmed (ransomware)
  backup_deletion       ransomware — shadow copy wipe
  lsass_access          credential access
  lsass_dump_score      credential dump severity
  persistence_keys      lateral movement / dwell depth
  suspicious_pairs      endpoint compromise depth
  encoded_cmds          attack sophistication
  signin_count          users actively impacted (proxy)
  is_off_hours / login  detection-delay multiplier

Business inputs (config.yml → business_impact block):
  company_size              smb | mid_market | enterprise
  annual_revenue            USD/EUR — used for downtime + GDPR calc
  employee_count            for productivity-loss calc
  avg_employee_hourly_cost  fully-loaded hourly wage (default 35)
  productivity_loss_pct     during incident (default 0.6)
  downtime_hours            actual or estimated hours of system unavailability
  vms_touched_this_incident how many VMs were affected
  estimated_data_exposed_gb known or estimated GB of data at risk
  estimated_records_at_risk customer/user records potentially exposed
  data_type_at_risk         pii | financial | health | credentials | ip | unknown
  critical_systems_impacted true | false
  users_impacted            headcount directly affected (or inferred from telemetry)
  currency                  USD | EUR | MAD (display only)

Sources:
  [1] Sophos, State of Ransomware 2025
  [2] IBM, Cost of a Data Breach Report 2025
  [3] ITIC, Hourly Cost of Downtime Survey 2024
"""

import math
from dataclasses import dataclass, field
from typing import Optional


# ── PUBLISHED BENCHMARKS ──────────────────────────────────────────────────

class Benchmark:
    # [1] Sophos State of Ransomware 2025 — mean recovery cost (excl. ransom)
    RANSOMWARE_RECOVERY = {
        "smb":        638_536,
        "mid_market": 1_530_000,
        "enterprise": 1_830_000,
    }
    RANSOM_MEDIAN_DEMAND  = 1_200_000
    RANSOM_MEDIAN_PAYMENT = 1_000_000

    # [2] IBM Cost of a Data Breach 2025
    BREACH_GLOBAL_AVG            = 4_440_000
    BREACH_CREDENTIAL_VECTOR     = 4_670_000
    BREACH_PER_RECORD_PII        = 150
    BREACH_PER_RECORD_IP         = 178

    # [3] ITIC Hourly Cost of Downtime 2024
    DOWNTIME_SMB_PER_HOUR        = 100_000
    DOWNTIME_MIDSIZE_PER_HOUR    = 300_000
    DOWNTIME_ENTERPRISE_PER_HOUR = 1_000_000

    SRC_RANSOMWARE = "Sophos, State of Ransomware 2025"
    SRC_BREACH     = "IBM, Cost of a Data Breach Report 2025"
    SRC_DOWNTIME   = "ITIC, Hourly Cost of Downtime Survey 2024"


# ── ATTACK VECTOR CLASSIFICATION ─────────────────────────────────────────

TECHNIQUE_TO_VECTOR = {
    "T1486":     "ransomware",
    "T1003":     "credential_dump",
    "T1078":     "credential_compromise",
    "T1078.002": "privilege_escalation",
    "T1071":     "c2_exfiltration",
    "T1041":     "c2_exfiltration",
    "T1110":     "brute_force",
    "T1059":     "execution",
    "T1059.001": "execution",
    "T1547":     "persistence",
    "T1562":     "defense_evasion",
    "T1021":     "lateral_movement",
}

# Base cost range (USD) per vector × company size: (low, mid, high)
# Derived from [1][2] adjusted for size; treat as order-of-magnitude
SIZE_INDEX = {"smb": 0, "mid_market": 1, "enterprise": 2}

BASE_COST_TABLE = {
    "ransomware":          [(80_000,  150_000,  400_000), (300_000,  800_000, 1_800_000), ( 800_000, 1_530_000, 3_000_000)],
    "credential_dump":     [(40_000,   90_000,  200_000), (200_000,  500_000, 1_200_000), ( 500_000, 1_200_000, 4_670_000)],
    "credential_compromise":[(30_000,  70_000,  180_000), (150_000,  400_000, 1_000_000), ( 400_000, 1_000_000, 4_670_000)],
    "privilege_escalation": [(25_000,  60_000,  150_000), (100_000,  300_000,   800_000), ( 300_000,   800_000, 2_000_000)],
    "c2_exfiltration":     [(50_000,  120_000,  300_000), (200_000,  600_000, 1_500_000), ( 600_000, 1_500_000, 4_000_000)],
    "brute_force":         [(10_000,   30_000,   80_000), ( 50_000,  150_000,   400_000), ( 150_000,   400_000, 1_000_000)],
    "execution":           [(20_000,   50_000,  120_000), ( 80_000,  200_000,   500_000), ( 200_000,   500_000, 1_500_000)],
    "persistence":         [(30_000,   70_000,  180_000), (100_000,  300_000,   700_000), ( 300_000,   700_000, 1_800_000)],
    "defense_evasion":     [(40_000,  100_000,  250_000), (150_000,  400_000, 1_000_000), ( 400_000, 1_000_000, 2_500_000)],
    "lateral_movement":    [(50_000,  130_000,  300_000), (200_000,  600_000, 1_500_000), ( 600_000, 1_500_000, 4_000_000)],
    "unknown":             [(15_000,   40_000,  100_000), ( 60_000,  180_000,   450_000), ( 180_000,   450_000, 1_200_000)],
}


# ── MULTIPLIER ENGINE ─────────────────────────────────────────────────────

@dataclass
class Multiplier:
    label:  str
    value:  float
    reason: str


def _derive_multipliers(row: dict, config: dict) -> list:
    mults = []
    biz   = config.get("business_impact", {})

    # Scope — VMs / systems touched
    vms = biz.get("vms_touched_this_incident", 1)
    if vms >= 21:
        mults.append(Multiplier("Étendue systèmes (≥21 VMs)", 2.5, f"{vms} systèmes touchés"))
    elif vms >= 6:
        mults.append(Multiplier("Étendue systèmes (6-20 VMs)", 1.5, f"{vms} systèmes touchés"))
    elif vms >= 2:
        mults.append(Multiplier("Étendue systèmes (2-5 VMs)", 1.2, f"{vms} systèmes touchés"))

    # Data volume — config override or file-write heuristic (0.5 GB/write)
    data_gb = biz.get("estimated_data_exposed_gb",
                      row.get("file_writes", 0) * 0.5)
    if data_gb > 1_000:
        mults.append(Multiplier("Volume données (>1 TB)", 3.0, f"{data_gb:.0f} GB exposés/chiffrés"))
    elif data_gb > 100:
        mults.append(Multiplier("Volume données (100 GB–1 TB)", 1.8, f"{data_gb:.0f} GB estimés"))

    # Ransomware signals
    ext  = row.get("extension_changes", 0)
    bkup = row.get("backup_deletion",   0)
    if ext > 0 and bkup > 0:
        mults.append(Multiplier("Chiffrement + suppression sauvegardes", 2.8,
                                "Extensions modifiées ET vssadmin delete détecté"))
    elif ext > 0:
        mults.append(Multiplier("Chiffrement de fichiers (ransomware)", 2.0,
                                "Extensions fichiers modifiées"))
    elif bkup > 0:
        mults.append(Multiplier("Suppression sauvegardes", 1.6,
                                "Commandes vssadmin delete"))

    # Credential dump severity
    if row.get("lsass_dump_score", 0) > 0:
        mults.append(Multiplier("Dump mémoire identifiants (confirmé)", 2.0,
                                "lsass.exe — masque d'accès dump confirmé"))
    elif row.get("lsass_access", 0) > 0:
        mults.append(Multiplier("Accès lsass.exe", 1.4,
                                "Accès processus gestion des mots de passe"))

    # Sensitive data type
    dtype = biz.get("data_type_at_risk", "unknown").lower()
    if dtype in ("pii", "financial", "health"):
        mults.append(Multiplier("Données sensibles (PII / financier / santé)", 2.5,
                                f"Type : {dtype} — amendes RGPD potentielles"))
    elif dtype in ("credentials", "intellectual_property", "ip"):
        mults.append(Multiplier("Données sensibles (IP / credentials)", 2.0,
                                f"Type : {dtype}"))

    # Critical systems
    if biz.get("critical_systems_impacted", False):
        mults.append(Multiplier("Systèmes critiques impactés", 2.0,
                                "Système de production / finance / base de données principale"))

    # Downtime duration
    dh = biz.get("downtime_hours", 0)
    if dh > 24:
        mults.append(Multiplier("Arrêt système >24h", 3.0, f"{dh}h d'indisponibilité"))
    elif dh > 4:
        mults.append(Multiplier("Arrêt système >4h", 1.5, f"{dh}h d'indisponibilité"))

    # Lateral movement depth
    if row.get("persistence_keys", 0) > 0 and row.get("signin_count", 0) > 3:
        mults.append(Multiplier("Déplacement latéral profond", 1.8,
                                "Persistance + connexions multi-machines"))
    elif row.get("persistence_keys", 0) > 0:
        mults.append(Multiplier("Persistance établie", 1.3,
                                "Clés Run modifiées"))

    # Attack sophistication
    if row.get("encoded_cmds", 0) > 0 and row.get("suspicious_pairs", 0) > 0:
        mults.append(Multiplier("Attaque sophistiquée", 1.4,
                                "Commandes chiffrées + paires processus suspectes"))

    # Off-hours detection delay
    if row.get("is_off_hours_login", 0) and row.get("is_off_hours", 0):
        mults.append(Multiplier("Délai détection (hors heures ouvrées)", 1.2,
                                "Activité hors surveillance normale"))

    # Users / accounts impacted
    users_impacted = biz.get(
        "users_impacted",
        row.get("signin_count", 0) + (1 if row.get("lsass_access") else 0)
    )
    if users_impacted >= 50:
        mults.append(Multiplier("Utilisateurs impactés (≥50)", 1.6, f"{users_impacted} utilisateurs"))
    elif users_impacted >= 10:
        mults.append(Multiplier("Utilisateurs impactés (10-49)", 1.2, f"{users_impacted} utilisateurs"))

    return mults


def _apply_multipliers(base_low, base_mid, base_high, multipliers):
    if not multipliers:
        return base_low, base_mid, base_high
    combined = math.prod(m.value for m in multipliers)
    # Cap: disclosed assumption — prevents astronomically implausible figures
    combined = min(combined, 8.0)
    return (
        round(base_low),
        round(base_mid  * min(combined, 4.0)),
        round(base_high * combined),
    )


def _downtime_cost(biz: dict) -> Optional[dict]:
    """Bottom-up downtime cost: your own revenue + headcount × hours."""
    revenue   = biz.get("annual_revenue", 0)
    headcount = biz.get("employee_count",  0)
    wage      = biz.get("avg_employee_hourly_cost", 35)
    loss_pct  = biz.get("productivity_loss_pct", 0.60)
    hours     = biz.get("downtime_hours", 0)

    if not hours or not (revenue or headcount):
        return None

    hourly_rev   = revenue / 8_760 if revenue else 0
    hourly_labor = headcount * wage * loss_pct
    per_hour     = hourly_rev + hourly_labor

    return {
        "hours":         hours,
        "cost_per_hour": round(per_hour),
        "total":         round(per_hour * hours),
        "breakdown": {
            "lost_revenue":      round(hourly_rev   * hours),
            "lost_productivity": round(hourly_labor * hours),
        },
    }


def _regulatory_estimate(biz: dict) -> Optional[dict]:
    """
    GDPR worst-case ceiling: Art. 83(5) — up to 4% of global annual turnover
    or €20M, whichever is HIGHER. This is a legal maximum, not a prediction.
    Notification cost: ~€15/record (EU average estimate).
    """
    revenue   = biz.get("annual_revenue", 0)
    records   = biz.get("estimated_records_at_risk", 0)
    dtype     = biz.get("data_type_at_risk", "unknown").lower()

    if dtype not in ("pii", "financial", "health") or not records:
        return None

    notification_cost  = records * 15
    gdpr_ceiling_pct   = revenue * 0.04 if revenue else 0
    gdpr_worst_case    = max(gdpr_ceiling_pct, 20_000_000)

    return {
        "notification_cost":     round(notification_cost),
        "gdpr_worst_case_fine":  round(gdpr_worst_case),
        "records_at_risk":       records,
        "note": "Plafond RGPD Art. 83(5) — maximum légal, non une prédiction",
    }


# ── RESULT DATACLASS ─────────────────────────────────────────────────────

@dataclass
class FinancialEstimate:
    low:  int
    mid:  int
    high: int
    currency: str

    vector:      str
    multipliers: list

    downtime:   Optional[dict]
    regulatory: Optional[dict]

    benchmark_label:  str
    benchmark_low:    int
    benchmark_high:   int
    benchmark_source: str

    assumptions: list = field(default_factory=list)


# ── MAIN ENTRY POINT ─────────────────────────────────────────────────────

def estimate(
    row:        dict,
    detections: list,
    config:     dict,
) -> Optional[FinancialEstimate]:

    biz = config.get("business_impact", {})
    if not biz:
        return None

    technique_id = detections[0].technique.id if detections else "unknown"
    vector       = TECHNIQUE_TO_VECTOR.get(technique_id, "unknown")
    size         = biz.get("company_size", "smb")
    size_idx     = SIZE_INDEX.get(size, 0)
    currency     = biz.get("currency", "USD")

    base_low, base_mid, base_high = BASE_COST_TABLE.get(
        vector, BASE_COST_TABLE["unknown"]
    )[size_idx]

    multipliers = _derive_multipliers(row, config)
    low, mid, high = _apply_multipliers(base_low, base_mid, base_high, multipliers)

    # External benchmark reference (context, NOT our estimate)
    if vector == "ransomware":
        ref   = Benchmark.RANSOMWARE_RECOVERY
        b_low = ref.get(size, ref["smb"])
        b_high = ref["enterprise"]
        b_src  = Benchmark.SRC_RANSOMWARE
        b_lbl  = "Coût moyen remédiation ransomware (hors rançon), organisations similaires"
    else:
        b_low  = Benchmark.BREACH_GLOBAL_AVG // 10
        b_high = Benchmark.BREACH_CREDENTIAL_VECTOR
        b_src  = Benchmark.SRC_BREACH
        b_lbl  = "Coût moyen mondial d'une violation (moyenne toutes tailles)"

    assumptions = [
        f"Vecteur supposé : {vector}  (technique {technique_id})",
        f"Taille organisation configurée : {size}",
        "Multiplicateur combiné plafonné à ×8 (hypothèse conservative divulguée)",
        "Coûts indirects — réputation, attrition clients — NON inclus",
        "ESTIMATION PIRE CAS — ne pas utiliser comme prévision comptable",
    ]

    return FinancialEstimate(
        low=low, mid=mid, high=high,
        currency=currency,
        vector=vector,
        multipliers=multipliers,
        downtime=_downtime_cost(biz),
        regulatory=_regulatory_estimate(biz),
        benchmark_label=b_lbl,
        benchmark_low=b_low,
        benchmark_high=b_high,
        benchmark_source=b_src,
        assumptions=assumptions,
    )
