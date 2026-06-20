# reporting/report_builder.py
"""
Builds two report variants from the same pipeline data:

  executive  → plain language, manager/director level, financial impact included
  technical  → full MITRE + feature telemetry detail, for SOC analysts

Both return (title: str, body: str).
The body is plain text so it renders correctly in email, Slack,
Teams, WhatsApp and SMS without any additional post-processing.
"""

from datetime import datetime, timezone
from reporting.financial_estimator import estimate as financial_estimate

SEVERITY_LABELS = {
    "critical": "🔴 CRITIQUE",
    "high":     "🟠 ÉLEVÉ",
    "medium":   "🟡 MOYEN",
    "info":     "🟢 INFORMATIF",
}

PLAIN_LANGUAGE = {
    "T1003":     "Une tentative de vol des mots de passe stockés en mémoire a été détectée.",
    "T1110":     "Plusieurs tentatives de connexion infructueuses ont été détectées.",
    "T1059":     "Une commande suspecte a été exécutée sur un poste de travail.",
    "T1059.001": "Une commande dissimulée/chiffrée a été exécutée sur un poste de travail.",
    "T1547":     "Un programme a tenté de s'installer pour démarrer automatiquement avec Windows.",
    "T1078":     "Un compte utilisateur a été utilisé dans des conditions inhabituelles.",
    "T1078.002": "Un compte a obtenu des droits d'accès élevés de façon suspecte.",
    "T1562":     "Une protection de sécurité (audit, MFA) a été désactivée ou modifiée.",
    "T1021":     "Un déplacement suspect entre plusieurs machines a été détecté.",
    "T1486":     "Des signes d'un rançongiciel (chiffrement de fichiers) ont été détectés.",
    "T1071":     "Une communication suspecte vers un serveur externe a été détectée.",
    "T1041":     "Un transfert important de données vers l'extérieur a été détecté.",
}

ACTION_LABELS = {
    "block": "✅ Compte bloqué automatiquement.",
    "mfa":   "✅ Nouvelle authentification (MFA) imposée à l'utilisateur.",
    "alert": "⚠️  Aucune action automatique — supervision manuelle requise.",
}

RECOMMENDATION_BY_SEVERITY = {
    "critical": "Vérifier l'identité physiquement avant toute réactivation. Contacter immédiatement l'équipe sécurité.",
    "high":     "Contacter l'utilisateur pour confirmer l'activité avant la fin de journée.",
    "medium":   "Surveiller ce compte lors des prochaines heures. Signaler tout comportement inhabituel.",
    "info":     "Aucune action requise pour le moment.",
}

NEXT_STEPS_BY_SEVERITY = {
    "critical": [
        "1. Vérifier si d'autres comptes ont été compromis",
        "2. Changer tous les mots de passe des systèmes impactés",
        "3. Activer la journalisation avancée sur les systèmes concernés",
        "4. Notifier la direction et le délégué à la protection des données (DPO)",
        "5. Évaluer l'obligation de notification RGPD (72h si données personnelles exposées)",
    ],
    "high": [
        "1. Forcer la réinitialisation du mot de passe utilisateur",
        "2. Vérifier les accès récents dans les journaux Azure AD",
        "3. Confirmer avec le responsable de l'utilisateur si l'activité est légitime",
    ],
    "medium": [
        "1. Surveiller les prochaines connexions de cet utilisateur",
        "2. Vérifier s'il existe des anomalies similaires sur d'autres comptes",
    ],
    "info": [
        "1. Aucune action urgente requise",
        "2. Inclure dans le rapport mensuel de sécurité",
    ],
}


def severity_from_score(score: float, config: dict) -> str:
    s = config.get("scoring", {})
    if score >= s.get("block_threshold", 0.85):
        return "critical"
    if score >= s.get("mfa_threshold",   0.70):
        return "high"
    if score >= s.get("alert_threshold", 0.50):
        return "medium"
    return "info"


def _fmt_currency(amount: int, currency: str = "USD") -> str:
    sym = {"USD": "$", "EUR": "€", "MAD": "MAD "}.get(currency, currency + " ")
    return f"{sym}{amount:,.0f}"


def _action_section(action: str, config: dict) -> str:
    """
    Shows what the action engine ACTUALLY executed, not just what was
    intended. ReportDispatcher passes action_confirmed/action_success
    through incident_overrides, which lands in config['business_impact'].
    If absent (e.g. report built standalone in tests), falls back to the
    generic intended-action label only.
    """
    base = ACTION_LABELS.get(action, ACTION_LABELS["alert"])
    biz  = config.get("business_impact", {})
    detail  = biz.get("action_confirmed")
    success = biz.get("action_success")

    if detail is None:
        return base

    icon = "✅" if success else "❌"
    return f"{base}\n{icon} Confirmation : {detail}"


def _financial_section(row, detections, severity, config) -> str:
    """Builds the financial-impact block for the executive report."""
    est = financial_estimate(row, detections, config)
    if est is None:
        return (
            "\n──────────────────────────────────────────\n"
            "IMPACT FINANCIER ESTIMÉ\n"
            "──────────────────────────────────────────\n"
            "Non calculé — configurez la section business_impact dans config.yml\n"
            "pour obtenir une estimation chiffrée.\n"
        )

    cur = est.currency
    lines = [
        "",
        "──────────────────────────────────────────",
        "IMPACT FINANCIER ESTIMÉ (PIRE CAS)",
        "──────────────────────────────────────────",
        f"Vecteur d'attaque : {est.vector}",
        "",
        f"  Fourchette basse  : {_fmt_currency(est.low,  cur)}",
        f"  Fourchette médiane: {_fmt_currency(est.mid,  cur)}   ← scénario central",
        f"  Fourchette haute  : {_fmt_currency(est.high, cur)}   ← pire cas",
        "",
    ]

    # Multipliers — show each factor that drove the number up
    if est.multipliers:
        lines.append("Facteurs aggravants détectés :")
        for m in est.multipliers:
            lines.append(f"  × {m.value:.1f}  {m.label}")
            lines.append(f"          └─ {m.reason}")
        lines.append("")

    # Downtime breakdown (only if configured)
    if est.downtime:
        dt = est.downtime
        lines += [
            "Détail du coût d'arrêt système :",
            f"  Durée estimée        : {dt['hours']}h",
            f"  Coût par heure       : {_fmt_currency(dt['cost_per_hour'], cur)}",
            f"    dont pertes revenus : {_fmt_currency(dt['breakdown']['lost_revenue'],      cur)}",
            f"    dont perte productivité : {_fmt_currency(dt['breakdown']['lost_productivity'], cur)}",
            f"  TOTAL arrêt système  : {_fmt_currency(dt['total'], cur)}",
            "",
        ]

    # Regulatory ceiling (GDPR)
    if est.regulatory:
        reg = est.regulatory
        lines += [
            "Exposition réglementaire (RGPD) :",
            f"  Enregistrements à risque : {reg['records_at_risk']:,}",
            f"  Coût notification estimé : {_fmt_currency(reg['notification_cost'], cur)}",
            f"  Amende RGPD max possible : {_fmt_currency(reg['gdpr_worst_case_fine'], cur)}",
            f"  ⚠  {reg['note']}",
            "",
        ]

    # External benchmark (always labeled clearly)
    lines += [
        f"Référence sectorielle ({est.benchmark_source}) :",
        f"  {est.benchmark_label}",
        f"  {_fmt_currency(est.benchmark_low, cur)} – {_fmt_currency(est.benchmark_high, cur)}",
        "  ⚠  Ces chiffres sont des moyennes sectorielles, PAS une prédiction",
        "     pour votre organisation spécifique.",
        "",
    ]

    # Disclosed assumptions
    lines.append("Hypothèses de calcul :")
    for a in est.assumptions:
        lines.append(f"  • {a}")

    return "\n".join(lines)


# ── EXECUTIVE REPORT ─────────────────────────────────────────────────────

def build_executive_report(
    user:       str,
    row:        dict,
    score:      float,
    severity:   str,
    detections: list,
    action:     str,
    config:     dict,
) -> tuple:

    top     = detections[0] if detections else None
    summary = (
        PLAIN_LANGUAGE.get(top.technique.id, "Une activité inhabituelle a été détectée.")
        if top else "Une activité inhabituelle a été détectée."
    )

    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    title   = f"Alerte sécurité — {user} — {SEVERITY_LABELS[severity]}"

    fin_section = _financial_section(row, detections, severity, config)

    next_steps = "\n".join(NEXT_STEPS_BY_SEVERITY.get(severity, []))

    body = "\n".join([
        f"{SEVERITY_LABELS[severity]}",
        f"Utilisateur concerné : {user}",
        f"Détecté le           : {now_str}",
        f"Score de risque      : {score:.0%}",
        "",
        "──────────────────────────────────────────",
        "CE QUI S'EST PASSÉ",
        "──────────────────────────────────────────",
        summary,
        "",
        "──────────────────────────────────────────",
        "ACTION AUTOMATIQUE PRISE",
        "──────────────────────────────────────────",
        _action_section(action, config),
        "",
        "──────────────────────────────────────────",
        "RECOMMANDATION IMMÉDIATE",
        "──────────────────────────────────────────",
        RECOMMENDATION_BY_SEVERITY[severity],
        "",
        fin_section,
        "",
        "──────────────────────────────────────────",
        "PROCHAINES ÉTAPES",
        "──────────────────────────────────────────",
        next_steps,
        "",
        "— Rapport généré automatiquement par ZeroTrust AI",
        "  Pour le rapport technique complet, contactez votre équipe SOC.",
    ])

    return title, body


# ── TECHNICAL REPORT ─────────────────────────────────────────────────────

def build_technical_report(
    user:              str,
    machine:           str,
    row:               dict,
    score:             float,
    severity:          str,
    detections:        list,
    feature_breakdown: dict,
    config:            dict,
) -> tuple:

    title = f"[{severity.upper()}] {user}@{machine} | score={score:.3f} | {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}"

    biz             = config.get("business_impact", {})
    action_detail   = biz.get("action_confirmed")
    action_success  = biz.get("action_success")
    action_line     = ""
    if action_detail is not None:
        icon        = "OK " if action_success else "FAIL"
        action_line = f"  Action   : [{icon}] {action_detail}"

    lines = [
        "══════════════════════════════════════════════════════",
        f"  ZEROTRUST AI — TECHNICAL INCIDENT REPORT",
        "══════════════════════════════════════════════════════",
        f"  User     : {user}",
        f"  Machine  : {machine}",
        f"  Window   : {row.get('window_start', '?')}",
        f"  Events   : {row.get('total_events', 0)}",
        f"  Score    : {score:.4f}  ({severity.upper()})",
    ]
    if action_line:
        lines.append(action_line)
    lines += [
        "══════════════════════════════════════════════════════",
        "",
        "── MITRE ATT&CK DETECTIONS ──────────────────────────",
    ]

    if detections:
        for d in detections:
            bar = "█" * int(d.confidence * 10) + "░" * (10 - int(d.confidence * 10))
            lines += [
                f"  [{d.technique.id}] {d.technique.name}",
                f"    Tactic     : {d.technique.tactic}",
                f"    Confidence : {bar} {d.confidence:.0%}",
                f"    Evidence   : {', '.join(d.evidence)}",
                f"    Action     : {d.action}",
                "",
            ]
    else:
        lines.append("  No MITRE techniques triggered this window.\n")

    lines.append("── SCORE CONTRIBUTION (sorted by weight) ────────────")
    for feat, contrib in sorted(feature_breakdown.items(),
                                key=lambda kv: kv[1], reverse=True):
        bar = "█" * int(contrib * 40)
        lines.append(f"  {feat:<22} +{contrib:.4f}  {bar}")

    lines += ["", "── RAW FEATURE VALUES (non-zero) ────────────────────"]
    raw_fields = [
        ("signin_count",        "Signins"),
        ("failed_logins",       "Failed logins"),
        ("is_off_hours_login",  "Off-hours login"),
        ("mfa_used",            "MFA used"),
        ("risk_level_max",      "Risk level (max)"),
        ("group_change",        "Group changes"),
        ("role_assigned",       "Roles assigned"),
        ("process_count",       "Processes created"),
        ("suspicious_pairs",    "Suspicious proc pairs"),
        ("encoded_cmds",        "Encoded commands"),
        ("download_cmds",       "Download commands"),
        ("elevated_procs",      "Elevated processes"),
        ("backup_deletion",     "Shadow copy deletion"),
        ("net_count",           "Network connections"),
        ("external_conns",      "External connections"),
        ("suspicious_ports",    "Suspicious ports"),
        ("lsass_access",        "lsass access events"),
        ("lsass_dump_score",    "lsass dump score"),
        ("file_writes",         "File writes"),
        ("suspicious_writes",   "Suspicious file writes"),
        ("extension_changes",   "Extension changes"),
        ("registry_writes",     "Registry writes"),
        ("persistence_keys",    "Persistence keys"),
    ]
    for field_key, label in raw_fields:
        val = row.get(field_key, 0)
        if val:
            flag = "  ⚠" if val > 0 and field_key in (
                "lsass_access", "lsass_dump_score", "backup_deletion",
                "extension_changes", "encoded_cmds", "suspicious_pairs"
            ) else "   "
            lines.append(f"  {flag} {label:<24} {val}")

    lines += ["", "── ENTRA ID ACTIVITY ────────────────────────────────"]
    lines.append(f"    Signins : {row.get('signin_count',0)}   Failed : {row.get('failed_logins',0)}   MFA : {bool(row.get('mfa_used',0))}   Risk : {row.get('risk_level_max',0)}")

    lines += ["", "── ENDPOINT ACTIVITY ────────────────────────────────"]
    lines.append(f"    Procs : {row.get('process_count',0)}   Net : {row.get('net_count',0)}   Files : {row.get('file_writes',0)}   Reg : {row.get('registry_writes',0)}")

    # Financial summary for SOC (short form — full section in executive)
    est = financial_estimate(row, detections, config)
    if est:
        cur = est.currency
        lines += [
            "",
            "── FINANCIAL IMPACT ESTIMATE (worst-case, for SOC context) ─",
            f"    Vector : {est.vector}",
            f"    Range  : {_fmt_currency(est.low,cur)} – {_fmt_currency(est.mid,cur)} – {_fmt_currency(est.high,cur)}",
            f"    Multipliers applied : {len(est.multipliers)}",
            f"    See executive report for full breakdown.",
        ]

    lines += [
        "",
        "══════════════════════════════════════════════════════",
        "  Generated by ZeroTrust AI — ZeroTrust AI v1.0",
        "══════════════════════════════════════════════════════",
    ]

    return title, "\n".join(lines)
