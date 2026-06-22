# reporting/report_html_builder.py
"""
Generates self-contained HTML files for both report variants.
All CSS is embedded — no external dependencies, opens in any browser.

Executive:  dark security dashboard aesthetic, financial impact cards,
            colour-coded severity, readable by non-technical staff
Technical:  monospace terminal feel, MITRE heat bars, raw feature table
"""

from datetime import datetime, timezone
from reporting.financial_estimator import estimate as financial_estimate

# ── SHARED HELPERS ────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "critical": ("#ff3b30", "#2d0a08"),
    "high":     ("#ff9500", "#2d1a00"),
    "medium":   ("#ffcc00", "#2d2500"),
    "info":     ("#34c759", "#0a2d14"),
}
SEVERITY_LABEL = {
    "critical": "CRITIQUE", "high": "ÉLEVÉ",
    "medium": "MOYEN",      "info": "INFORMATIF",
}
ACTION_TEXT = {
    "block": ("Compte bloqué automatiquement", "#ff3b30"),
    "mfa":   ("Sessions révoquées · MFA forcé", "#ff9500"),
    "alert": ("Alerte — supervision manuelle requise", "#ffcc00"),
}

PLAIN_LANGUAGE = {
    "T1003":     "Tentative de vol des mots de passe stockés en mémoire.",
    "T1110":     "Plusieurs tentatives de connexion infructueuses détectées.",
    "T1059":     "Commande suspecte exécutée sur un poste de travail.",
    "T1059.001": "Commande dissimulée/chiffrée exécutée sur un poste de travail.",
    "T1547":     "Programme installé pour démarrer automatiquement avec Windows.",
    "T1078":     "Compte utilisateur utilisé dans des conditions inhabituelles.",
    "T1078.002": "Compte ayant obtenu des droits d'accès élevés de façon suspecte.",
    "T1562":     "Protection de sécurité (audit, MFA) désactivée ou modifiée.",
    "T1021":     "Déplacement suspect entre plusieurs machines détecté.",
    "T1486":     "Signes de rançongiciel détectés — chiffrement massif de fichiers.",
    "T1071":     "Communication suspecte vers un serveur externe.",
    "T1041":     "Transfert important de données vers l'extérieur.",
}
RECOMMENDATION = {
    "critical": "Vérifier l'identité physiquement avant toute réactivation. Contacter l'équipe sécurité immédiatement.",
    "high":     "Contacter l'utilisateur pour confirmer l'activité avant la fin de journée.",
    "medium":   "Surveiller ce compte lors des prochaines heures.",
    "info":     "Aucune action requise pour le moment.",
}
NEXT_STEPS = {
    "critical": ["Vérifier si d'autres comptes ont été compromis",
                 "Changer tous les mots de passe des systèmes impactés",
                 "Activer la journalisation avancée sur les systèmes concernés",
                 "Notifier la direction et le DPO",
                 "Évaluer l'obligation de notification RGPD (72h si données personnelles)"],
    "high":     ["Forcer la réinitialisation du mot de passe utilisateur",
                 "Vérifier les accès récents dans les journaux Azure AD",
                 "Confirmer avec le responsable si l'activité est légitime"],
    "medium":   ["Surveiller les prochaines connexions de cet utilisateur",
                 "Vérifier s'il existe des anomalies sur d'autres comptes"],
    "info":     ["Aucune action urgente requise",
                 "Inclure dans le rapport mensuel de sécurité"],
}

def _fmt(amount, currency="EUR"):
    sym = {"USD": "$", "EUR": "€", "MAD": "MAD "}.get(currency, currency + " ")
    return f"{sym}{amount:,.0f}"

def _now():
    return datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")

def severity_from_score(score, config):
    s = config.get("scoring", {})
    if score >= s.get("block_threshold", 0.85): return "critical"
    if score >= s.get("mfa_threshold",   0.70): return "high"
    if score >= s.get("alert_threshold", 0.50): return "medium"
    return "info"


# ══════════════════════════════════════════════════════════════════════════
# EXECUTIVE REPORT
# ══════════════════════════════════════════════════════════════════════════

_EXEC_CSS = """
* { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --border:   #30363d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --accent:   #58a6ff;
}
body {
  font-family: -apple-system, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 0;
}
.page { max-width: 860px; margin: 0 auto; padding: 40px 24px 80px; }

/* Header */
.header { border-bottom: 1px solid var(--border); padding-bottom: 28px; margin-bottom: 32px; }
.header-top { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }
.logo { font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); }
.logo strong { color:var(--accent); font-size:15px; display:block; letter-spacing:.04em; margin-bottom:2px; }
.badge {
  padding: 6px 16px; border-radius: 4px; font-size:12px;
  font-weight:700; letter-spacing:.08em; text-transform:uppercase;
}
.meta { margin-top:20px; display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.meta-item { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px 16px; }
.meta-item .label { font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-bottom:4px; }
.meta-item .value { font-size:15px; font-weight:600; }

/* Score bar */
.score-wrap { margin:28px 0; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px 24px; }
.score-label { font-size:11px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-bottom:10px; }
.score-bar-bg { height:8px; background:#21262d; border-radius:4px; overflow:hidden; }
.score-bar-fill { height:100%; border-radius:4px; transition:width .6s; }
.score-number { margin-top:8px; font-size:28px; font-weight:700; }

/* Sections */
.section { margin-bottom:24px; }
.section-title {
  font-size:10px; text-transform:uppercase; letter-spacing:.12em;
  color:var(--muted); margin-bottom:10px; padding-bottom:6px;
  border-bottom:1px solid var(--border);
}
.card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:18px 20px; }
.card + .card { margin-top:10px; }

/* Action banner */
.action-banner {
  border-radius:8px; padding:16px 20px;
  border-left:4px solid;
  display:flex; align-items:center; gap:14px;
  font-weight:600; font-size:15px;
}
.action-icon { font-size:22px; }

/* Financial cards */
.fin-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:14px; }
.fin-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px; text-align:center; }
.fin-card .fin-label { font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-bottom:6px; }
.fin-card .fin-amount { font-size:22px; font-weight:700; }
.fin-card.central { border-color:var(--accent); }
.fin-card.central .fin-amount { color:var(--accent); }
.multipliers { display:flex; flex-direction:column; gap:6px; margin-bottom:14px; }
.mult-row { display:flex; align-items:center; gap:10px; font-size:13px; }
.mult-badge {
  background:#1f2937; border:1px solid #374151; border-radius:4px;
  padding:2px 8px; font-size:11px; font-weight:700; min-width:42px; text-align:center; color:#f59e0b;
}
.mult-reason { color:var(--muted); font-size:12px; }
.downtime-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.dt-item { background:#0d1117; border-radius:6px; padding:12px 14px; }
.dt-item .dt-label { font-size:10px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:4px; }
.dt-item .dt-val { font-size:16px; font-weight:600; }
.gdpr-box { background:#1a0a0a; border:1px solid #5c1a1a; border-radius:6px; padding:14px 16px; margin-top:10px; }
.gdpr-box .gdpr-title { color:#ff6b6b; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
.ref-box { background:#0d1117; border-left:3px solid var(--border); padding:10px 14px; margin-top:10px; font-size:12px; color:var(--muted); border-radius:0 4px 4px 0; }

/* Steps */
.steps { list-style:none; display:flex; flex-direction:column; gap:8px; }
.steps li { display:flex; gap:12px; align-items:flex-start; font-size:14px; }
.step-num { background:var(--accent); color:#000; border-radius:50%; width:22px; height:22px;
  font-size:11px; font-weight:700; display:flex; align-items:center; justify-content:center; flex-shrink:0; margin-top:1px; }
.assumption { font-size:11px; color:var(--muted); border-top:1px solid var(--border);
  padding-top:10px; margin-top:10px; line-height:1.7; }

/* Footer */
.footer { margin-top:48px; border-top:1px solid var(--border); padding-top:18px;
  font-size:11px; color:var(--muted); display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }

@media(max-width:600px){
  .fin-grid { grid-template-columns:1fr; }
  .downtime-grid { grid-template-columns:1fr; }
  .header-top { flex-direction:column; }
}
"""

def build_executive_html(user, row, score, severity, detections, action, config):
    top        = detections[0] if detections else None
    sev_color, sev_bg = SEVERITY_COLOR[severity]
    sev_label  = SEVERITY_LABEL[severity]
    summary    = PLAIN_LANGUAGE.get(top.technique.id, "Activité inhabituelle détectée.") if top else "Activité inhabituelle détectée."
    act_text, act_color = ACTION_TEXT.get(action, ACTION_TEXT["alert"])
    act_icon   = {"block": "🔒", "mfa": "🔐", "alert": "⚠️"}.get(action, "⚠️")
    biz_cfg    = config.get("business_impact", {})
    confirm_detail  = biz_cfg.get("action_confirmed")
    confirm_success = biz_cfg.get("action_success")
    score_pct  = int(score * 100)
    est        = financial_estimate(row, detections, config)
    cur        = config.get("business_impact", {}).get("currency", "EUR")
    recs       = NEXT_STEPS.get(severity, [])

    # Financial section
    fin_html = ""
    if est:
        mults_html = "".join(f"""
          <div class="mult-row">
            <span class="mult-badge">×{m.value:.1f}</span>
            <div>
              <span>{m.label}</span>
              <span class="mult-reason"> — {m.reason}</span>
            </div>
          </div>""" for m in est.multipliers)

        dt_html = ""
        if est.downtime:
            dt = est.downtime
            dt_html = f"""
          <div class="section-title" style="margin-top:16px">Détail arrêt système</div>
          <div class="downtime-grid">
            <div class="dt-item"><div class="dt-label">Durée</div><div class="dt-val">{dt['hours']}h</div></div>
            <div class="dt-item"><div class="dt-label">Coût / heure</div><div class="dt-val">{_fmt(dt['cost_per_hour'],cur)}</div></div>
            <div class="dt-item"><div class="dt-label">Pertes revenus</div><div class="dt-val">{_fmt(dt['breakdown']['lost_revenue'],cur)}</div></div>
            <div class="dt-item"><div class="dt-label">Perte productivité</div><div class="dt-val">{_fmt(dt['breakdown']['lost_productivity'],cur)}</div></div>
          </div>"""

        reg_html = ""
        if est.regulatory:
            reg = est.regulatory
            reg_html = f"""
          <div class="gdpr-box">
            <div class="gdpr-title">⚖ Exposition RGPD</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px;">
              <div><div class="dt-label">Enregistrements à risque</div><strong>{reg['records_at_risk']:,}</strong></div>
              <div><div class="dt-label">Coût notification estimé</div><strong>{_fmt(reg['notification_cost'],cur)}</strong></div>
              <div style="grid-column:1/-1"><div class="dt-label">Amende RGPD max possible</div>
                <strong style="color:#ff6b6b;font-size:18px">{_fmt(reg['gdpr_worst_case_fine'],cur)}</strong></div>
            </div>
            <div style="font-size:11px;color:#8b949e;margin-top:8px">{reg['note']}</div>
          </div>"""

        assump = " &bull; ".join(est.assumptions)
        fin_html = f"""
        <div class="section">
          <div class="section-title">Impact financier estimé — pire cas</div>
          <div class="fin-grid">
            <div class="fin-card">
              <div class="fin-label">Fourchette basse</div>
              <div class="fin-amount">{_fmt(est.low,cur)}</div>
            </div>
            <div class="fin-card central">
              <div class="fin-label">Scénario central</div>
              <div class="fin-amount">{_fmt(est.mid,cur)}</div>
            </div>
            <div class="fin-card">
              <div class="fin-label">Pire cas</div>
              <div class="fin-amount">{_fmt(est.high,cur)}</div>
            </div>
          </div>
          <div class="card">
            <div class="section-title">Facteurs aggravants détectés</div>
            <div class="multipliers">{mults_html}</div>
            {dt_html}
            {reg_html}
            <div class="ref-box">
              <strong>Référence sectorielle</strong> — {est.benchmark_label}<br>
              {_fmt(est.benchmark_low,cur)} – {_fmt(est.benchmark_high,cur)}
              &nbsp;·&nbsp; <em>{est.benchmark_source}</em><br>
              ⚠ Moyennes sectorielles — pas une prédiction pour votre organisation.
            </div>
            <div class="assumption">{assump}</div>
          </div>
        </div>"""

    steps_html = "".join(f'<li><span class="step-num">{i+1}</span><span>{s}</span></li>' for i, s in enumerate(recs))

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alerte Sécurité — {user} — {sev_label}</title>
<style>{_EXEC_CSS}</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div class="header-top">
      <div class="logo">
        <strong>ZeroTrust AI</strong>
        Rapport d'incident — Confidentiel Direction
      </div>
      <span class="badge" style="background:{sev_bg};color:{sev_color};border:1px solid {sev_color}">
        {sev_label}
      </span>
    </div>
    <div class="meta">
      <div class="meta-item"><div class="label">Utilisateur</div><div class="value">{user}</div></div>
      <div class="meta-item"><div class="label">Détecté le</div><div class="value" style="font-size:13px">{_now()}</div></div>
      <div class="meta-item"><div class="label">Technique principale</div>
        <div class="value" style="font-size:13px">{top.technique.id + " — " + top.technique.name if top else "—"}</div></div>
      <div class="meta-item"><div class="label">Tactique</div>
        <div class="value" style="font-size:13px">{top.technique.tactic if top else "—"}</div></div>
    </div>
  </div>

  <!-- SCORE -->
  <div class="score-wrap">
    <div class="score-label">Score de risque</div>
    <div class="score-bar-bg">
      <div class="score-bar-fill" style="width:{score_pct}%;background:{sev_color}"></div>
    </div>
    <div class="score-number" style="color:{sev_color}">{score_pct}%</div>
  </div>

  <!-- WHAT HAPPENED -->
  <div class="section">
    <div class="section-title">Ce qui s'est passé</div>
    <div class="card" style="font-size:15px;line-height:1.7">{summary}</div>
  </div>

  <!-- ACTION TAKEN -->
  <div class="section">
    <div class="section-title">Action automatique prise</div>
    <div class="action-banner" style="background:{sev_bg};border-color:{act_color}">
      <span class="action-icon">{act_icon}</span>
      <span style="color:{act_color}">{act_text}</span>
    </div>
    {f'''<div style="margin-top:8px;font-size:13px;color:{"#3fb950" if confirm_success else "#ff3b30"}">
      {"✅" if confirm_success else "❌"} Confirmation : {confirm_detail}
    </div>''' if confirm_detail else ""}
  </div>

  <!-- RECOMMENDATION -->
  <div class="section">
    <div class="section-title">Recommandation immédiate</div>
    <div class="card">{RECOMMENDATION[severity]}</div>
  </div>

  <!-- FINANCIAL IMPACT -->
  {fin_html}

  <!-- NEXT STEPS -->
  <div class="section">
    <div class="section-title">Prochaines étapes</div>
    <div class="card"><ul class="steps">{steps_html}</ul></div>
  </div>

  <div class="footer">
    <span>ZeroTrust AI — Rapport généré automatiquement</span>
    <span>Pour le rapport technique complet, contactez votre équipe SOC.</span>
  </div>
</div>
</body>
</html>"""
    return f"Alerte Sécurité — {user} — {sev_label}", html


# ══════════════════════════════════════════════════════════════════════════
# TECHNICAL REPORT
# ══════════════════════════════════════════════════════════════════════════

_TECH_CSS = """
* { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg:      #0a0e14;
  --surface: #0d1117;
  --panel:   #161b22;
  --border:  #21262d;
  --text:    #cdd9e5;
  --muted:   #636e7b;
  --green:   #3fb950;
  --yellow:  #d29922;
  --red:     #f85149;
  --orange:  #db6d28;
  --blue:    #58a6ff;
  --purple:  #bc8cff;
  --mono: 'JetBrains Mono','Fira Code','Cascadia Code',monospace;
}
body { font-family:var(--mono); background:var(--bg); color:var(--text); font-size:13px; line-height:1.6; }
.page { max-width:1000px; margin:0 auto; padding:32px 20px 80px; }

/* Header bar */
.topbar {
  background:var(--surface); border:1px solid var(--border); border-radius:8px;
  padding:16px 20px; margin-bottom:24px;
  display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;
}
.topbar-left .product { font-size:12px; letter-spacing:.1em; text-transform:uppercase; color:var(--blue); font-weight:700; }
.topbar-left .subtitle { font-size:11px; color:var(--muted); margin-top:2px; }
.sev-pill {
  padding:4px 14px; border-radius:20px; font-size:11px; font-weight:700;
  letter-spacing:.08em; text-transform:uppercase;
}

/* Meta grid */
.meta-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin-bottom:24px; }
.meta-cell { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:12px 14px; }
.meta-cell .k { font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-bottom:3px; }
.meta-cell .v { font-weight:600; font-size:14px; }

/* Section */
.block { margin-bottom:20px; }
.block-title {
  font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted);
  margin-bottom:8px; display:flex; align-items:center; gap:8px;
}
.block-title::after { content:''; flex:1; height:1px; background:var(--border); }

/* MITRE card */
.technique-card { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:14px 16px; margin-bottom:8px; }
.tech-header { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
.tech-id { color:var(--blue); font-weight:700; font-size:13px; }
.tech-name { color:var(--text); font-weight:600; }
.tech-tactic { font-size:11px; color:var(--purple); text-transform:uppercase; letter-spacing:.06em; }
.conf-bar-bg { height:4px; background:var(--border); border-radius:2px; margin:8px 0 6px; }
.conf-bar-fill { height:100%; border-radius:2px; }
.evidence-list { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
.evidence-pill {
  background:#1c2128; border:1px solid var(--border); border-radius:4px;
  padding:2px 10px; font-size:11px; color:var(--yellow);
}
.action-pill { font-size:11px; font-weight:700; padding:3px 10px; border-radius:4px; }

/* Breakdown bars */
.feat-row { display:flex; align-items:center; gap:10px; margin-bottom:5px; font-size:12px; }
.feat-name { color:var(--muted); min-width:180px; }
.feat-bar-bg { flex:1; height:6px; background:var(--border); border-radius:3px; overflow:hidden; }
.feat-bar-fill { height:100%; border-radius:3px; background: linear-gradient(90deg,#1f6feb,var(--blue)); }
.feat-val { color:var(--blue); min-width:48px; text-align:right; }

/* Raw feature table */
table { width:100%; border-collapse:collapse; font-size:12px; }
th { background:var(--surface); color:var(--muted); text-align:left; padding:6px 10px;
     border-bottom:1px solid var(--border); text-transform:uppercase; font-size:10px; letter-spacing:.08em; }
td { padding:5px 10px; border-bottom:1px solid var(--border); }
tr:last-child td { border-bottom:none; }
.warn { color:var(--red); font-weight:700; }
.ok   { color:var(--green); }

/* Financial mini block */
.fin-mini { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }
.fin-mini-cell { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:10px 12px; }
.fin-mini-cell .lbl { font-size:10px; color:var(--muted); margin-bottom:3px; }
.fin-mini-cell .val { font-size:15px; font-weight:700; color:var(--blue); }

.footer { margin-top:40px; border-top:1px solid var(--border); padding-top:14px;
  font-size:11px; color:var(--muted); display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; }

@media(max-width:640px){ .fin-mini{grid-template-columns:1fr;} .meta-grid{grid-template-columns:1fr 1fr;} }
"""

_ACTION_PILL_STYLE = {
    "block": ("background:#3d0000;color:#ff6b6b;border:1px solid #7f1d1d", "BLOQUER"),
    "mfa":   ("background:#2d1a00;color:#f59e0b;border:1px solid #78350f", "FORCER MFA"),
    "alert": ("background:#1c200d;color:#84cc16;border:1px solid #365314", "ALERTER"),
}

def build_technical_html(user, machine, row, score, severity, detections, feature_breakdown, config):
    sev_color, sev_bg = SEVERITY_COLOR[severity]
    sev_label  = SEVERITY_LABEL[severity]
    score_pct  = int(score * 100)
    est        = financial_estimate(row, detections, config)
    cur        = config.get("business_impact", {}).get("currency", "EUR")

    # MITRE cards
    tech_cards = ""
    for d in detections:
        conf_pct = int(d.confidence * 100)
        a_style, a_label = _ACTION_PILL_STYLE.get(d.action, _ACTION_PILL_STYLE["alert"])
        evid = "".join(f'<span class="evidence-pill">{e}</span>' for e in d.evidence)
        tech_cards += f"""
        <div class="technique-card">
          <div class="tech-header">
            <div>
              <span class="tech-id">{d.technique.id}</span>
              <span class="tech-name"> — {d.technique.name}</span><br>
              <span class="tech-tactic">{d.technique.tactic}</span>
            </div>
            <div style="text-align:right">
              <div style="font-size:18px;font-weight:700;color:{sev_color}">{conf_pct}%</div>
              <div style="font-size:10px;color:var(--muted)">confiance</div>
            </div>
          </div>
          <div class="conf-bar-bg">
            <div class="conf-bar-fill" style="width:{conf_pct}%;background:{sev_color}"></div>
          </div>
          <div class="evidence-list">{evid}</div>
          <div style="margin-top:8px">
            <span class="action-pill" style="{a_style}">ACTION: {a_label}</span>
          </div>
        </div>"""

    if not tech_cards:
        tech_cards = '<div style="color:var(--muted);padding:12px">Aucune technique MITRE déclenchée.</div>'

    # Score contribution bars
    max_contrib = max(feature_breakdown.values(), default=1)
    bar_rows = ""
    for feat, val in sorted(feature_breakdown.items(), key=lambda kv: kv[1], reverse=True):
        pct = int((val / max_contrib) * 100)
        bar_rows += f"""
        <div class="feat-row">
          <span class="feat-name">{feat}</span>
          <div class="feat-bar-bg"><div class="feat-bar-fill" style="width:{pct}%"></div></div>
          <span class="feat-val">+{val:.4f}</span>
        </div>"""

    # Raw features table
    RAW = [
        ("signin_count",       "Signins"),
        ("failed_logins",      "Échecs de connexion"),
        ("is_off_hours_login", "Hors horaires"),
        ("mfa_used",           "MFA utilisé"),
        ("risk_level_max",     "Niveau de risque (max)"),
        ("group_change",       "Changements de groupe"),
        ("role_assigned",      "Rôles attribués"),
        ("process_count",      "Processus créés"),
        ("suspicious_pairs",   "Paires suspectes"),
        ("encoded_cmds",       "Commandes chiffrées"),
        ("download_cmds",      "Commandes download"),
        ("elevated_procs",     "Processus élevés"),
        ("backup_deletion",    "Suppression sauvegardes"),
        ("net_count",          "Connexions réseau"),
        ("external_conns",     "Connexions externes"),
        ("suspicious_ports",   "Ports suspects"),
        ("lsass_access",       "Accès lsass"),
        ("lsass_dump_score",   "Score dump lsass"),
        ("file_writes",        "Écritures fichiers"),
        ("suspicious_writes",  "Écritures suspectes"),
        ("extension_changes",  "Changements extension"),
        ("registry_writes",    "Écritures registre"),
        ("persistence_keys",   "Clés de persistance"),
    ]
    HIGH_RISK = {"lsass_access","lsass_dump_score","backup_deletion",
                 "extension_changes","encoded_cmds","suspicious_pairs","suspicious_writes"}
    table_rows = ""
    for field_key, label in RAW:
        val = row.get(field_key, 0)
        if val:
            css = "warn" if field_key in HIGH_RISK else "ok"
            flag = "⚠" if field_key in HIGH_RISK else "✓"
            table_rows += f'<tr><td class="{css}">{flag}</td><td>{label}</td><td><code>{field_key}</code></td><td class="{css}">{val}</td></tr>'
    if not table_rows:
        table_rows = '<tr><td colspan="4" style="color:var(--muted);padding:12px">Aucun indicateur non-nul.</td></tr>'

    # Financial mini
    fin_html = ""
    if est:
        fin_html = f"""
        <div class="block">
          <div class="block-title">Estimation financière (pire cas)</div>
          <div class="fin-mini">
            <div class="fin-mini-cell"><div class="lbl">Vecteur</div><div class="val" style="font-size:13px">{est.vector}</div></div>
            <div class="fin-mini-cell"><div class="lbl">Fourchette</div><div class="val" style="font-size:12px">{_fmt(est.low,cur)} – {_fmt(est.high,cur)}</div></div>
            <div class="fin-mini-cell"><div class="lbl">Central</div><div class="val">{_fmt(est.mid,cur)}</div></div>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:8px">
            {len(est.multipliers)} facteurs aggravants appliqués — voir rapport exécutif pour le détail.
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>[{severity.upper()}] {user}@{machine}</title>
<style>{_TECH_CSS}</style>
</head>
<body>
<div class="page">

  <!-- TOPBAR -->
  <div class="topbar">
    <div class="topbar-left">
      <div class="product">ZeroTrust AI — Rapport Technique SOC</div>
      <div class="subtitle">Classification : CONFIDENTIEL ÉQUIPE SÉCURITÉ</div>
    </div>
    <span class="sev-pill" style="background:{sev_bg};color:{sev_color};border:1px solid {sev_color}">
      {sev_label}
    </span>
  </div>

  <!-- META -->
  <div class="meta-grid">
    <div class="meta-cell"><div class="k">Utilisateur</div><div class="v">{user}</div></div>
    <div class="meta-cell"><div class="k">Machine</div><div class="v" style="font-size:12px">{machine}</div></div>
    <div class="meta-cell"><div class="k">Score de risque</div><div class="v" style="color:{sev_color}">{score_pct}%</div></div>
    <div class="meta-cell"><div class="k">Fenêtre d'analyse</div><div class="v" style="font-size:12px">{row.get('window_start','?')[:16]}</div></div>
    <div class="meta-cell"><div class="k">Événements analysés</div><div class="v">{row.get('total_events',0)}</div></div>
    <div class="meta-cell"><div class="k">Généré le</div><div class="v" style="font-size:12px">{_now()}</div></div>
  </div>

  <!-- MITRE -->
  <div class="block">
    <div class="block-title">Détections MITRE ATT&CK</div>
    {tech_cards}
  </div>

  <!-- SCORE BREAKDOWN -->
  <div class="block">
    <div class="block-title">Contribution au score (par feature)</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:16px 18px">
      {bar_rows}
    </div>
  </div>

  <!-- RAW FEATURES -->
  <div class="block">
    <div class="block-title">Indicateurs bruts (valeurs non-nulles)</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:6px;overflow:auto">
      <table>
        <tr><th></th><th>Indicateur</th><th>Champ</th><th>Valeur</th></tr>
        {table_rows}
      </table>
    </div>
  </div>

  <!-- ENTRA + ENDPOINT SUMMARY -->
  <div class="block">
    <div class="block-title">Synthèse activité</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div style="background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px 16px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:8px">Entra ID</div>
        <div>Signins: <strong>{row.get('signin_count',0)}</strong> &nbsp;|&nbsp; Échecs: <strong>{row.get('failed_logins',0)}</strong></div>
        <div>MFA: <strong>{'Oui' if row.get('mfa_used') else 'Non'}</strong> &nbsp;|&nbsp; Risque: <strong>{row.get('risk_level_max',0)}</strong></div>
      </div>
      <div style="background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px 16px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:8px">Endpoint (Sysmon)</div>
        <div>Processus: <strong>{row.get('process_count',0)}</strong> &nbsp;|&nbsp; Réseau: <strong>{row.get('net_count',0)}</strong></div>
        <div>Fichiers: <strong>{row.get('file_writes',0)}</strong> &nbsp;|&nbsp; Registre: <strong>{row.get('registry_writes',0)}</strong></div>
      </div>
    </div>
  </div>

  {fin_html}

  <div class="footer">
    <span>ZeroTrust AI v1.0 — Rapport technique automatique</span>
    <span>{user} · {machine} · score={score:.4f}</span>
  </div>
</div>
</body>
</html>"""

    return f"[{severity.upper()}] {user}@{machine} — Technical Report", html
