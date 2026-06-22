# reporting/technical_report_v2.py
"""
Single-file technical incident report. Combines the SOC technical
detail and the board-level financial/operational chapters into one
HTML document, per the explicit structure requested: cover page,
executive summary, 7 chapters, annexes (A-D), footer.

Design system (locked, must match reporting/charts.py exactly):
  - Background zinc-950-equivalent, never pure black: #11151C
  - One brand accent (desaturated institutional blue): #5B92D6
  - Severity palette (semantic only, never decorative): red/orange/gold/teal
  - Fonts: Public Sans (text) + IBM Plex Mono (data, IDs, code) - no Inter, no serif
  - Single corner-radius scale: 6px everywhere
  - No em dash anywhere in visible text
  - No repeated eyebrow micro-labels per section (numbered headings only)

Usage:
    from reporting.incident_data import IncidentData
    from reporting.technical_report_v2 import build_report
    title, html = build_report(incident, charts)
"""

from datetime import datetime, timezone

# ── LOCKED PALETTE (mirrors charts.py) ────────────────────────────────
BG      = "#11151C"
PANEL   = "#171C25"
PANEL2  = "#1C2230"
GRID    = "#262E3B"
TEXT    = "#D7DEE7"
MUTED   = "#7C879A"
ACCENT  = "#5B92D6"
CRIT    = "#D9594E"
HIGH    = "#D98A3D"
MED     = "#C9AE4A"
INFO    = "#3FA589"

SEV_COLOR = {"critical": CRIT, "high": HIGH, "medium": MED, "info": INFO}
SEV_LABEL = {"critical": "CRITIQUE", "high": "ELEVE", "medium": "MOYEN", "info": "INFORMATIF"}

VECTOR_PLAYBOOK = {
    "ransomware": {
        "containment": "Isoler les machines touchees du reseau (desactivation carte reseau ou VLAN de quarantaine). Ne pas eteindre les machines : la memoire vive peut contenir des cles de dechiffrement.",
        "eradication": "Identifier et supprimer le binaire malveillant et ses mecanismes de persistance. Reinitialiser tous les identifiants potentiellement exposes.",
        "recovery":    "Restaurer les fichiers chiffres depuis une sauvegarde anterieure a l'infection. Verifier l'integrite des sauvegardes avant restauration.",
        "checklist":   "Tester la restauration reelle des sauvegardes, pas seulement leur existence.",
        "future":      "Ransomware avec triple extorsion (chiffrement, exfiltration, menace de publication) reste le scenario de recidive le plus probable pour ce vecteur.",
    },
    "credential_dump": {
        "containment": "Forcer la deconnexion de toutes les sessions actives de l'utilisateur concerne.",
        "eradication": "Reinitialiser le mot de passe de tous les comptes ayant pu etre exposes via ce poste, y compris les comptes de service.",
        "recovery":    "Reactiver l'acces uniquement apres confirmation que le poste est assaini (reimagement recommande).",
        "checklist":   "Verifier si Credential Guard et LSA Protection sont actives sur ce poste.",
        "future":      "Revente des identifiants compromis sur des marches clandestins, suivie d'un acces ulterieur par un tiers different.",
    },
}
DEFAULT_PLAYBOOK = {
    "containment": "Isoler le poste concerne et limiter les acces du compte utilisateur.",
    "eradication": "Identifier et neutraliser la cause racine de l'activite detectee.",
    "recovery":    "Reactiver l'acces apres verification de l'assainissement complet.",
    "checklist":   "Documenter l'incident dans le registre de securite.",
    "future":      "Recidive possible du meme vecteur tant que la cause racine n'est pas corrigee.",
}

PRIORITY_PLAN = {
    "critical": [
        ("P0", "Isoler la machine du reseau", "moins d'1h", "Equipe IR"),
        ("P0", "Tester la restauration de sauvegarde", "moins de 4h", "Equipe Sauvegarde"),
        ("P1", "Supprimer le mecanisme de persistance identifie", "moins de 8h", "Equipe IR"),
        ("P1", "Reinitialiser tous les identifiants exposes", "moins de 8h", "Equipe Identite"),
        ("P2", "Analyser les IOCs dans le SIEM", "moins de 24h", "Equipe SOC"),
        ("P3", "Mettre a jour les regles EDR", "moins de 72h", "Equipe Securite"),
    ],
    "high": [
        ("P1", "Confirmer l'activite avec l'utilisateur concerne", "24h", "Manager direct"),
        ("P1", "Verifier les acces recents dans les journaux Azure AD", "24h", "Equipe SOC"),
        ("P2", "Analyser les IOCs dans le SIEM", "7 jours", "Equipe SOC"),
    ],
    "medium": [
        ("P2", "Surveiller le compte sur les prochaines 48h", "48h", "Equipe SOC"),
        ("P3", "Documenter l'incident", "14 jours", "RSSI"),
    ],
    "info": [
        ("P3", "Inclure dans le rapport mensuel de securite", "30 jours", "RSSI"),
    ],
}

GLOSSARY = [
    ("Sysmon", "Outil de journalisation systeme Windows utilise pour la telemetrie endpoint."),
    ("Entra ID", "Service d'identite et d'acces de Microsoft (anciennement Azure AD)."),
    ("MITRE ATT&CK", "Referentiel standard des tactiques et techniques d'attaque observees."),
    ("lsass.exe", "Processus Windows gerant l'authentification, cible frequente du vol d'identifiants."),
    ("Ransomware", "Logiciel malveillant chiffrant des fichiers en echange d'une rancon."),
    ("MFA", "Authentification multi-facteurs (mot de passe plus second facteur)."),
    ("IOC", "Indicateur de compromission : artefact technique signalant une activite malveillante."),
    ("RGPD", "Reglement General sur la Protection des Donnees (Union Europeenne)."),
    ("Kill chain", "Sequence des etapes d'une attaque, de l'acces initial a l'impact final."),
    ("SOC", "Security Operations Center, equipe en charge de la surveillance securite continue."),
]


def _fmt(amount, currency="EUR"):
    if amount is None:
        return "Non disponible"
    sym = {"USD": "$", "EUR": "EUR ", "MAD": "MAD "}.get(currency, currency + " ")
    return f"{sym}{amount:,.0f}".replace(",", " ")


def _now_str():
    return datetime.now(timezone.utc).strftime("%d/%m/%Y a %H:%M UTC")


def _img(b64: str, alt: str) -> str:
    if not b64:
        return f'<p class="chart-missing">Graphique non disponible : donnees insuffisantes pour "{alt}".</p>'
    return f'<img class="chart" src="data:image/png;base64,{b64}" alt="{alt}">'


def _svg_gauge(pct, color, size=140):
    r = size / 2 - 12
    c = size / 2
    circ = 2 * 3.14159265 * r
    offset = circ * (1 - pct / 100)
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  <circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{GRID}" stroke-width="10"/>
  <circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{color}" stroke-width="10"
    stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"
    transform="rotate(-90 {c} {c})"/>
  <text x="{c}" y="{c-2}" text-anchor="middle" class="gauge-val" style="fill:{color}">{pct}%</text>
  <text x="{c}" y="{c+18}" text-anchor="middle" class="gauge-sub">SCORE</text>
</svg>'''


_CSS = f"""
@import url('https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');
* {{ margin:0; padding:0; box-sizing:border-box; }}
:root {{
  --bg:{BG}; --panel:{PANEL}; --panel2:{PANEL2}; --grid:{GRID};
  --text:{TEXT}; --muted:{MUTED}; --accent:{ACCENT};
  --crit:{CRIT}; --high:{HIGH}; --med:{MED}; --info:{INFO};
  --radius:6px;
  --sans:'Public Sans',-apple-system,'Segoe UI',sans-serif;
  --mono:'IBM Plex Mono','JetBrains Mono',monospace;
}}
body {{ font-family:var(--sans); background:var(--bg); color:var(--text); font-size:14px; line-height:1.65; }}
.doc {{ max-width:1080px; margin:0 auto; padding:0 0 90px; }}

/* COVER */
.cover {{ background:var(--panel); border-bottom:2px solid var(--accent); padding:40px 48px; position:relative; }}
.stamp {{
  position:absolute; top:34px; right:48px; border:2px solid var(--crit); color:var(--crit);
  padding:7px 16px; font-family:var(--mono); font-size:11px; font-weight:700; letter-spacing:.1em;
  border-radius:var(--radius);
}}
.wordmark {{ font-family:var(--mono); font-size:11px; letter-spacing:.16em; color:var(--accent); text-transform:uppercase; }}
.cover h1 {{ font-size:25px; font-weight:700; margin:12px 0 18px; max-width:680px; }}
.cover-meta {{ display:grid; grid-template-columns:repeat(5,1fr); gap:16px; border-top:1px solid var(--grid); padding-top:18px; }}
.cover-meta .k {{ font-size:9.5px; text-transform:uppercase; color:var(--muted); letter-spacing:.08em; margin-bottom:4px; }}
.cover-meta .v {{ font-family:var(--mono); font-size:13px; font-weight:600; }}

/* LAYOUT */
.layout {{ display:grid; grid-template-columns:190px 1fr; }}
.toc {{ padding:32px 18px; border-right:1px solid var(--grid); position:sticky; top:0; align-self:start; max-height:100vh; overflow:auto; }}
.toc-title {{ font-size:9.5px; text-transform:uppercase; color:var(--muted); letter-spacing:.1em; margin-bottom:12px; }}
.toc a {{ display:block; font-size:11.5px; color:var(--text); text-decoration:none; padding:5px 0 5px 9px; border-left:2px solid transparent; }}
.toc a:hover {{ color:var(--accent); border-left-color:var(--accent); }}
.content {{ padding:34px 44px; }}

/* CHAPTERS */
.chapter {{ margin-bottom:38px; scroll-margin-top:18px; }}
.chapter h2 {{ font-size:18px; font-weight:700; margin-bottom:14px; padding-bottom:9px; border-bottom:1px solid var(--grid); }}
.chapter h2 .num {{ color:var(--accent); font-family:var(--mono); margin-right:8px; }}
.chapter h3 {{ font-size:13px; font-weight:600; margin:18px 0 8px; color:var(--accent); }}
.lede {{ font-size:13.5px; max-width:75ch; }}

.panel {{ background:var(--panel); border:1px solid var(--grid); border-radius:var(--radius); padding:16px 18px; margin-bottom:10px; }}

/* GAUGE / SUMMARY */
.gauge-row {{ display:flex; align-items:center; gap:26px; margin-bottom:16px; flex-wrap:wrap; }}
.gauge-val {{ font-family:var(--mono); font-size:23px; font-weight:700; }}
.gauge-sub {{ font-family:var(--mono); font-size:9px; fill:var(--muted); letter-spacing:.1em; }}
.sev-badge {{ display:inline-flex; padding:6px 14px; border-radius:var(--radius); font-family:var(--mono); font-weight:700; font-size:12px; letter-spacing:.05em; }}

table.qa {{ width:100%; border-collapse:collapse; }}
table.qa td {{ padding:9px 4px; border-bottom:1px solid var(--grid); vertical-align:top; }}
table.qa td:first-child {{ width:200px; color:var(--muted); font-size:12px; }}
table.qa td:last-child {{ font-weight:500; }}

/* TABLES */
table.data {{ width:100%; border-collapse:collapse; font-size:12.5px; margin:10px 0 16px; }}
table.data th {{ text-align:left; padding:8px 12px; font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); border-bottom:1px solid var(--grid); }}
table.data td {{ padding:8px 12px; border-bottom:1px solid var(--grid); }}
table.data tr:last-child td {{ border-bottom:none; }}
.pill {{ display:inline-block; padding:2px 10px; border-radius:var(--radius); font-size:10.5px; font-weight:700; font-family:var(--mono); color:#0A0D12; }}

/* CHARTS */
img.chart {{ width:100%; max-width:100%; border-radius:var(--radius); border:1px solid var(--grid); display:block; margin:10px 0 16px; }}
.chart-missing {{ color:var(--muted); font-size:12px; font-style:italic; padding:14px 0; }}

/* FINANCE STAT BLOCKS */
.stat-row {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:14px 0; }}
.stat-block {{ background:var(--panel2); border:1px solid var(--grid); border-left:3px solid var(--accent); border-radius:var(--radius); padding:14px 16px; }}
.stat-block.mid {{ border-left-color:var(--crit); }}
.stat-block .stat-label {{ font-size:9.5px; text-transform:uppercase; color:var(--muted); letter-spacing:.06em; margin-bottom:5px; }}
.stat-block .stat-val {{ font-family:var(--mono); font-size:19px; font-weight:700; }}

.mult-list {{ margin:10px 0; }}
.mult-item {{ display:flex; gap:10px; padding:7px 0; border-bottom:1px solid var(--grid); font-size:12.5px; }}
.mult-tag {{ font-family:var(--mono); font-weight:700; color:var(--high); min-width:38px; }}

.callout {{ background:var(--panel2); border-left:3px solid var(--accent); padding:14px 18px; margin:12px 0; border-radius:0 var(--radius) var(--radius) 0; font-size:12.5px; }}
.callout.crit {{ border-left-color:var(--crit); }}

/* DECISION GRID */
.decision-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:14px 0; }}
.decision-col {{ padding:16px 18px; border-radius:var(--radius); border:1px solid var(--grid); }}
.decision-col.yes {{ border-left:3px solid var(--info); }}
.decision-col.no {{ border-left:3px solid var(--crit); }}
.decision-col h4 {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; margin-bottom:8px; }}
.decision-col ul {{ padding-left:16px; font-size:12.5px; line-height:1.8; }}

/* FOOTER */
.footer {{ padding:26px 44px; border-top:1px solid var(--grid); font-size:10.5px; color:var(--muted); display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; }}

/* CODE/IOC BLOCK */
pre.code {{ background:var(--panel2); border:1px solid var(--grid); border-radius:var(--radius); padding:12px 14px; font-family:var(--mono); font-size:11.5px; overflow:auto; color:var(--text); }}

@media (max-width:760px) {{
  .layout {{ grid-template-columns:1fr; }}
  .toc {{ display:none; }}
  .content {{ padding:22px 18px; }}
  .cover {{ padding:26px 20px; }}
  .stamp {{ position:static; display:inline-block; margin-top:12px; }}
  .stat-row, .decision-grid, .cover-meta {{ grid-template-columns:1fr 1fr; }}
}}
"""


def build_report(incident, charts: dict) -> tuple:
    sev = incident.severity
    color = SEV_COLOR[sev]
    sev_label = SEV_LABEL[sev]
    score_pct = int(incident.score * 100)
    est = incident.financial
    cur = est.currency if est else "EUR"
    vector = est.vector if est else "unknown"
    pb = VECTOR_PLAYBOOK.get(vector, DEFAULT_PLAYBOOK)
    top = incident.detections[0] if incident.detections else None

    # ── TOC ──
    toc_items = [
        ("resume", "Resume executif"), ("ch1", "1. Impact financier"),
        ("ch2", "2. Impact operationnel"), ("ch3", "3. Risques futurs"),
        ("ch4", "4. Mesures deployees"), ("ch5", "5. Recommandations"),
        ("ch6", "6. Indicateurs"), ("ch7", "7. Lecons apprises"), ("annexes", "Annexes"),
    ]
    toc_html = "".join(f'<a href="#{i}">{t}</a>' for i, t in toc_items)

    # ── RESUME ──
    qa_rows = [
        ("Quoi", f"{vector.capitalize()}" + (f" detecte via {top.technique.id}" if top else "")),
        ("Quand", incident.window_start[:16].replace("T", " ")),
        ("Qui", incident.user),
        ("Impact", f"{_fmt(est.low, cur)} a {_fmt(est.high, cur)} (estimation pire cas)" if est else "Non chiffre"),
        ("Action", incident.action_confirmed or "Aucune action confirmee"),
        ("Recommandation", pb["checklist"]),
    ]
    qa_html = "".join(f'<tr><td>{q}</td><td>{a}</td></tr>' for q, a in qa_rows)

    resume_html = f'''
    <div class="gauge-row">
      {_svg_gauge(score_pct, color)}
      <span class="sev-badge" style="background:{color};color:#0A0D12">{sev_label}</span>
    </div>
    <table class="qa">{qa_html}</table>
    {_img(charts.get("event_breakdown",""), "Repartition des evenements par type")}
    '''

    # ── CHAPTER 1: FINANCIAL ──
    if est:
        mult_html = "".join(
            f'<div class="mult-item"><span class="mult-tag">x{m.value:.1f}</span><div><strong>{m.label}</strong><br><span style="color:var(--muted);font-size:11.5px">{m.reason}</span></div></div>'
            for m in est.multipliers
        )
        dt_html = ""
        if est.downtime:
            dt = est.downtime
            dt_html = f'''
            <h3>1.2 Detail de l'arret systeme</h3>
            <table class="data">
              <tr><th>Element</th><th>Valeur</th></tr>
              <tr><td>Duree</td><td>{dt["hours"]}h</td></tr>
              <tr><td>Cout par heure</td><td>{_fmt(dt["cost_per_hour"], cur)}</td></tr>
              <tr><td>Pertes de revenus</td><td>{_fmt(dt["breakdown"]["lost_revenue"], cur)}</td></tr>
              <tr><td>Perte de productivite</td><td>{_fmt(dt["breakdown"]["lost_productivity"], cur)}</td></tr>
              <tr><td><strong>Total arret systeme</strong></td><td><strong>{_fmt(dt["total"], cur)}</strong></td></tr>
            </table>'''
        reg_html = ""
        if est.regulatory:
            reg = est.regulatory
            reg_html = f'''
            <h3>1.3 Exposition reglementaire (RGPD)</h3>
            <div class="callout crit">
              {reg["note"]}<br><br>
              Enregistrements a risque : <strong>{reg["records_at_risk"]:,}</strong><br>
              Cout de notification estime : <strong>{_fmt(reg["notification_cost"], cur)}</strong><br>
              Amende RGPD maximum possible : <strong style="color:var(--crit);font-size:16px">{_fmt(reg["gdpr_worst_case_fine"], cur)}</strong>
            </div>'''
        ch1_html = f'''
        <h3>1.1 Fourchette financiere (estimation pire cas)</h3>
        <div class="stat-row">
          <div class="stat-block"><div class="stat-label">Bas</div><div class="stat-val">{_fmt(est.low, cur)}</div></div>
          <div class="stat-block mid"><div class="stat-label">Central</div><div class="stat-val">{_fmt(est.mid, cur)}</div></div>
          <div class="stat-block"><div class="stat-label">Pire cas</div><div class="stat-val">{_fmt(est.high, cur)}</div></div>
        </div>
        <h3>Facteurs aggravants ({len(est.multipliers)})</h3>
        <div class="mult-list">{mult_html}</div>
        {dt_html}
        {reg_html}
        <h3>Reference sectorielle</h3>
        <div class="callout">
          {est.benchmark_label}<br>
          <strong>{_fmt(est.benchmark_low, cur)} a {_fmt(est.benchmark_high, cur)}</strong>, source : {est.benchmark_source}
          <p style="color:var(--muted);font-size:11px;margin-top:6px">Moyenne sectorielle, non une prediction pour cette organisation specifique.</p>
        </div>
        '''
    else:
        ch1_html = '<p class="lede" style="color:var(--muted)">Non chiffre : configuration business_impact requise.</p>'

    # ── CHAPTER 2: OPERATIONAL ──
    biz = {}
    vms = 1
    downtime_h = 0
    users_imp = incident.row.get("signin_count", 0)
    if est and est.downtime:
        downtime_h = est.downtime["hours"]
    ch2_html = f'''
    <table class="data">
      <tr><th>Systeme touche</th><th>Duree arret</th><th>Utilisateurs impactes</th><th>Volume fichiers</th><th>Statut</th></tr>
      <tr><td>{incident.machine}</td><td>{downtime_h}h (est.)</td><td>{users_imp}</td><td>{incident.row.get("file_writes",0)}</td><td>En recherche</td></tr>
    </table>
    '''

    # ── CHAPTER 3: RISKS ──
    risk_rows = "".join(
        f'<tr><td>{d.technique.id}</td><td>{d.technique.tactic}</td><td>{d.confidence:.0%}</td>'
        f'<td>{", ".join(d.evidence[:2])}</td>'
        f'<td><span class="pill" style="background:{SEV_COLOR["critical"] if d.action=="block" else SEV_COLOR["high"]}">{d.action.upper()}</span></td></tr>'
        for d in incident.detections
    ) or '<tr><td colspan="5" style="color:var(--muted)">Aucune technique detectee.</td></tr>'
    ch3_html = f'''
    {_img(charts.get("risk_matrix",""), "Matrice des risques")}
    <h3>3.2 Detail par technique</h3>
    <table class="data"><tr><th>Technique</th><th>Tactique</th><th>Confiance</th><th>Preuves</th><th>Action</th></tr>{risk_rows}</table>
    <h3>3.3 Scenarios futurs</h3>
    <p class="lede">{pb["future"]}</p>
    '''

    # ── CHAPTER 4: MEASURES ──
    plan_rows = "".join(
        f'<tr><td><span class="pill" style="background:var(--accent)">{p}</span></td><td>{a}</td><td>{e}</td><td>{r}</td></tr>'
        for p, a, e, r in PRIORITY_PLAN.get(sev, PRIORITY_PLAN["info"])
    )
    act_ok = incident.action_success if incident.action_success is not None else True
    ch4_html = f'''
    <h3>4.1 Action automatique deja executee</h3>
    <div class="callout {"crit" if not act_ok else ""}">
      {"Confirmee" if act_ok else "Echec"} : <strong>{incident.action_confirmed or "Aucune action enregistree"}</strong>
    </div>
    <h3>4.2 Confinement, eradication, recuperation</h3>
    <table class="data">
      <tr><th>Phase</th><th>Action recommandee</th></tr>
      <tr><td><strong>Confinement</strong></td><td>{pb["containment"]}</td></tr>
      <tr><td><strong>Eradication</strong></td><td>{pb["eradication"]}</td></tr>
      <tr><td><strong>Recuperation</strong></td><td>{pb["recovery"]}</td></tr>
    </table>
    <h3>4.3 Plan d'action priorise</h3>
    <table class="data"><tr><th>Priorite</th><th>Action</th><th>Echeance</th><th>Responsable</th></tr>{plan_rows}</table>
    '''

    # ── CHAPTER 5: BOARD RECOMMENDATIONS ──
    ch5_html = (f'''
    <div class="decision-grid">
      <div class="decision-col yes">
        <h4 style="color:var(--info)">Si investissement maintenant</h4>
        <ul>
          <li>{_fmt(est.mid, cur)} evites (scenario central)</li>
          <li>Temps de recuperation reduit</li>
          <li>Conformite reglementaire maintenue</li>
        </ul>
      </div>
      <div class="decision-col no">
        <h4 style="color:var(--crit)">Si aucune action n'est prise</h4>
        <ul>
          <li>Perte probable {_fmt(est.low, cur)} a {_fmt(est.high, cur)}</li>
          <li>Recidive possible du vecteur {vector}</li>
          <li>Exposition reglementaire potentielle</li>
        </ul>
      </div>
    </div>
    ''') if est else '<p class="lede" style="color:var(--muted)">Argumentaire chiffre indisponible.</p>'

    # ── CHAPTER 6: KPI ──
    ch6_html = f'''
    <table class="data">
      <tr><th>Indicateur</th><th>Valeur</th><th>Objectif</th></tr>
      <tr><td>Delai de detection</td><td>{incident.detection_delay_minutes if incident.detection_delay_minutes is not None else "N/D"} min</td><td>moins de 60 min</td></tr>
      <tr><td>Score actuel</td><td>{score_pct}%</td><td>moins de 50%</td></tr>
      <tr><td>Fenetre analysee</td><td>{incident.window_start[11:16]} a {incident.window_end[11:16]}</td><td></td></tr>
    </table>
    {_img(charts.get("score_evolution",""), "Evolution du score composite")}
    '''

    # ── CHAPTER 7: LESSONS ──
    mfa_txt = "Actif" if incident.mfa_active else ("Inactif" if incident.mfa_active is not None else "Non renseigne")
    ch7_html = f'''
    <table class="data">
      <tr><th>Constat</th><th>Donnee</th></tr>
      <tr><td>Delai detection vs objectif</td><td>{incident.detection_delay_minutes or "N/D"} min (objectif moins de 60 min)</td></tr>
      <tr><td>MFA actif sur le compte</td><td>{mfa_txt}</td></tr>
      <tr><td>Action automatique</td><td>{"Confirmee" if act_ok else "Echec, intervention manuelle requise"}</td></tr>
    </table>
    <h3>Recommandation de processus</h3>
    <div class="callout">Lien avec le vecteur ({vector}) : {pb["checklist"]}</div>
    '''

    # ── ANNEXES ──
    ioc_rows = "".join(
        f'<tr><td>{i.ioc_type}</td><td>{i.value}</td><td>{i.sha256 or "N/D"}</td><td>{i.first_seen or "N/D"}</td><td>{i.last_seen or "N/D"}</td></tr>'
        for i in incident.iocs
    ) or '<tr><td colspan="5" style="color:var(--muted)">Aucun IOC structure disponible pour cette fenetre. Voir journaux Sysmon/Entra ID bruts.</td></tr>'

    coc = incident.chain_of_custody
    coc_html = f'''
    Collecte par : {coc.collected_by if coc else "Non renseigne"}<br>
    Outil : {coc.tool if coc else "Sysmon + Microsoft Graph API"}<br>
    Horodatage : {coc.collected_at if coc else _now_str()}<br>
    Hash d'integrite : {(coc.integrity_hash if coc and coc.integrity_hash else "Non calcule")}
    '''

    ir = incident.ir_contact
    ir_html = f'''
    Equipe : {ir.team_name if ir else "Equipe Securite"}<br>
    Contact : {(ir.email if ir and ir.email else "Non renseigne")} {(("/ " + ir.phone) if ir and ir.phone else "")}<br>
    {(ir.note if ir else "Validation humaine requise avant cloture de l'incident")}
    '''

    ins = incident.insurance
    ins_html = (f'''
    Assureur : {ins.insurer or "Non renseigne"}<br>
    Reference police : {ins.policy_ref or "Non renseignee"}<br>
    Plafond : {_fmt(ins.limit, ins.currency) if ins.limit else "Non renseigne"}, franchise : {_fmt(ins.deductible, ins.currency) if ins.deductible else "Non renseignee"}<br>
    Couverture : {ins.coverage or "Non renseignee"}
    ''') if ins else 'Aucune information d\'assurance cyber renseignee pour cet incident.'

    rgpd_ref = incident.rgpd_template_ref or "Aucun gabarit de notification RGPD associe a cet incident."

    annex_html = f'''
    <h3>A. Chronologie</h3>
    {_img(charts.get("kill_chain",""), "Chronologie de la chaine d'attaque")}
    <h3>B. Glossaire</h3>
    <table class="data">
      <tr><th>Terme</th><th>Definition</th></tr>
      {"".join(f"<tr><td>{t}</td><td>{d}</td></tr>" for t, d in GLOSSARY)}
    </table>
    <h3>C. Reference du dossier</h3>
    <p class="lede" style="font-family:var(--mono)">{incident.reference}</p>
    <h3>D. Indicateurs de compromission (IOC)</h3>
    <table class="data"><tr><th>Type</th><th>Valeur</th><th>SHA256</th><th>Premiere observation</th><th>Derniere observation</th></tr>{ioc_rows}</table>
    <h3>E. Chaine de conservation des preuves</h3>
    <div class="panel">{coc_html}</div>
    <h3>F. Contact equipe IR</h3>
    <div class="panel">{ir_html}</div>
    <h3>G. Assurance cyber</h3>
    <div class="panel">{ins_html}</div>
    <h3>H. Gabarit de notification RGPD</h3>
    <div class="panel">{rgpd_ref}</div>
    <h3>I. Indicateurs bruts (histogramme)</h3>
    {_img(charts.get("raw_indicators",""), "Histogramme des indicateurs bruts")}
    '''

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>[{sev_label}] {incident.user}@{incident.machine}, Rapport Technique</title>
<style>{_CSS}</style>
</head>
<body>
<div class="doc">

  <div class="cover">
    <div class="stamp">CONFIDENTIEL<br>DIRECTION</div>
    <div class="wordmark">ZeroTrust AI, Securite de l'information</div>
    <h1>[{sev_label}] {incident.user}@{incident.machine}, Rapport Technique</h1>
    <div class="cover-meta">
      <div><div class="k">Reference</div><div class="v">{incident.reference}</div></div>
      <div><div class="k">Score</div><div class="v" style="color:{color}">{score_pct}%</div></div>
      <div><div class="k">Evenements</div><div class="v">{incident.row.get("total_events",0)}</div></div>
      <div><div class="k">Fenetre</div><div class="v">{incident.window_start[11:16]}</div></div>
      <div><div class="k">Genere</div><div class="v">{_now_str()[:16]}</div></div>
    </div>
  </div>

  <div class="layout">
    <nav class="toc">
      <div class="toc-title">Sommaire</div>
      {toc_html}
    </nav>

    <div class="content">

      <section class="chapter" id="resume">
        <h2>Resume executif</h2>
        {resume_html}
      </section>

      <section class="chapter" id="ch1">
        <h2><span class="num">1</span>Impact financier</h2>
        {ch1_html}
      </section>

      <section class="chapter" id="ch2">
        <h2><span class="num">2</span>Impact operationnel</h2>
        {ch2_html}
      </section>

      <section class="chapter" id="ch3">
        <h2><span class="num">3</span>Risques et menaces futures</h2>
        {ch3_html}
      </section>

      <section class="chapter" id="ch4">
        <h2><span class="num">4</span>Mesures de securite deployees</h2>
        {ch4_html}
      </section>

      <section class="chapter" id="ch5">
        <h2><span class="num">5</span>Recommandations pour le Conseil</h2>
        {ch5_html}
      </section>

      <section class="chapter" id="ch6">
        <h2><span class="num">6</span>Indicateurs (KPI)</h2>
        {ch6_html}
      </section>

      <section class="chapter" id="ch7">
        <h2><span class="num">7</span>Lecons apprises</h2>
        {ch7_html}
      </section>

      <section class="chapter" id="annexes">
        <h2>Annexes</h2>
        {annex_html}
      </section>

    </div>
  </div>

  <div class="footer">
    <span>Rapport genere automatiquement par ZeroTrust AI, version 1.0</span>
    <span>{incident.reference}, {_now_str()}</span>
  </div>
</div>
</body>
</html>"""
    return f"[{sev_label}] {incident.user}@{incident.machine}, Rapport Technique", html
