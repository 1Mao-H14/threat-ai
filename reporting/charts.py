# reporting/charts.py
"""
Five Plotly charts, exported as base64 PNG for direct embedding via
<img src="data:image/png;base64,...">. Requires kaleido for static
image export.

    pip install plotly kaleido

Theme: matched to the report's locked palette (reporting/technical_report_v2.py).
One accent (institutional blue) for neutral/informational series, the
separate severity palette (red/orange/gold/teal) reserved for risk
signal only, never used decoratively.
"""

import base64
import io

import plotly.graph_objects as go

# ── LOCKED PALETTE (must match technical_report_v2.py exactly) ─────────
BG_DARK     = "#11151C"
PANEL_DARK  = "#171C25"
GRID        = "#262E3B"
TEXT        = "#D7DEE7"
MUTED       = "#7C879A"
ACCENT      = "#5B92D6"   # institutional blue, the one locked brand accent
CRIT        = "#D9594E"
HIGH        = "#D98A3D"
MED         = "#C9AE4A"
INFO        = "#3FA589"
GRAY        = "#3A4250"

FONT_FAMILY = "IBM Plex Mono, monospace"

_LAYOUT_BASE = dict(
    paper_bgcolor=BG_DARK,
    plot_bgcolor=BG_DARK,
    font=dict(family=FONT_FAMILY, color=TEXT, size=12),
    margin=dict(l=50, r=30, t=46, b=44),
)


def _fig_to_base64_png(fig: go.Figure, width: int = 760, height: int = 380, scale: int = 2) -> str:
    """Renders the figure to PNG bytes via kaleido and returns a base64 string
    (no data: prefix, the caller wraps that)."""
    png_bytes = fig.to_image(format="png", width=width, height=height, scale=scale, engine="kaleido")
    return base64.b64encode(png_bytes).decode("ascii")


# ══════════════════════════════════════════════════════════════════════
# CHART 1 — Pie: répartition des événements par type
# ══════════════════════════════════════════════════════════════════════

def chart_event_breakdown(event_breakdown: list) -> str:
    """event_breakdown: list of EventTypeBreakdown(label, count)."""
    if not event_breakdown:
        return ""

    color_map = {
        "Credential Dump": CRIT, "PowerShell": HIGH, "Backup": MED,
        "Persistence": ACCENT, "Autres": GRAY,
    }
    labels = [e.label for e in event_breakdown]
    values = [e.count for e in event_breakdown]
    colors = [color_map.get(l, GRAY) for l in labels]

    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.45,
        marker=dict(colors=colors, line=dict(color=BG_DARK, width=2)),
        textinfo="label+value", textfont=dict(family=FONT_FAMILY, color=TEXT, size=12),
        sort=False,
    )])
    fig.update_layout(
        **_LAYOUT_BASE,
        title=dict(text="Répartition des événements détectés par type", font=dict(size=13)),
        showlegend=True,
        legend=dict(orientation="h", y=-0.12, font=dict(size=10)),
    )
    return _fig_to_base64_png(fig, width=620, height=420)


# ══════════════════════════════════════════════════════════════════════
# CHART 2 — Scatter: matrice des risques (sévérité x confiance)
# ══════════════════════════════════════════════════════════════════════

def chart_risk_matrix(detections: list, feature_breakdown: dict) -> str:
    """detections: list[Detection] (technique.id, technique.severity, confidence)."""
    if not detections:
        return ""

    xs, ys, sizes, texts, colors = [], [], [], [], []
    max_contrib = max(feature_breakdown.values(), default=1) or 1
    for d in detections:
        xs.append(d.technique.severity)
        ys.append(d.confidence)
        # size scaled by a representative contribution if available, else flat
        sizes.append(28 + 22 * (max_contrib > 0))
        texts.append(d.technique.id)
        sev = d.technique.severity
        colors.append(CRIT if sev >= 0.85 else HIGH if sev >= 0.70 else MED)

    fig = go.Figure()

    # High-risk zone rectangle (confiance >= 0.85, severité >= 0.8)
    fig.add_shape(
        type="rect", x0=0.8, x1=1.02, y0=0.85, y1=1.02,
        fillcolor=CRIT, opacity=0.10, line=dict(width=0),
    )
    fig.add_annotation(
        x=0.91, y=1.0, text="ZONE HAUT RISQUE", showarrow=False,
        font=dict(size=9, color=CRIT), yshift=10,
    )

    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", text=texts, textposition="top center",
        textfont=dict(size=10, color=TEXT),
        marker=dict(size=sizes, color=colors, line=dict(width=1.5, color=BG_DARK)),
    ))

    fig.update_layout(
        **_LAYOUT_BASE,
        title=dict(text="Matrice des risques (sévérité x confiance)", font=dict(size=13)),
        xaxis=dict(title="Sévérité", range=[0, 1.05], gridcolor=GRID, zerolinecolor=GRID),
        yaxis=dict(title="Confiance", range=[0, 1.05], gridcolor=GRID, zerolinecolor=GRID),
        showlegend=False,
    )
    return _fig_to_base64_png(fig, width=620, height=440)


# ══════════════════════════════════════════════════════════════════════
# CHART 3 — Line: évolution du score composite
# ══════════════════════════════════════════════════════════════════════

def chart_score_evolution(score_timeline: list, block_threshold: float = 0.85,
                           detection_label: str = "Détection") -> str:
    """score_timeline: list[ScorePoint(timestamp, score)]."""
    if not score_timeline or len(score_timeline) < 2:
        return ""

    xs = [p.timestamp for p in score_timeline]
    ys = [p.score for p in score_timeline]

    fig = go.Figure()

    fig.add_shape(
        type="rect", xref="paper", x0=0, x1=1, y0=block_threshold, y1=1.02,
        fillcolor=CRIT, opacity=0.10, line=dict(width=0),
    )
    fig.add_annotation(
        xref="paper", x=0.02, y=block_threshold + (1 - block_threshold) / 2,
        text="CRITIQUE", showarrow=False, font=dict(size=9, color=CRIT), xanchor="left",
    )

    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="lines+markers", line=dict(color=ACCENT, width=2.5),
        marker=dict(size=6, color=ACCENT),
        fill="tozeroy", fillcolor="rgba(91,146,214,0.10)",
    ))

    # Mark the detection point: the last point at/above threshold
    peak_idx = max(range(len(ys)), key=lambda i: ys[i])
    fig.add_annotation(
        x=xs[peak_idx], y=ys[peak_idx], text=detection_label, showarrow=True,
        arrowhead=2, arrowcolor=CRIT, font=dict(size=10, color=CRIT), ay=-30,
    )

    fig.update_layout(
        **_LAYOUT_BASE,
        title=dict(text="Évolution du score composite", font=dict(size=13)),
        xaxis=dict(title="", gridcolor=GRID, zerolinecolor=GRID),
        yaxis=dict(title="Score", range=[0, 1.05], gridcolor=GRID, zerolinecolor=GRID),
        showlegend=False,
    )
    return _fig_to_base64_png(fig, width=720, height=360)


# ══════════════════════════════════════════════════════════════════════
# CHART 4 — Gantt-like timeline: chronologie kill chain
# ══════════════════════════════════════════════════════════════════════

def chart_kill_chain_timeline(kill_chain_phases: list, detection_time: str = None,
                               detection_delay_minutes: int = None) -> str:
    """kill_chain_phases: list[KillChainPhase(tactic, start, end)] with HH:MM strings."""
    if not kill_chain_phases:
        return ""

    def _to_minutes(hhmm: str) -> float:
        h, m = hhmm.split(":")
        return int(h) * 60 + int(m)

    fig = go.Figure()
    colors_cycle = [ACCENT, HIGH, MED, CRIT, INFO]

    for i, phase in enumerate(kill_chain_phases):
        start = _to_minutes(phase.start)
        end = _to_minutes(phase.end)
        fig.add_trace(go.Bar(
            x=[end - start], y=[phase.tactic], base=[start], orientation="h",
            marker=dict(color=colors_cycle[i % len(colors_cycle)]),
            text=f"{phase.start}-{phase.end}", textposition="inside",
            textfont=dict(size=9, color=BG_DARK),
            showlegend=False,
        ))

    if detection_time and detection_delay_minutes is not None:
        det_min = _to_minutes(detection_time)
        fig.add_vline(x=det_min, line=dict(color=CRIT, width=2, dash="dash"))
        fig.add_annotation(
            x=det_min, y=len(kill_chain_phases) - 0.5, text=f"Détection (+{detection_delay_minutes} min)",
            showarrow=False, font=dict(size=9, color=CRIT), xanchor="left", yshift=14,
        )

    fig.update_layout(
        **_LAYOUT_BASE,
        title=dict(text="Chronologie de la chaîne d'attaque", font=dict(size=13)),
        xaxis=dict(title="Minutes depuis le début de la fenêtre", gridcolor=GRID, zerolinecolor=GRID),
        yaxis=dict(title="", gridcolor=GRID),
        barmode="stack",
    )
    return _fig_to_base64_png(fig, width=720, height=320)


# ══════════════════════════════════════════════════════════════════════
# CHART 5 — Bar: histogramme des indicateurs bruts
# ══════════════════════════════════════════════════════════════════════

def chart_raw_indicators(row: dict) -> str:
    fields = [
        ("lsass_access", "lsass_access"), ("lsass_dump_score", "lsass_dump_score"),
        ("backup_deletion", "backup_deletion"), ("extension_changes", "extension_changes"),
        ("encoded_cmds", "encoded_cmds"), ("suspicious_pairs", "suspicious_pairs"),
        ("failed_logins", "failed_logins"), ("external_conns", "external_conns"),
        ("file_writes", "file_writes"), ("persistence_keys", "persistence_keys"),
    ]
    present = [(label, row.get(key, 0)) for key, label in fields if row.get(key, 0)]
    if not present:
        return ""

    labels = [p[0] for p in present]
    values = [p[1] for p in present]
    colors = [CRIT if v >= 1 else GRAY for v in values]

    fig = go.Figure(data=[go.Bar(
        x=labels, y=values, marker=dict(color=colors),
        text=values, textposition="outside", textfont=dict(size=10, color=TEXT),
    )])
    fig.update_layout(
        **_LAYOUT_BASE,
        title=dict(text="Indicateurs bruts (valeurs non nulles)", font=dict(size=13)),
        xaxis=dict(tickangle=-35, gridcolor=GRID, tickfont=dict(size=10)),
        yaxis=dict(title="Valeur", gridcolor=GRID, zerolinecolor=GRID),
        showlegend=False,
    )
    return _fig_to_base64_png(fig, width=760, height=380)


# ══════════════════════════════════════════════════════════════════════
# CONVENIENCE: build all 5 at once
# ══════════════════════════════════════════════════════════════════════

def build_all_charts(incident) -> dict:
    """incident: IncidentData instance. Returns dict of base64 strings,
    empty string for any chart whose input data wasn't supplied."""
    block_thresh = 0.85
    if incident.financial and hasattr(incident, "block_threshold"):
        block_thresh = incident.block_threshold

    detection_time = None
    if incident.score_timeline:
        peak = max(incident.score_timeline, key=lambda p: p.score)
        detection_time = peak.timestamp

    return {
        "event_breakdown":   chart_event_breakdown(incident.event_breakdown),
        "risk_matrix":       chart_risk_matrix(incident.detections, incident.feature_breakdown),
        "score_evolution":   chart_score_evolution(incident.score_timeline, block_thresh),
        "kill_chain":        chart_kill_chain_timeline(
                                  incident.kill_chain_phases,
                                  detection_time,
                                  incident.detection_delay_minutes,
                              ),
        "raw_indicators":    chart_raw_indicators(incident.row),
    }
