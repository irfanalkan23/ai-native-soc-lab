"""FastAPI application for the SOC Analyst UI presentation layer.

Architecture Principle:
    Exclusively provides read-only presentation endpoints:
    - GET /: Server-rendered analyst incident console (list).
    - GET /incidents/{incident_id}: Server-rendered incident detail page.
    - GET /api/incidents: Allowlisted incident summaries as JSON.
    - GET /api/incidents/{incident_id}: Allowlisted incident detail as JSON.
    Existing persisted incident artifacts are consumed through a read-only UI path.
    Holds ZERO execution authority: cannot invoke tools, run SPL, mutate policy,
    call providers, trigger actions, or modify RuntimeGuard.
"""

import html
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse

from ui.audit_reader import (
    DEFAULT_AUDIT_LIMIT,
    DEFAULT_AUDIT_LOG_PATH,
    MAX_AUDIT_LIMIT,
    MIN_AUDIT_LIMIT,
    AuditReader,
)
from ui.incident_reader import (
    DEFAULT_INCIDENTS_DIR,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MIN_LIMIT,
    IncidentReader,
)
from ui.models import (
    AuditEventView,
    IncidentDetailView,
    IncidentSummaryView,
)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _esc(val: Any) -> str:
    """Safely escape text for HTML output to prevent XSS."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


def _clamp_risk_score(score: Any) -> int:
    """Defensively clamp risk score for visual bar presentation (0..100)."""
    try:
        if isinstance(score, (int, float)):
            return max(0, min(100, int(score)))
        if isinstance(score, str) and score.strip().lstrip("-").isdigit():
            return max(0, min(100, int(score.strip())))
    except (ValueError, TypeError):
        pass
    return 0


def _resolve_approval_display_state(detail: IncidentDetailView) -> tuple[str, str]:
    """Deterministically map approval state to presentation label and CSS class.

    Fails visually conservative (UNKNOWN) on malformed or unexpected values.
    """
    app_stat = (detail.approval_status or "").strip().upper()

    if not detail.requires_human_approval:
        if app_stat in ("NOT_REQUIRED", ""):
            return ("NOT REQUIRED", "app-not-req")
        if app_stat == "APPROVED":
            return ("APPROVED", "app-approved")
        if app_stat == "DENIED":
            return ("DENIED", "app-denied")
        return ("UNKNOWN", "app-unknown")

    # Policy explicitly requires human approval
    if app_stat == "APPROVED":
        return ("APPROVED", "app-approved")
    if app_stat == "DENIED":
        return ("DENIED", "app-denied")
    if app_stat in ("PENDING", "PENDING_APPROVAL", "REQUIRED / PENDING", "REQUIRED", "NOT_REQUIRED"):
        # When approval is mandated but not yet decided, status is pending
        return ("REQUIRED / PENDING", "app-pending")

    return ("UNKNOWN", "app-unknown")


def _resolve_simulation_display_state(detail: IncidentDetailView) -> tuple[str, str]:
    """Deterministically map simulation execution status to label and CSS class.

    Fails visually conservative (UNKNOWN) on malformed or unexpected values.
    """
    sim_stat = (detail.simulation_status or "").strip().upper()
    if sim_stat == "NOT_EXECUTED":
        return ("NOT EXECUTED", "sim-not-executed")
    if sim_stat == "SIMULATED":
        return ("SIMULATED", "sim-simulated")
    if sim_stat in ("BLOCKED", "DENIED", "BLOCKED / DENIED"):
        return ("BLOCKED / DENIED", "sim-denied")
    return ("UNKNOWN", "sim-unknown")


def _render_policy_reason_chips(reasons: List[str]) -> str:
    """Render allowlisted policy reason codes as bounded, escaped chips."""
    if not reasons:
        return '<span class="sub-text">None</span>'
    chips = [f'<span class="policy-chip">{_esc(r)}</span>' for r in reasons if str(r).strip()]
    if not chips:
        return '<span class="sub-text">None</span>'
    return f'<div class="policy-chips">{"".join(chips)}</div>'


def _render_governance_pipeline(detail: IncidentDetailView) -> str:
    """Render the 5-step control-flow / decision-state visualization pipeline:

    Evidence -> AI Advisory -> Deterministic Policy -> Human Approval -> Permitted / Simulated Action
    """
    # 1. Evidence state
    has_evidence = bool(
        detail.modsecurity_evidence is not None
        or (detail.sysmon_evidence is not None and (
            detail.sysmon_evidence.decoded_command
            or detail.sysmon_evidence.image
            or detail.sysmon_evidence.command_line
            or detail.sysmon_evidence.evidence_source != "Unknown"
        ))
    )
    ev_label = "AVAILABLE" if has_evidence else "NOT AVAILABLE"
    ev_class = "pipe-success" if has_evidence else "pipe-muted"
    ev_type = detail.evidence_type.upper().replace("_", " ")

    # 2. AI Advisory state
    has_ai = bool(
        detail.investigation_summary
        or detail.confidence_level
        or detail.recommended_next_step
    )
    ai_label = "AVAILABLE" if has_ai else "NOT AVAILABLE"
    ai_class = "pipe-ai" if has_ai else "pipe-muted"
    ai_conf = f"Conf: {_esc(detail.confidence_level.upper())}" if detail.confidence_level else "Advisory"

    # 3. Deterministic Policy state
    r_level = (detail.risk_level or "UNKNOWN").upper()
    pol_label = f"{r_level} ({detail.risk_score})"
    pol_class = f"pipe-{r_level.lower()}" if r_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "pipe-muted"
    pol_action = _esc(detail.proposed_action)

    # 4. Human Approval state
    app_label, _ = _resolve_approval_display_state(detail)
    app_pipe_class = (
        "pipe-success" if app_label == "APPROVED"
        else ("pipe-danger" if app_label == "DENIED"
        else ("pipe-warn" if "PENDING" in app_label
        else "pipe-muted"))
    )

    # 5. Permitted / Simulated Action state
    sim_label, _ = _resolve_simulation_display_state(detail)
    sim_pipe_class = (
        "pipe-sim" if sim_label == "SIMULATED"
        else ("pipe-muted" if sim_label == "NOT EXECUTED"
        else "pipe-danger")
    )

    return f"""<div class="governance-pipeline">
  <div class="pipeline-stage">
    <div class="stage-step">Stage 1 &bull; Evidence</div>
    <div class="stage-name">{_esc(ev_type)}</div>
    <span class="badge {ev_class}">{ev_label}</span>
    <div class="stage-sub">Telemetry Intake</div>
  </div>
  <div class="pipeline-arrow">&rarr;</div>
  <div class="pipeline-stage">
    <div class="stage-step">Stage 2 &bull; AI Advisory</div>
    <div class="stage-name">Hypothesis / Context</div>
    <span class="badge {ai_class}">{ai_label}</span>
    <div class="stage-sub">{ai_conf}</div>
  </div>
  <div class="pipeline-arrow">&rarr;</div>
  <div class="pipeline-stage stage-highlight">
    <div class="stage-step">Stage 3 &bull; Deterministic Policy</div>
    <div class="stage-name">Authoritative Gate</div>
    <span class="badge {pol_class}">{pol_label}</span>
    <div class="stage-sub mono" style="font-size: 0.6875rem;">{pol_action}</div>
  </div>
  <div class="pipeline-arrow">&rarr;</div>
  <div class="pipeline-stage">
    <div class="stage-step">Stage 4 &bull; Human Approval</div>
    <div class="stage-name">Consequential Guard</div>
    <span class="badge {app_pipe_class}">{app_label}</span>
    <div class="stage-sub">{"Strict Gate" if detail.requires_human_approval else "Auto Disposition"}</div>
  </div>
  <div class="pipeline-arrow">&rarr;</div>
  <div class="pipeline-stage">
    <div class="stage-step">Stage 5 &bull; Permitted / Simulated Action</div>
    <div class="stage-name">Action State</div>
    <span class="badge {sim_pipe_class}">{sim_label}</span>
    <div class="stage-sub" style="color: var(--status-critical); font-weight: 600;">Containment: NOT IMPLEMENTED</div>
  </div>
</div>"""


def _render_audit_timeline(events: List[AuditEventView]) -> str:
    """Render bounded chronological audit events as a structured timeline."""
    if not events:
        return (
            '<div class="empty-state" style="padding: 24px; text-align: center;">'
            '<p style="color: var(--text-muted); margin: 0;">No persisted audit events are available for this incident.</p>'
            '</div>'
        )

    rows = []
    for ev in events:
        out_upper = (ev.outcome or "").upper()
        if out_upper == "SUCCESS":
            out_class = "audit-outcome-success"
        elif out_upper in ("DENIED", "FAILED"):
            out_class = "audit-outcome-failed"
        elif out_upper == "REQUESTED":
            out_class = "audit-outcome-req"
        else:
            out_class = "audit-outcome-info"

        ts_str = (
            f'<span class="mono" style="font-size: 0.75rem; color: var(--text-muted);">{_esc(ev.timestamp)}</span>'
            if ev.timestamp
            else f'<span class="mono" style="font-size: 0.75rem; color: var(--text-muted);">Step #{ev.sequence}</span>'
        )

        rows.append(f"""<div class="audit-timeline-row">
  <div class="audit-row-left">
    <span class="mono audit-seq-badge">#{ev.sequence}</span>
    <span class="badge cat-policy" style="font-size: 0.6875rem;">{_esc(ev.category)}</span>
    <span class="mono audit-event-type">{_esc(ev.event_type)}</span>
  </div>
  <div class="audit-row-mid">
    <span class="mono audit-detail-code">{_esc(ev.detail_code)}</span>
  </div>
  <div class="audit-row-right">
    <span class="badge {out_class}">{_esc(ev.outcome)}</span>
    {ts_str}
  </div>
</div>""")

    return f'<div class="audit-timeline-list">{"".join(rows)}</div>'


def _render_incident_rows(incidents: List[IncidentSummaryView]) -> str:
    """Render HTML table rows from allowlisted incident view models."""
    if not incidents:
        return (
            '<tr><td colspan="10" class="empty-state">'
            '<h3>No Investigated Incidents Found</h3>'
            '<p>No incident records exist in the configured artifacts directory.</p>'
            '</td></tr>'
        )

    rows: List[str] = []
    for inc in incidents:
        # Risk badge class
        r_level = (inc.risk_level or "").upper()
        if r_level == "CRITICAL":
            risk_class = "risk-critical"
        elif r_level == "HIGH":
            risk_class = "risk-high"
        elif r_level == "MEDIUM":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"

        # TI badge class
        ti_stat = (inc.threat_intel_status or "").upper()
        if ti_stat == "ENRICHED":
            ti_class = "ti-enriched"
        elif ti_stat == "SKIPPED_INELIGIBLE":
            ti_class = "ti-skipped"
        elif ti_stat == "LOOKUP_FAILED":
            ti_class = "ti-failed"
        else:
            ti_class = "ti-skipped"

        # Approval class & label
        app_stat = (inc.approval_status or "").upper()
        if app_stat == "APPROVED":
            app_class = "app-approved"
        elif app_stat == "DENIED":
            app_class = "app-denied"
        else:
            app_class = "app-not-req"

        app_req_label = "Approval Required" if inc.requires_human_approval else "Auto Disposition"

        # Asset / Source cell
        asset_html = f'<span class="mono">{_esc(inc.target_host)}</span>'
        if inc.source_ip:
            asset_html += f'<div class="sub-text mono">IP: {_esc(inc.source_ip)}</div>'

        # MITRE cell
        mitre_html = f'<span class="mono">{_esc(inc.mitre_technique_id)}</span>' if inc.mitre_technique_id else '<span class="sub-text">&mdash;</span>'

        # TI cell
        ti_html = f'<span class="badge {ti_class}">{_esc(inc.threat_intel_status)}</span>' if inc.threat_intel_status else '<span class="sub-text">&mdash;</span>'

        # Jira cell
        jira_html = f'<span class="jira-pill">{_esc(inc.jira_ticket_key)}</span>' if inc.jira_ticket_key else '<span class="sub-text">None</span>'

        row = f"""<tr>
  <td>
    <a href="/incidents/{_esc(inc.incident_id)}" class="mono incident-id" style="color: var(--accent-cyan); text-decoration: none; font-weight: 600;">{_esc(inc.incident_id)}</a>
    <div class="sub-text mono">{_esc(inc.created_at_utc)}</div>
  </td>
  <td>
    <strong>{_esc(inc.detection_name)}</strong>
    <div class="sub-text mono">{_esc(inc.detection_id)}</div>
  </td>
  <td>
    {asset_html}
  </td>
  <td>
    <span class="badge-category cat-policy">DETERMINISTIC POLICY</span><br>
    <span class="badge {risk_class}">Score: {inc.risk_score} &bull; {_esc(inc.risk_level)}</span>
  </td>
  <td>
    <span class="badge-category cat-ai">AI ADVISORY</span><br>
    <span class="badge cat-ai">Confidence: {_esc(inc.confidence_level)}</span>
  </td>
  <td>
    {mitre_html}
  </td>
  <td>
    {ti_html}
  </td>
  <td>
    <span class="badge-category cat-approval">HUMAN APPROVAL</span><br>
    <span class="{app_class}">{_esc(inc.approval_status)}</span>
    <div class="sub-text">{app_req_label}</div>
  </td>
  <td>
    <span class="badge-category cat-sim">SIMULATED / NOT EXECUTED</span><br>
    <strong>{_esc(inc.simulation_status)}</strong>
    <div class="sub-text mono">{_esc(inc.proposed_action)}</div>
  </td>
  <td>
    {jira_html}
  </td>
</tr>"""
        rows.append(row)

    return "\n".join(rows)


def _render_evidence_section(detail: IncidentDetailView) -> str:
    """Render bounded evidence section for WEB01 ModSecurity or DC01 Sysmon."""
    if detail.modsecurity_evidence is not None:
        ev = detail.modsecurity_evidence
        return f"""<div class="table-container">
  <table>
    <thead>
      <tr>
        <th>Host</th>
        <th>Source IP</th>
        <th>Rule ID</th>
        <th>Rule Message</th>
        <th>Severity</th>
        <th>Anomaly Score</th>
        <th>Unique Transaction ID</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="mono">{_esc(ev.host)}</td>
        <td class="mono">{_esc(ev.src_ip)}</td>
        <td class="mono">{ev.rule_id}</td>
        <td>{_esc(ev.rule_msg)}</td>
        <td><span class="badge risk-critical">{_esc(ev.severity)}</span></td>
        <td class="mono">{ev.anomaly_score}</td>
        <td class="mono" style="font-size: 0.75rem;">{_esc(ev.unique_id)}</td>
      </tr>
    </tbody>
  </table>
</div>"""

    if detail.sysmon_evidence is not None:
        ev = detail.sysmon_evidence
        items = [
            f'<div class="prop-item"><span class="prop-label">Target Host</span><span class="prop-value mono">{_esc(ev.target_host)}</span></div>',
            f'<div class="prop-item"><span class="prop-label">Target User</span><span class="prop-value mono">{_esc(ev.target_user)}</span></div>',
            f'<div class="prop-item prop-full"><span class="prop-label">Evidence Source</span><span class="prop-value mono">{_esc(ev.evidence_source)}</span></div>',
        ]
        if ev.image:
            items.append(f'<div class="prop-item prop-full"><span class="prop-label">Image</span><span class="prop-value mono">{_esc(ev.image)}</span></div>')
        if ev.command_line:
            items.append(f'<div class="prop-item prop-full"><span class="prop-label">Command Line</span><pre class="code-box"><code>{_esc(ev.command_line)}</code></pre></div>')
        if ev.parent_image:
            items.append(f'<div class="prop-item prop-full"><span class="prop-label">Parent Image</span><span class="prop-value mono">{_esc(ev.parent_image)}</span></div>')
        if ev.parent_command_line:
            items.append(f'<div class="prop-item prop-full"><span class="prop-label">Parent Command Line</span><pre class="code-box"><code>{_esc(ev.parent_command_line)}</code></pre></div>')

        decoded_box = ""
        if ev.decoded_command:
            decoded_box = f"""<div style="margin-top: 16px;">
  <div class="prop-label" style="margin-bottom: 6px;">Decoded Command-Line Evidence</div>
  <pre class="code-box"><code>{_esc(ev.decoded_command)}</code></pre>
</div>"""

        return f"""<div class="prop-list">
  {"".join(items)}
</div>
{decoded_box}"""

    return f'<div class="prop-value">Standard endpoint telemetry recorded for host: {_esc(detail.target_host)}</div>'


def create_app(
    incidents_dir: Optional[Union[Path, str]] = None,
    audit_path: Optional[Union[Path, str]] = None,
) -> FastAPI:
    """Create and configure a read-only FastAPI application instance."""
    app = FastAPI(
        title="AI-Native SOC Lab — Investigation Console",
        description="Read-only analyst presentation interface for investigated incidents.",
        version="1.0.0",
        docs_url=None,  # Disable OpenAPI UI to avoid unneeded endpoints
        redoc_url=None,
        openapi_url=None,
    )

    reader = IncidentReader(incidents_dir or DEFAULT_INCIDENTS_DIR)
    audit_reader = AuditReader(audit_path or DEFAULT_AUDIT_LOG_PATH)

    @app.get("/api/incidents", response_class=JSONResponse)
    def get_incidents(
        limit: int = Query(default=DEFAULT_LIMIT, ge=MIN_LIMIT, le=MAX_LIMIT)
    ) -> List[Dict[str, Any]]:
        """Return a bounded, deterministically ordered list of incident summaries.

        Read-only endpoint. Accepts zero caller SPL or execution directives.
        """
        incidents = reader.list_incidents(limit=limit)
        return [inc.to_dict() for inc in incidents]

    @app.get("/api/incidents/{incident_id}", response_class=JSONResponse)
    def get_incident_detail_api(incident_id: str) -> Dict[str, Any]:
        """Return allowlisted structured details for a single incident by identifier.

        Read-only endpoint. Rejects unknown identifiers and path traversal attempts with 404.
        """
        incident = reader.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        return incident.to_dict()

    @app.get("/api/incidents/{incident_id}/audit", response_class=JSONResponse)
    def get_incident_audit_events_api(
        incident_id: str,
        limit: int = Query(default=DEFAULT_AUDIT_LIMIT, ge=MIN_AUDIT_LIMIT, le=MAX_AUDIT_LIMIT),
    ) -> List[Dict[str, Any]]:
        """Return bounded allowlisted audit events correlated to an incident.

        Read-only endpoint. Rejects unknown identifiers with 404.
        """
        incident = reader.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        events = audit_reader.get_incident_events(incident_id, limit=limit)
        return [ev.to_dict() for ev in events]

    @app.get("/", response_class=HTMLResponse)
    def get_analyst_console() -> HTMLResponse:
        """Render the read-only SOC analyst incident investigation console."""
        incidents = reader.list_incidents(limit=MAX_LIMIT)

        # Calculate metrics
        total = len(incidents)
        high_critical = sum(1 for inc in incidents if (inc.risk_level or "").upper() in ("HIGH", "CRITICAL"))

        template_path = _TEMPLATES_DIR / "incidents.html"
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_html = f.read()
        except OSError:
            template_html = "<html><body><h1>AI-Native SOC Lab</h1><p>{{TABLE_ROWS}}</p></body></html>"

        table_rows = _render_incident_rows(incidents)

        rendered = template_html.replace("{{TOTAL_INCIDENTS}}", str(total))
        rendered = rendered.replace("{{HIGH_CRITICAL_COUNT}}", str(high_critical))
        rendered = rendered.replace("{{TABLE_ROWS}}", table_rows)

        return HTMLResponse(content=rendered, status_code=status.HTTP_200_OK)

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def get_incident_detail_page(incident_id: str) -> HTMLResponse:
        """Render the deep inspection detail view for a single incident."""
        detail = reader.get_incident(incident_id)
        if detail is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        template_path = _TEMPLATES_DIR / "incident_detail.html"
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_html = f.read()
        except OSError:
            template_html = "<html><body><h1>Incident Detail</h1><p>{{INCIDENT_ID}}</p></body></html>"

        # Risk calculation & badge class
        clamped_score = _clamp_risk_score(detail.risk_score)
        r_level = (detail.risk_level or "").upper()
        if r_level == "CRITICAL":
            risk_class = "risk-critical"
        elif r_level == "HIGH":
            risk_class = "risk-high"
        elif r_level == "MEDIUM":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"

        # Approval state resolution
        app_label, app_class = _resolve_approval_display_state(detail)

        # Simulation state resolution
        sim_label, sim_class = _resolve_simulation_display_state(detail)

        # Threat Intelligence Presentation (Part A)
        ti = detail.threat_intel
        ti_stat_raw = (ti.status or "NOT_PERFORMED").strip().upper()

        if ti_stat_raw == "ENRICHED":
            ti_status_display = "ENRICHED"
            ti_class = "ti-enriched"
            ti_status_note = "Normalized provider result was persisted during the incident workflow."
        elif ti_stat_raw == "SKIPPED_INELIGIBLE":
            ti_status_display = "SKIPPED_INELIGIBLE"
            ti_class = "ti-skipped"
            ti_status_note = "External enrichment was not performed because the indicator did not meet deterministic eligibility policy."
        elif ti_stat_raw == "LOOKUP_FAILED":
            ti_status_display = "LOOKUP_FAILED"
            ti_class = "ti-failed"
            ti_status_note = "An eligible lookup was attempted but enrichment did not complete successfully."
        elif ti_stat_raw == "NOT_PERFORMED":
            ti_status_display = "NOT_PERFORMED"
            ti_class = "ti-skipped"
            ti_status_note = "No threat intelligence lookup was performed for this alert."
        else:
            ti_status_display = _esc(ti_stat_raw)
            ti_class = "ti-skipped"
            ti_status_note = "Threat intelligence status was not recognized or recorded."

        ti_rows_list = []
        if ti.indicator:
            ti_rows_list.append(f"""<div class="prop-item">
  <span class="prop-label">Indicator</span>
  <span class="prop-value mono">{_esc(ti.indicator)}</span>
</div>""")
        if ti.indicator_type:
            ti_rows_list.append(f"""<div class="prop-item">
  <span class="prop-label">Indicator Type</span>
  <span class="prop-value mono">{_esc(ti.indicator_type)}</span>
</div>""")
        if ti.provider:
            ti_rows_list.append(f"""<div class="prop-item">
  <span class="prop-label">Provider</span>
  <span class="prop-value mono">{_esc(ti.provider)}</span>
</div>""")
        if ti.verdict:
            ti_rows_list.append(f"""<div class="prop-item">
  <span class="prop-label">Verdict</span>
  <span class="prop-value mono">{_esc(ti.verdict)}</span>
</div>""")
        if any(c is not None for c in (ti.malicious_count, ti.suspicious_count, ti.harmless_count, ti.undetected_count)):
            m_cnt = ti.malicious_count if ti.malicious_count is not None else 0
            s_cnt = ti.suspicious_count if ti.suspicious_count is not None else 0
            h_cnt = ti.harmless_count if ti.harmless_count is not None else 0
            u_cnt = ti.undetected_count if ti.undetected_count is not None else 0
            ti_rows_list.append(f"""<div class="prop-item prop-full">
  <span class="prop-label">Detection Counts</span>
  <span class="prop-value">Malicious: {m_cnt} &bull; Suspicious: {s_cnt} &bull; Harmless: {h_cnt} &bull; Undetected: {u_cnt}</span>
</div>""")
        if ti.skip_reason:
            reason_label = "Failure Reason" if ti_stat_raw == "LOOKUP_FAILED" else "Skip Reason"
            ti_rows_list.append(f"""<div class="prop-item prop-full">
  <span class="prop-label">{reason_label}</span>
  <span class="prop-value mono">{_esc(ti.skip_reason)}</span>
</div>""")

        ti_detail_rows = "".join(ti_rows_list) if ti_rows_list else """<div class="prop-item prop-full">
  <span class="prop-label">Enrichment State</span>
  <span class="prop-value" style="color: var(--text-muted);">No enrichment metrics recorded for this alert.</span>
</div>"""

        # Jira Tracking Presentation (Part B)
        if detail.jira_ticket_key:
            jira_display = f'<span class="mono" style="color: var(--accent-cyan); font-weight: 600;">{_esc(detail.jira_ticket_key)}</span>'
        else:
            jira_display = '<span style="color: var(--text-muted);">Not created / None</span>'

        # Audit Timeline Presentation (Part C)
        audit_events = audit_reader.get_incident_events(detail.incident_id, limit=DEFAULT_AUDIT_LIMIT)
        audit_timeline_html = _render_audit_timeline(audit_events)

        source_ip_meta = ""
        if detail.source_ip:
            source_ip_meta = f'<div class="meta-item"><span class="prop-label">Source IP:</span> <span class="mono">{_esc(detail.source_ip)}</span></div>'

        policy_reasons_str = ", ".join(_esc(r) for r in detail.policy_reason_codes) if detail.policy_reason_codes else "None"
        policy_chips_html = _render_policy_reason_chips(detail.policy_reason_codes)
        governance_pipeline_html = _render_governance_pipeline(detail)
        evidence_content = _render_evidence_section(detail)

        rendered = template_html.replace("{{INCIDENT_ID}}", _esc(detail.incident_id))
        rendered = rendered.replace("{{DETECTION_NAME}}", _esc(detail.detection_name))
        rendered = rendered.replace("{{DETECTION_ID}}", _esc(detail.detection_id))
        rendered = rendered.replace("{{TARGET_HOST}}", _esc(detail.target_host))
        rendered = rendered.replace("{{SOURCE_IP_META}}", source_ip_meta)
        rendered = rendered.replace("{{CREATED_AT_UTC}}", _esc(detail.created_at_utc))
        rendered = rendered.replace("{{GOVERNANCE_PIPELINE}}", governance_pipeline_html)
        rendered = rendered.replace("{{RISK_SCORE}}", str(detail.risk_score))
        rendered = rendered.replace("{{CLAMPED_RISK_SCORE}}", str(clamped_score))
        rendered = rendered.replace("{{RISK_BAR_STYLE}}", f'style="width: {clamped_score}%;"')
        rendered = rendered.replace("{{RISK_LEVEL}}", _esc(detail.risk_level))
        rendered = rendered.replace("{{RISK_LEVEL_LOWER}}", _esc((detail.risk_level or "low").lower()))
        rendered = rendered.replace("{{RISK_BADGE_CLASS}}", risk_class)
        rendered = rendered.replace("{{DISPOSITION}}", _esc(detail.disposition))
        rendered = rendered.replace("{{PROPOSED_ACTION}}", _esc(detail.proposed_action))
        rendered = rendered.replace("{{REQUIRES_APPROVAL}}", "Yes (Strict Gate)" if detail.requires_human_approval else "No (Auto Disposition)")
        rendered = rendered.replace("{{APPROVAL_STATUS}}", _esc(detail.approval_status))
        rendered = rendered.replace("{{APPROVAL_STATUS_CLASS}}", app_class)
        rendered = rendered.replace("{{APPROVAL_DISPLAY_LABEL}}", _esc(app_label))
        rendered = rendered.replace("{{APPROVAL_REASON}}", _esc(detail.approval_reason_code or "None"))
        rendered = rendered.replace("{{SIMULATION_STATUS}}", _esc(detail.simulation_status))
        rendered = rendered.replace("{{SIMULATION_STATUS_CLASS}}", sim_class)
        rendered = rendered.replace("{{SIMULATION_DISPLAY_LABEL}}", _esc(sim_label))
        rendered = rendered.replace("{{SIMULATION_DETAIL_CODE}}", _esc(detail.simulation_detail_code))
        rendered = rendered.replace("{{POLICY_REASONS}}", policy_reasons_str)
        rendered = rendered.replace("{{POLICY_REASONS_CHIPS}}", policy_chips_html)
        rendered = rendered.replace("{{CONFIDENCE_LEVEL}}", _esc(detail.confidence_level))
        rendered = rendered.replace("{{SUSPICIOUS_COUNT}}", str(detail.suspicious_indicator_count))
        rendered = rendered.replace("{{INVESTIGATION_SUMMARY}}", _esc(detail.investigation_summary or "No summary available."))
        rendered = rendered.replace("{{RECOMMENDED_NEXT_STEP}}", _esc(detail.recommended_next_step or "No recommended next step."))
        rendered = rendered.replace("{{MITRE_TECHNIQUE}}", _esc(detail.mitre_technique_id or "Not available"))
        rendered = rendered.replace("{{JIRA_TICKET}}", jira_display)
        rendered = rendered.replace("{{TI_STATUS}}", ti_status_display)
        rendered = rendered.replace("{{TI_BADGE_CLASS}}", ti_class)
        rendered = rendered.replace("{{TI_INDICATOR}}", _esc(ti.indicator or detail.source_ip or "None"))
        rendered = rendered.replace("{{TI_DETAIL_ROWS}}", ti_detail_rows)
        rendered = rendered.replace("{{TI_STATUS_NOTE}}", _esc(ti_status_note))
        rendered = rendered.replace("{{EVIDENCE_CONTENT}}", evidence_content)
        rendered = rendered.replace("{{AUDIT_TIMELINE_CONTENT}}", audit_timeline_html)

        return HTMLResponse(content=rendered, status_code=status.HTTP_200_OK)

    return app
