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

from ui.incident_reader import (
    DEFAULT_INCIDENTS_DIR,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MIN_LIMIT,
    IncidentReader,
)
from ui.models import IncidentDetailView, IncidentSummaryView

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _esc(val: Any) -> str:
    """Safely escape text for HTML output to prevent XSS."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


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


def create_app(incidents_dir: Optional[Union[Path, str]] = None) -> FastAPI:
    """Create and configure a read-only FastAPI application instance."""
    app = FastAPI(
        title="AI-Native SOC Lab — Investigation Console",
        description="Read-only analyst presentation interface for investigated incidents.",
        version="1.0.0",
        docs_url=None,  # Disable OpenAPI UI to avoid unneeded endpoints
        redoc_url=None,
    )

    reader = IncidentReader(incidents_dir or DEFAULT_INCIDENTS_DIR)

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

        # Risk badge class
        r_level = (detail.risk_level or "").upper()
        if r_level == "CRITICAL":
            risk_class = "risk-critical"
        elif r_level == "HIGH":
            risk_class = "risk-high"
        elif r_level == "MEDIUM":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"

        # Approval class
        app_stat = (detail.approval_status or "").upper()
        if app_stat == "APPROVED":
            app_class = "app-approved"
        elif app_stat == "DENIED":
            app_class = "app-denied"
        else:
            app_class = "app-not-req"

        # TI badge class
        ti_stat = (detail.threat_intel.status or "").upper()
        if ti_stat == "ENRICHED":
            ti_class = "ti-enriched"
        elif ti_stat == "SKIPPED_INELIGIBLE":
            ti_class = "ti-skipped"
        elif ti_stat == "LOOKUP_FAILED":
            ti_class = "ti-failed"
        else:
            ti_class = "ti-skipped"

        # TI Detail Rows
        ti = detail.threat_intel
        if ti.status == "ENRICHED":
            ti_detail_rows = f"""<div class="prop-item">
  <span class="prop-label">Provider</span>
  <span class="prop-value mono">{_esc(ti.provider or 'VirusTotal')}</span>
</div>
<div class="prop-item">
  <span class="prop-label">Verdict</span>
  <span class="prop-value mono">{_esc(ti.verdict or 'Clean')}</span>
</div>
<div class="prop-item prop-full">
  <span class="prop-label">Detection Counts</span>
  <span class="prop-value">Malicious: {ti.malicious_count if ti.malicious_count is not None else 0} &bull; Suspicious: {ti.suspicious_count if ti.suspicious_count is not None else 0} &bull; Harmless: {ti.harmless_count if ti.harmless_count is not None else 0}</span>
</div>"""
        elif ti.status == "SKIPPED_INELIGIBLE":
            ti_detail_rows = f"""<div class="prop-item prop-full">
  <span class="prop-label">Skip Reason</span>
  <span class="prop-value mono">{_esc(ti.skip_reason or 'private_source_ip_ineligible')}</span>
</div>"""
        elif ti.status == "LOOKUP_FAILED":
            ti_detail_rows = f"""<div class="prop-item prop-full">
  <span class="prop-label">Lookup Error Code</span>
  <span class="prop-value mono" style="color: var(--status-critical);">{_esc(ti.skip_reason or 'lookup_failed')}</span>
</div>"""
        else:
            ti_detail_rows = """<div class="prop-item prop-full">
  <span class="prop-label">Enrichment Note</span>
  <span class="prop-value" style="color: var(--text-muted);">No threat intelligence lookup performed for this alert.</span>
</div>"""

        source_ip_meta = ""
        if detail.source_ip:
            source_ip_meta = f'<div class="meta-item"><span class="prop-label">Source IP:</span> <span class="mono">{_esc(detail.source_ip)}</span></div>'

        policy_reasons_str = ", ".join(_esc(r) for r in detail.policy_reason_codes) if detail.policy_reason_codes else "None"
        evidence_content = _render_evidence_section(detail)

        rendered = template_html.replace("{{INCIDENT_ID}}", _esc(detail.incident_id))
        rendered = rendered.replace("{{DETECTION_NAME}}", _esc(detail.detection_name))
        rendered = rendered.replace("{{DETECTION_ID}}", _esc(detail.detection_id))
        rendered = rendered.replace("{{TARGET_HOST}}", _esc(detail.target_host))
        rendered = rendered.replace("{{SOURCE_IP_META}}", source_ip_meta)
        rendered = rendered.replace("{{CREATED_AT_UTC}}", _esc(detail.created_at_utc))
        rendered = rendered.replace("{{RISK_SCORE}}", str(detail.risk_score))
        rendered = rendered.replace("{{RISK_LEVEL}}", _esc(detail.risk_level))
        rendered = rendered.replace("{{RISK_BADGE_CLASS}}", risk_class)
        rendered = rendered.replace("{{DISPOSITION}}", _esc(detail.disposition))
        rendered = rendered.replace("{{PROPOSED_ACTION}}", _esc(detail.proposed_action))
        rendered = rendered.replace("{{REQUIRES_APPROVAL}}", "Yes (Strict Gate)" if detail.requires_human_approval else "No (Auto Disposition)")
        rendered = rendered.replace("{{APPROVAL_STATUS}}", _esc(detail.approval_status))
        rendered = rendered.replace("{{APPROVAL_STATUS_CLASS}}", app_class)
        rendered = rendered.replace("{{APPROVAL_REASON}}", _esc(detail.approval_reason_code or "None"))
        rendered = rendered.replace("{{SIMULATION_STATUS}}", _esc(detail.simulation_status))
        rendered = rendered.replace("{{SIMULATION_DETAIL_CODE}}", _esc(detail.simulation_detail_code))
        rendered = rendered.replace("{{POLICY_REASONS}}", policy_reasons_str)
        rendered = rendered.replace("{{CONFIDENCE_LEVEL}}", _esc(detail.confidence_level))
        rendered = rendered.replace("{{SUSPICIOUS_COUNT}}", str(detail.suspicious_indicator_count))
        rendered = rendered.replace("{{INVESTIGATION_SUMMARY}}", _esc(detail.investigation_summary or "No summary available."))
        rendered = rendered.replace("{{RECOMMENDED_NEXT_STEP}}", _esc(detail.recommended_next_step or "No recommended next step."))
        rendered = rendered.replace("{{MITRE_TECHNIQUE}}", _esc(detail.mitre_technique_id or "Not available"))
        rendered = rendered.replace("{{JIRA_TICKET}}", f'<span class="mono" style="color: var(--accent-cyan);">{_esc(detail.jira_ticket_key)}</span>' if detail.jira_ticket_key else '<span style="color: var(--text-muted);">Not created / None</span>')
        rendered = rendered.replace("{{TI_STATUS}}", _esc(detail.threat_intel.status or "NOT_PERFORMED"))
        rendered = rendered.replace("{{TI_BADGE_CLASS}}", ti_class)
        rendered = rendered.replace("{{TI_INDICATOR}}", _esc(detail.threat_intel.indicator or detail.source_ip or "None"))
        rendered = rendered.replace("{{TI_DETAIL_ROWS}}", ti_detail_rows)
        rendered = rendered.replace("{{EVIDENCE_CONTENT}}", evidence_content)

        return HTMLResponse(content=rendered, status_code=status.HTTP_200_OK)

    return app
