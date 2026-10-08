"""FastAPI application for the SOC Analyst UI presentation layer.

Architecture Principle:
    Exclusively provides read-only presentation endpoints:
    - GET /api/incidents: Allowlisted incident summaries as JSON.
    - GET /: Server-rendered analyst incident console.
    Holds ZERO execution authority: cannot invoke tools, run SPL, mutate policy,
    call providers, trigger actions, or modify RuntimeGuard.
"""

import html
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Query, status
from fastapi.responses import HTMLResponse, JSONResponse

from ui.incident_reader import (
    DEFAULT_INCIDENTS_DIR,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MIN_LIMIT,
    IncidentReader,
)
from ui.models import IncidentSummaryView

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
    <span class="mono incident-id">{_esc(inc.incident_id)}</span>
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
            # Fallback if template file is missing
            template_html = "<html><body><h1>AI-Native SOC Lab</h1><p>{{TABLE_ROWS}}</p></body></html>"

        table_rows = _render_incident_rows(incidents)

        rendered = template_html.replace("{{TOTAL_INCIDENTS}}", str(total))
        rendered = rendered.replace("{{HIGH_CRITICAL_COUNT}}", str(high_critical))
        rendered = rendered.replace("{{TABLE_ROWS}}", table_rows)

        return HTMLResponse(content=rendered, status_code=status.HTTP_200_OK)

    return app
