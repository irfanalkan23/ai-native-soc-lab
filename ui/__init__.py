"""AI-Native SOC Lab — Analyst UI Presentation Layer.

Milestone 15: Read-Only SOC Analyst UI.
Zero privileged tool authority. Pure presentation layer.
"""

from ui.models import IncidentSummaryView
from ui.incident_reader import IncidentReader
from ui.app import create_app

__all__ = ["IncidentSummaryView", "IncidentReader", "create_app"]
