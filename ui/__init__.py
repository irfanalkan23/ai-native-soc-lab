"""AI-Native SOC Lab — Analyst UI Presentation Layer.

Milestone 15A: Read-Only Incident List Console.
Zero privileged tool authority. Pure presentation layer.
"""

from ui.models import IncidentSummaryView
from ui.incident_reader import IncidentReader
from ui.app import create_app

__all__ = ["IncidentSummaryView", "IncidentReader", "create_app"]
