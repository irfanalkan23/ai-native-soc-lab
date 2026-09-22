#!/usr/bin/env python3
"""Manual live smoke test for Jira Cloud REST API v3 adapter.

Exercises the JiraTicketClient against a live Jira Cloud instance using environment
variables. Strictly reads credentials from os.environ (zero dotenv parsing).

Usage:
  Set environment variables in your terminal session:
    export JIRA_BASE_URL="https://your-domain.atlassian.net"
    export JIRA_USER_EMAIL="your-email@example.com"
    export JIRA_API_TOKEN="your-api-token"

  Execute:
    python scripts/run_jira_smoke.py --project SEC --issue-type Task

Security Guarantees:
  - Zero hardcoded credentials; reads strictly from os.environ.
  - Secret masking: Basic Authorization header and API tokens are never printed.
  - Raw response bodies and headers are not printed or persisted.
  - Zero live network requests run as part of normal automated test suites.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.providers.jira_provider import (
    JiraConfigError,
    JiraCredentialError,
    JiraError,
    JiraTicketClient,
)
from investigator.ticketing import (
    ALLOWED_TICKET_LABELS,
    TicketConfig,
    TicketPriority,
    TicketRequest,
    TicketingError,
)


def run_smoke(
    project_key: str,
    issue_type: str,
    summary: str = "AI-Native SOC Lab -- Integration Smoke Test",
    description: str = "Controlled synthetic smoke test issued by run_jira_smoke.py.",
) -> int:
    """Execute live ticket creation against Jira Cloud using environment variables."""
    # 1. Validate operator inputs through TicketConfig boundary
    try:
        config = TicketConfig(
            project_key=project_key,
            issue_type=issue_type,
            allowed_labels=tuple(sorted(ALLOWED_TICKET_LABELS)),
            include_decoded_command=False,
        )
    except TicketingError as err:
        sys.stderr.write(f"[!] Configuration validation failed: {err}\n")
        return 1

    # 2. Build sample request
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    request = TicketRequest(
        incident_id=f"INC-SMOKE-{now_str}",
        project_key=config.project_key,
        issue_type=config.issue_type,
        summary=summary,
        description=description,
        priority=TicketPriority.MEDIUM,
        labels=("ai-native-soc", "benign-test"),
        external_reference=f"SMOKE-{now_str}",
    )

    # 3. Construct client strictly from os.environ
    try:
        client = JiraTicketClient.from_env()
    except (JiraConfigError, JiraCredentialError) as err:
        sys.stderr.write(f"[!] Environment configuration error: {err}\n")
        sys.stderr.write("[!] Required environment variables:\n")
        sys.stderr.write("      JIRA_BASE_URL    (e.g. https://your-domain.atlassian.net)\n")
        sys.stderr.write("      JIRA_USER_EMAIL  (e.g. user@example.com)\n")
        sys.stderr.write("      JIRA_API_TOKEN   (Atlassian API token)\n")
        return 1

    sys.stdout.write("[*] Initiating live Jira Cloud smoke test...\n")
    sys.stdout.write(f"[*] Target host: {client._config.host}\n")
    sys.stdout.write(f"[*] Project:     {request.project_key}\n")
    sys.stdout.write(f"[*] Issue Type:  {request.issue_type}\n")
    sys.stdout.flush()

    # 4. Dispatch single POST attempt
    try:
        result = client.create_ticket(request)
    except JiraError as err:
        sys.stderr.write(f"[!] Jira ticket creation failed: {type(err).__name__} ({err})\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[!] Unexpected error during smoke test: {type(exc).__name__}\n")
        return 1

    if result.success:
        sys.stdout.write("\n[+] Ticket created successfully!\n")
        sys.stdout.write(f"    Ticket Key:   {result.ticket_key}\n")
        sys.stdout.write(f"    Provider:     {result.provider}\n")
        sys.stdout.write(f"    Detail Code:  {result.detail_code}\n")
        sys.stdout.write(f"    Created At:   {result.created_at_utc}\n")
        return 0
    else:
        sys.stderr.write(f"[!] Ticket creation returned failure: {result.detail_code}\n")
        return 1


def main() -> int:
    """CLI entry point for manual live smoke test."""
    parser = argparse.ArgumentParser(
        description="AI-Native SOC Lab -- Manual Live Jira Cloud Smoke Test",
    )
    parser.add_argument(
        "--project",
        default="SEC",
        help="Jira project key (e.g. SEC, must match an existing project in Jira Cloud).",
    )
    parser.add_argument(
        "--issue-type",
        default="Task",
        help="Jira issue type (e.g. Task, Incident, Bug; must exist in project schema).",
    )
    parser.add_argument(
        "--summary",
        default="AI-Native SOC Lab -- Integration Smoke Test",
        help="Summary line for smoke test issue.",
    )
    args = parser.parse_args()

    return run_smoke(
        project_key=args.project,
        issue_type=args.issue_type,
        summary=args.summary,
    )


if __name__ == "__main__":
    sys.exit(main())
