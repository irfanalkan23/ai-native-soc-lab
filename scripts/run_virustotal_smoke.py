"""Controlled standalone VirusTotal live smoke-test harness.

Advisory evidence only: Threat intelligence possesses ZERO authority over
policy, risk scoring, containment, Jira tickets, or Splunk queries.

Operational invariants:
  - Single environment secret: reads only VIRUSTOTAL_API_KEY from process environment.
  - Zero filesystem I/O: no .env parsing, no config files.
  - Zero command-line credential passing: API keys are never accepted via CLI args.
  - Exact one lookup: single GET dispatch to VirusTotal REST API v3; zero retries.
  - Public IP only: fixed default 8.8.8.8, optional --ip passed through ThreatIntelRequest.
  - Sanitized output: prints only normalized allowlisted fields; zero secrets or raw JSON.
  - Deterministic exit codes:
      0 = success (FOUND or NOT_FOUND)
      2 = local configuration, credential syntax, or indicator validation error
      3 = provider authentication, authorization, or rate limiting / quota error
      4 = network, TLS, redirect, or remote 5xx server error
      5 = schema violation, oversized response, or unexpected provider response
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Callable, Mapping, Optional, Sequence, TextIO

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from investigator.providers.virustotal_provider import (
    VirusTotalApiConfig,
    VirusTotalCredentialError,
    VirusTotalCredentials,
    VirusTotalError,
    VirusTotalResponseError,
    VirusTotalThreatIntelClient,
    VirusTotalTransportError,
)
from investigator.threat_intel import (
    ThreatIntelClient,
    ThreatIntelClientError,
    ThreatIntelRequest,
    ThreatIntelRequestError,
    ThreatIntelResult,
)

DEFAULT_SMOKE_INDICATOR = "8.8.8.8"


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for VirusTotal smoke runner."""
    parser = argparse.ArgumentParser(
        description="Controlled standalone VirusTotal IP lookup smoke test (offline-tested harness).",
        prog="run_virustotal_smoke.py",
    )
    parser.add_argument(
        "--ip",
        type=str,
        default=DEFAULT_SMOKE_INDICATOR,
        help=f"Target public IP indicator to query (default: {DEFAULT_SMOKE_INDICATOR}).",
    )
    return parser


def run_smoke(
    argv: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    client_factory: Optional[Callable[[VirusTotalCredentials, VirusTotalApiConfig], ThreatIntelClient]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Execute a single-attempt VirusTotal IP enrichment smoke test."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    # 1. Parse CLI arguments
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code != 0 else 0

    # 2. Validate Indicator via ThreatIntelRequest boundary
    try:
        request = ThreatIntelRequest(indicator_value=args.ip)
    except ThreatIntelRequestError:
        err.write(
            "VT_SMOKE_REQUEST_ERROR: Indicator must be a valid, globally routable public IP literal.\n"
        )
        return 2

    # 3. Read and validate environment API key
    resolved_env = env if env is not None else os.environ
    raw_key = resolved_env.get("VIRUSTOTAL_API_KEY")

    if raw_key is None or not raw_key.strip():
        err.write("VT_SMOKE_CONFIG_ERROR: VIRUSTOTAL_API_KEY environment variable is not set.\n")
        return 2

    try:
        credentials = VirusTotalCredentials(api_key=raw_key)
    except VirusTotalCredentialError:
        err.write(
            "VT_SMOKE_CREDENTIAL_ERROR: API key fails syntax validation (whitespace, length, or control chars).\n"
        )
        return 2

    # 4. Construct provider client (factory seam for offline tests)
    config = VirusTotalApiConfig(
        timeout_seconds=5.0,
        max_response_bytes=65536,
    )
    factory = client_factory or (
        lambda c, cfg: VirusTotalThreatIntelClient(credentials=c, config=cfg)
    )

    try:
        client = factory(credentials, config)
    except Exception:
        err.write("VT_SMOKE_CONFIG_ERROR: Failed to initialize VirusTotal client.\n")
        return 2

    # 5. Dispatch exactly one lookup
    try:
        result = client.lookup(request)
    except VirusTotalResponseError as exc:
        code_str = str(exc)
        if code_str == "vt_auth_failed":
            err.write("VT_SMOKE_AUTH_ERROR: VirusTotal rejected API key (authentication failed).\n")
            return 3
        elif code_str == "vt_forbidden":
            err.write("VT_SMOKE_FORBIDDEN: Access forbidden (insufficient privileges or account suspension).\n")
            return 3
        elif code_str == "vt_rate_limited":
            err.write("VT_SMOKE_RATE_LIMITED: VirusTotal request rate limit or quota exceeded.\n")
            return 3
        elif code_str == "vt_remote_error":
            err.write("VT_SMOKE_REMOTE_ERROR: VirusTotal server returned an upstream 5xx error.\n")
            return 4
        elif code_str == "vt_bad_request":
            err.write("VT_SMOKE_PROVIDER_ERROR: VirusTotal returned 400 Bad Request.\n")
            return 5
        elif code_str == "vt_unexpected_status":
            err.write("VT_SMOKE_PROVIDER_ERROR: Unexpected HTTP status returned by provider.\n")
            return 5
        elif code_str == "vt_response_too_large":
            err.write("VT_SMOKE_SCHEMA_ERROR: Response exceeded 64 KiB safety cap.\n")
            return 5
        elif code_str == "vt_invalid_json":
            err.write("VT_SMOKE_SCHEMA_ERROR: Provider returned malformed JSON.\n")
            return 5
        elif code_str == "vt_schema_invalid":
            err.write("VT_SMOKE_SCHEMA_ERROR: Provider returned unallowlisted schema.\n")
            return 5
        elif code_str == "vt_indicator_mismatch":
            err.write("VT_SMOKE_SCHEMA_ERROR: Response ID does not match requested IP indicator.\n")
            return 5
        else:
            err.write("VT_SMOKE_PROVIDER_ERROR: Provider response error.\n")
            return 5
    except VirusTotalTransportError as exc:
        code_str = str(exc)
        if code_str == "vt_redirect_rejected":
            err.write("VT_SMOKE_TRANSPORT_ERROR: HTTP redirect rejected by policy.\n")
            return 4
        elif code_str == "vt_transport_error":
            err.write("VT_SMOKE_TRANSPORT_ERROR: HTTPS transport, connection, or TLS negotiation failed.\n")
            return 4
        else:
            err.write("VT_SMOKE_TRANSPORT_ERROR: Transport failure.\n")
            return 4
    except (VirusTotalError, ThreatIntelClientError):
        err.write("VT_SMOKE_PROVIDER_ERROR: Threat intelligence client error.\n")
        return 5
    except Exception:
        err.write("VT_SMOKE_UNEXPECTED_ERROR: An unexpected error occurred.\n")
        return 5

    # 6. Render normalized allowlisted output only
    out.write("=== VirusTotal Live Smoke Test Result ===\n")
    out.write(f"Provider:             {result.provider}\n")
    out.write(f"Indicator Type:       {result.indicator_type}\n")
    out.write(f"Indicator Value:      {result.indicator_value}\n")
    out.write(f"Lookup Status:        {result.lookup_status.value}\n")
    out.write(f"Detail Code:          {result.detail_code}\n")
    out.write(f"Malicious Count:      {result.malicious_count}\n")
    out.write(f"Suspicious Count:     {result.suspicious_count}\n")
    out.write(f"Harmless Count:       {result.harmless_count}\n")
    out.write(f"Undetected Count:     {result.undetected_count}\n")
    out.write(f"Last Analysis (UTC):  {result.last_analysis_utc}\n")
    out.write("=========================================\n")

    return 0


if __name__ == "__main__":
    sys.exit(run_smoke())
