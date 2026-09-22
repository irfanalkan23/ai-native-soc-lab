"""Jira Cloud REST API v3 Ticket Adapter.

Provides a synchronous downstream external tracking/reporting sink for dispatching
validated TicketRequest objects to Jira Cloud via POST /rest/api/3/issue.

Architecture Guarantees:
  - Synchronous Execution: create_ticket() executes synchronously; Jira has ZERO
    response authority over policy, investigation, or containment decisions.
  - Write-Only Boundary: Fixed endpoint POST /rest/api/3/issue only. Zero support
    for issue modification, transitions, comments, assignments, attachments,
    deletion, JQL searching, or webhooks.
  - Standard Library Transport: Built strictly on http.client and ssl. Zero
    third-party dependencies (no requests, no httpx, no urllib3).
  - Single-Attempt Dispatch: One POST attempt only; zero automatic retry on failure
    to guarantee duplicate tickets are never generated downstream.
  - Redirect Rejection: HTTP 3xx redirects are rejected immediately without following.
  - Plaintext ADF Mapping: Descriptions are structured as Atlassian Document Format (ADF)
    v1 plain text nodes, preserving ticket description as plain text content and
    avoiding HTML/Markdown interpretation by our mapper.
  - Response Privacy: Raw response bodies and headers are not logged or persisted;
    only minimum validated fields (ticket_key, detail_code, created_at_utc) are
    retained in TicketResult.
  - Secret Hygiene: Jira API tokens and Authorization headers are masked in __repr__
    and __str__ and never exposed in exceptions, console logs, or audit records.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import json
import os
import re
import ssl
from typing import Any, Dict, Mapping, Optional
import urllib.parse

from investigator.ticketing import (
    SAFE_TICKET_KEY_PATTERN,
    TicketClient,
    TicketClientError,
    TicketConfigError,
    TicketRequest,
    TicketResult,
    TicketingError,
)

# ---------------------------------------------------------------------------
# Constants & Bounds
# ---------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 65536  # 64 KiB maximum bounded read
DEFAULT_TIMEOUT_SECONDS = 10.0
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 60.0

MAX_EMAIL_LENGTH = 254
MAX_API_TOKEN_LENGTH = 512

JIRA_ISSUE_ENDPOINT = "/rest/api/3/issue"
ATLASSIAN_HOST_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net$"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class JiraError(TicketingError):
    """Base exception for all Jira provider errors."""
    pass


class JiraConfigError(JiraError, TicketConfigError):
    """Raised when Jira configuration is invalid or unallowlisted."""
    pass


class JiraCredentialError(JiraError, TicketConfigError):
    """Raised when Jira credentials are missing or invalid."""
    pass


class JiraTransportError(JiraError, TicketClientError):
    """Raised when Jira network transport fails (connection, TLS, timeout, redirect)."""
    pass


class JiraResponseError(JiraError, TicketClientError):
    """Raised when Jira returns a non-201 response, oversized body, or invalid JSON/schema."""
    pass


# ---------------------------------------------------------------------------
# Credentials Container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JiraCredentials:
    """Immutable Jira Cloud authentication credentials.

    Enforces secret masking in __repr__ and __str__ so email and tokens
    are never leaked into loggers, exception traces, or console streams.
    """
    email: str
    api_token: str

    def __post_init__(self) -> None:
        if type(self.email) is not str or not self.email.strip():
            raise JiraCredentialError("Jira user email must be a non-empty string")
        if len(self.email) > MAX_EMAIL_LENGTH:
            raise JiraCredentialError(f"Jira user email exceeds maximum length {MAX_EMAIL_LENGTH}")
        if any(c in self.email for c in "\r\n\t"):
            raise JiraCredentialError("Jira user email cannot contain control characters")

        if type(self.api_token) is not str or not self.api_token.strip():
            raise JiraCredentialError("Jira API token must be a non-empty string")
        if len(self.api_token) > MAX_API_TOKEN_LENGTH:
            raise JiraCredentialError(f"Jira API token exceeds maximum length {MAX_API_TOKEN_LENGTH}")
        if any(c in self.api_token for c in "\r\n\t"):
            raise JiraCredentialError("Jira API token cannot contain control characters")

    def __repr__(self) -> str:
        return "JiraCredentials(email='***', api_token='***')"

    def __str__(self) -> str:
        return "JiraCredentials(email='***', api_token='***')"

    def get_basic_auth_header(self) -> str:
        """Compute the HTTP Basic Authorization header value."""
        raw = f"{self.email}:{self.api_token}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        return f"Basic {encoded}"


STATIC_HTTP_ERROR_MAPPING = {
    400: "jira_payload_rejected",
    401: "jira_authentication_failed",
    403: "jira_authorization_failed",
    404: "jira_endpoint_or_project_not_found",
    429: "jira_rate_limited",
}


def map_jira_http_status_to_error_code(status: int) -> str:
    """Map HTTP status code to static sanitized error detail code."""
    if status in STATIC_HTTP_ERROR_MAPPING:
        return STATIC_HTTP_ERROR_MAPPING[status]
    if 500 <= status <= 599:
        return "jira_remote_service_error"
    return "jira_unexpected_status"


# ---------------------------------------------------------------------------
# Configuration Container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JiraApiConfig:
    """Validated Jira Cloud API endpoint configuration.

    Enforces strict URL parsing and hostname allowlisting:
    - Scheme must be exactly 'https'
    - Hostname must match '*.atlassian.net'
    - Disallows credentials in URL, query parameters, URL fragments, non-root paths,
      and non-443 explicit ports.
    """
    base_url: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if type(self.base_url) is not str or not self.base_url.strip():
            raise JiraConfigError("base_url must be a non-empty string")

        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme != "https":
            raise JiraConfigError("base_url scheme must be exactly 'https'")
        if parsed.username or parsed.password:
            raise JiraConfigError("base_url must not contain embedded username or password")
        if parsed.query:
            raise JiraConfigError("base_url must not contain query parameters")
        if parsed.fragment:
            raise JiraConfigError("base_url must not contain URL fragment")
        if parsed.path not in ("", "/"):
            raise JiraConfigError("base_url path must be empty or '/'")

        try:
            port = parsed.port
        except ValueError:
            raise JiraConfigError("base_url contains invalid port")

        if port is not None and port != 443:
            raise JiraConfigError("base_url explicit port must be 443 or omitted")

        hostname = parsed.hostname
        if not hostname:
            raise JiraConfigError("base_url missing hostname")
        hostname = hostname.lower()
        if not ATLASSIAN_HOST_PATTERN.match(hostname):
            raise JiraConfigError("base_url hostname must match expected '*.atlassian.net' format")

        if type(self.timeout_seconds) not in (int, float):
            raise JiraConfigError("timeout_seconds must be a numeric value")
        if not (MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise JiraConfigError(
                f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
            )

    @property
    def host(self) -> str:
        """Target hostname in lowercase."""
        parsed = urllib.parse.urlsplit(self.base_url)
        return (parsed.hostname or "").lower()

    @property
    def port(self) -> int:
        """Target port (443)."""
        parsed = urllib.parse.urlsplit(self.base_url)
        try:
            return parsed.port or 443
        except ValueError:
            raise JiraConfigError("base_url contains invalid port")


# ---------------------------------------------------------------------------
# Payload Mapper
# ---------------------------------------------------------------------------

class JiraPayloadMapper:
    """Transforms a validated TicketRequest into a Jira Cloud REST API v3 payload.

    Design Details:
      - Plaintext ADF Mapping: Formats description as an Atlassian Document Format (ADF)
        doc v1 containing a single paragraph with a plain text node. This preserves the
        ticket description as plain text content and avoids HTML/Markdown interpretation
        by our mapper.
      - Priority Omission: Top-level Jira priority is omitted in V1 to avoid site-specific
        schema rejections; provider-neutral priority is captured in the summary and
        description text.
    """
    @staticmethod
    def build_issue_payload(request: TicketRequest) -> Dict[str, Any]:
        """Construct deterministic Jira Cloud REST API v3 issue payload."""
        if type(request) is not TicketRequest:
            raise TicketClientError(f"request must be exact TicketRequest, got {type(request).__name__}")

        description_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": request.description,
                        }
                    ],
                }
            ],
        }

        return {
            "fields": {
                "project": {
                    "key": request.project_key,
                },
                "issuetype": {
                    "name": request.issue_type,
                },
                "summary": request.summary,
                "description": description_adf,
                "labels": list(request.labels),
            }
        }


# ---------------------------------------------------------------------------
# Jira Ticket Client
# ---------------------------------------------------------------------------

class JiraTicketClient:
    """Synchronous downstream external tracking/reporting sink for Jira Cloud.

    Implements the TicketClient protocol using standard library http.client and ssl.
    Single POST attempt to /rest/api/3/issue with zero retries and zero redirects.
    """
    def __init__(self, config: JiraApiConfig, credentials: JiraCredentials) -> None:
        if type(config) is not JiraApiConfig:
            raise JiraConfigError(f"config must be JiraApiConfig, got {type(config).__name__}")
        if type(credentials) is not JiraCredentials:
            raise JiraCredentialError(f"credentials must be JiraCredentials, got {type(credentials).__name__}")
        self._config = config
        self._credentials = credentials

    def __repr__(self) -> str:
        return f"JiraTicketClient(host={self._config.host!r}, port={self._config.port!r})"

    def __str__(self) -> str:
        return f"JiraTicketClient(host={self._config.host!r}, port={self._config.port!r})"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "JiraTicketClient":
        """Factory method to construct client from environment variables.

        Reads strictly from os.environ (or provided mapping). Does not parse or load
        .env files.
        """
        source = env if env is not None else os.environ

        base_url = source.get("JIRA_BASE_URL")
        if not base_url or not base_url.strip():
            raise JiraConfigError("environment variable JIRA_BASE_URL is required")

        email = source.get("JIRA_USER_EMAIL")
        if not email or not email.strip():
            raise JiraCredentialError("environment variable JIRA_USER_EMAIL is required")

        api_token = source.get("JIRA_API_TOKEN")
        if not api_token or not api_token.strip():
            raise JiraCredentialError("environment variable JIRA_API_TOKEN is required")

        config = JiraApiConfig(base_url=base_url)
        credentials = JiraCredentials(email=email, api_token=api_token)
        return cls(config=config, credentials=credentials)

    def create_ticket(self, request: TicketRequest) -> TicketResult:
        """Synchronously create an issue in Jira Cloud via REST API v3.

        Guarantees:
          - Single POST attempt only; zero retries.
          - Rejects 3xx redirects immediately.
          - Response reading occurs before connection close.
          - Reads bounded response up to 64 KiB.
          - Enforces that returned issue key matches request project key.
          - Raw response bodies and headers are not logged or persisted; only minimum
            validated fields are retained in TicketResult.
        """
        if type(request) is not TicketRequest:
            raise TicketClientError(f"request must be exact TicketRequest, got {type(request).__name__}")

        payload = JiraPayloadMapper.build_issue_payload(request)
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        headers = {
            "Authorization": self._credentials.get_basic_auth_header(),
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "ai-native-soc-lab/1.0",
        }

        ssl_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            host=self._config.host,
            port=self._config.port,
            timeout=self._config.timeout_seconds,
            context=ssl_ctx,
        )

        try:
            try:
                conn.request("POST", JIRA_ISSUE_ENDPOINT, body=body_bytes, headers=headers)
                resp = conn.getresponse()
            except (http.client.HTTPException, OSError, TimeoutError) as exc:
                raise JiraTransportError("jira_transport_error") from exc

            # Reject redirects immediately
            if 300 <= resp.status < 400:
                raise JiraTransportError("jira_redirect_rejected")

            # Status check for non-201
            if resp.status != 201:
                raise JiraResponseError(map_jira_http_status_to_error_code(resp.status))

            # Bounded response read (MUST occur before connection close)
            try:
                raw_body = resp.read(MAX_RESPONSE_BYTES + 1)
            except (http.client.HTTPException, OSError, TimeoutError) as exc:
                raise JiraTransportError("jira_transport_error") from exc

            if len(raw_body) > MAX_RESPONSE_BYTES:
                raise JiraResponseError("response exceeded maximum size limit")

            # Parse JSON
            try:
                data = json.loads(raw_body.decode("utf-8"))
            except Exception as exc:
                raise JiraResponseError("failed to parse Jira response JSON") from exc

            if not isinstance(data, dict):
                raise JiraResponseError("Jira response JSON must be an object")

            ticket_key = data.get("key")
            if type(ticket_key) is not str or not SAFE_TICKET_KEY_PATTERN.match(ticket_key):
                raise JiraResponseError("jira_ticket_key_invalid")

            expected_prefix = f"{request.project_key}-"
            if not ticket_key.startswith(expected_prefix):
                raise JiraResponseError("jira_ticket_key_project_mismatch")

            now_utc = datetime.now(timezone.utc).isoformat()
            return TicketResult(
                success=True,
                provider="jira_cloud",
                ticket_key=ticket_key,
                detail_code="ticket_created_jira",
                created_at_utc=now_utc,
            )
        finally:
            conn.close()
