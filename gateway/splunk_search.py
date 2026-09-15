"""Bounded, read-only Splunk search client for local Splunk Free instances.

Security Boundary Guarantees:
1. Hardcoded endpoint: strictly targets https://localhost:8089/services/search/jobs/export.
2. No arbitrary SPL execution: queries are constructed via deterministic policy templates.
3. No path or URL parameter accepted from caller.
4. No administrative, user, or config endpoints are callable.
5. No subprocess, shell, curl, or external binaries used.
6. Fails closed on invalid inputs, connection failures, timeouts, or non-JSON responses.
7. Fails closed on Splunk server WARN/ERROR/FATAL message envelopes.
8. Enforces strict schema: all 7 detection fields are mandatory on every event.
9. Enforces maximum response size bound (1MB) to prevent unbounded memory consumption.
10. Enforces post-parse result-count bound matching caller's validated limit.
11. Sanitizes error messages: never echoes raw response body into exceptions or logs.
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from gateway.policy import (
    ALLOWED_FIELDS,
    PolicyValidationError,
    build_allowlisted_spl,
    validate_search_request,
)

# Hardcoded export endpoint: caller cannot change or override this URL
SPLUNK_EXPORT_ENDPOINT = "https://localhost:8089/services/search/jobs/export"
DEFAULT_TIMEOUT_SECONDS = 15.0
# Maximum response body size for bounded search queries (1MB)
MAX_RESPONSE_BYTES = 1_048_576


class SplunkSearchError(Exception):
    """Base exception for all Splunk search operations."""
    pass


class SplunkConnectionError(SplunkSearchError):
    """Raised on connection timeout, refusal, or network failure."""
    pass


class SplunkResponseError(SplunkSearchError):
    """Raised when Splunk returns an HTTP error, message envelope, or unexpected response."""
    pass


class SplunkSearchClient:
    """Read-only client executing bounded, allowlisted Splunk search queries."""

    def __init__(
        self,
        verify_tls: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        """Initialize the search client.

        TLS Verification Architecture Note:
        Splunk Free on localhost generates a self-signed certificate upon installation.
        For local lab validation on localhost:8089, verify_tls defaults to False.
        This behavior is strictly intended for isolated local lab testing.
        In production environments, verify_tls must be True and validate against a
        trusted enterprise Certificate Authority (CA) chain.

        Args:
            verify_tls: Whether to verify the SSL certificate (False for local lab self-signed cert).
            timeout: Finite network request timeout in seconds (must be positive).
            opener: Optional custom urllib OpenerDirector for testing/transport mocking.
        """
        if timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {timeout}")

        self._timeout = float(timeout)
        self._verify_tls = verify_tls

        # Explicit TLS context configuration
        if not self._verify_tls:
            # LAB-ONLY: Explicitly disable cert validation for localhost self-signed Splunk cert
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self._ssl_context = ssl.create_default_context()

        self._opener = opener

    @property
    def endpoint(self) -> str:
        """Expose the immutable hardcoded endpoint."""
        return SPLUNK_EXPORT_ENDPOINT

    def search_encoded_powershell(
        self,
        host: str = "DC01",
        minutes: int = 15,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Query Splunk for suspicious encoded PowerShell executions on host DC01.

        Enforces policy validation before dispatching the request. The caller can
        only supply bounded parameters (host, minutes, limit); arbitrary SPL and
        endpoint paths cannot be supplied.

        Args:
            host: Target host name (strictly 'DC01').
            minutes: Lookback window in minutes (1-60).
            limit: Maximum events to return (1-50).

        Returns:
            List of dictionaries containing all 7 mandatory allowlisted fields:
            _time, host, User, Image, CommandLine, ParentImage, ParentCommandLine.

        Raises:
            PolicyValidationError: If inputs violate policy boundaries.
            SplunkConnectionError: If Splunk cannot be reached or times out.
            SplunkResponseError: If Splunk returns an error envelope, HTTP error,
                                 malformed data, missing mandatory fields, or excess events.
        """
        # Step 1: Validate input through policy gate
        request = validate_search_request(
            query_type="encoded_powershell_matches",
            host=host,
            minutes=minutes,
            limit=limit,
        )

        # Step 2: Construct non-arbitrary SPL from template
        spl = build_allowlisted_spl(request)

        # Step 3: Execute query against fixed export endpoint
        payload = urllib.parse.urlencode({
            "search": spl,
            "output_mode": "json",
        }).encode("utf-8")

        req = urllib.request.Request(
            url=SPLUNK_EXPORT_ENDPOINT,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "AI-Native-SOC-Lab/SearchClient-v1",
            },
        )

        raw_response = self._execute_http(req)

        # Step 4: Parse structured response and extract allowlisted fields
        records = self._parse_json_stream(raw_response)

        # Step 5: Defense-in-depth: enforce post-parsing result count limit
        if len(records) > request.limit:
            raise SplunkResponseError(
                f"Splunk returned {len(records)} events, exceeding requested limit of {request.limit}"
            )

        return records

    def _execute_http(self, req: urllib.request.Request) -> str:
        """Execute the HTTP request using bounded reads and sanitized error reporting."""
        try:
            if self._opener:
                response = self._opener.open(req, timeout=self._timeout)
            else:
                response = urllib.request.urlopen(
                    req,
                    timeout=self._timeout,
                    context=self._ssl_context,
                )
            with response:
                # Bounded read: Read up to MAX_RESPONSE_BYTES + 1 to detect oversized responses
                raw_bytes = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_bytes) > MAX_RESPONSE_BYTES:
                    raise SplunkResponseError(
                        f"Splunk response exceeded maximum allowed limit of {MAX_RESPONSE_BYTES} bytes"
                    )
                return raw_bytes.decode("utf-8", errors="replace")

        except urllib.error.HTTPError as err:
            # Sanitize: Report HTTP code and reason only. Never leak raw response body.
            raise SplunkResponseError(
                f"Splunk returned HTTP {err.code}: {err.reason}"
            ) from err

        except (urllib.error.URLError, TimeoutError, OSError) as err:
            # Sanitize: Concise connection error without raw memory dumps
            raise SplunkConnectionError(
                f"Failed to connect to Splunk at {SPLUNK_EXPORT_ENDPOINT}: {type(err).__name__}"
            ) from err

    def _parse_json_stream(self, raw_data: str) -> List[Dict[str, Any]]:
        """Parse Splunk export output_mode=json stream into structured records.

        Enforces:
        - Rejection of server messages (WARN, ERROR, FATAL envelopes).
        - Schema completeness: all 7 detection fields must be present and non-empty.
        - Fail-closed parsing on malformed JSON or unexpected structures.
        """
        stripped = raw_data.strip()
        if not stripped:
            return []

        records: List[Dict[str, Any]] = []

        # Parse JSON lines (standard export stream format)
        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        for line_num, line in enumerate(lines, start=1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as err:
                raise SplunkResponseError(
                    f"Malformed non-JSON response from Splunk on line {line_num}: {err}"
                ) from err

            if not isinstance(obj, dict):
                raise SplunkResponseError(
                    f"Unexpected JSON token type on line {line_num}: expected object, got {type(obj).__name__}"
                )

            # Check for Splunk message envelopes (WARN, ERROR, FATAL)
            if "messages" in obj and isinstance(obj["messages"], list):
                for msg in obj["messages"]:
                    if isinstance(msg, dict):
                        msg_type = str(msg.get("type", "")).upper()
                        if msg_type in ("ERROR", "WARN", "FATAL"):
                            raise SplunkResponseError(
                                f"Splunk returned server message with severity {msg_type}"
                            )

            # Ignore non-event metadata lines (e.g. preview-only or empty results without 'result')
            if "result" not in obj:
                continue

            result_map = obj["result"]
            if not isinstance(result_map, dict):
                raise SplunkResponseError(
                    f"Event envelope on line {line_num} contains non-dict result payload"
                )

            # Enforce mandatory detection fields contract:
            # All 7 fields must exist and be non-empty strings. Partial records are rejected.
            missing_or_empty = [
                field for field in ALLOWED_FIELDS
                if field not in result_map or not str(result_map[field]).strip()
            ]
            if missing_or_empty:
                raise SplunkResponseError(
                    f"Event record on line {line_num} missing required detection fields: {sorted(missing_or_empty)}"
                )

            # Extract strictly the allowlisted fields
            record = {
                field: str(result_map[field])
                for field in ALLOWED_FIELDS
            }
            records.append(record)

        return records
