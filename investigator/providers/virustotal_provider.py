"""VirusTotal REST API v3 Threat Intelligence IP Provider Adapter.

Architecture Guarantees:
  - Advisory Evidence Only: Threat intelligence results possess ZERO authority to
    alter endpoint state, change risk scoring, approve actions, execute containment,
    or modify Jira/Splunk workflows.
  - Bounded Public-IP Scope Only: Exclusively queries /api/v3/ip_addresses/{ip}
    for pre-validated, globally routable public IPs. Domains, URLs, hashes, and CIDRs
    are rejected at the ThreatIntelRequest schema boundary.
  - Fixed Single-Endpoint Transport: Hardcoded destination host www.virustotal.com:443.
    Zero caller-controlled host, port, scheme, path prefix, or method configuration.
    Zero query parameters or request body. GET only.
  - Standard Library HTTPS Transport: Built strictly on http.client and ssl. Zero
    third-party dependencies (no requests, no httpx, no urllib3).
  - Single-Attempt Dispatch: One GET attempt only; zero automatic retry on failure.
  - Redirect Rejection: HTTP 3xx redirects are rejected immediately without following.
  - Hard Capped Response: Maximum response size bounded at <= 64 KiB (65536 bytes).
    Oversized responses fail closed immediately.
  - Ephemeral Data Processing: Raw provider responses are parsed into normalized
    primitives and immediately discarded; raw JSON is never logged or persisted.
  - Secret Hygiene: API keys are masked in __repr__ and __str__ and never exposed
    in exceptions, URLs, console logs, or audit records.
  - No Environment or Filesystem Access: This core module reads no files and accesses
    no environment variables (zero process environment lookups, no from_env).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import json
import ssl
from typing import Callable, Optional

from investigator.threat_intel import (
    _canonicalize_public_ip,
    ThreatIntelClient,
    ThreatIntelClientError,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
)

# ---------------------------------------------------------------------------
# Constants & Fixed Endpoint Invariants
# ---------------------------------------------------------------------------

VIRUSTOTAL_HOST = "www.virustotal.com"
VIRUSTOTAL_PORT = 443
VIRUSTOTAL_ENDPOINT_PREFIX = "/api/v3/ip_addresses/"

MAX_API_KEY_LENGTH = 512  # Local safety bound, not a provider format claim
MIN_RESPONSE_CAP_BYTES = 1024
MAX_ALLOWED_RESPONSE_CAP = 65536  # Hard limit: exactly 64 KiB
DEFAULT_TIMEOUT_SECONDS = 5.0
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 60.0
MAX_EPOCH_TIMESTAMP = 4102444800  # Year 2100 sanity boundary


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VirusTotalError(ThreatIntelClientError):
    """Base exception for all VirusTotal provider errors."""


class VirusTotalConfigError(VirusTotalError):
    """Raised when VirusTotal configuration is invalid."""


class VirusTotalCredentialError(VirusTotalError):
    """Raised when VirusTotal credentials are invalid."""


class VirusTotalTransportError(VirusTotalError):
    """Raised when VirusTotal HTTP transport, TLS, or redirect fails."""


class VirusTotalResponseError(VirusTotalError):
    """Raised when VirusTotal returns an error response, oversized body, or invalid schema."""


# ---------------------------------------------------------------------------
# Credentials Container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VirusTotalCredentials:
    """Immutable credentials container with local safety bound and secret masking."""

    api_key: str

    def __post_init__(self) -> None:
        if type(self.api_key) is not str:
            raise VirusTotalCredentialError("api_key must be exact str type")

        stripped = self.api_key.strip()
        if not stripped or self.api_key != stripped:
            raise VirusTotalCredentialError(
                "api_key must be non-empty and have no leading/trailing whitespace"
            )

        if len(self.api_key) < 1 or len(self.api_key) > MAX_API_KEY_LENGTH:
            raise VirusTotalCredentialError(
                f"api_key length must be between 1 and {MAX_API_KEY_LENGTH} characters (local safety bound)"
            )

        if any(c in self.api_key for c in "\r\n\t "):
            raise VirusTotalCredentialError("api_key must not contain whitespace or control characters")

    def __repr__(self) -> str:
        return "VirusTotalCredentials(api_key='***')"

    def __str__(self) -> str:
        return "VirusTotalCredentials(api_key='***')"


# ---------------------------------------------------------------------------
# Configuration Container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VirusTotalApiConfig:
    """Bounded operational parameters for VirusTotal API communication."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = MAX_ALLOWED_RESPONSE_CAP

    def __post_init__(self) -> None:
        if type(self.timeout_seconds) not in (int, float) or isinstance(self.timeout_seconds, bool):
            raise VirusTotalConfigError("timeout_seconds must be an int or float")
        if self.timeout_seconds < MIN_TIMEOUT_SECONDS or self.timeout_seconds > MAX_TIMEOUT_SECONDS:
            raise VirusTotalConfigError(
                f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds"
            )

        if type(self.max_response_bytes) is not int or isinstance(self.max_response_bytes, bool):
            raise VirusTotalConfigError("max_response_bytes must be exact int")
        if self.max_response_bytes < MIN_RESPONSE_CAP_BYTES or self.max_response_bytes > MAX_ALLOWED_RESPONSE_CAP:
            raise VirusTotalConfigError(
                f"max_response_bytes must be between {MIN_RESPONSE_CAP_BYTES} and {MAX_ALLOWED_RESPONSE_CAP} bytes (64 KiB)"
            )


# ---------------------------------------------------------------------------
# Connection Factory Type & Default
# ---------------------------------------------------------------------------

_ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], http.client.HTTPSConnection]


def _default_connection_factory(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(
        host=host,
        port=port,
        timeout=timeout,
        context=context,
    )


# ---------------------------------------------------------------------------
# Provider Client Implementation
# ---------------------------------------------------------------------------

class VirusTotalThreatIntelClient:
    """Synchronous provider adapter for VirusTotal REST API v3 IP lookups."""

    def __init__(
        self,
        credentials: VirusTotalCredentials,
        config: Optional[VirusTotalApiConfig] = None,
        _connection_factory: Optional[_ConnectionFactory] = None,
    ) -> None:
        if type(credentials) is not VirusTotalCredentials:
            raise VirusTotalCredentialError("credentials must be exact VirusTotalCredentials instance")
        self._credentials = credentials

        resolved_config = config if config is not None else VirusTotalApiConfig()
        if type(resolved_config) is not VirusTotalApiConfig:
            raise VirusTotalConfigError("config must be exact VirusTotalApiConfig instance")
        self._config = resolved_config

        self._connection_factory = _connection_factory or _default_connection_factory

    def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """Query VirusTotal REST API v3 for a validated public IP indicator."""
        if type(request) is not ThreatIntelRequest:
            raise ThreatIntelClientError("request must be exact ThreatIntelRequest instance")

        if request.indicator_type != "ip":
            raise ThreatIntelClientError("indicator_type must be exact str 'ip'")

        ssl_ctx = ssl.create_default_context()
        conn: Optional[http.client.HTTPSConnection] = None

        try:
            try:
                conn = self._connection_factory(
                    VIRUSTOTAL_HOST,
                    VIRUSTOTAL_PORT,
                    float(self._config.timeout_seconds),
                    ssl_ctx,
                )
            except Exception:
                raise VirusTotalTransportError("vt_transport_error") from None

            try:
                path = f"{VIRUSTOTAL_ENDPOINT_PREFIX}{request.indicator_value}"
                headers = {
                    "x-apikey": self._credentials.api_key,
                    "Accept": "application/json",
                    "User-Agent": "ai-native-soc-lab/1.0",
                }

                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()

                if 300 <= resp.status < 400:
                    raise VirusTotalTransportError("vt_redirect_rejected")
                elif resp.status == 400:
                    raise VirusTotalResponseError("vt_bad_request")
                elif resp.status == 401:
                    raise VirusTotalResponseError("vt_auth_failed")
                elif resp.status == 403:
                    raise VirusTotalResponseError("vt_forbidden")
                elif resp.status == 429:
                    raise VirusTotalResponseError("vt_rate_limited")
                elif 500 <= resp.status <= 599:
                    raise VirusTotalResponseError("vt_remote_error")
                elif resp.status != 200 and resp.status != 404:
                    raise VirusTotalResponseError("vt_unexpected_status")

                max_bytes = self._config.max_response_bytes
                raw_bytes = resp.read(max_bytes + 1)
                if len(raw_bytes) > max_bytes:
                    raise VirusTotalResponseError("vt_response_too_large")

                if resp.status == 200:
                    return self._parse_200_response(raw_bytes, request)
                else:  # resp.status == 404
                    return self._parse_404_response(raw_bytes, request)

            except (VirusTotalError, ThreatIntelClientError):
                raise
            except (http.client.HTTPException, OSError, TimeoutError):
                raise VirusTotalTransportError("vt_transport_error") from None

        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _parse_404_response(self, raw_bytes: bytes, request: ThreatIntelRequest) -> ThreatIntelResult:
        """Parse HTTP 404 response to determine if resource is genuinely not found."""
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise VirusTotalResponseError("vt_invalid_json")

        try:
            payload = json.loads(text)
        except ValueError:
            raise VirusTotalResponseError("vt_invalid_json")

        if type(payload) is not dict:
            raise VirusTotalResponseError("vt_endpoint_not_found")

        error_obj = payload.get("error")
        if type(error_obj) is not dict:
            raise VirusTotalResponseError("vt_endpoint_not_found")

        code = error_obj.get("code")
        if type(code) is not str or code != "NotFoundError":
            raise VirusTotalResponseError("vt_endpoint_not_found")

        # Ignore error.message entirely, construct normalized NOT_FOUND
        return ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value=request.indicator_value,
            lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ip_lookup_not_found",
            last_analysis_utc=None,
        )

    def _parse_200_response(self, raw_bytes: bytes, request: ThreatIntelRequest) -> ThreatIntelResult:
        """Parse HTTP 200 response into normalized ThreatIntelResult."""
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise VirusTotalResponseError("vt_invalid_json")

        try:
            payload = json.loads(text)
        except ValueError:
            raise VirusTotalResponseError("vt_invalid_json")

        if type(payload) is not dict:
            raise VirusTotalResponseError("vt_schema_invalid")

        data = payload.get("data")
        if type(data) is not dict:
            raise VirusTotalResponseError("vt_schema_invalid")

        if data.get("type") != "ip_address":
            raise VirusTotalResponseError("vt_schema_invalid")

        raw_id = data.get("id")
        if type(raw_id) is not str:
            raise VirusTotalResponseError("vt_schema_invalid")

        try:
            canonical_id = _canonicalize_public_ip(raw_id)
        except ValueError:
            raise VirusTotalResponseError("vt_indicator_mismatch")

        if canonical_id != request.indicator_value:
            raise VirusTotalResponseError("vt_indicator_mismatch")

        attributes = data.get("attributes")
        if type(attributes) is not dict:
            raise VirusTotalResponseError("vt_schema_invalid")

        stats = attributes.get("last_analysis_stats")
        if type(stats) is not dict:
            raise VirusTotalResponseError("vt_schema_invalid")

        for counter_name in ("malicious", "suspicious", "harmless", "undetected"):
            val = stats.get(counter_name)
            if type(val) is not int or isinstance(val, bool) or val < 0 or val > 256:
                raise VirusTotalResponseError("vt_schema_invalid")

        epoch_val = attributes.get("last_analysis_date")
        last_analysis_utc: Optional[str] = None
        if epoch_val is not None:
            if type(epoch_val) is not int or isinstance(epoch_val, bool):
                raise VirusTotalResponseError("vt_schema_invalid")
            if epoch_val < 0 or epoch_val > MAX_EPOCH_TIMESTAMP:
                raise VirusTotalResponseError("vt_schema_invalid")
            dt = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
            last_analysis_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        result = ThreatIntelResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value=request.indicator_value,
            lookup_status=ThreatIntelLookupStatus.FOUND,
            malicious_count=stats["malicious"],
            suspicious_count=stats["suspicious"],
            harmless_count=stats["harmless"],
            undetected_count=stats["undetected"],
            detail_code="ip_lookup_found",
            last_analysis_utc=last_analysis_utc,
        )

        if (
            result.indicator_type != request.indicator_type
            or result.indicator_value != request.indicator_value
        ):
            raise VirusTotalResponseError("vt_indicator_mismatch")

        return result
