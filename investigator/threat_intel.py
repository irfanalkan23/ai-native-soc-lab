"""Deterministic Threat Intelligence Contract and Provider-Neutral Schemas.

Architecture Principle:
    AI proposes
    -> deterministic policy evaluates
    -> human approves consequential actions
    -> deterministic executor acts
    -> everything is logged and evaluated

Trust & Scope Boundaries:
    - Advisory Evidence Only: Threat intelligence is strictly advisory evidence.
      It possesses ZERO authority to change endpoint state, approve actions,
      execute actions, bypass deterministic policy, create arbitrary network
      requests, modify Jira tickets, or alter Splunk queries.
    - Zero External Network / Zero Credentials: This core module remains strictly
      provider-neutral, makes zero network calls, connects to no remote APIs,
      uses no API tokens, and imports no HTTP/socket libraries. Future network
      adapters (such as VirusTotal) are implemented separately in provider modules.
    - Public / Globally Routable IP Scope Only: In V1, threat intelligence is
      bounded exclusively to IP address enrichment. Non-global, private, loopback,
      link-local, multicast, unspecified, and reserved addresses are rejected.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Mapping, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Schema Bounds & Allowlisted Constants
# ---------------------------------------------------------------------------

MAX_INDICATOR_VALUE_LENGTH = 45  # Maximum length of standard IPv6 string representation

ALLOWED_TI_PROVIDERS = frozenset({
    "fake_threat_intel",
    "virustotal",
})

ALLOWED_TI_DETAIL_CODES = frozenset({
    "ip_lookup_found",
    "ip_lookup_not_found",
})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatIntelLookupStatus(Enum):
    """Normalized indicator lookup status."""
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ThreatIntelError(Exception):
    """Base exception for all threat intelligence errors."""


class ThreatIntelRequestError(ThreatIntelError):
    """Raised when ThreatIntelRequest validation fails."""


class ThreatIntelResultError(ThreatIntelError):
    """Raised when ThreatIntelResult validation fails."""


class ThreatIntelClientError(ThreatIntelError):
    """Raised when a ThreatIntelClient encounters an internal, configuration, or binding error."""


# ---------------------------------------------------------------------------
# Shared Canonical Validation Helper
# ---------------------------------------------------------------------------

def _canonicalize_public_ip(value: str) -> str:
    """Validate that value is a single, valid, globally routable public IP.

    Returns the normalized canonical IP string.
    Raises ValueError on any syntax or policy violation.

    Policy Note:
        is_global alone is insufficient for this project's external-enrichment
        policy; therefore multicast and other special-use categories are
        explicitly rejected.
    """
    if type(value) is not str:
        raise ValueError("indicator_value must be exact str type")

    if value != value.strip():
        raise ValueError("indicator_value contains leading or trailing whitespace")

    if not value:
        raise ValueError("indicator_value cannot be empty")

    if len(value) > MAX_INDICATOR_VALUE_LENGTH:
        raise ValueError(
            f"indicator_value exceeds maximum length of {MAX_INDICATOR_VALUE_LENGTH} characters"
        )

    # Disallow structural separators that indicate non-single-IP syntax
    if "%" in value:
        raise ValueError("IPv6 scope or zone identifiers are not allowed")
    if "/" in value:
        raise ValueError("CIDR notation or path separators not allowed in indicator_value")
    if "://" in value:
        raise ValueError("URLs not allowed in indicator_value")
    if "," in value:
        raise ValueError("Comma-separated lists not allowed in indicator_value")

    # Strict standard library IP parsing
    # Automatically rejects bracketed IPv6+port, IPv4:port, and malformed octets/hex
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address format: {exc}") from exc

    # Enforce strict public routability predicate
    if (
        not ip.is_global
        or ip.is_multicast
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
    ):
        raise ValueError(f"IP address {value} is not a globally routable public IP")

    return str(ip)


def _validate_utc_timestamp(ts: str) -> None:
    """Validate that timestamp is an ISO 8601 string with UTC offset exactly zero.

    Raises ThreatIntelResultError if invalid.
    """
    if len(ts) > 35:
        raise ThreatIntelResultError("last_analysis_utc exceeds maximum length")
    if not (ts.endswith("Z") or ts.endswith("+00:00")):
        raise ThreatIntelResultError("last_analysis_utc must explicitly indicate UTC offset (Z or +00:00)")
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ThreatIntelResultError(f"Malformed last_analysis_utc timestamp: {exc}") from exc

    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ThreatIntelResultError("last_analysis_utc must have a zero UTC offset")


# ---------------------------------------------------------------------------
# Request Schema
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatIntelRequest:
    """Immutable request contract for threat intelligence lookup."""

    indicator_value: str
    indicator_type: str = "ip"

    def __post_init__(self) -> None:
        if type(self.indicator_type) is not str or self.indicator_type != "ip":
            raise ThreatIntelRequestError("indicator_type must be exact str 'ip'")

        try:
            canonical_ip = _canonicalize_public_ip(self.indicator_value)
        except ValueError as exc:
            raise ThreatIntelRequestError(str(exc)) from exc

        object.__setattr__(self, "indicator_value", canonical_ip)


# ---------------------------------------------------------------------------
# Result Schema
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatIntelResult:
    """Immutable normalized threat intelligence result contract."""

    provider: str
    indicator_type: str
    indicator_value: str
    lookup_status: ThreatIntelLookupStatus
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    detail_code: str
    last_analysis_utc: Optional[str] = None

    def __post_init__(self) -> None:
        # 1. Provider allowlist
        if type(self.provider) is not str or self.provider not in ALLOWED_TI_PROVIDERS:
            raise ThreatIntelResultError(
                f"provider {self.provider!r} is not in ALLOWED_TI_PROVIDERS"
            )

        # 2. Indicator type
        if type(self.indicator_type) is not str or self.indicator_type != "ip":
            raise ThreatIntelResultError("indicator_type must be exact str 'ip'")

        # 3. Canonical public IP validation
        try:
            canonical_ip = _canonicalize_public_ip(self.indicator_value)
        except ValueError as exc:
            raise ThreatIntelResultError(f"indicator_value invalid: {exc}") from exc

        if self.indicator_value != canonical_ip:
            raise ThreatIntelResultError(
                f"indicator_value {self.indicator_value!r} is not in canonical form {canonical_ip!r}"
            )

        # 4. Lookup status enum
        if type(self.lookup_status) is not ThreatIntelLookupStatus:
            raise ThreatIntelResultError("lookup_status must be a ThreatIntelLookupStatus enum")

        # 5. Analysis counters
        for name in ("malicious_count", "suspicious_count", "harmless_count", "undetected_count"):
            val = getattr(self, name)
            if type(val) is not int or val < 0 or val > 256:
                raise ThreatIntelResultError(
                    f"{name} must be exact int between 0 and 256, got {val!r}"
                )

        # 6. Detail code allowlist
        if type(self.detail_code) is not str or self.detail_code not in ALLOWED_TI_DETAIL_CODES:
            raise ThreatIntelResultError(
                f"detail_code {self.detail_code!r} is not in ALLOWED_TI_DETAIL_CODES"
            )

        # 7. Status coupling & timestamp validation
        if self.lookup_status == ThreatIntelLookupStatus.FOUND:
            if self.detail_code != "ip_lookup_found":
                raise ThreatIntelResultError(
                    "detail_code must be 'ip_lookup_found' when lookup_status is FOUND"
                )
            if self.last_analysis_utc is not None:
                if type(self.last_analysis_utc) is not str:
                    raise ThreatIntelResultError("last_analysis_utc must be str or None")
                _validate_utc_timestamp(self.last_analysis_utc)

        elif self.lookup_status == ThreatIntelLookupStatus.NOT_FOUND:
            if self.detail_code != "ip_lookup_not_found":
                raise ThreatIntelResultError(
                    "detail_code must be 'ip_lookup_not_found' when lookup_status is NOT_FOUND"
                )
            if (
                self.malicious_count != 0
                or self.suspicious_count != 0
                or self.harmless_count != 0
                or self.undetected_count != 0
            ):
                raise ThreatIntelResultError(
                    "all counters must be 0 when lookup_status is NOT_FOUND"
                )
            if self.last_analysis_utc is not None:
                raise ThreatIntelResultError(
                    "last_analysis_utc must be None when lookup_status is NOT_FOUND"
                )


# ---------------------------------------------------------------------------
# Client Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class ThreatIntelClient(Protocol):
    """Protocol for provider-neutral threat intelligence clients."""

    def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """Query threat intelligence for a validated indicator."""
        ...


# ---------------------------------------------------------------------------
# Fake Client Implementation
# ---------------------------------------------------------------------------

class FakeThreatIntelClient:
    """Deterministic, in-memory threat intelligence client for offline testing.

    Accepts an injected mapping of IP string -> ThreatIntelResult.
    All fixtures are validated at construction time. Fixture classifications
    are purely synthetic lab fixtures and carry no real-world reputation claims.
    """

    def __init__(
        self,
        fixtures: Optional[Mapping[str, ThreatIntelResult]] = None,
    ) -> None:
        self._fixtures: dict[str, ThreatIntelResult] = {}
        if fixtures is not None:
            if not isinstance(fixtures, Mapping):
                raise ThreatIntelClientError("fixtures must be a mapping of IP -> ThreatIntelResult")

            for raw_ip, result in fixtures.items():
                try:
                    canonical_key = _canonicalize_public_ip(raw_ip)
                except ValueError as exc:
                    raise ThreatIntelClientError(
                        f"Fixture IP key {raw_ip!r} is invalid: {exc}"
                    ) from exc

                if type(result) is not ThreatIntelResult:
                    raise ThreatIntelClientError(
                        f"Fixture value for {raw_ip!r} must be exact ThreatIntelResult instance"
                    )

                if result.indicator_value != canonical_key:
                    raise ThreatIntelClientError(
                        f"Fixture key {canonical_key!r} does not match result indicator_value {result.indicator_value!r}"
                    )

                if result.indicator_type != "ip":
                    raise ThreatIntelClientError(
                        f"Fixture result indicator_type must be 'ip', got {result.indicator_type!r}"
                    )

                self._fixtures[canonical_key] = result

    def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """Lookup an indicator against registered fixtures, or return NOT_FOUND."""
        if type(request) is not ThreatIntelRequest:
            raise ThreatIntelClientError("request must be exact ThreatIntelRequest instance")

        ip = request.indicator_value
        if ip in self._fixtures:
            result = self._fixtures[ip]
        else:
            result = ThreatIntelResult(
                provider="fake_threat_intel",
                indicator_type="ip",
                indicator_value=ip,
                lookup_status=ThreatIntelLookupStatus.NOT_FOUND,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                detail_code="ip_lookup_not_found",
                last_analysis_utc=None,
            )

        # Defensive request/result binding check before returning
        if (
            result.indicator_type != request.indicator_type
            or result.indicator_value != request.indicator_value
        ):
            raise ThreatIntelClientError(
                f"indicator_mismatch: result ({result.indicator_type}:{result.indicator_value}) "
                f"does not match request ({request.indicator_type}:{request.indicator_value})"
            )

        return result


# ---------------------------------------------------------------------------
# Normalized Policy Signal Schema
# ---------------------------------------------------------------------------

# Allowlisted detail codes that may appear inside ThreatIntelPolicySignal.
# Only these bounded codes are accepted; arbitrary provider text is rejected.
ALLOWED_TI_SIGNAL_DETAIL_CODES = frozenset({
    "ti_not_applicable",
    "ti_not_found",
    "ti_found",
    "ti_error",
})


class ThreatIntelSignalStatus(str, Enum):
    """Normalized status of a threat-intel enrichment attempt.

    NOT_APPLICABLE: No valid public IPv4 candidate was available for lookup.
    NOT_FOUND:      A lookup was performed but the provider has no result.
    ERROR:          A bounded provider or integration failure occurred.
    FOUND:          The provider returned a result for the requested indicator.
    """
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    FOUND = "FOUND"


@dataclass(frozen=True)
class ThreatIntelPolicySignal:
    """Normalized, provider-neutral threat-intel evidence for policy evaluation.

    Architecture Note:
        This dataclass carries EVIDENCE ONLY.  It does NOT contain a
        corroboration_score or any policy scoring interpretation.
        RiskPolicyEngine is the sole authority that converts this evidence
        into additive risk-score contributions.

    Constraints:
        - No raw provider JSON, vendor engine names, or HTTP metadata.
        - detail_code is an allowlisted bounded code only.
        - Count fields: exact int, not bool, 0 <= value <= 256.
        - Status/field consistency is validated in __post_init__.
    """
    status: ThreatIntelSignalStatus
    indicator: Optional[str]          # canonical public IP, or None
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    detail_code: str

    def __post_init__(self) -> None:
        # 1. status must be ThreatIntelSignalStatus
        if type(self.status) is not ThreatIntelSignalStatus:
            raise ThreatIntelError(
                f"ThreatIntelPolicySignal.status must be ThreatIntelSignalStatus, "
                f"got {type(self.status).__name__}"
            )

        # 2. detail_code allowlist
        if type(self.detail_code) is not str or self.detail_code not in ALLOWED_TI_SIGNAL_DETAIL_CODES:
            raise ThreatIntelError(
                f"ThreatIntelPolicySignal.detail_code {self.detail_code!r} is not allowlisted"
            )

        # 3. count field types and bounds
        for field_name in ("malicious_count", "suspicious_count", "harmless_count", "undetected_count"):
            val = getattr(self, field_name)
            if type(val) is bool or type(val) is not int:
                raise ThreatIntelError(
                    f"ThreatIntelPolicySignal.{field_name} must be exact int, got {type(val).__name__}"
                )
            if not (0 <= val <= 256):
                raise ThreatIntelError(
                    f"ThreatIntelPolicySignal.{field_name} must be 0-256, got {val}"
                )

        # 4. Status-specific consistency checks
        if self.status is ThreatIntelSignalStatus.NOT_APPLICABLE:
            if self.indicator is not None:
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: indicator must be None when status is NOT_APPLICABLE"
                )
            if any(getattr(self, f) != 0 for f in ("malicious_count", "suspicious_count", "harmless_count", "undetected_count")):
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: all counts must be 0 when status is NOT_APPLICABLE"
                )
            if self.detail_code != "ti_not_applicable":
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: detail_code must be 'ti_not_applicable' when status is NOT_APPLICABLE"
                )

        elif self.status is ThreatIntelSignalStatus.NOT_FOUND:
            if self.indicator is None or type(self.indicator) is not str:
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: indicator must be a str when status is NOT_FOUND"
                )
            if any(getattr(self, f) != 0 for f in ("malicious_count", "suspicious_count", "harmless_count", "undetected_count")):
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: all counts must be 0 when status is NOT_FOUND"
                )
            if self.detail_code != "ti_not_found":
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: detail_code must be 'ti_not_found' when status is NOT_FOUND"
                )

        elif self.status is ThreatIntelSignalStatus.ERROR:
            if self.indicator is not None and type(self.indicator) is not str:
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: indicator must be str or None when status is ERROR"
                )
            if any(getattr(self, f) != 0 for f in ("malicious_count", "suspicious_count", "harmless_count", "undetected_count")):
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: all counts must be 0 when status is ERROR"
                )
            if self.detail_code != "ti_error":
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: detail_code must be 'ti_error' when status is ERROR"
                )

        elif self.status is ThreatIntelSignalStatus.FOUND:
            if self.indicator is None or type(self.indicator) is not str:
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: indicator must be a str when status is FOUND"
                )
            if self.detail_code != "ti_found":
                raise ThreatIntelError(
                    "ThreatIntelPolicySignal: detail_code must be 'ti_found' when status is FOUND"
                )


# ---------------------------------------------------------------------------
# Enrichment Helper
# ---------------------------------------------------------------------------

def enrich_threat_intel(
    canonical_ip: Optional[str],
    client: "ThreatIntelClient",
    runtime_guard: object,
    audit_log: object,
    incident_id: str,
) -> "ThreatIntelPolicySignal":
    """Perform a bounded, deterministic threat-intel enrichment for one IP.

    Architecture responsibilities:
        1. Short-circuit to NOT_APPLICABLE if no valid candidate is provided.
        2. Call RuntimeGuard.check_execution_permitted(THREAT_INTEL) before any lookup.
        3. Build ThreatIntelRequest (re-validates canonical public IP via schema boundary).
        4. Call ThreatIntelClient.lookup() exactly once.
        5. Validate result indicator matches request indicator.
        6. Normalize ThreatIntelResult -> ThreatIntelPolicySignal.
        7. Convert bounded provider exceptions to ERROR signal (no risk increase).
        8. Emit bounded audit events (THREAT_INTEL_REQUESTED, THREAT_INTEL_COMPLETED).

    Args:
        canonical_ip:    A canonical public IPv4 string, or None.
        client:          Provider-neutral ThreatIntelClient instance.
        runtime_guard:   RuntimeGuard instance (duck-typed to avoid circular import).
        audit_log:       AuditLog instance (duck-typed to avoid circular import).
        incident_id:     Bounded incident identifier for audit records.

    Returns:
        ThreatIntelPolicySignal -- evidence only, no policy score.
    """
    # Import locally to avoid circular imports; these are pure data types.
    from investigator.audit import AuditEvent, AuditEventType, AuditLog as _AuditLog
    from investigator.runtime_guard import RuntimeCheckpoint, RuntimeHaltError

    def _audit(event_type: "AuditEventType", detail_code: str) -> None:
        """Emit one bounded audit event if an AuditLog is attached."""
        if audit_log is None or not isinstance(audit_log, _AuditLog):
            return
        seq = len(audit_log.events())
        audit_log.append(AuditEvent(
            event_type=event_type,
            incident_id=incident_id,
            sequence=seq,
            detail_code=detail_code,
        ))

    # 1. No valid candidate -> NOT_APPLICABLE, no network interaction
    if canonical_ip is None:
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.NOT_APPLICABLE,
            indicator=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_not_applicable",
        )

    # 2. RuntimeGuard boundary check before any lookup.
    #
    # ARCHITECTURE INVARIANT: RuntimeHaltError is NOT caught here.
    # A RuntimeGuard halt is a global execution abort signal, not a provider
    # error.  It must propagate to the caller (run_demo or integration test)
    # which is responsible for aborting the entire workflow.
    #
    # Only ThreatIntelError (provider-specific failure) is normalized to an
    # ERROR signal below.  These two paths must never be conflated.
    runtime_guard.check_execution_permitted(RuntimeCheckpoint.THREAT_INTEL)
    # RuntimeHaltError propagates unconditionally from here.

    # 3. Emit REQUESTED audit event (before network call, detail code is bounded)
    _audit(AuditEventType.THREAT_INTEL_REQUESTED, "PUBLIC_IP_SELECTED")

    # 4. Build request (re-validates canonical IP via ThreatIntelRequest schema boundary)
    try:
        request = ThreatIntelRequest(indicator_type="ip", indicator_value=canonical_ip)
    except ThreatIntelRequestError:
        _audit(AuditEventType.THREAT_INTEL_COMPLETED, "TI_ERROR")
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.ERROR,
            indicator=canonical_ip,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_error",
        )

    # 5. Perform exactly one lookup
    try:
        result = client.lookup(request)
    except ThreatIntelError:
        _audit(AuditEventType.THREAT_INTEL_COMPLETED, "TI_ERROR")
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.ERROR,
            indicator=canonical_ip,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_error",
        )

    # 6. Validate result indicator matches request (fail-closed on mismatch)
    if result.indicator_value != request.indicator_value or result.indicator_type != request.indicator_type:
        _audit(AuditEventType.THREAT_INTEL_COMPLETED, "TI_ERROR")
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.ERROR,
            indicator=canonical_ip,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_error",
        )

    # 7. Normalize ThreatIntelResult -> ThreatIntelPolicySignal
    if result.lookup_status is ThreatIntelLookupStatus.NOT_FOUND:
        _audit(AuditEventType.THREAT_INTEL_COMPLETED, "TI_NOT_FOUND")
        return ThreatIntelPolicySignal(
            status=ThreatIntelSignalStatus.NOT_FOUND,
            indicator=result.indicator_value,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            undetected_count=0,
            detail_code="ti_not_found",
        )

    # ThreatIntelLookupStatus.FOUND
    _audit(AuditEventType.THREAT_INTEL_COMPLETED, "TI_FOUND")
    return ThreatIntelPolicySignal(
        status=ThreatIntelSignalStatus.FOUND,
        indicator=result.indicator_value,
        malicious_count=result.malicious_count,
        suspicious_count=result.suspicious_count,
        harmless_count=result.harmless_count,
        undetected_count=result.undetected_count,
        detail_code="ti_found",
    )
