"""Normalized Apache ModSecurity / OWASP CRS Evidence Contract.

Architecture Principle:
    AI proposes -> deterministic policy evaluates -> human approves consequential actions
    -> system executes only permitted/simulated actions -> everything is logged/evaluated.

Trust & Scope Boundaries:
    - Evidence Contract Only: This module provides an immutable, normalized data model
      for ModSecurity SQL injection (SQLi) attack events detected on WEB01.
    - Zero External Network / Zero Subprocess: Pure standard library data validation.
    - Fail-Closed: Missing, malformed, non-SQLi, or incomplete fragment records are
      strictly rejected with ModSecurityValidationError.
"""

from dataclasses import dataclass
import ipaddress
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Supported Schema Bounds & CRS Constants
# ---------------------------------------------------------------------------

SUPPORTED_RULE_IDS = frozenset({
    942100,  # SQL Injection Attack Detected via libinjection
})

SUPPORTED_RULE_MSGS = frozenset({
    "SQL Injection Attack Detected via libinjection",
})

SUPPORTED_SEVERITIES = frozenset({
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
})

DISALLOWED_UNIQUE_IDS = frozenset({
    "-",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ModSecurityError(Exception):
    """Base exception for ModSecurity evidence errors."""


class ModSecurityValidationError(ModSecurityError, ValueError):
    """Raised when ModSecurity evidence schema or boundary validation fails."""


# ---------------------------------------------------------------------------
# Normalized Evidence Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModSecuritySqliEvidence:
    """Immutable normalized evidence record for ModSecurity SQLi detection on WEB01.

    Guarantees:
    - All fields are strictly validated on instantiation.
    - Complete transaction fields must be present (fragments lacking transaction
      context are rejected).
    - Immutable dataclass (frozen=True) prevents modification after validation.
    - Deterministic to_dict() returns stable fields with strict types.
    """

    host: str
    src_ip: str
    rule_id: int
    rule_msg: str
    severity: str
    anomaly_score: int
    unique_id: str

    def __post_init__(self) -> None:
        """Validate all fields deterministically against schema bounds."""
        # 1. host validation
        if type(self.host) is not str:
            raise ModSecurityValidationError(
                f"host must be a non-empty string, got {type(self.host).__name__}"
            )
        if not self.host.strip():
            raise ModSecurityValidationError("host cannot be empty or whitespace-only")

        # 2. src_ip validation (Milestone 12B: IPv4 only)
        if type(self.src_ip) is not str:
            raise ModSecurityValidationError(
                f"src_ip must be an IPv4 address string, got {type(self.src_ip).__name__}"
            )
        src_ip_clean = self.src_ip.strip()
        if not src_ip_clean:
            raise ModSecurityValidationError("src_ip cannot be empty or whitespace-only")
        if any(token in self.src_ip for token in ("://", "/")):
            # Explicitly reject URLs and CIDR notation
            raise ModSecurityValidationError(
                f"src_ip must be a plain IPv4 address without URI scheme or CIDR: {self.src_ip}"
            )

        # Explicitly reject syntactically valid IPv6 addresses (contract is IPv4-only)
        try:
            ipaddress.IPv6Address(src_ip_clean)
            raise ModSecurityValidationError(
                f"src_ip '{self.src_ip}' is an IPv6 address; Milestone 12B strictly requires IPv4"
            )
        except ipaddress.AddressValueError:
            pass  # Not an IPv6 address; proceed to IPv4 validation

        # Validate strictly as IPv4
        try:
            ipaddress.IPv4Address(src_ip_clean)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise ModSecurityValidationError(
                f"src_ip is not a valid IPv4 address: {self.src_ip}"
            ) from exc

        # 3. rule_id validation
        # In Python, bool is a subclass of int, so type() check is required
        if type(self.rule_id) is not int:
            raise ModSecurityValidationError(
                f"rule_id must be an integer, got {type(self.rule_id).__name__}"
            )
        if self.rule_id not in SUPPORTED_RULE_IDS:
            raise ModSecurityValidationError(
                f"rule_id {self.rule_id} is unsupported; expected one of {sorted(SUPPORTED_RULE_IDS)}"
            )

        # 4. rule_msg validation
        if type(self.rule_msg) is not str:
            raise ModSecurityValidationError(
                f"rule_msg must be a string, got {type(self.rule_msg).__name__}"
            )
        if not self.rule_msg.strip():
            raise ModSecurityValidationError("rule_msg cannot be empty or whitespace-only")
        if self.rule_msg not in SUPPORTED_RULE_MSGS:
            raise ModSecurityValidationError(
                f"rule_msg '{self.rule_msg}' is not a supported SQLi detection message"
            )

        # 5. severity validation
        if type(self.severity) is not str:
            raise ModSecurityValidationError(
                f"severity must be a string, got {type(self.severity).__name__}"
            )
        if not self.severity.strip():
            raise ModSecurityValidationError("severity cannot be empty or whitespace-only")
        if self.severity not in SUPPORTED_SEVERITIES:
            raise ModSecurityValidationError(
                f"severity '{self.severity}' is unsupported; expected one of {sorted(SUPPORTED_SEVERITIES)}"
            )

        # 6. anomaly_score validation
        if type(self.anomaly_score) is not int:
            raise ModSecurityValidationError(
                f"anomaly_score must be an integer, got {type(self.anomaly_score).__name__}"
            )
        if self.anomaly_score < 0:
            raise ModSecurityValidationError(
                f"anomaly_score must be non-negative, got {self.anomaly_score}"
            )

        # 7. unique_id validation
        if type(self.unique_id) is not str:
            raise ModSecurityValidationError(
                f"unique_id must be a string, got {type(self.unique_id).__name__}"
            )
        if not self.unique_id.strip():
            raise ModSecurityValidationError("unique_id cannot be empty or whitespace-only")
        if self.unique_id.strip() in DISALLOWED_UNIQUE_IDS:
            raise ModSecurityValidationError(
                f"unique_id contains placeholder value: '{self.unique_id}'"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation of evidence record."""
        return {
            "host": self.host,
            "src_ip": self.src_ip,
            "rule_id": self.rule_id,
            "rule_msg": self.rule_msg,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "unique_id": self.unique_id,
        }
