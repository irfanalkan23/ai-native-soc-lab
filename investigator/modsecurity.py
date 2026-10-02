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
import re
from typing import Any, Dict, List, Optional


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


# ---------------------------------------------------------------------------
# Deterministic Raw Event Parser
# ---------------------------------------------------------------------------

def parse_modsecurity_sqli_event(raw_event: str, host: str) -> ModSecuritySqliEvidence:
    """Parse a raw ModSecurity audit log transaction and extract SQLi evidence.

    Deterministic Extraction Strategy:
    1. Validate input types and non-empty invariants.
    2. Extract transaction identifiers and client IPv4 from Section A header:
       --<unique_id>-A--
       [timestamp] <unique_id> <client_ip> <client_port> <server_ip> <server_port>
    3. Isolate CRS alert messages and specifically target rule 942100.
       Extract severity strictly from rule 942100's alert block to avoid
       capturing earlier rules (e.g. 920350 WARNING).
    4. Extract inbound anomaly score from correlation rule result.
    5. Construct and return ModSecuritySqliEvidence, enforcing final schema
       invariants and deep immutability.
    """
    if type(raw_event) is not str:
        raise ModSecurityValidationError(
            f"raw_event must be a string, got {type(raw_event).__name__}"
        )
    if not raw_event.strip():
        raise ModSecurityValidationError("raw_event cannot be empty or whitespace-only")

    if type(host) is not str:
        raise ModSecurityValidationError(
            f"host must be a string, got {type(host).__name__}"
        )
    if not host.strip():
        raise ModSecurityValidationError("host cannot be empty or whitespace-only")

    # 1. Extract Section A (Transaction Header)
    sec_a_match = re.search(
        r"--([A-Za-z0-9_\-]+)-A--[^\n]*\n\s*\[[^\]]+\]\s+(\S+)\s+(\S+)",
        raw_event,
    )
    if not sec_a_match:
        raise ModSecurityValidationError(
            "Transaction Section A header containing unique_id and client IP not found"
        )

    delim_uid, header_uid, raw_src_ip = sec_a_match.groups()
    if delim_uid in DISALLOWED_UNIQUE_IDS or header_uid in DISALLOWED_UNIQUE_IDS:
        raise ModSecurityValidationError("Transaction contains invalid or placeholder unique_id")
    if delim_uid != header_uid:
        raise ModSecurityValidationError(
            f"Transaction unique_id mismatch between delimiter '{delim_uid}' and header '{header_uid}'"
        )
    unique_id = header_uid

    # 2. Extract SQLi detection block (Rule 942100)
    # Split on Message: boundaries to isolate individual rule alerts
    message_chunks = re.split(r"(?:^|\n)Message:\s*", raw_event)

    sqli_rule_found = False
    extracted_rule_id: Optional[int] = None
    extracted_rule_msg: Optional[str] = None
    extracted_severity: Optional[str] = None

    for chunk in message_chunks:
        id_match = re.search(r'\[id\s+"(\d+)"\]', chunk)
        if not id_match:
            continue
        rule_id_int = int(id_match.group(1))
        if rule_id_int == 942100:
            sqli_rule_found = True
            extracted_rule_id = rule_id_int

            msg_match = re.search(r'\[msg\s+"([^"]+)"\]', chunk)
            if msg_match:
                extracted_rule_msg = msg_match.group(1)

            sev_match = re.search(r'\[severity\s+"([^"]+)"\]', chunk)
            if sev_match:
                extracted_severity = sev_match.group(1)
            break

    if not sqli_rule_found or extracted_rule_id is None:
        raise ModSecurityValidationError(
            "Supported SQLi rule ID 942100 not found in transaction"
        )

    if extracted_rule_msg != "SQL Injection Attack Detected via libinjection":
        raise ModSecurityValidationError(
            f"Rule 942100 missing required SQLi detection message; found '{extracted_rule_msg}'"
        )

    if not extracted_severity:
        raise ModSecurityValidationError(
            "Rule 942100 missing severity tag"
        )

    # 3. Extract Inbound Anomaly Score
    score_match = re.search(
        r"Inbound Anomaly Score Exceeded[^(]*\(Total Score:\s*([^)]+)\)",
        raw_event,
    )
    if not score_match:
        raise ModSecurityValidationError(
            "Inbound anomaly score correlation entry not found in transaction"
        )

    raw_score_str = score_match.group(1).strip()
    try:
        anomaly_score = int(raw_score_str)
    except ValueError as exc:
        raise ModSecurityValidationError(
            f"Malformed anomaly score '{raw_score_str}': must be an integer"
        ) from exc

    if anomaly_score < 0:
        raise ModSecurityValidationError(
            f"Negative anomaly score '{anomaly_score}' is not allowed"
        )

    # 4. Construct and return normalized evidence record
    return ModSecuritySqliEvidence(
        host=host,
        src_ip=raw_src_ip,
        rule_id=extracted_rule_id,
        rule_msg=extracted_rule_msg,
        severity=extracted_severity,
        anomaly_score=anomaly_score,
        unique_id=unique_id,
    )


# ---------------------------------------------------------------------------
# Deterministic Result Normalization
# ---------------------------------------------------------------------------

def normalize_modsecurity_sqli_record(record: Dict[str, Any]) -> ModSecuritySqliEvidence:
    """Normalize a single Splunk result record into an immutable ModSecuritySqliEvidence.

    Expects a dictionary with:
    - '_raw': Non-empty string of raw ModSecurity transaction log text.
    - 'host': Non-empty string of the target host (e.g. 'web01').

    Fails closed with ModSecurityValidationError if:
    - record is not a dict
    - '_raw' or 'host' is missing, empty, or whitespace-only
    - parsing '_raw' fails via parse_modsecurity_sqli_event
    """
    if not isinstance(record, dict):
        raise ModSecurityValidationError(
            f"record must be a dict, got {type(record).__name__}"
        )
    if "_raw" not in record:
        raise ModSecurityValidationError("Record missing mandatory '_raw' field")
    if "host" not in record:
        raise ModSecurityValidationError("Record missing mandatory 'host' field")

    raw_event = record["_raw"]
    host = record["host"]

    if type(raw_event) is not str or not raw_event.strip():
        raise ModSecurityValidationError("Record '_raw' field must be a non-empty string")
    if type(host) is not str or not host.strip():
        raise ModSecurityValidationError("Record 'host' field must be a non-empty string")

    return parse_modsecurity_sqli_event(raw_event=raw_event, host=host)


def normalize_modsecurity_sqli_results(records: List[Dict[str, Any]]) -> List[ModSecuritySqliEvidence]:
    """Normalize a batch of Splunk result records into a list of ModSecuritySqliEvidence.

    Preserves deterministic ordering. Fails closed with ModSecurityValidationError
    if any record in the batch fails normalization.
    """
    if not isinstance(records, list):
        raise ModSecurityValidationError(
            f"records must be a list, got {type(records).__name__}"
        )
    return [normalize_modsecurity_sqli_record(rec) for rec in records]
