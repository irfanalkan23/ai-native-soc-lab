"""Deterministic IOC Extraction for Threat-Intel Enrichment Gate.

Architecture Principle:
    Extract IP candidates ONLY from deterministic, trusted sources:

        1. deterministic_decoded_command  (highest precedence)
        2. InvestigationInput.command_line (second precedence)

    NEVER extract from:
        - InvestigationResult.summary
        - InvestigationResult.observations
        - InvestigationResult.suspicious_indicators
        - InvestigationResult.recommended_next_step
        - Any other model-generated narrative field

    Reason: Model-generated text is untrusted.  The model must not select the
    destination of an external threat-intelligence lookup.

Security Scope:
    - Public / globally routable IPv4 only.
    - Private, loopback, link-local, multicast, unspecified, and reserved
      addresses are rejected via the ThreatIntelRequest schema boundary.
    - CIDR notation, host:port syntax, and URL syntax are rejected.
    - Deduplication is applied before the cap.
    - MAX_TI_IP_LOOKUPS_PER_INCIDENT = 1  (at most one candidate returned).
"""

import re
from typing import Optional, Sequence

from investigator.schemas import InvestigationInput
from investigator.threat_intel import ThreatIntelRequest, ThreatIntelRequestError


# Maximum number of IPs surfaced per incident for threat-intel enrichment.
MAX_TI_IP_LOOKUPS_PER_INCIDENT: int = 1

# Regex that matches bare dotted-decimal IPv4 tokens in a string.
# Requires word-boundary or non-digit/non-dot on both sides so that:
#   - "8.8.8.8"   -> matched
#   - "8.8.8.8/24" -> "8.8.8.8" token is found but then rejected by ThreatIntelRequest (CIDR)
#   - "8.8.8.8:80" -> "8.8.8.8" token is found but ":" suffix means host:port; we strip
#                     the port before passing to validation
#
# NOTE: We intentionally extract the bare IP token and then let ThreatIntelRequest
# perform all policy validation (public/private/CIDR/URL checks).  This avoids
# duplicating IP validation logic in multiple modules.
_IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)"
)


def _candidate_tokens_from_text(text: str) -> list[tuple[str, bool]]:
    """Extract bare IPv4 candidate strings from a text.

    Returns a list of (token, is_forbidden) tuples where is_forbidden is True
    when the token is followed by CIDR prefix notation (e.g., /24).
    URL paths (e.g., /payload after an IP in a URL) are NOT marked forbidden;
    they rely on the ThreatIntelRequest boundary to strip paths if needed.

    Specifically:
        8.8.8.8/24   -> is_forbidden=True  (CIDR, digit follows the /)
        8.8.8.8/s    -> is_forbidden=False (URL path, non-digit follows the /)
        8.8.8.8:8080 -> is_forbidden=True  (host:port)
    """
    results = []
    for m in _IPV4_CANDIDATE_PATTERN.finditer(text):
        token = m.group(1)
        end = m.end()
        next_char = text[end:end + 1]
        after_slash = text[end + 1:end + 2] if len(text) > end + 1 else ""
        # CIDR: /digit (e.g. /24, /8, /32)
        is_cidr = next_char == "/" and after_slash.isdigit()
        # host:port: colon followed by digit
        is_port = next_char == ":" and after_slash.isdigit()
        is_forbidden = is_cidr or is_port
        results.append((token, is_forbidden))
    return results


def extract_candidate_public_ips(
    alert: InvestigationInput,
    deterministic_decoded_command: Optional[str] = None,
) -> Optional[str]:
    """Extract at most one canonical public IPv4 from trusted sources.

    Sources are evaluated in precedence order:

        1. deterministic_decoded_command (if provided and non-empty)
        2. alert.command_line

    Model-generated narrative fields on InvestigationResult are never
    inspected.  This function does not accept an InvestigationResult argument.

    Validation:
        Each candidate token is passed through ThreatIntelRequest.__init__(),
        which enforces all public-IP policy rules (global routability,
        no CIDR, no host:port, no URL, no private/loopback/reserved ranges).
        Any candidate that fails validation is silently skipped.

    Deduplication:
        Duplicate canonical IPs across sources are collapsed to a single entry.
        Only the first valid unique candidate (up to MAX_TI_IP_LOOKUPS_PER_INCIDENT)
        is returned.

    Args:
        alert:                       Validated InvestigationInput (original alert).
        deterministic_decoded_command: Trusted decoded command string produced by
                                      the deterministic Base64 decoder tool, or None.

    Returns:
        A single canonical public IPv4 string, or None if no valid candidate found.
    """
    seen: set[str] = set()
    candidates: list[str] = []

    def _try_add(token: str, is_forbidden: bool = False) -> None:
        """Validate a candidate via ThreatIntelRequest and add if valid and new."""
        # Reject tokens immediately followed by CIDR or port separators
        if is_forbidden:
            return
        # Strip common host:port suffix before validation (e.g. "8.8.8.8:8080")
        bare = token.split(":")[0] if ":" in token else token
        # Reject if token has a slash (CIDR or URL fragment)
        if "/" in bare:
            return
        try:
            req = ThreatIntelRequest(indicator_type="ip", indicator_value=bare)
            canonical = req.indicator_value
        except ThreatIntelRequestError:
            return

        if canonical not in seen:
            seen.add(canonical)
            candidates.append(canonical)

    # --- Source 1: deterministic decoded command (highest trust / precedence) ---
    if deterministic_decoded_command and deterministic_decoded_command.strip():
        for token, is_forbidden in _candidate_tokens_from_text(deterministic_decoded_command):
            _try_add(token, is_forbidden)
            if len(candidates) >= MAX_TI_IP_LOOKUPS_PER_INCIDENT:
                return candidates[0]

    # --- Source 2: original alert command_line ---
    for token, is_forbidden in _candidate_tokens_from_text(alert.command_line):
        _try_add(token, is_forbidden)
        if len(candidates) >= MAX_TI_IP_LOOKUPS_PER_INCIDENT:
            return candidates[0]

    return candidates[0] if candidates else None
