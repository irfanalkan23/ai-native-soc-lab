"""Eligibility-Gated Threat Intelligence Integration for ModSecurity SQLi Evidence.

Architecture Principle:
    Validated ModSecurity evidence -> deterministic scope classification ->
    if ineligible (private, loopback, multicast, etc.): skip TI lookup
    if eligible (globally routable public IPv4): call bounded threat_intel_lookup.

Scope & Security Guarantees:
1. Composition Boundary:
   - Composes investigator.modsecurity (ModSecuritySqliEvidence) and
     investigator.threat_intel (IndicatorScope, ThreatIntelObservation).
   - Keeps foundational threat_intel.py independent of web application telemetry.
2. Deterministic Eligibility Gating:
   - No AI decision in eligibility.
   - classify_ipv4_scope(evidence.src_ip) decides deterministically.
   - Private IPs (such as WEB01 192.168.1.100) are never passed to external lookups.
3. Fail-Closed Validation:
   - Rejects non-ModSecuritySqliEvidence inputs.
   - Rejects non-callable threat_intel_lookup dependencies.
   - Rejects lookup return values that do not conform to ThreatIntelObservation.
   - Preserves provider / tool execution errors without swallowing or fallback.
4. Immutability:
   - ModSecuritySqliEvidence and ModSecurityEnrichmentResult are frozen dataclasses.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from investigator.modsecurity import ModSecuritySqliEvidence
import investigator.threat_intel as ti_module
from investigator.threat_intel import (
    IndicatorScope,
    ThreatIntelObservation,
)


@dataclass(frozen=True)
class ModSecurityEnrichmentResult:
    """Immutable normalized enrichment result for ModSecurity SQLi evidence.

    Guarantees:
    - evidence is an instance of ModSecuritySqliEvidence.
    - scope is an instance of IndicatorScope.
    - enriched is a boolean indicating whether threat intelligence lookup occurred.
    - If scope.external_ti_eligible is False:
        enriched must be False, observation must be None,
        skip_reason must be f"ineligible_scope:{scope.scope}".
    - If scope.external_ti_eligible is True:
        scope.scope must be "public", enriched must be True,
        observation must be ThreatIntelObservation, skip_reason must be None.
    - Immutable dataclass (frozen=True) prevents modification after creation.
    - Deterministic to_dict() returns stable fields with strict types.
    """

    evidence: ModSecuritySqliEvidence
    scope: IndicatorScope
    enriched: bool
    observation: Optional[ThreatIntelObservation]
    skip_reason: Optional[str]

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, ModSecuritySqliEvidence):
            raise TypeError(
                f"evidence must be ModSecuritySqliEvidence, got {type(self.evidence).__name__}"
            )

        if not isinstance(self.scope, IndicatorScope):
            raise TypeError(
                f"scope must be IndicatorScope, got {type(self.scope).__name__}"
            )

        if type(self.enriched) is not bool:
            raise TypeError(
                f"enriched must be bool, got {type(self.enriched).__name__}"
            )

        # Enforce consistency between scope and enrichment state
        if not self.scope.external_ti_eligible:
            # INELIGIBLE scope invariant
            if self.enriched:
                raise ValueError(
                    f"Contradictory state: scope '{self.scope.scope}' is ineligible but enriched is True"
                )
            if self.observation is not None:
                raise ValueError(
                    f"Contradictory state: scope '{self.scope.scope}' is ineligible but observation is present"
                )
            expected_skip_reason = f"ineligible_scope:{self.scope.scope}"
            if self.skip_reason != expected_skip_reason:
                raise ValueError(
                    f"skip_reason must be '{expected_skip_reason}' for ineligible scope '{self.scope.scope}', "
                    f"got {self.skip_reason!r}"
                )
        else:
            # ELIGIBLE/PUBLIC scope invariant
            if self.scope.scope != "public":
                raise ValueError(
                    f"Contradictory state: eligible scope must be 'public', got '{self.scope.scope}'"
                )
            if not self.enriched:
                raise ValueError(
                    "Contradictory state: scope is public/eligible but enriched is False without execution failure"
                )
            if not isinstance(self.observation, ThreatIntelObservation):
                raise TypeError(
                    f"observation must be ThreatIntelObservation when enriched=True, got {type(self.observation).__name__}"
                )
            if self.skip_reason is not None:
                raise ValueError(
                    f"Contradictory state: skip_reason must be None when enriched=True, got {self.skip_reason!r}"
                )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation of enrichment result."""
        return {
            "evidence": self.evidence.to_dict(),
            "scope": self.scope.to_dict(),
            "enriched": self.enriched,
            "observation": self.observation.to_dict() if self.observation is not None else None,
            "skip_reason": self.skip_reason,
        }


def enrich_modsecurity_source_ip(
    evidence: ModSecuritySqliEvidence,
    threat_intel_lookup: Callable[[str], ThreatIntelObservation],
) -> ModSecurityEnrichmentResult:
    """Enrich validated ModSecurity SQLi evidence with bounded threat intelligence.

    Deterministic Flow:
    1. Validates input types fail-closed.
    2. Classifies source IPv4 scope via classify_ipv4_scope(evidence.src_ip).
    3. If external_ti_eligible is False:
       - Threat intelligence lookup is NOT called.
       - Returns ModSecurityEnrichmentResult with enriched=False and skip_reason.
    4. If external_ti_eligible is True:
       - Calls threat_intel_lookup(scope.indicator) exactly once.
       - Validates that returned result is a ThreatIntelObservation.
       - Returns ModSecurityEnrichmentResult with enriched=True and observation.
    """
    if evidence is None:
        raise ValueError("evidence cannot be None")
    if not isinstance(evidence, ModSecuritySqliEvidence):
        raise TypeError(
            f"evidence must be ModSecuritySqliEvidence, got {type(evidence).__name__}"
        )

    if threat_intel_lookup is None:
        raise ValueError("threat_intel_lookup cannot be None")
    if not callable(threat_intel_lookup):
        raise TypeError(
            f"threat_intel_lookup must be callable, got {type(threat_intel_lookup).__name__}"
        )

    # Classify source IP scope deterministically
    scope = ti_module.classify_ipv4_scope(evidence.src_ip)

    # Gate: If ineligible, do NOT invoke lookup
    if not scope.external_ti_eligible:
        return ModSecurityEnrichmentResult(
            evidence=evidence,
            scope=scope,
            enriched=False,
            observation=None,
            skip_reason=f"ineligible_scope:{scope.scope}",
        )

    # Eligible: invoke supplied bounded lookup exactly once
    observation = threat_intel_lookup(scope.indicator)

    if observation is None:
        raise ValueError("threat_intel_lookup returned None for eligible public IP")
    if not isinstance(observation, ThreatIntelObservation):
        raise TypeError(
            f"threat_intel_lookup must return ThreatIntelObservation, got {type(observation).__name__}"
        )

    return ModSecurityEnrichmentResult(
        evidence=evidence,
        scope=scope,
        enriched=True,
        observation=observation,
        skip_reason=None,
    )
