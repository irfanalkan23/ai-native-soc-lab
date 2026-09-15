"""Local static MITRE ATT&CK mapping tool for verified lab detections.

Architecture Guarantee:
This module uses purely local, static lookup tables without external API calls,
network requests, or dynamic code generation.
"""

from dataclasses import dataclass
from typing import Dict, Optional


class MitreMappingError(ValueError):
    """Raised when an unknown detection cannot be mapped to MITRE ATT&CK."""
    pass


@dataclass(frozen=True)
class MitreMapping:
    """Immutable structured record representing an ATT&CK mapping."""
    mapped: bool
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic_id: Optional[str]
    tactic_name: Optional[str]
    detection_ref: str


# Static allowlist of verified lab detections to MITRE mappings
_STATIC_MITRE_DATABASE: Dict[str, Dict[str, str]] = {
    "suspicious_encoded_powershell": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    "suspicious encoded powershell execution": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    "encoded_powershell_matches": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    "4e4f13c0-89a9-4f0e-a08f-b70b9c19e729": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
}


def map_detection_to_mitre(
    detection_ref: str,
    fail_closed: bool = True,
) -> MitreMapping:
    """Map a detection rule name or identifier to its verified MITRE ATT&CK technique.

    Args:
        detection_ref: Detection rule name, query key, or rule ID.
        fail_closed: If True, raises MitreMappingError on unknown detections;
                     if False, returns an unmapped MitreMapping result.

    Returns:
        MitreMapping dataclass with technique and tactic identifiers.

    Raises:
        MitreMappingError: If fail_closed=True and detection is not in the static map.
    """
    if type(detection_ref) is not str:
        raise MitreMappingError(
            f"Expected detection_ref str, got {type(detection_ref).__name__}"
        )

    if type(fail_closed) is not bool:
        raise MitreMappingError(
            f"Expected fail_closed bool, got {type(fail_closed).__name__}"
        )

    normalized_key = detection_ref.strip().lower()
    mapping_data = _STATIC_MITRE_DATABASE.get(normalized_key)

    if mapping_data is not None:
        return MitreMapping(
            mapped=True,
            technique_id=mapping_data["technique_id"],
            technique_name=mapping_data["technique_name"],
            tactic_id=mapping_data["tactic_id"],
            tactic_name=mapping_data["tactic_name"],
            detection_ref=detection_ref,
        )

    if fail_closed:
        raise MitreMappingError(
            f"No verified MITRE ATT&CK mapping exists for detection: '{detection_ref}'"
        )

    return MitreMapping(
        mapped=False,
        technique_id=None,
        technique_name=None,
        tactic_id=None,
        tactic_name=None,
        detection_ref=detection_ref,
    )
