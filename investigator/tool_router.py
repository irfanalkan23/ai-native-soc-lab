"""Deterministic tool router for AI-assisted SOC investigation.

Security & Architecture Guarantees:
1. Explicit Tool Allowlist: Only predefined, audited tools can be invoked.
2. No Dynamic Invocation: No eval(), exec(), __import__(), or getattr() dispatch.
3. No Arbitrary SPL or URLs: Callers cannot pass custom queries or endpoints.
4. Input Validation: Tool arguments are strictly typed and validated before execution.
5. Untrusted Data Boundary: All tool arguments and outputs are treated strictly as
   UNTRUSTED DATA. Telemetry strings or decoded payloads cannot modify router
   tables, alter execution flow, or invoke arbitrary capabilities.
"""

from typing import Any, Dict, List, Optional

from gateway.policy import PolicyValidationError
from gateway.splunk_search import (
    SplunkConnectionError,
    SplunkResponseError,
    SplunkSearchClient,
    SplunkSearchError,
)
from investigator.providers.virustotal_provider import (
    VirusTotalError,
    VirusTotalThreatIntelClient,
)
from investigator.threat_intel import (
    ThreatIntelError,
    ThreatIntelObservation,
    ThreatIntelRequest,
    _canonicalize_public_ip,
    normalize_virustotal_result,
)
from investigator.tools.base64_decoder import (
    DecodeResult,
    DecoderError,
    decode_powershell_base64,
)
from investigator.tools.mitre_mapper import (
    MitreMapping,
    MitreMappingError,
    map_detection_to_mitre,
)


class ToolValidationError(ValueError):
    """Raised when an unallowlisted tool or invalid tool argument is provided."""
    pass


class ToolExecutionError(Exception):
    """Raised when an allowlisted tool fails closed during execution."""
    pass


ALLOWED_TOOLS: frozenset[str] = frozenset({
    "bounded_splunk_search",
    "decode_base64_powershell",
    "map_mitre_technique",
    "threat_intel_lookup",
})

_BASE_ALLOWED_TOOLS: frozenset[str] = frozenset({
    "bounded_splunk_search",
    "decode_base64_powershell",
    "map_mitre_technique",
})

ALLOWED_SPLUNK_QUERY_TYPES = frozenset({
    "encoded_powershell_matches",
    "powershell_network_retrieval_matches",
})


class ToolRouter:
    """Deterministic tool execution router for the AI investigator."""

    def __init__(
        self,
        splunk_client: Optional[SplunkSearchClient] = None,
        vt_client: Optional[VirusTotalThreatIntelClient] = None,
    ) -> None:
        """Initialize router with existing bounded Splunk client and optional VT client.

        Args:
            splunk_client: Optional pre-configured SplunkSearchClient instance.
                           Defaults to local bounded client.
            vt_client: Optional pre-configured VirusTotalThreatIntelClient instance.
        """
        self._splunk_client = splunk_client or SplunkSearchClient(verify_tls=False)
        self._vt_client = vt_client

    @property
    def allowed_tools(self) -> frozenset[str]:
        """Return the immutable set of allowlisted tool names."""
        if self._vt_client is not None:
            return ALLOWED_TOOLS
        return _BASE_ALLOWED_TOOLS

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute an allowlisted tool with strictly validated arguments.

        Fails closed on unallowlisted tool names, unrecognized arguments,
        or policy violations.

        Args:
            tool_name: Name of the allowlisted tool.
            arguments: Dictionary of keyword arguments for the tool.

        Returns:
            Structured tool result.

        Raises:
            ToolValidationError: If tool name is unknown or arguments are invalid.
            ToolExecutionError: If tool execution encounters a failure.
        """
        if type(tool_name) is not str:
            raise ToolValidationError(
                f"Expected tool_name str, got {type(tool_name).__name__}"
            )

        if tool_name not in ALLOWED_TOOLS:
            raise ToolValidationError(
                f"Unauthorized tool '{tool_name}'. Allowed tools: {sorted(ALLOWED_TOOLS)}"
            )

        if not isinstance(arguments, dict):
            raise ToolValidationError(
                f"Expected arguments dict, got {type(arguments).__name__}"
            )

        # Dispatch via explicit, static branch (no eval/getattr/dynamic dispatch)
        if tool_name == "bounded_splunk_search":
            return self._execute_splunk_search(arguments)
        elif tool_name == "decode_base64_powershell":
            return self._execute_base64_decoder(arguments)
        elif tool_name == "map_mitre_technique":
            return self._execute_mitre_mapper(arguments)
        elif tool_name == "threat_intel_lookup":
            return self._execute_threat_intel_lookup(arguments)
        else:
            # Unreachable due to allowlist check, but fail closed defensively
            raise ToolValidationError(f"Unknown tool: {tool_name}")

    def _execute_splunk_search(self, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate arguments and invoke bounded Splunk search."""
        # Disallow attempts to pass SPL or URL parameters explicitly
        for forbidden in ("search", "spl", "query", "url", "path", "endpoint"):
            if forbidden in args:
                raise ToolValidationError(
                    f"Parameter '{forbidden}' is strictly prohibited in bounded_splunk_search"
                )

        allowed_args = {"query_type", "host", "minutes", "limit"}
        unrecognized = set(args.keys()) - allowed_args
        if unrecognized:
            raise ToolValidationError(
                f"Unrecognized arguments for bounded_splunk_search: {sorted(unrecognized)}"
            )

        if "query_type" in args:
            raw_query_type = args["query_type"]
            if type(raw_query_type) is not str:
                raise ToolValidationError(
                    f"Expected query_type str, got {type(raw_query_type).__name__}"
                )
            if raw_query_type not in ALLOWED_SPLUNK_QUERY_TYPES:
                raise ToolValidationError(
                    f"Unauthorized query_type '{raw_query_type}'. Allowed: {sorted(ALLOWED_SPLUNK_QUERY_TYPES)}"
                )
            query_type = raw_query_type
        else:
            query_type = "encoded_powershell_matches"

        host = args.get("host", "DC01")
        minutes = args.get("minutes", 15)
        limit = args.get("limit", 10)

        try:
            if query_type == "encoded_powershell_matches":
                return self._splunk_client.search_encoded_powershell(
                    host=host,
                    minutes=minutes,
                    limit=limit,
                )
            elif query_type == "powershell_network_retrieval_matches":
                return self._splunk_client.search_powershell_network_retrieval(
                    host=host,
                    minutes=minutes,
                    limit=limit,
                )
            else:
                raise ToolValidationError(f"Unauthorized query_type '{query_type}'")
        except (PolicyValidationError, ValueError) as err:
            raise ToolValidationError(f"Search input validation failed: {err}") from err
        except SplunkSearchError as err:
            raise ToolExecutionError(f"Splunk search execution failed: {err}") from err

    def _execute_base64_decoder(self, args: Dict[str, Any]) -> DecodeResult:
        """Validate arguments and invoke local Base64 decoder."""
        allowed_args = {"encoded_input"}
        unrecognized = set(args.keys()) - allowed_args
        if unrecognized:
            raise ToolValidationError(
                f"Unrecognized arguments for decode_base64_powershell: {sorted(unrecognized)}"
            )

        if "encoded_input" not in args:
            raise ToolValidationError(
                "Missing required argument 'encoded_input' for decode_base64_powershell"
            )

        encoded_input = args["encoded_input"]
        try:
            return decode_powershell_base64(encoded_input)
        except DecoderError as err:
            raise ToolExecutionError(f"Base64 decoding failed: {err}") from err

    def _execute_mitre_mapper(self, args: Dict[str, Any]) -> MitreMapping:
        """Validate arguments and invoke local MITRE mapper."""
        allowed_args = {"detection_ref", "fail_closed"}
        unrecognized = set(args.keys()) - allowed_args
        if unrecognized:
            raise ToolValidationError(
                f"Unrecognized arguments for map_mitre_technique: {sorted(unrecognized)}"
            )

        if "detection_ref" not in args:
            raise ToolValidationError(
                "Missing required argument 'detection_ref' for map_mitre_technique"
            )

        detection_ref = args["detection_ref"]
        fail_closed = args.get("fail_closed", True)
        if type(fail_closed) is not bool:
            raise ToolValidationError(
                f"Expected fail_closed bool, got {type(fail_closed).__name__}"
            )

        try:
            return map_detection_to_mitre(
                detection_ref=detection_ref,
                fail_closed=fail_closed,
            )
        except MitreMappingError as err:
            raise ToolExecutionError(f"MITRE mapping failed: {err}") from err

    def _execute_threat_intel_lookup(self, args: Dict[str, Any]) -> ThreatIntelObservation:
        """Validate arguments and invoke bounded Threat Intelligence IP lookup."""
        allowed_args = {"indicator"}
        unrecognized = set(args.keys()) - allowed_args
        if unrecognized:
            raise ToolValidationError(
                f"Unrecognized arguments for threat_intel_lookup: {sorted(unrecognized)}"
            )

        if "indicator" not in args:
            raise ToolValidationError(
                "Missing required argument 'indicator' for threat_intel_lookup"
            )

        raw_indicator = args["indicator"]
        try:
            canonical_ip = _canonicalize_public_ip(raw_indicator)
        except (ValueError, TypeError) as err:
            raise ToolValidationError(f"Invalid indicator for threat_intel_lookup: {err}") from err

        if self._vt_client is None:
            raise ToolExecutionError("Threat intelligence client is not configured")

        try:
            req = ThreatIntelRequest(
                indicator_value=canonical_ip,
                indicator_type="ip",
            )
            result = self._vt_client.lookup(req)
            return normalize_virustotal_result(result)
        except (VirusTotalError, ThreatIntelError) as err:
            raise ToolExecutionError("Threat intelligence lookup execution failed") from err
