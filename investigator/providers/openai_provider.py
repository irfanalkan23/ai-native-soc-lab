"""OpenAI Responses API provider adapter for the AI investigator.

Architecture Principle:
  AI proposes / interprets.
  Deterministic code validates, routes, limits, and enforces.

This adapter is a pure translator:
  ModelRequest  ->  OpenAI Responses API  ->  ModelDecision

It NEVER:
  - invokes ToolRouter or any investigator tool directly
  - imports gateway.splunk_search
  - calls subprocess or os.system
  - returns raw provider SDK objects
  - exposes API keys, headers, or raw response bodies in exceptions

Prompt-injection boundary:
  System instructions (trusted) are passed via the Responses API
  'instructions' parameter — a dedicated system-instruction field kept
  separate from the user-supplied evidence input.

  ALL InvestigationInput fields and prior tool results are serialized as
  a user-role message and are explicitly labelled UNTRUSTED EVIDENCE in
  the instructions. The model is told to treat that content as inert data
  and never to follow instructions embedded within it.

Output bounds:
  MAX_OUTPUT_TOKENS=1024 is an intentional operational cap for concise
  investigation decisions. The local InvestigationResult schema permits
  larger theoretical maximum payloads, but the provider is deliberately
  constrained to produce substantially smaller practical responses.

Retry policy:
  max_retries=2 (SDK default 2). Only transient network/provider errors
  are retried. Malformed output, schema violations, and policy failures
  are never retried — they fail closed immediately.
"""

import json
import os
from typing import Any, Dict, Optional

from investigator.model import (
    DecisionType,
    ModelDecision,
    ModelRequest,
    ModelValidationError,
    ToolRequest,
)
from investigator.schemas import (
    InvestigationResult,
    SchemaValidationError,
)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

#: Intentional operational cap for concise investigation decisions.
#: The local InvestigationResult schema permits larger theoretical maximum
#: payloads, but the provider is deliberately constrained to produce
#: substantially smaller practical responses.
MAX_OUTPUT_TOKENS: int = 1024

#: Maximum length of the model name string accepted from the environment.
#: Guards against obvious misconfiguration or injection in env variables.
MAX_MODEL_NAME_LENGTH: int = 128

#: Request timeout in seconds. The Responses API is typically fast;
#: 30 seconds is the specified maximum.
REQUEST_TIMEOUT: float = 30.0

#: Maximum SDK-level retries for transient provider/network errors.
#: Must not exceed 2 per specification.
MAX_RETRIES: int = 2

#: Maximum length of a raw response text that will be parsed.
#: If the model returns more than this many characters of JSON, fail closed.
MAX_RAW_RESPONSE_LENGTH: int = 8192

#: JSON output format contract appended to system instructions in every request.
#: This tells the model exactly what JSON structure to emit.
#: It is provider-specific and kept here, not in the provider-neutral model.py.
RESPONSE_FORMAT_INSTRUCTIONS: str = """\

JSON OUTPUT CONTRACT
========================
You MUST respond with a single valid JSON object. No markdown, no commentary.
The JSON object must have exactly ONE of the following two forms:

Form A — Tool request:
{
  "decision_type": "tool_request",
  "tool_name": "<one of: bounded_splunk_search | decode_base64_powershell | map_mitre_technique>",
  "arguments": { "<key>": "<primitive value>" }
}

Form B — Final result:
{
  "decision_type": "final_result",
  "final_result": {
    "summary": "<non-empty string, max 2000 chars>",
    "observations": ["<string>", ...],
    "decoded_command": "<string or null>",
    "mitre_techniques": ["<string>", ...],
    "suspicious_indicators": ["<string>", ...],
    "recommended_next_step": "<non-empty string, max 500 chars>",
    "confidence_level": "<low | medium | high>",
    "evidence_refs": ["<string>", ...]
  }
}

Rules:
- decision_type must be exactly "tool_request" or "final_result".
- Do not include both tool_name and final_result in the same response.
- argument values must be strings, numbers, booleans, or null (no nested objects/lists).
- confidence_level must be exactly one of: low, medium, high.
- Do not include markdown code fences or any text outside the JSON object.
"""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OpenAIProviderError(Exception):
    """Base class for all sanitized OpenAI provider errors."""
    pass


class OpenAIConfigurationError(OpenAIProviderError):
    """Raised when configuration (env vars, bounds) is invalid.

    Never includes the API key or env contents.
    """
    pass


class OpenAIRequestError(OpenAIProviderError):
    """Raised for transient or network-level provider failures (timeout, auth).

    The exception message contains only a sanitized type code — never raw
    headers, API key, or full HTTP response body.
    """
    pass


class OpenAIResponseError(OpenAIProviderError):
    """Raised when the provider response cannot be parsed into a ModelDecision.

    The exception message contains only a sanitized description. Raw response
    text is never included.
    """
    pass


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

class _OpenAIConfig:
    """Validated configuration for the OpenAI provider adapter.

    Reads exclusively from os.environ. Never touches dotenv or .env files.
    Raises OpenAIConfigurationError for any invalid value.
    """
    __slots__ = ("api_key", "model_name")

    def __init__(self) -> None:
        # --- API key ---
        raw_key = os.environ.get("OPENAI_API_KEY", "")
        if type(raw_key) is not str or not raw_key.strip():
            raise OpenAIConfigurationError(
                "OPENAI_API_KEY environment variable is missing or empty"
            )
        # Only basic type/non-empty validation. No pattern check, no logging.
        self.api_key: str = raw_key

        # --- Model name ---
        raw_model = os.environ.get("OPENAI_MODEL", "")
        if type(raw_model) is not str or not raw_model.strip():
            raise OpenAIConfigurationError(
                "OPENAI_MODEL environment variable is missing or empty"
            )
        if len(raw_model) > MAX_MODEL_NAME_LENGTH:
            raise OpenAIConfigurationError(
                f"OPENAI_MODEL value exceeds maximum length {MAX_MODEL_NAME_LENGTH}"
            )
        self.model_name: str = raw_model


# ---------------------------------------------------------------------------
# Request serialization
# ---------------------------------------------------------------------------

def _serialize_investigation_input(inp: Any) -> Dict[str, str]:
    """Return a plain dict of all InvestigationInput fields.

    No dynamic serialization — each field is listed explicitly so that
    no unexpected attributes can be inadvertently included.
    """
    return {
        "incident_id": inp.incident_id,
        "timestamp": inp.timestamp,
        "host": inp.host,
        "user": inp.user,
        "image": inp.image,
        "command_line": inp.command_line,
        "parent_image": inp.parent_image,
        "parent_command_line": inp.parent_command_line,
        "detection_name": inp.detection_name,
        "detection_id": inp.detection_id,
    }


def _serialize_prior_results(prior_tool_results: tuple) -> list:
    """Return a list of sanitized tool result dicts from ToolResultEnvelope objects.

    Only the fields that are safe to pass to the model are included.
    """
    results = []
    for env in prior_tool_results:
        results.append({
            "tool_name": env.tool_name,
            "success": env.success,
            "result_text": env.result_text,
            "error_code": env.error_code,
        })
    return results


def _build_user_message(request: ModelRequest) -> str:
    """Serialize the investigation evidence into a bounded JSON user message.

    The message is explicitly labelled as UNTRUSTED EVIDENCE to reinforce
    the instruction boundary. No system instructions are included here.
    """
    payload = {
        "UNTRUSTED_EVIDENCE_JSON": {
            "investigation_input": _serialize_investigation_input(
                request.investigation_input
            ),
            "prior_tool_results": _serialize_prior_results(
                request.prior_tool_results
            ),
            "remaining_tool_budget": request.remaining_tool_budget,
        }
    }
    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _extract_text_from_response(response: Any) -> str:
    """Extract the text content from a Responses API Response object.

    Fails closed if output is absent, malformed, or oversized.

    Args:
        response: openai.types.responses.Response object.

    Returns:
        Raw text string from the first text output item.

    Raises:
        OpenAIResponseError: On any structural problem.
    """
    output = getattr(response, "output", None)
    if not output:
        raise OpenAIResponseError("provider_response_empty: no output items")

    # Iterate output items looking for the first message with text content
    for item in output:
        item_type = getattr(item, "type", None)
        if item_type != "message":
            continue
        content_list = getattr(item, "content", None)
        if not content_list:
            continue
        for content_item in content_list:
            content_type = getattr(content_item, "type", None)
            if content_type == "output_text":
                text = getattr(content_item, "text", None)
                if type(text) is not str or not text.strip():
                    raise OpenAIResponseError(
                        "provider_response_empty: output_text is empty"
                    )
                if len(text) > MAX_RAW_RESPONSE_LENGTH:
                    raise OpenAIResponseError(
                        "provider_response_too_large: output exceeds max length"
                    )
                return text
            elif content_type == "refusal":
                raise OpenAIResponseError(
                    "provider_refusal: model declined to produce output"
                )

    raise OpenAIResponseError(
        "provider_response_no_text: no output_text content found"
    )


def _parse_json_response(raw_text: str) -> dict:
    """Parse and basic-validate the model's JSON output.

    Fails closed on any parse or structural error.

    Args:
        raw_text: Raw string from the model output.

    Returns:
        Parsed dict.

    Raises:
        OpenAIResponseError: If the text is not valid JSON or not a dict.
    """
    try:
        parsed = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        raise OpenAIResponseError(
            "provider_malformed_json: response is not valid JSON"
        )
    if not isinstance(parsed, dict):
        raise OpenAIResponseError(
            f"provider_response_not_object: expected JSON object, got {type(parsed).__name__}"
        )
    return parsed


def _parse_tool_request(data: dict) -> ModelDecision:
    """Build a TOOL_REQUEST ModelDecision from a parsed provider dict.

    Delegates all final validation to ToolRequest and ModelDecision
    constructors — those are the authoritative validation points.

    Raises:
        OpenAIResponseError: If required fields are absent or wrong types.
        ModelValidationError: If ToolRequest or ModelDecision validation fails.
    """
    tool_name = data.get("tool_name")
    if type(tool_name) is not str or not tool_name.strip():
        raise OpenAIResponseError(
            "provider_tool_request_missing_name: tool_name must be a non-empty str"
        )

    raw_args = data.get("arguments", {})
    if not isinstance(raw_args, dict):
        raise OpenAIResponseError(
            "provider_tool_request_bad_args: arguments must be a JSON object"
        )

    # Validate argument primitiveness before constructing ToolRequest
    _ALLOWED = (str, int, bool, type(None))
    for k, v in raw_args.items():
        if type(k) is not str:
            raise OpenAIResponseError(
                "provider_tool_request_bad_arg_key: argument key must be str"
            )
        if not isinstance(v, _ALLOWED):
            raise OpenAIResponseError(
                f"provider_tool_request_bad_arg_value: argument '{k}' has "
                f"non-primitive type {type(v).__name__}"
            )

    # ToolRequest and ModelDecision constructors will perform final validation
    tool_req = ToolRequest(tool_name=tool_name, arguments=raw_args)
    return ModelDecision(
        decision_type=DecisionType.TOOL_REQUEST,
        tool_request=tool_req,
    )


def _parse_final_result(data: dict) -> ModelDecision:
    """Build a FINAL_RESULT ModelDecision from a parsed provider dict.

    All InvestigationResult bounds are enforced by the InvestigationResult
    constructor. This function only maps JSON keys to constructor arguments.

    Raises:
        OpenAIResponseError: If the final_result field is missing or not a dict.
        SchemaValidationError: If InvestigationResult validation fails.
        ModelValidationError: If ModelDecision validation fails.
    """
    fr_data = data.get("final_result")
    if not isinstance(fr_data, dict):
        raise OpenAIResponseError(
            "provider_final_result_missing: final_result must be a JSON object"
        )

    # Map JSON fields → InvestigationResult constructor
    # Any missing/wrong-type field will be caught by InvestigationResult.__post_init__
    try:
        result = InvestigationResult(
            summary=fr_data.get("summary", ""),
            observations=fr_data.get("observations", []),
            decoded_command=fr_data.get("decoded_command"),
            mitre_techniques=fr_data.get("mitre_techniques", []),
            suspicious_indicators=fr_data.get("suspicious_indicators", []),
            recommended_next_step=fr_data.get("recommended_next_step", ""),
            confidence_level=fr_data.get("confidence_level", ""),
            evidence_refs=fr_data.get("evidence_refs", []),
        )
    except (SchemaValidationError, TypeError) as exc:
        raise OpenAIResponseError(
            f"provider_final_result_invalid: {type(exc).__name__}"
        ) from exc

    return ModelDecision(
        decision_type=DecisionType.FINAL_RESULT,
        final_result=result,
    )


def _parse_response_to_decision(raw_text: str) -> ModelDecision:
    """Parse and validate a raw provider JSON string into a ModelDecision.

    Enforces the discriminated-union contract:
      - Exactly one branch (tool_request OR final_result) must be present.
      - decision_type must be a known value.
      - No raw provider objects or strings pass through.

    Args:
        raw_text: Raw JSON string from the model output.

    Returns:
        Validated ModelDecision.

    Raises:
        OpenAIResponseError: On any structural, type, or parsing failure.
        ModelValidationError: Propagated from ToolRequest/ModelDecision.
        SchemaValidationError: Propagated from InvestigationResult.
    """
    data = _parse_json_response(raw_text)

    decision_type_str = data.get("decision_type")
    if type(decision_type_str) is not str or not decision_type_str.strip():
        raise OpenAIResponseError(
            "provider_missing_decision_type: decision_type field is absent or empty"
        )

    # Discriminate on decision_type
    if decision_type_str == "tool_request":
        # Reject any response that also claims to be a final result
        if "final_result" in data and data["final_result"] is not None:
            raise OpenAIResponseError(
                "provider_ambiguous_decision: tool_request branch "
                "must not include final_result"
            )
        return _parse_tool_request(data)

    elif decision_type_str == "final_result":
        # Reject any response that also claims a tool request
        if "tool_name" in data and data["tool_name"] is not None:
            raise OpenAIResponseError(
                "provider_ambiguous_decision: final_result branch "
                "must not include tool_name"
            )
        return _parse_final_result(data)

    else:
        raise OpenAIResponseError(
            f"provider_unknown_decision_type: unrecognised value "
            f"(length {len(decision_type_str)})"
        )


# ---------------------------------------------------------------------------
# Provider adapter
# ---------------------------------------------------------------------------

class OpenAIModel:
    """OpenAI Responses API adapter implementing the provider-neutral model interface.

    Public interface:
        decide(request: ModelRequest) -> ModelDecision

    This class is a pure translator. It never imports or calls ToolRouter,
    SplunkSearchClient, subprocess, or any live investigator tool.

    Configuration is read from os.environ at construction time:
        OPENAI_API_KEY  — non-empty str
        OPENAI_MODEL    — non-empty str, max MAX_MODEL_NAME_LENGTH chars

    Raises:
        OpenAIConfigurationError: If env configuration is invalid.
    """

    def __init__(self) -> None:
        """Construct the adapter, reading configuration from os.environ.

        Raises:
            OpenAIConfigurationError: If OPENAI_API_KEY or OPENAI_MODEL is
                missing, empty, or violates bounds.
        """
        config = _OpenAIConfig()
        self._model_name: str = config.model_name

        # Lazy import keeps the SDK out of the import chain for tests that
        # mock at the class level. The import is still module-level safe.
        try:
            import openai
            self._client = openai.OpenAI(
                api_key=config.api_key,
                timeout=REQUEST_TIMEOUT,
                max_retries=MAX_RETRIES,
            )
        except Exception as exc:
            # Do not include api_key or any secret in the message
            raise OpenAIConfigurationError(
                f"Failed to initialise OpenAI client: {type(exc).__name__}"
            ) from exc

    def decide(self, request: ModelRequest) -> ModelDecision:
        """Call the OpenAI Responses API and return a validated ModelDecision.

        Keeps system instructions separate from untrusted evidence:
          - instructions= parameter: trusted static developer instructions
          - input= parameter: untrusted serialized investigation evidence

        Output is parsed and validated into local dataclasses. No SDK objects
        are returned to the caller.

        Args:
            request: ModelRequest from InvestigationOrchestrator.

        Returns:
            Validated ModelDecision (either TOOL_REQUEST or FINAL_RESULT).

        Raises:
            OpenAIRequestError: On timeout or provider-side transient failure.
            OpenAIResponseError: On malformed, empty, or invalid model output.
            ModelValidationError: Propagated from ToolRequest/ModelDecision.
            SchemaValidationError: Propagated from InvestigationResult.
        """
        user_message = _build_user_message(request)

        # Compose effective instructions: provider-neutral system instructions
        # plus provider-specific JSON output contract. The existing
        # INVESTIGATOR_SYSTEM_INSTRUCTIONS constant is never modified.
        effective_instructions = request.system_instructions + RESPONSE_FORMAT_INSTRUCTIONS

        try:
            import openai
            response = self._client.responses.create(
                model=self._model_name,
                # Trusted system-level instructions — kept separate from evidence
                instructions=effective_instructions,
                # Untrusted evidence input — explicitly labelled in the payload
                input=user_message,
                # Intentional operational cap — provider constrained to concise decisions
                max_output_tokens=MAX_OUTPUT_TOKENS,
                # Request JSON-formatted output
                text={"format": {"type": "json_object"}},
                # Disable server-side storage of requests
                store=False,
            )
        except openai.APITimeoutError as exc:
            raise OpenAIRequestError(
                "provider_timeout: request timed out"
            ) from exc
        except openai.AuthenticationError as exc:
            raise OpenAIRequestError(
                "provider_auth_error: authentication failed"
            ) from exc
        except openai.RateLimitError as exc:
            raise OpenAIRequestError(
                "provider_rate_limit: rate limit exceeded"
            ) from exc
        except openai.APIStatusError as exc:
            raise OpenAIRequestError(
                f"provider_api_error: HTTP {exc.status_code}"
            ) from exc
        except openai.APIError as exc:
            raise OpenAIRequestError(
                f"provider_api_error: {type(exc).__name__}"
            ) from exc

        # Extract and parse text — all failures are OpenAIResponseError
        raw_text = _extract_text_from_response(response)
        return _parse_response_to_decision(raw_text)
