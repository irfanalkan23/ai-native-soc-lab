"""Local Base64 decoder tool for PowerShell -EncodedCommand payloads.

Security Boundary & Non-Execution Guarantee:
This tool is strictly analytical: it decodes Base64 payloads into text strings.
It NEVER executes, evaluates, or invokes shell interpreters on decoded content.
All decoded text must be treated as UNTRUSTED DATA by downstream callers.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional


class DecoderError(ValueError):
    """Raised when Base64 decoding fails due to malformed content or size limits."""
    pass


# Maximum allowed Base64 string length to prevent memory exhaustion (32 KB)
MAX_ENCODED_INPUT_LENGTH = 32_768


@dataclass(frozen=True)
class DecodeResult:
    """Immutable structured result from Base64 decoding."""
    success: bool
    decoded_text: str
    encoding: str
    byte_count: int


def decode_powershell_base64(encoded_input: str) -> DecodeResult:
    """Decode a Base64 encoded PowerShell command line argument.

    PowerShell's -EncodedCommand parameter encodes scripts as UTF-16LE (Unicode).
    This function extracts and decodes the payload strictly in-memory.

    Args:
        encoded_input: Either a standalone Base64 string or a command line
                       containing -EncodedCommand / -enc.

    Returns:
        DecodeResult containing the decoded text and encoding.

    Raises:
        DecoderError: If input is oversized, malformed, or fails closed.
    """
    if type(encoded_input) is not str:
        raise DecoderError(
            f"Expected string input, got {type(encoded_input).__name__}"
        )

    stripped = encoded_input.strip()
    if not stripped:
        raise DecoderError("Input cannot be empty")

    if len(stripped) > MAX_ENCODED_INPUT_LENGTH:
        raise DecoderError(
            f"Input length ({len(stripped)}) exceeds maximum allowed bound of {MAX_ENCODED_INPUT_LENGTH} characters"
        )

    # Extract Base64 token if passed a full command line
    payload = _extract_base64_token(stripped)

    # Decode Base64 bytes (strict validation)
    try:
        raw_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as err:
        raise DecoderError(f"Malformed Base64 payload: {err}") from err

    if not raw_bytes:
        raise DecoderError("Decoded payload resulted in empty byte sequence")

    # PowerShell -EncodedCommand encodes characters strictly as UTF-16LE
    try:
        decoded_text = raw_bytes.decode("utf-16le")
    except UnicodeDecodeError as err:
        raise DecoderError(
            f"Failed to decode payload bytes as UTF-16LE: {err}"
        ) from err

    return DecodeResult(
        success=True,
        decoded_text=decoded_text,
        encoding="utf-16le",
        byte_count=len(raw_bytes),
    )


def _extract_base64_token(command_or_token: str) -> str:
    """Extract the Base64 token from a command line if flag is present, else return as-is."""
    # Match -EncodedCommand, -encodedcommand, -enc, etc. followed by the payload token
    flag_pattern = r"(?i)(?:^|\s)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)"
    match = re.search(flag_pattern, command_or_token)
    if match:
        return match.group(1).strip()
    # Otherwise assume the entire string is the Base64 token
    return command_or_token
