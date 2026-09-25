"""Unit, lifecycle, and security boundary tests for VirusTotal IP provider adapter.

All tests are 100% offline and use mocked HTTPS connections. Zero live network calls.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
import http.client
import json
from pathlib import Path
import ssl
import unittest
from unittest.mock import MagicMock

from investigator.providers.virustotal_provider import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_ALLOWED_RESPONSE_CAP,
    MAX_API_KEY_LENGTH,
    VIRUSTOTAL_ENDPOINT_PREFIX,
    VIRUSTOTAL_HOST,
    VIRUSTOTAL_PORT,
    VirusTotalApiConfig,
    VirusTotalConfigError,
    VirusTotalCredentialError,
    VirusTotalCredentials,
    VirusTotalError,
    VirusTotalResponseError,
    VirusTotalThreatIntelClient,
    VirusTotalTransportError,
)
from investigator.threat_intel import (
    ThreatIntelClient,
    ThreatIntelClientError,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelRequestError,
    ThreatIntelResult,
)


def _build_valid_vt_200_payload(
    ip: str = "8.8.8.8",
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 85,
    undetected: int = 5,
    last_analysis_date: int = 1774440000,
) -> dict:
    """Helper to build a valid VirusTotal v3 IP analysis JSON structure."""
    return {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "last_analysis_date": last_analysis_date,
            },
        }
    }


class TestVirusTotalCredentials(unittest.TestCase):
    """Test VirusTotalCredentials validation and secret masking."""

    def test_valid_credentials_construction(self) -> None:
        """Valid string key constructs frozen credentials."""
        creds = VirusTotalCredentials(api_key="valid-test-api-key-12345")
        self.assertEqual(creds.api_key, "valid-test-api-key-12345")

    def test_repr_and_str_mask_secret(self) -> None:
        """__repr__ and __str__ mask the secret token completely."""
        raw_key = "super-secret-key-that-must-never-leak"
        creds = VirusTotalCredentials(api_key=raw_key)
        self.assertNotIn(raw_key, repr(creds))
        self.assertNotIn(raw_key, str(creds))
        self.assertEqual(repr(creds), "VirusTotalCredentials(api_key='***')")
        self.assertEqual(str(creds), "VirusTotalCredentials(api_key='***')")

    def test_empty_or_whitespace_key_rejected(self) -> None:
        """Empty, whitespace-only, or untrimmed keys are rejected."""
        for bad_key in ["", "   ", " key", "key ", "\tkey", "\n"]:
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(VirusTotalCredentialError):
                    VirusTotalCredentials(api_key=bad_key)

    def test_whitespace_and_control_chars_rejected(self) -> None:
        """Keys containing whitespace, CR, LF, or TAB are rejected."""
        for bad_key in ["key with space", "key\r\n", "key\t123", "key\n"]:
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(VirusTotalCredentialError):
                    VirusTotalCredentials(api_key=bad_key)

    def test_oversized_key_rejected(self) -> None:
        """Key exceeding local safety bound of 512 characters is rejected."""
        oversized = "a" * (MAX_API_KEY_LENGTH + 1)
        with self.assertRaises(VirusTotalCredentialError) as ctx:
            VirusTotalCredentials(api_key=oversized)
        self.assertIn("local safety bound", str(ctx.exception))

    def test_non_str_key_rejected(self) -> None:
        """Non-string types are strictly rejected."""
        for bad_type in [None, 12345, True, False, ["key"]]:
            with self.subTest(bad_type=bad_type):
                with self.assertRaises(VirusTotalCredentialError):
                    VirusTotalCredentials(api_key=bad_type)  # type: ignore[arg-type]

    def test_immutability(self) -> None:
        """VirusTotalCredentials is frozen."""
        creds = VirusTotalCredentials(api_key="initial-key")
        with self.assertRaises(FrozenInstanceError):
            creds.api_key = "new-key"  # type: ignore[misc]


class TestVirusTotalApiConfig(unittest.TestCase):
    """Test VirusTotalApiConfig bounds and invariants."""

    def test_default_config_valid(self) -> None:
        """Default config provides bounded parameters."""
        config = VirusTotalApiConfig()
        self.assertEqual(config.timeout_seconds, DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(config.max_response_bytes, MAX_ALLOWED_RESPONSE_CAP)

    def test_timeout_bounds_enforced(self) -> None:
        """Timeout must be between 0.1 and 60.0 seconds; bools rejected."""
        for bad_timeout in [0.05, 60.1, -1.0, 100.0, True, False, "5.0", None]:
            with self.subTest(bad_timeout=bad_timeout):
                with self.assertRaises(VirusTotalConfigError):
                    VirusTotalApiConfig(timeout_seconds=bad_timeout)  # type: ignore[arg-type]

    def test_max_response_bytes_bounds_enforced(self) -> None:
        """max_response_bytes must be exact int between 1024 and 65536; bools rejected."""
        for bad_bytes in [512, 65537, 100000, True, False, 1024.0, "65536", None]:
            with self.subTest(bad_bytes=bad_bytes):
                with self.assertRaises(VirusTotalConfigError):
                    VirusTotalApiConfig(max_response_bytes=bad_bytes)  # type: ignore[arg-type]

    def test_immutability(self) -> None:
        """VirusTotalApiConfig is frozen."""
        config = VirusTotalApiConfig()
        with self.assertRaises(FrozenInstanceError):
            config.timeout_seconds = 10.0  # type: ignore[misc]


class TestVirusTotalThreatIntelClient(unittest.TestCase):
    """Test VirusTotalThreatIntelClient request formatting, response parsing, and error mapping."""

    def setUp(self) -> None:
        self.creds = VirusTotalCredentials(api_key="test-virustotal-api-key")
        self.config = VirusTotalApiConfig(timeout_seconds=5.0, max_response_bytes=65536)
        self.valid_req = ThreatIntelRequest(indicator_value="8.8.8.8")

    def test_protocol_conformance(self) -> None:
        """VirusTotalThreatIntelClient conforms to ThreatIntelClient protocol."""
        client = VirusTotalThreatIntelClient(credentials=self.creds, config=self.config)
        self.assertIsInstance(client, ThreatIntelClient)

    def test_client_init_type_validation(self) -> None:
        """Constructor rejects invalid credentials or config types."""
        with self.assertRaises(VirusTotalCredentialError):
            VirusTotalThreatIntelClient(credentials="not-creds")  # type: ignore[arg-type]
        with self.assertRaises(VirusTotalConfigError):
            VirusTotalThreatIntelClient(credentials=self.creds, config={"timeout": 5})  # type: ignore[arg-type]

    def test_lookup_rejects_non_threat_intel_request(self) -> None:
        """lookup() rejects non-ThreatIntelRequest arguments."""
        client = VirusTotalThreatIntelClient(credentials=self.creds, config=self.config)
        with self.assertRaises(ThreatIntelClientError):
            client.lookup("8.8.8.8")  # type: ignore[arg-type]

    def test_fixed_endpoint_and_headers_enforced(self) -> None:
        """Client sends GET to hardcoded www.virustotal.com:443 with exact path and x-apikey header."""
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(_build_valid_vt_200_payload("8.8.8.8")).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        factory = MagicMock(return_value=mock_conn)
        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=factory,
        )

        result = client.lookup(self.valid_req)
        self.assertEqual(result.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(result.provider, "virustotal")

        # Verify fixed destination parameters
        factory.assert_called_once()
        call_args = factory.call_args[0]
        self.assertEqual(call_args[0], VIRUSTOTAL_HOST)
        self.assertEqual(call_args[1], VIRUSTOTAL_PORT)
        self.assertEqual(call_args[2], 5.0)

        # Verify exact request parameters
        mock_conn.request.assert_called_once()
        req_args, req_kwargs = mock_conn.request.call_args
        self.assertEqual(req_args[0], "GET")
        self.assertEqual(req_args[1], f"{VIRUSTOTAL_ENDPOINT_PREFIX}8.8.8.8")
        self.assertNotIn("?", req_args[1])  # No query string

        # Verify no request body provided in positional or keyword arguments
        self.assertEqual(len(req_args), 2)
        self.assertNotIn("body", req_kwargs)

        headers = req_kwargs["headers"]
        self.assertEqual(headers["x-apikey"], "test-virustotal-api-key")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["User-Agent"], "ai-native-soc-lab/1.0")

    def test_successful_ipv4_lookup_200(self) -> None:
        """Valid 200 JSON parses into normalized ThreatIntelResult."""
        payload = _build_valid_vt_200_payload(
            ip="8.8.8.8",
            malicious=10,
            suspicious=2,
            harmless=75,
            undetected=3,
            last_analysis_date=1774440000,
        )
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        result = client.lookup(self.valid_req)
        self.assertEqual(result.provider, "virustotal")
        self.assertEqual(result.indicator_type, "ip")
        self.assertEqual(result.indicator_value, "8.8.8.8")
        self.assertEqual(result.lookup_status, ThreatIntelLookupStatus.FOUND)
        self.assertEqual(result.malicious_count, 10)
        self.assertEqual(result.suspicious_count, 2)
        self.assertEqual(result.harmless_count, 75)
        self.assertEqual(result.undetected_count, 3)
        self.assertEqual(result.detail_code, "ip_lookup_found")
        self.assertEqual(result.last_analysis_utc, "2026-03-25T12:00:00Z")

    def test_successful_ipv6_lookup_with_canonicalization_200(self) -> None:
        """IPv6 response ID canonicalizes cleanly and matches canonical request indicator."""
        uncompressed_ip = "2001:4860:4860:0000:0000:0000:0000:8888"
        canonical_ip = "2001:4860:4860::8888"
        req = ThreatIntelRequest(indicator_value=canonical_ip)

        payload = _build_valid_vt_200_payload(
            ip=uncompressed_ip,  # Provider returned uncompressed format
            malicious=0,
            suspicious=0,
            harmless=80,
            undetected=10,
            last_analysis_date=1774440000,
        )
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        result = client.lookup(req)
        self.assertEqual(result.indicator_value, canonical_ip)
        self.assertEqual(result.lookup_status, ThreatIntelLookupStatus.FOUND)

    def test_successful_lookup_with_none_timestamp(self) -> None:
        """200 response with absent last_analysis_date sets last_analysis_utc=None."""
        payload = {
            "data": {
                "id": "8.8.8.8",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10,
                    },
                },
            }
        }
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        result = client.lookup(self.valid_req)
        self.assertIsNone(result.last_analysis_utc)
        self.assertEqual(result.lookup_status, ThreatIntelLookupStatus.FOUND)

    def test_http_404_with_exact_not_found_error_code(self) -> None:
        """404 with exact NotFoundError JSON returns normalized NOT_FOUND result."""
        payload = {
            "error": {
                "code": "NotFoundError",
                "message": "IP address 8.8.8.8 was not found in VirusTotal database",
            }
        }
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        result = client.lookup(self.valid_req)
        self.assertEqual(result.provider, "virustotal")
        self.assertEqual(result.lookup_status, ThreatIntelLookupStatus.NOT_FOUND)
        self.assertEqual(result.indicator_value, "8.8.8.8")
        self.assertEqual(result.malicious_count, 0)
        self.assertEqual(result.suspicious_count, 0)
        self.assertEqual(result.harmless_count, 0)
        self.assertEqual(result.undetected_count, 0)
        self.assertEqual(result.detail_code, "ip_lookup_not_found")
        self.assertIsNone(result.last_analysis_utc)

    def test_http_404_with_unexpected_error_code_fails(self) -> None:
        """404 with non-NotFoundError code raises VirusTotalResponseError('vt_endpoint_not_found')."""
        payload = {
            "error": {
                "code": "WrongErrorCode",
                "message": "Some other error",
            }
        }
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        with self.assertRaises(VirusTotalResponseError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_endpoint_not_found")

    def test_http_404_error_code_type_enforcement(self) -> None:
        """404 error.code must be exact str 'NotFoundError'; non-str types fail closed."""
        bad_codes = [None, 123, True, ["NotFoundError"], {"value": "NotFoundError"}]
        for bad_code in bad_codes:
            with self.subTest(bad_code=bad_code):
                payload = {"error": {"code": bad_code}}
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = 404
                mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalResponseError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_endpoint_not_found")

    def test_http_404_with_html_or_non_json_fails(self) -> None:
        """404 with non-JSON body raises VirusTotalResponseError('vt_invalid_json')."""
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b"<html><head><title>404 Not Found</title></head></html>"
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        with self.assertRaises(VirusTotalResponseError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_invalid_json")

    def test_http_status_code_mappings(self) -> None:
        """Standard HTTP error codes map to static sanitized detail codes without reading body."""
        status_mappings = [
            (400, "vt_bad_request"),
            (401, "vt_auth_failed"),
            (403, "vt_forbidden"),
            (429, "vt_rate_limited"),
            (500, "vt_remote_error"),
            (502, "vt_remote_error"),
            (503, "vt_remote_error"),
            (504, "vt_remote_error"),
            (418, "vt_unexpected_status"),
        ]
        for status, expected_code in status_mappings:
            with self.subTest(status=status, expected_code=expected_code):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = status
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalResponseError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), expected_code)
                mock_resp.read.assert_not_called()

    def test_non_200_non_404_do_not_read_body(self) -> None:
        """Statuses 301, 400, 401, 403, 429, 500, 418 must NEVER call resp.read()."""
        for status in [301, 400, 401, 403, 429, 500, 418]:
            with self.subTest(status=status):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = status
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                expected_exc = VirusTotalTransportError if 300 <= status < 400 else VirusTotalResponseError
                with self.assertRaises(expected_exc):
                    client.lookup(self.valid_req)
                mock_resp.read.assert_not_called()

    def test_http_redirect_rejected(self) -> None:
        """HTTP 3xx redirects are rejected immediately without following and without reading body."""
        for redirect_status in [301, 302, 307, 308]:
            with self.subTest(status=redirect_status):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = redirect_status
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalTransportError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_redirect_rejected")
                mock_resp.read.assert_not_called()

    def test_response_size_cap_enforced(self) -> None:
        """Response exceeding max_response_bytes raises VirusTotalResponseError('vt_response_too_large')."""
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        # Return 65537 bytes (1 byte over default 64 KiB cap)
        mock_resp.read.return_value = b"x" * (MAX_ALLOWED_RESPONSE_CAP + 1)
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        with self.assertRaises(VirusTotalResponseError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_response_too_large")

    def test_configured_lower_response_cap_enforced(self) -> None:
        """Client enforces configured lower response cap (e.g. 2048) and reads max_bytes + 1."""
        lower_config = VirusTotalApiConfig(max_response_bytes=2048)
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"x" * 2049
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=lower_config,
            _connection_factory=lambda *args: mock_conn,
        )

        with self.assertRaises(VirusTotalResponseError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_response_too_large")
        mock_resp.read.assert_called_once_with(2049)

    def test_secret_sentinel_leak_prevention(self) -> None:
        """Sentinel API key never leaks into repr, str, transport errors, or response errors."""
        sentinel_key = "SUPER_SECRET_VT_SENTINEL_12345"
        creds = VirusTotalCredentials(api_key=sentinel_key)

        # 1. repr and str check
        self.assertNotIn(sentinel_key, repr(creds))
        self.assertNotIn(sentinel_key, str(creds))

        # 2. VirusTotalTransportError from lower-level exception containing sentinel
        mock_conn = MagicMock()
        mock_conn.request.side_effect = OSError(f"Connection failed to {sentinel_key}")
        client = VirusTotalThreatIntelClient(
            credentials=creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )
        with self.assertRaises(VirusTotalTransportError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_transport_error")
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn(sentinel_key, str(ctx.exception))

        # 3. VirusTotalResponseError for static HTTP status mapping
        for status in [400, 401, 403, 429, 500]:
            mock_conn_status = MagicMock()
            mock_resp_status = MagicMock()
            mock_resp_status.status = status
            mock_conn_status.getresponse.return_value = mock_resp_status
            client_status = VirusTotalThreatIntelClient(
                credentials=creds,
                config=self.config,
                _connection_factory=lambda *args: mock_conn_status,
            )
            with self.assertRaises(VirusTotalResponseError) as ctx_status:
                client_status.lookup(self.valid_req)
            self.assertNotIn(sentinel_key, str(ctx_status.exception))

        # 4. VirusTotalResponseError for malformed provider data
        mock_conn_malformed = MagicMock()
        mock_resp_malformed = MagicMock()
        mock_resp_malformed.status = 200
        mock_resp_malformed.read.return_value = b"invalid json data"
        mock_conn_malformed.getresponse.return_value = mock_resp_malformed
        client_malformed = VirusTotalThreatIntelClient(
            credentials=creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn_malformed,
        )
        with self.assertRaises(VirusTotalResponseError) as ctx_malformed:
            client_malformed.lookup(self.valid_req)
        self.assertEqual(str(ctx_malformed.exception), "vt_invalid_json")
        self.assertNotIn(sentinel_key, str(ctx_malformed.exception))

    def test_no_retry_on_429(self) -> None:
        """HTTP 429 invokes factory, request, and getresponse exactly once with zero retry."""
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 429
        mock_conn.getresponse.return_value = mock_resp
        factory = MagicMock(return_value=mock_conn)

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=factory,
        )

        with self.assertRaises(VirusTotalResponseError):
            client.lookup(self.valid_req)

        factory.assert_called_once()
        mock_conn.request.assert_called_once()
        mock_conn.getresponse.assert_called_once()

    def test_no_retry_on_500(self) -> None:
        """HTTP 500 invokes factory, request, and getresponse exactly once with zero retry."""
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_conn.getresponse.return_value = mock_resp
        factory = MagicMock(return_value=mock_conn)

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=factory,
        )

        with self.assertRaises(VirusTotalResponseError):
            client.lookup(self.valid_req)

        factory.assert_called_once()
        mock_conn.request.assert_called_once()
        mock_conn.getresponse.assert_called_once()

    def test_no_retry_and_close_on_transport_failure_after_creation(self) -> None:
        """Transport failure after connection creation does not retry and guarantees conn.close()."""
        mock_conn = MagicMock()
        mock_conn.request.side_effect = OSError("Connection reset by peer")
        factory = MagicMock(return_value=mock_conn)

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=factory,
        )

        with self.assertRaises(VirusTotalTransportError):
            client.lookup(self.valid_req)

        factory.assert_called_once()
        mock_conn.request.assert_called_once()
        mock_conn.close.assert_called_once()

    def test_malformed_json_or_invalid_utf8(self) -> None:
        """Invalid UTF-8 or malformed JSON raises VirusTotalResponseError('vt_invalid_json')."""
        for bad_payload in [b"\xff\xfe\xfd", b"{broken json", b"", b"   "]:
            with self.subTest(bad_payload=bad_payload):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = bad_payload
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalResponseError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_invalid_json")

    def test_schema_structural_violations(self) -> None:
        """Missing or malformed JSON structural fields raise VirusTotalResponseError('vt_schema_invalid')."""
        invalid_payloads = [
            [],  # Non-dict root
            {},  # Missing data
            {"data": "not-a-dict"},
            {"data": {"type": "file", "id": "8.8.8.8"}},  # type != ip_address
            {"data": {"type": "ip_address"}},  # Missing id
            {"data": {"type": "ip_address", "id": "8.8.8.8"}},  # Missing attributes
            {"data": {"type": "ip_address", "id": "8.8.8.8", "attributes": {}}},  # Missing stats
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalResponseError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_schema_invalid")

    def test_counter_type_and_range_violations(self) -> None:
        """Counters must be exact int between 0 and 256; bools, floats, and strings rejected."""
        base_payload = _build_valid_vt_200_payload("8.8.8.8")
        bad_counter_values = [True, False, 1.0, "10", -1, 257, 1000, None]

        for field in ("malicious", "suspicious", "harmless", "undetected"):
            for bad_val in bad_counter_values:
                with self.subTest(field=field, bad_val=bad_val):
                    payload = json.loads(json.dumps(base_payload))
                    payload["data"]["attributes"]["last_analysis_stats"][field] = bad_val

                    mock_conn = MagicMock()
                    mock_resp = MagicMock()
                    mock_resp.status = 200
                    mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
                    mock_conn.getresponse.return_value = mock_resp

                    client = VirusTotalThreatIntelClient(
                        credentials=self.creds,
                        config=self.config,
                        _connection_factory=lambda *args: mock_conn,
                    )

                    with self.assertRaises(VirusTotalResponseError) as ctx:
                        client.lookup(self.valid_req)
                    self.assertEqual(str(ctx.exception), "vt_schema_invalid")

    def test_timestamp_type_and_bounds_violations(self) -> None:
        """last_analysis_date must be exact int epoch between 0 and 4102444800."""
        base_payload = _build_valid_vt_200_payload("8.8.8.8")
        bad_timestamps = [True, False, 1774440000.5, "1774440000", -1, 5000000000]

        for bad_ts in bad_timestamps:
            with self.subTest(bad_ts=bad_ts):
                payload = json.loads(json.dumps(base_payload))
                payload["data"]["attributes"]["last_analysis_date"] = bad_ts

                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalResponseError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_schema_invalid")

    def test_identity_mismatch_fails_closed(self) -> None:
        """Response data.id differing from requested canonical IP raises 'vt_indicator_mismatch'."""
        payload = _build_valid_vt_200_payload("1.1.1.1")  # Request is for 8.8.8.8
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn,
        )

        with self.assertRaises(VirusTotalResponseError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_indicator_mismatch")

    def test_transport_exception_sanitized_from_none(self) -> None:
        """Transport exceptions map strictly to static 'vt_transport_error' with __cause__ is None."""
        for exc in [
            http.client.HTTPException("raw internal http error"),
            OSError("Connection refused: 127.0.0.1"),
            TimeoutError("timed out after 5.0 seconds"),
        ]:
            with self.subTest(exc=exc):
                mock_conn = MagicMock()
                mock_conn.request.side_effect = exc

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                with self.assertRaises(VirusTotalTransportError) as ctx:
                    client.lookup(self.valid_req)
                self.assertEqual(str(ctx.exception), "vt_transport_error")
                self.assertIsNone(ctx.exception.__cause__)

    def test_connection_factory_failure_maps_to_transport_error(self) -> None:
        """If connection factory raises, map to vt_transport_error and do not attempt close()."""
        def failing_factory(*args):
            raise OSError("Network unreachable")

        client = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=failing_factory,
        )

        with self.assertRaises(VirusTotalTransportError) as ctx:
            client.lookup(self.valid_req)
        self.assertEqual(str(ctx.exception), "vt_transport_error")
        self.assertIsNone(ctx.exception.__cause__)

    def test_connection_lifecycle_closed_on_all_paths(self) -> None:
        """HTTPS connection is closed exactly once across success, 404, errors, and exceptions."""
        scenarios = [
            ("200_success", 200, json.dumps(_build_valid_vt_200_payload("8.8.8.8")).encode("utf-8")),
            ("404_not_found", 404, json.dumps({"error": {"code": "NotFoundError"}}).encode("utf-8")),
            ("500_error", 500, None),
            ("oversized", 200, b"x" * 70000),
            ("malformed_json", 200, b"not json"),
        ]
        for name, status, body in scenarios:
            with self.subTest(scenario=name):
                mock_conn = MagicMock()
                mock_resp = MagicMock()
                mock_resp.status = status
                if body is not None:
                    mock_resp.read.return_value = body
                mock_conn.getresponse.return_value = mock_resp

                client = VirusTotalThreatIntelClient(
                    credentials=self.creds,
                    config=self.config,
                    _connection_factory=lambda *args: mock_conn,
                )

                try:
                    client.lookup(self.valid_req)
                except Exception:
                    pass

                mock_conn.close.assert_called_once()

        # Explicit test for transport exception after connection creation
        mock_conn_exc = MagicMock()
        mock_conn_exc.request.side_effect = OSError("Socket drop")
        client_exc = VirusTotalThreatIntelClient(
            credentials=self.creds,
            config=self.config,
            _connection_factory=lambda *args: mock_conn_exc,
        )
        try:
            client_exc.lookup(self.valid_req)
        except Exception:
            pass
        mock_conn_exc.close.assert_called_once()


class TestVirusTotalSecurityBoundaries(unittest.TestCase):
    """Verify security isolation, AST module boundaries, and filesystem independence."""

    def setUp(self) -> None:
        self.module_path = (
            Path(__file__).resolve().parent.parent
            / "investigator"
            / "providers"
            / "virustotal_provider.py"
        )
        self.assertTrue(self.module_path.exists(), f"Module {self.module_path} not found")
        self.source = self.module_path.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_no_forbidden_network_or_system_modules(self) -> None:
        """virustotal_provider.py must import zero requests, httpx, urllib, or subprocess libraries."""
        forbidden_modules = {
            "urllib",
            "urllib.request",
            "urllib.parse",
            "requests",
            "httpx",
            "subprocess",
        }
        imported_modules: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module)

        for forbidden in forbidden_modules:
            self.assertNotIn(
                forbidden,
                imported_modules,
                f"Forbidden module '{forbidden}' imported in virustotal_provider.py",
            )

    def test_no_forbidden_function_calls(self) -> None:
        """virustotal_provider.py must not call eval, exec, or os.system."""
        forbidden_calls: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    forbidden_calls.append(node.func.id)
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "system"
                ):
                    forbidden_calls.append("os.system")

        self.assertEqual(forbidden_calls, [])

    def test_no_environment_access(self) -> None:
        """virustotal_provider.py must not access os.environ or getenv."""
        self.assertNotIn("os.environ", self.source)
        self.assertNotIn("getenv", self.source)

    def test_filesystem_independence(self) -> None:
        """virustotal_provider.py must not read, write, or access files (no open, Path, pathlib)."""
        forbidden_fs_calls: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"open", "Path"}:
                    forbidden_fs_calls.append(node.func.id)
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "read_text",
                    "write_text",
                    "read_bytes",
                    "write_bytes",
                }:
                    forbidden_fs_calls.append(node.func.attr)

        self.assertEqual(
            forbidden_fs_calls,
            [],
            f"Forbidden filesystem calls detected: {forbidden_fs_calls}",
        )
        self.assertNotIn("pathlib", self.source)

    def test_host_constant_is_literal_string(self) -> None:
        """VIRUSTOTAL_HOST must be exact literal 'www.virustotal.com' without escape characters."""
        self.assertEqual(VIRUSTOTAL_HOST, "www.virustotal.com")
        self.assertNotIn("\\", VIRUSTOTAL_HOST)


if __name__ == "__main__":
    unittest.main()
