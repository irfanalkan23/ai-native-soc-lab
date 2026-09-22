"""Unit and security boundary tests for Jira Cloud REST API v3 adapter.

All tests are 100% offline and use mocked transport. Zero live network calls.
"""

from __future__ import annotations

import base64
import http.client
import io
import json
import sys
import unittest
from unittest.mock import MagicMock, patch

from investigator.providers.jira_provider import (
    ATLASSIAN_HOST_PATTERN,
    DEFAULT_TIMEOUT_SECONDS,
    JIRA_ISSUE_ENDPOINT,
    MAX_API_TOKEN_LENGTH,
    MAX_EMAIL_LENGTH,
    MAX_RESPONSE_BYTES,
    JiraApiConfig,
    JiraConfigError,
    JiraCredentialError,
    JiraCredentials,
    JiraError,
    JiraPayloadMapper,
    JiraResponseError,
    JiraTicketClient,
    JiraTransportError,
)
from investigator.ticketing import (
    TicketClientError,
    TicketPriority,
    TicketRequest,
    TicketResult,
    TicketingError,
)


def _create_sample_ticket_request(
    project_key: str = "SEC",
    issue_type: str = "Incident",
    summary: str = "Suspicious activity detected on DC01",
    description: str = "Detailed description of incident",
    priority: TicketPriority = TicketPriority.HIGH,
    labels: tuple = ("ai-native-soc", "powershell"),
    external_reference: str = "INC-2026-0001",
) -> TicketRequest:
    """Helper to create a validated TicketRequest for testing."""
    return TicketRequest(
        incident_id="INC-2026-0001",
        project_key=project_key,
        issue_type=issue_type,
        summary=summary,
        description=description,
        priority=priority,
        labels=labels,
        external_reference=external_reference,
    )


class TestJiraCredentials(unittest.TestCase):
    """Test JiraCredentials validation, masking, and header derivation."""

    def test_valid_credentials(self) -> None:
        creds = JiraCredentials(email="soc-bot@example.atlassian.net", api_token="secret_token_123")
        self.assertEqual(creds.email, "soc-bot@example.atlassian.net")
        self.assertEqual(creds.api_token, "secret_token_123")

    def test_credentials_masking(self) -> None:
        creds = JiraCredentials(email="soc-bot@example.atlassian.net", api_token="secret_token_123")
        repr_str = repr(creds)
        str_str = str(creds)
        self.assertNotIn("soc-bot@example.atlassian.net", repr_str)
        self.assertNotIn("secret_token_123", repr_str)
        self.assertNotIn("soc-bot@example.atlassian.net", str_str)
        self.assertNotIn("secret_token_123", str_str)
        self.assertIn("***", repr_str)

    def test_empty_email_rejected(self) -> None:
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="", api_token="secret")
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="   ", api_token="secret")

    def test_empty_token_rejected(self) -> None:
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="soc@example.com", api_token="")
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="soc@example.com", api_token="   ")

    def test_email_length_limit(self) -> None:
        too_long = "a" * 250 + "@example.com"
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email=too_long, api_token="secret")

    def test_token_length_limit(self) -> None:
        too_long = "x" * (MAX_API_TOKEN_LENGTH + 1)
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="soc@example.com", api_token=too_long)

    def test_control_characters_rejected(self) -> None:
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="soc\n@example.com", api_token="secret")
        with self.assertRaises(JiraCredentialError):
            JiraCredentials(email="soc@example.com", api_token="secret\r\n")

    def test_basic_auth_header_derivation(self) -> None:
        creds = JiraCredentials(email="user@test.atlassian.net", api_token="tokenABC")
        expected_raw = "user@test.atlassian.net:tokenABC".encode("utf-8")
        expected_b64 = base64.b64encode(expected_raw).decode("ascii")
        self.assertEqual(creds.get_basic_auth_header(), f"Basic {expected_b64}")


class TestJiraApiConfig(unittest.TestCase):
    """Test hardened validation of JiraApiConfig base_url and timeouts."""

    def test_valid_base_urls(self) -> None:
        cfg1 = JiraApiConfig(base_url="https://sec-corp.atlassian.net")
        self.assertEqual(cfg1.host, "sec-corp.atlassian.net")
        self.assertEqual(cfg1.port, 443)

        cfg2 = JiraApiConfig(base_url="https://sec-corp.atlassian.net/")
        self.assertEqual(cfg2.host, "sec-corp.atlassian.net")
        self.assertEqual(cfg2.port, 443)

        cfg3 = JiraApiConfig(base_url="https://sec-corp.atlassian.net:443")
        self.assertEqual(cfg3.host, "sec-corp.atlassian.net")
        self.assertEqual(cfg3.port, 443)

    def test_non_https_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="http://sec-corp.atlassian.net")
        self.assertIn("scheme must be exactly 'https'", str(ctx.exception))

    def test_non_atlassian_hostname_rejected(self) -> None:
        invalid_hosts = [
            "https://evil.com",
            "https://atlassian.net",
            "https://notatlassian.net",
            "https://myjira.example.org",
            "https://sec-corp.atlassian.net.evil.com",
        ]
        for url in invalid_hosts:
            with self.assertRaises(JiraConfigError):
                JiraApiConfig(base_url=url)

    def test_query_string_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net?test=1")
        self.assertIn("query parameters", str(ctx.exception))

    def test_fragment_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net#anchor")
        self.assertIn("fragment", str(ctx.exception))

    def test_embedded_credentials_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://user:pass@sec-corp.atlassian.net")
        self.assertIn("username or password", str(ctx.exception))

    def test_non_root_path_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net/rest/api/3")
        self.assertIn("path must be empty or '/'", str(ctx.exception))

    def test_explicit_non_443_port_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net:8443")
        self.assertIn("port must be 443 or omitted", str(ctx.exception))

    def test_alphabetic_port_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net:abc")
        self.assertEqual(str(ctx.exception), "base_url contains invalid port")

    def test_out_of_range_port_rejected(self) -> None:
        with self.assertRaises(JiraConfigError) as ctx:
            JiraApiConfig(base_url="https://sec-corp.atlassian.net:99999")
        self.assertEqual(str(ctx.exception), "base_url contains invalid port")

    def test_timeout_bounds_validation(self) -> None:
        cfg = JiraApiConfig(base_url="https://sec.atlassian.net", timeout_seconds=5.0)
        self.assertEqual(cfg.timeout_seconds, 5.0)

        with self.assertRaises(JiraConfigError):
            JiraApiConfig(base_url="https://sec.atlassian.net", timeout_seconds=0.05)

        with self.assertRaises(JiraConfigError):
            JiraApiConfig(base_url="https://sec.atlassian.net", timeout_seconds=120.0)

        with self.assertRaises(JiraConfigError):
            JiraApiConfig(base_url="https://sec.atlassian.net", timeout_seconds="ten")  # type: ignore[arg-type]

        # Exact type check: bool is not accepted as numeric timeout
        with self.assertRaises(JiraConfigError):
            JiraApiConfig(base_url="https://sec.atlassian.net", timeout_seconds=True)  # type: ignore[arg-type]


class TestJiraPayloadMapper(unittest.TestCase):
    """Test payload mapping, ADF plaintext formatting, and priority exclusion."""

    def test_build_issue_payload_structure(self) -> None:
        req = _create_sample_ticket_request(
            project_key="SEC",
            issue_type="Incident",
            summary="Endpoint containment alert",
            description="Detailed evidence text line 1\nLine 2",
            priority=TicketPriority.CRITICAL,
            labels=("ai-native-soc", "powershell"),
        )
        payload = JiraPayloadMapper.build_issue_payload(req)

        self.assertIn("fields", payload)
        fields = payload["fields"]
        self.assertEqual(fields["project"], {"key": "SEC"})
        self.assertEqual(fields["issuetype"], {"name": "Incident"})
        self.assertEqual(fields["summary"], "Endpoint containment alert")
        self.assertEqual(fields["labels"], ["ai-native-soc", "powershell"])

        # Jira priority is intentionally omitted in V1
        self.assertNotIn("priority", fields)

        # ADF formatting checks
        desc = fields["description"]
        self.assertEqual(desc["type"], "doc")
        self.assertEqual(desc["version"], 1)
        self.assertEqual(len(desc["content"]), 1)
        paragraph = desc["content"][0]
        self.assertEqual(paragraph["type"], "paragraph")
        self.assertEqual(len(paragraph["content"]), 1)
        text_node = paragraph["content"][0]
        self.assertEqual(text_node["type"], "text")
        self.assertEqual(text_node["text"], "Detailed evidence text line 1\nLine 2")

    def test_mapper_rejects_non_ticket_request(self) -> None:
        with self.assertRaises(TicketClientError):
            JiraPayloadMapper.build_issue_payload({"not": "a_request"})  # type: ignore[arg-type]


class TestJiraTicketClient(unittest.TestCase):
    """Test JiraTicketClient operations, mocked HTTP calls, and error handling."""

    def setUp(self) -> None:
        self.config = JiraApiConfig(base_url="https://test-soc.atlassian.net")
        self.credentials = JiraCredentials(email="bot@test-soc.atlassian.net", api_token="secret-token-xyz")
        self.client = JiraTicketClient(config=self.config, credentials=self.credentials)
        self.sample_request = _create_sample_ticket_request()

    def test_repr_and_str_masking(self) -> None:
        repr_str = repr(self.client)
        str_str = str(self.client)
        self.assertNotIn("secret-token-xyz", repr_str)
        self.assertNotIn("bot@test-soc.atlassian.net", repr_str)
        self.assertNotIn("secret-token-xyz", str_str)
        self.assertIn("test-soc.atlassian.net", repr_str)

    def test_from_env_success(self) -> None:
        env = {
            "JIRA_BASE_URL": "https://env-soc.atlassian.net",
            "JIRA_USER_EMAIL": "env-bot@env-soc.atlassian.net",
            "JIRA_API_TOKEN": "token-from-env",
        }
        client = JiraTicketClient.from_env(env)
        self.assertEqual(client._config.host, "env-soc.atlassian.net")
        self.assertEqual(client._credentials.email, "env-bot@env-soc.atlassian.net")

    def test_from_env_missing_vars_raise(self) -> None:
        with self.assertRaises(JiraConfigError):
            JiraTicketClient.from_env({})

        with self.assertRaises(JiraCredentialError):
            JiraTicketClient.from_env({"JIRA_BASE_URL": "https://env-soc.atlassian.net"})

        with self.assertRaises(JiraCredentialError):
            JiraTicketClient.from_env({
                "JIRA_BASE_URL": "https://env-soc.atlassian.net",
                "JIRA_USER_EMAIL": "bot@env-soc.atlassian.net",
            })

    @patch("http.client.HTTPSConnection")
    def test_create_ticket_success_201(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"id": "10050", "key": "SEC-0042"}).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        result = self.client.create_ticket(self.sample_request)

        self.assertIsInstance(result, TicketResult)
        self.assertTrue(result.success)
        self.assertEqual(result.provider, "jira_cloud")
        self.assertEqual(result.ticket_key, "SEC-0042")
        self.assertEqual(result.detail_code, "ticket_created_jira")
        self.assertTrue(result.created_at_utc.endswith("+00:00") or result.created_at_utc.endswith("Z"))

        # Verify exact request parameters
        mock_conn.request.assert_called_once()
        args, kwargs = mock_conn.request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], JIRA_ISSUE_ENDPOINT)
        sent_headers = kwargs["headers"]
        self.assertTrue(sent_headers["Authorization"].startswith("Basic "))
        self.assertEqual(sent_headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(sent_headers["Accept"], "application/json")
        self.assertEqual(sent_headers["User-Agent"], "ai-native-soc-lab/1.0")

        # Verify payload content sent
        sent_body = json.loads(kwargs["body"].decode("utf-8"))
        self.assertEqual(sent_body["fields"]["project"]["key"], "SEC")
        self.assertEqual(sent_body["fields"]["summary"], self.sample_request.summary)

        mock_conn.close.assert_called_once()

    @patch("http.client.HTTPSConnection")
    def test_response_read_before_connection_close_lifecycle_regression(self, mock_conn_cls: MagicMock) -> None:
        """Regression test: response read() must execute before connection close()."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        conn_is_closed = False

        def mark_closed() -> None:
            nonlocal conn_is_closed
            conn_is_closed = True

        mock_conn.close.side_effect = mark_closed

        mock_resp = MagicMock()
        mock_resp.status = 201

        def guarded_read(n: int) -> bytes:
            if conn_is_closed:
                raise AssertionError("resp.read() was called AFTER HTTPSConnection.close()!")
            return json.dumps({"id": "10050", "key": "SEC-0042"}).encode("utf-8")

        mock_resp.read.side_effect = guarded_read
        mock_conn.getresponse.return_value = mock_resp

        result = self.client.create_ticket(self.sample_request)
        self.assertTrue(result.success)
        self.assertEqual(result.ticket_key, "SEC-0042")
        self.assertTrue(conn_is_closed)

    @patch("http.client.HTTPSConnection")
    def test_returned_ticket_key_project_prefix_matches(self, mock_conn_cls: MagicMock) -> None:
        """Key matching request.project_key prefix is accepted."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"id": "10050", "key": "SEC-1234"}).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        result = self.client.create_ticket(self.sample_request)
        self.assertEqual(result.ticket_key, "SEC-1234")

    @patch("http.client.HTTPSConnection")
    def test_returned_ticket_key_project_mismatch_fails_closed(self, mock_conn_cls: MagicMock) -> None:
        """Key from a different project fails closed with jira_ticket_key_project_mismatch."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"id": "10050", "key": "OTHER-1234"}).encode("utf-8")
        mock_conn.getresponse.return_value = mock_resp

        with self.assertRaises(JiraResponseError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertEqual(str(ctx.exception), "jira_ticket_key_project_mismatch")

    @patch("http.client.HTTPSConnection")
    def test_single_attempt_only_no_retries(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.read.return_value = b'{"errorMessages":["Internal Server Error"]}'
        mock_conn.getresponse.return_value = mock_resp

        with self.assertRaises(JiraResponseError) as ctx:
            self.client.create_ticket(self.sample_request)

        self.assertEqual(str(ctx.exception), "jira_remote_service_error")
        # Ensure only a single attempt was made
        self.assertEqual(mock_conn.request.call_count, 1)

    @patch("http.client.HTTPSConnection")
    def test_redirects_rejected_immediately(self, mock_conn_cls: MagicMock) -> None:
        for code in (301, 302, 307, 308):
            mock_conn = MagicMock()
            mock_conn_cls.return_value = mock_conn

            mock_resp = MagicMock()
            mock_resp.status = code
            mock_conn.getresponse.return_value = mock_resp

            with self.assertRaises(JiraTransportError) as ctx:
                self.client.create_ticket(self.sample_request)
            self.assertEqual(str(ctx.exception), "jira_redirect_rejected")

    @patch("http.client.HTTPSConnection")
    def test_oversized_response_rejected(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b"x" * (MAX_RESPONSE_BYTES + 1)
        mock_conn.getresponse.return_value = mock_resp

        with self.assertRaises(JiraResponseError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertIn("response exceeded maximum size limit", str(ctx.exception))

    @patch("http.client.HTTPSConnection")
    def test_non_201_errors_mapped_and_do_not_leak_response_body(self, mock_conn_cls: MagicMock) -> None:
        status_expected_map = {
            400: "jira_payload_rejected",
            401: "jira_authentication_failed",
            403: "jira_authorization_failed",
            404: "jira_endpoint_or_project_not_found",
            429: "jira_rate_limited",
            500: "jira_remote_service_error",
            502: "jira_remote_service_error",
            503: "jira_remote_service_error",
            418: "jira_unexpected_status",
        }
        sensitive_body = b'{"errorMessages":["Forbidden: internal secret key 12345 leaked!"]}'
        for status, expected_code in status_expected_map.items():
            mock_conn = MagicMock()
            mock_conn_cls.return_value = mock_conn

            mock_resp = MagicMock()
            mock_resp.status = status
            mock_resp.read.return_value = sensitive_body
            mock_conn.getresponse.return_value = mock_resp

            with self.assertRaises(JiraResponseError) as ctx:
                self.client.create_ticket(self.sample_request)

            err_msg = str(ctx.exception)
            self.assertEqual(err_msg, expected_code)
            self.assertNotIn("secret key 12345", err_msg)
            self.assertNotIn("internal", err_msg)

    @patch("http.client.HTTPSConnection")
    def test_invalid_json_in_201_raises_response_error(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b"Not JSON at all!"
        mock_conn.getresponse.return_value = mock_resp

        with self.assertRaises(JiraResponseError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertIn("failed to parse Jira response JSON", str(ctx.exception))

    @patch("http.client.HTTPSConnection")
    def test_missing_or_invalid_key_in_201_raises_response_error(self, mock_conn_cls: MagicMock) -> None:
        invalid_bodies = [
            b'{"id": "10001"}',  # missing key
            b'{"id": "10001", "key": "lowercase-123"}',  # invalid key format
            b'{"id": "10001", "key": ""}',
            b'{"id": "10001", "key": 123}',
        ]
        for body in invalid_bodies:
            mock_conn = MagicMock()
            mock_conn_cls.return_value = mock_conn

            mock_resp = MagicMock()
            mock_resp.status = 201
            mock_resp.read.return_value = body
            mock_conn.getresponse.return_value = mock_resp

            with self.assertRaises(JiraResponseError) as ctx:
                self.client.create_ticket(self.sample_request)
            self.assertEqual(str(ctx.exception), "jira_ticket_key_invalid")

    @patch("http.client.HTTPSConnection")
    def test_transport_os_error_wrapped(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.request.side_effect = OSError("Connection refused")

        with self.assertRaises(JiraTransportError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertEqual(str(ctx.exception), "jira_transport_error")

    @patch("http.client.HTTPSConnection")
    def test_transport_timeout_error_wrapped(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.request.side_effect = TimeoutError("Timed out")

        with self.assertRaises(JiraTransportError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertEqual(str(ctx.exception), "jira_transport_error")

    @patch("http.client.HTTPSConnection")
    def test_transport_read_error_wrapped(self, mock_conn_cls: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.side_effect = OSError("Socket read error")
        mock_conn.getresponse.return_value = mock_resp

        with self.assertRaises(JiraTransportError) as ctx:
            self.client.create_ticket(self.sample_request)
        self.assertEqual(str(ctx.exception), "jira_transport_error")


class TestJiraSecurityBoundaries(unittest.TestCase):
    """Test architectural and security boundaries for Jira provider."""

    def test_no_forbidden_dependencies(self) -> None:
        forbidden = ("requests", "httpx", "urllib3", "aiohttp", "dotenv")
        for module_name in forbidden:
            self.assertNotIn(
                module_name,
                sys.modules.get("investigator.providers.jira_provider", {}).__dict__ if "investigator.providers.jira_provider" in sys.modules else (),
            )

    def test_exception_hierarchy(self) -> None:
        self.assertTrue(issubclass(JiraError, TicketingError))
        self.assertTrue(issubclass(JiraConfigError, JiraError))
        self.assertTrue(issubclass(JiraCredentialError, JiraError))
        self.assertTrue(issubclass(JiraTransportError, TicketClientError))
        self.assertTrue(issubclass(JiraResponseError, TicketClientError))


if __name__ == "__main__":
    unittest.main()
