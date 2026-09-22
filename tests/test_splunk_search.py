"""Unit tests for bounded Splunk search client."""

import io
import json
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from gateway.policy import ALLOWED_FIELDS, PolicyValidationError
from gateway.splunk_search import (
    MAX_RESPONSE_BYTES,
    SPLUNK_EXPORT_ENDPOINT,
    SplunkConnectionError,
    SplunkResponseError,
    SplunkSearchClient,
)


class TestSplunkSearchClient(unittest.TestCase):
    """Test transport mocking, response parsing, and error handling for Splunk search."""

    def setUp(self) -> None:
        self.client = SplunkSearchClient(verify_tls=False, timeout=10.0)

    def _create_mock_response(self, content_str: str) -> MagicMock:
        """Create a mock HTTP response object returning content_str."""
        mock_resp = MagicMock()
        mock_resp.read.side_effect = lambda size=-1: content_str.encode("utf-8")[:size] if size != -1 else content_str.encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp

    def test_proof_caller_cannot_change_rest_endpoint(self) -> None:
        """Proof: REST endpoint is immutable and no path/URL parameters are accepted."""
        self.assertEqual(self.client.endpoint, SPLUNK_EXPORT_ENDPOINT)
        self.assertEqual(
            self.client.endpoint,
            "https://localhost:8089/services/search/jobs/export",
        )

        with self.assertRaises(TypeError):
            self.client.search_encoded_powershell(
                host="DC01",
                minutes=15,
                limit=10,
                url="https://localhost:8089/services/authentication/users",  # type: ignore[call-arg]
            )

        with self.assertRaises(TypeError):
            self.client.search_encoded_powershell(
                host="DC01",
                minutes=15,
                limit=10,
                path="/services/apps/local",  # type: ignore[call-arg]
            )

    def test_proof_no_generic_run_spl_interface(self) -> None:
        """Proof: Client does not expose a generic run_spl or execute_spl method."""
        self.assertFalse(hasattr(self.client, "run_spl"))
        self.assertFalse(hasattr(self.client, "execute_spl"))
        self.assertFalse(hasattr(self.client, "raw_search"))

    def test_valid_request_success(self) -> None:
        """Verify successful search execution and parsing of JSON stream."""
        mock_export_stream = (
            '{"preview":false,"offset":0,"lastrow":true,"result":{'
            '"_time":"2026-09-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
            '"CommandLine":"powershell.exe -NoProfile -EncodedCommand VwBy...",'
            '"ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"ParentCommandLine":"\\"C:\\\\Windows\\\\system32\\\\cmd.exe\\"",'
            '"unrelated_internal_field":"leak_test"'
            '}}\n'
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(mock_export_stream)

            results = self.client.search_encoded_powershell(
                host="DC01",
                minutes=15,
                limit=10,
            )

            mock_urlopen.assert_called_once()
            called_req = mock_urlopen.call_args[0][0]
            self.assertEqual(called_req.full_url, SPLUNK_EXPORT_ENDPOINT)
            self.assertEqual(called_req.get_method(), "POST")

            self.assertEqual(len(results), 1)
            event = results[0]
            self.assertEqual(event["host"], "DC01")
            self.assertEqual(event["User"], "SOCLAB\\Administrator")
            self.assertIn("-EncodedCommand", event["CommandLine"])

            self.assertNotIn("unrelated_internal_field", event)
            self.assertEqual(set(event.keys()), set(ALLOWED_FIELDS))

    def test_json_warn_envelope_fails_closed(self) -> None:
        """Proof: Splunk WARN message envelope raises SplunkResponseError."""
        warn_stream = '{"messages":[{"type":"WARN","text":"Search auto-finalized early"}]}\n'
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(warn_stream)
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)
            self.assertIn("WARN", str(ctx.exception))

    def test_json_error_envelope_fails_closed(self) -> None:
        """Proof: Splunk ERROR message envelope raises SplunkResponseError."""
        error_stream = '{"messages":[{"type":"ERROR","text":"Index main not accessible"}]}\n'
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(error_stream)
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)
            self.assertIn("ERROR", str(ctx.exception))

    def test_malformed_partial_result_record_fails_closed(self) -> None:
        """Proof: Missing or empty mandatory fields cause event rejection."""
        # Case 1: Missing CommandLine
        partial_stream_1 = (
            '{"result":{'
            '"_time":"2026-09-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
            '"ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"ParentCommandLine":"cmd.exe"'
            '}}\n'
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(partial_stream_1)
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)
            self.assertIn("missing required detection fields", str(ctx.exception).lower())

        # Case 2: Empty Image value
        partial_stream_2 = (
            '{"result":{'
            '"_time":"2026-09-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"   ",'
            '"CommandLine":"powershell.exe -enc test",'
            '"ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"ParentCommandLine":"cmd.exe"'
            '}}\n'
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(partial_stream_2)
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)
            self.assertIn("missing required detection fields", str(ctx.exception).lower())

    def test_too_many_returned_results_fails_closed(self) -> None:
        """Proof: Returning more records than the validated limit raises SplunkResponseError."""
        single_event = (
            '{"result":{'
            '"_time":"2026-09-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"C:\\\\powershell.exe",'
            '"CommandLine":"powershell.exe -enc test",'
            '"ParentImage":"cmd.exe",'
            '"ParentCommandLine":"cmd.exe"'
            '}}\n'
        )
        # 3 events returned when limit is set to 2
        excess_stream = single_event * 3
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(excess_stream)
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=2)
            self.assertIn("exceeding requested limit", str(ctx.exception).lower())

    def test_oversized_response_body_fails_closed(self) -> None:
        """Proof: Responses exceeding MAX_RESPONSE_BYTES raise SplunkResponseError."""
        mock_resp = MagicMock()
        # Return bytes greater than MAX_RESPONSE_BYTES
        mock_resp.read.return_value = b"A" * (MAX_RESPONSE_BYTES + 10)
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)
            self.assertIn("exceeded maximum allowed limit", str(ctx.exception).lower())

    def test_http_error_does_not_expose_raw_response_body_content(self) -> None:
        """Proof: HTTP errors do not leak sensitive raw response text in exceptions."""
        sensitive_payload = b'{"secret_internal_token": "super_secret_12345", "leak": "database_error"}'
        mock_http_err = urllib.error.HTTPError(
            url=SPLUNK_EXPORT_ENDPOINT,
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=io.BytesIO(sensitive_payload),
        )
        with patch("urllib.request.urlopen", side_effect=mock_http_err):
            with self.assertRaises(SplunkResponseError) as ctx:
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)

            err_msg = str(ctx.exception)
            self.assertIn("HTTP 500: Internal Server Error", err_msg)
            # Ensure sensitive payload tokens are completely sanitized out
            self.assertNotIn("super_secret_12345", err_msg)
            self.assertNotIn("secret_internal_token", err_msg)
            self.assertNotIn("database_error", err_msg)

    def test_empty_response(self) -> None:
        """Verify handling when search returns zero matching events."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response("")
            results = self.client.search_encoded_powershell(host="DC01", minutes=5, limit=5)
            self.assertEqual(results, [])

    def test_malformed_non_json_response(self) -> None:
        """Proof: Fails closed on HTML or malformed non-JSON data from Splunk."""
        bad_responses = [
            "<html><body>502 Bad Gateway</body></html>",
            "<response status='unknown'>error</response>",
            '{"preview":false, broken json line',
            "Plain text crash traceback",
        ]
        for bad_data in bad_responses:
            with self.subTest(bad_data=bad_data):
                with patch("urllib.request.urlopen") as mock_urlopen:
                    mock_urlopen.return_value = self._create_mock_response(bad_data)
                    with self.assertRaises(SplunkResponseError):
                        self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)

    def test_connection_timeout(self) -> None:
        """Verify that connection timeout raises SplunkConnectionError."""
        with patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
            with self.assertRaises(SplunkConnectionError):
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)

    def test_connection_network_refused(self) -> None:
        """Verify that connection refusal raises SplunkConnectionError."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused [WinError 10061]"),
        ):
            with self.assertRaises(SplunkConnectionError):
                self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)

    def test_invalid_client_timeout_value(self) -> None:
        """Verify that non-positive timeout values fail validation."""
        with self.assertRaises(ValueError):
            SplunkSearchClient(timeout=0)
        with self.assertRaises(ValueError):
            SplunkSearchClient(timeout=-5.0)

    def test_spl_query_dispatch_payload_verification(self) -> None:
        """Verify that the outgoing HTTP request body dispatches the updated allowlisted SPL."""
        import urllib.parse
        mock_export_stream = (
            '{"preview":false,"offset":0,"lastrow":true,"result":{'
            '"_time":"2026-09-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
            '"CommandLine":"powershell.exe -NoProfile -EncodedCommand VwBy...",'
            '"ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"ParentCommandLine":"\\"C:\\\\Windows\\\\system32\\\\cmd.exe\\""'
            '}}\n'
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(mock_export_stream)
            self.client.search_encoded_powershell(host="DC01", minutes=15, limit=10)

            mock_urlopen.assert_called_once()
            called_req = mock_urlopen.call_args[0][0]
            parsed_body = urllib.parse.parse_qs(called_req.data.decode("utf-8"))
            self.assertIn("search", parsed_body)
            spl_sent = parsed_body["search"][0]

            self.assertIn("<EventID>1</EventID>", spl_sent)
            self.assertIn('rex field=_raw "<Data Name=[\'\\"]Image[\'\\"]>(?<Image>[^<]+)</Data>"', spl_sent)
            self.assertIn('rex field=_raw "<Data Name=[\'\\"]CommandLine[\'\\"]>(?<CommandLine>[^<]+)</Data>"', spl_sent)
            self.assertIn('where match(Image, "(?i)powershell[.]exe$")', spl_sent)
            self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])-(encodedcommand|enc)([[:space:]]|$)")', spl_sent)
            self.assertIn("| sort - _time", spl_sent)
            self.assertIn("| head 10", spl_sent)
            self.assertIn("| table _time host User Image CommandLine ParentImage ParentCommandLine", spl_sent)


if __name__ == "__main__":
    unittest.main()
