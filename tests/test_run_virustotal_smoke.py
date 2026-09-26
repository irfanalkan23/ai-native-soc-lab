"""Offline unit, CLI, error mapping, and security boundary tests for VirusTotal smoke runner.

100% offline. Zero live network calls. Zero credential persistence.
"""

from __future__ import annotations

import ast
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock

from investigator.providers.virustotal_provider import (
    VirusTotalResponseError,
    VirusTotalTransportError,
)
from investigator.threat_intel import (
    ThreatIntelLookupStatus,
    ThreatIntelResult,
)
from scripts.run_virustotal_smoke import run_smoke


def _build_mock_result(
    indicator: str = "8.8.8.8",
    status: ThreatIntelLookupStatus = ThreatIntelLookupStatus.FOUND,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 85,
    undetected: int = 5,
    last_analysis_utc: str | None = "2026-03-25T12:00:00Z",
) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider="virustotal",
        indicator_type="ip",
        indicator_value=indicator,
        lookup_status=status,
        detail_code="ip_lookup_found" if status == ThreatIntelLookupStatus.FOUND else "ip_lookup_not_found",
        malicious_count=malicious,
        suspicious_count=suspicious,
        harmless_count=harmless,
        undetected_count=undetected,
        last_analysis_utc=last_analysis_utc,
    )


class TestVirusTotalSmokeRunner(unittest.TestCase):
    """Offline unit tests for scripts/run_virustotal_smoke.py."""

    def setUp(self) -> None:
        self.valid_env = {"VIRUSTOTAL_API_KEY": "test-valid-api-key-12345"}
        self.mock_client = MagicMock()
        self.client_factory = MagicMock(return_value=self.mock_client)

    # -----------------------------------------------------------------------
    # A. Environment Boundary Tests
    # -----------------------------------------------------------------------

    def test_missing_env_key_exits_2(self) -> None:
        """Missing VIRUSTOTAL_API_KEY fails immediately with exit code 2 and static message."""
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=[],
            env={},
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 2)
        self.assertIn("VT_SMOKE_CONFIG_ERROR", stderr.getvalue())
        self.client_factory.assert_not_called()
        self.mock_client.lookup.assert_not_called()

    def test_empty_or_whitespace_key_exits_2(self) -> None:
        """Empty or whitespace-only keys fail immediately with exit code 2."""
        for bad_val in ["", "   ", "\t", "\n"]:
            with self.subTest(bad_val=bad_val):
                stdout, stderr = io.StringIO(), io.StringIO()
                code = run_smoke(
                    argv=[],
                    env={"VIRUSTOTAL_API_KEY": bad_val},
                    client_factory=self.client_factory,
                    stdout=stdout,
                    stderr=stderr,
                )
                self.assertEqual(code, 2)
                self.assertIn("VT_SMOKE_CONFIG_ERROR", stderr.getvalue())
                self.client_factory.assert_not_called()

    def test_invalid_credential_syntax_exits_2(self) -> None:
        """Keys with internal spaces, control chars, or exceeding length bounds exit 2."""
        bad_keys = ["key with space", "key\r\n", "a" * 513]
        for bad_key in bad_keys:
            with self.subTest(bad_key=bad_key):
                stdout, stderr = io.StringIO(), io.StringIO()
                code = run_smoke(
                    argv=[],
                    env={"VIRUSTOTAL_API_KEY": bad_key},
                    client_factory=self.client_factory,
                    stdout=stdout,
                    stderr=stderr,
                )
                self.assertEqual(code, 2)
                self.assertIn("VT_SMOKE_CREDENTIAL_ERROR", stderr.getvalue())
                self.client_factory.assert_not_called()

    # -----------------------------------------------------------------------
    # B. CLI Validation Tests
    # -----------------------------------------------------------------------

    def test_default_cli_queries_8_8_8_8(self) -> None:
        """Zero CLI arguments queries default indicator 8.8.8.8."""
        self.mock_client.lookup.return_value = _build_mock_result("8.8.8.8")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=[],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 0)
        self.mock_client.lookup.assert_called_once()
        req = self.mock_client.lookup.call_args[0][0]
        self.assertEqual(req.indicator_value, "8.8.8.8")

    def test_valid_ipv4_override(self) -> None:
        """Valid public IPv4 override is accepted."""
        self.mock_client.lookup.return_value = _build_mock_result("1.1.1.1")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=["--ip", "1.1.1.1"],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 0)
        req = self.mock_client.lookup.call_args[0][0]
        self.assertEqual(req.indicator_value, "1.1.1.1")

    def test_valid_ipv6_override_canonicalized(self) -> None:
        """Valid public IPv6 override is canonicalized and accepted."""
        self.mock_client.lookup.return_value = _build_mock_result("2606:4700:4700::1111")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=["--ip", "2606:4700:4700::1111"],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 0)
        req = self.mock_client.lookup.call_args[0][0]
        self.assertEqual(req.indicator_value, "2606:4700:4700::1111")

    def test_invalid_or_non_public_ips_rejected(self) -> None:
        """Private, loopback, multicast, documentation, CIDR, URL, and scoped IPs exit 2."""
        invalid_indicators = [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "192.0.2.1",
            "8.8.8.8/32",
            "https://8.8.8.8",
            "8.8.8.8:443",
            "2606:4700:4700::1111%eth0",
            "example.com",
            "not-an-ip",
        ]
        for bad_ip in invalid_indicators:
            with self.subTest(bad_ip=bad_ip):
                stdout, stderr = io.StringIO(), io.StringIO()
                code = run_smoke(
                    argv=["--ip", bad_ip],
                    env=self.valid_env,
                    client_factory=self.client_factory,
                    stdout=stdout,
                    stderr=stderr,
                )
                self.assertEqual(code, 2)
                self.assertIn("VT_SMOKE_REQUEST_ERROR", stderr.getvalue())
                self.client_factory.assert_not_called()

    def test_argparse_missing_ip_argument_fails(self) -> None:
        """Invoking with --ip but omitting the argument exits 2 without calling client."""
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=["--ip"],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 2)
        self.client_factory.assert_not_called()
        self.mock_client.lookup.assert_not_called()
        self.assertNotIn("test-valid-api-key", stdout.getvalue())
        self.assertNotIn("test-valid-api-key", stderr.getvalue())

    # -----------------------------------------------------------------------
    # C. Successful FOUND Tests
    # -----------------------------------------------------------------------

    def test_successful_found_output(self) -> None:
        """Valid FOUND result prints normalized allowlisted fields and exits 0."""
        self.mock_client.lookup.return_value = _build_mock_result(
            indicator="8.8.8.8",
            status=ThreatIntelLookupStatus.FOUND,
            malicious=1,
            suspicious=0,
            harmless=80,
            undetected=10,
            last_analysis_utc="2026-03-25T12:00:00Z",
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=[],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")

        out = stdout.getvalue()
        self.assertIn("=== VirusTotal Live Smoke Test Result ===", out)
        self.assertIn("Provider:             virustotal", out)
        self.assertIn("Indicator Type:       ip", out)
        self.assertIn("Indicator Value:      8.8.8.8", out)
        self.assertIn("Lookup Status:        FOUND", out)
        self.assertIn("Detail Code:          ip_lookup_found", out)
        self.assertIn("Malicious Count:      1", out)
        self.assertIn("Suspicious Count:     0", out)
        self.assertIn("Harmless Count:       80", out)
        self.assertIn("Undetected Count:     10", out)
        self.assertIn("Last Analysis (UTC):  2026-03-25T12:00:00Z", out)

    # -----------------------------------------------------------------------
    # D. Successful NOT_FOUND Tests
    # -----------------------------------------------------------------------

    def test_successful_not_found_output(self) -> None:
        """Valid NOT_FOUND result prints normalized allowlisted fields and exits 0."""
        self.mock_client.lookup.return_value = _build_mock_result(
            indicator="8.8.8.8",
            status=ThreatIntelLookupStatus.NOT_FOUND,
            malicious=0,
            suspicious=0,
            harmless=0,
            undetected=0,
            last_analysis_utc=None,
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_smoke(
            argv=[],
            env=self.valid_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")

        out = stdout.getvalue()
        self.assertIn("Lookup Status:        NOT_FOUND", out)
        self.assertIn("Detail Code:          ip_lookup_not_found", out)
        self.assertIn("Malicious Count:      0", out)
        self.assertIn("Last Analysis (UTC):  None", out)

    # -----------------------------------------------------------------------
    # E. Static Error Mappings & Exit Codes
    # -----------------------------------------------------------------------

    def test_error_mappings_and_exit_codes(self) -> None:
        """Provider detail codes map to static operator-safe messages and exact exit codes."""
        error_cases = [
            # Exit 3: Auth, forbidden, rate-limited
            (VirusTotalResponseError("vt_auth_failed"), 3, "VT_SMOKE_AUTH_ERROR"),
            (VirusTotalResponseError("vt_forbidden"), 3, "VT_SMOKE_FORBIDDEN"),
            (VirusTotalResponseError("vt_rate_limited"), 3, "VT_SMOKE_RATE_LIMITED"),
            # Exit 4: Transport, redirect, remote 5xx
            (VirusTotalTransportError("vt_redirect_rejected"), 4, "VT_SMOKE_TRANSPORT_ERROR"),
            (VirusTotalTransportError("vt_transport_error"), 4, "VT_SMOKE_TRANSPORT_ERROR"),
            (VirusTotalResponseError("vt_remote_error"), 4, "VT_SMOKE_REMOTE_ERROR"),
            # Exit 5: Schema, bad request, unexpected status
            (VirusTotalResponseError("vt_bad_request"), 5, "VT_SMOKE_PROVIDER_ERROR"),
            (VirusTotalResponseError("vt_unexpected_status"), 5, "VT_SMOKE_PROVIDER_ERROR"),
            (VirusTotalResponseError("vt_response_too_large"), 5, "VT_SMOKE_SCHEMA_ERROR"),
            (VirusTotalResponseError("vt_invalid_json"), 5, "VT_SMOKE_SCHEMA_ERROR"),
            (VirusTotalResponseError("vt_schema_invalid"), 5, "VT_SMOKE_SCHEMA_ERROR"),
            (VirusTotalResponseError("vt_indicator_mismatch"), 5, "VT_SMOKE_SCHEMA_ERROR"),
            (VirusTotalResponseError("vt_other_unknown"), 5, "VT_SMOKE_PROVIDER_ERROR"),
        ]
        for exc, expected_code, expected_prefix in error_cases:
            with self.subTest(exc=str(exc), code=expected_code):
                self.mock_client.lookup.side_effect = exc
                stdout, stderr = io.StringIO(), io.StringIO()
                code = run_smoke(
                    argv=[],
                    env=self.valid_env,
                    client_factory=self.client_factory,
                    stdout=stdout,
                    stderr=stderr,
                )
                self.assertEqual(code, expected_code)
                self.assertIn(expected_prefix, stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")

    # -----------------------------------------------------------------------
    # F. Secret Sentinel Tests
    # -----------------------------------------------------------------------

    def test_secret_sentinel_never_leaks(self) -> None:
        """Sentinel API key never appears in stdout or stderr across success or error paths."""
        sentinel_key = "SUPER_SECRET_VT_SENTINEL_12345"
        sentinel_env = {"VIRUSTOTAL_API_KEY": sentinel_key}

        # Case 1: Success output
        self.mock_client.lookup.return_value = _build_mock_result("8.8.8.8")
        stdout, stderr = io.StringIO(), io.StringIO()
        run_smoke(
            argv=[],
            env=sentinel_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertNotIn(sentinel_key, stdout.getvalue())
        self.assertNotIn(sentinel_key, stderr.getvalue())

        # Case 2: Static VirusTotalTransportError
        self.mock_client.lookup.side_effect = VirusTotalTransportError("vt_transport_error")
        stdout, stderr = io.StringIO(), io.StringIO()
        code_transport = run_smoke(
            argv=[],
            env=sentinel_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code_transport, 4)
        self.assertNotIn(sentinel_key, stdout.getvalue())
        self.assertNotIn(sentinel_key, stderr.getvalue())

        # Case 3: Injected lower-level generic exception containing sentinel in message
        raw_msg = f"internal database socket failure containing {sentinel_key}"
        self.mock_client.lookup.side_effect = RuntimeError(raw_msg)
        stdout, stderr = io.StringIO(), io.StringIO()
        code_generic = run_smoke(
            argv=[],
            env=sentinel_env,
            client_factory=self.client_factory,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(code_generic, 5)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(sentinel_key, stderr.getvalue())
        self.assertNotIn(raw_msg, stderr.getvalue())
        self.assertNotIn("RuntimeError", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertEqual(
            stderr.getvalue(),
            "VT_SMOKE_UNEXPECTED_ERROR: An unexpected error occurred.\n",
        )

    # -----------------------------------------------------------------------
    # G. Exactly-One-Lookup Invariant Tests
    # -----------------------------------------------------------------------

    def test_exactly_one_lookup_and_no_retry(self) -> None:
        """Client lookup is called exactly once across success, 429, 500, and transport errors."""
        scenarios = [
            ("success", _build_mock_result("8.8.8.8"), None),
            ("auth_fail", None, VirusTotalResponseError("vt_auth_failed")),
            ("rate_limited", None, VirusTotalResponseError("vt_rate_limited")),
            ("transport_fail", None, VirusTotalTransportError("vt_transport_error")),
            ("remote_fail", None, VirusTotalResponseError("vt_remote_error")),
        ]
        for name, return_val, side_effect in scenarios:
            with self.subTest(scenario=name):
                mock_c = MagicMock()
                if side_effect:
                    mock_c.lookup.side_effect = side_effect
                else:
                    mock_c.lookup.return_value = return_val

                factory = MagicMock(return_value=mock_c)
                stdout, stderr = io.StringIO(), io.StringIO()
                run_smoke(
                    argv=[],
                    env=self.valid_env,
                    client_factory=factory,
                    stdout=stdout,
                    stderr=stderr,
                )
                factory.assert_called_once()
                mock_c.lookup.assert_called_once()


    def test_direct_cli_operator_execution(self) -> None:
        """Direct invocation via 'python scripts/run_virustotal_smoke.py' exits 2 when key is absent."""
        repo_root = Path(__file__).resolve().parent.parent
        script_path = repo_root / "scripts" / "run_virustotal_smoke.py"

        # Explicitly remove VIRUSTOTAL_API_KEY from environment copy
        clean_env = os.environ.copy()
        clean_env.pop("VIRUSTOTAL_API_KEY", None)

        proc = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            env=clean_env,
        )

        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertIn("VT_SMOKE_CONFIG_ERROR", proc.stderr)
        self.assertNotIn("ModuleNotFoundError", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)


class TestVirusTotalSmokeSecurityBoundaries(unittest.TestCase):
    """Verify security isolation, AST module boundaries, and filesystem independence."""

    def setUp(self) -> None:
        self.script_path = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "run_virustotal_smoke.py"
        )
        self.assertTrue(self.script_path.exists(), f"Script {self.script_path} not found")
        self.source = self.script_path.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_no_forbidden_network_or_system_modules(self) -> None:
        """Smoke script must import zero requests, httpx, urllib, or subprocess libraries."""
        forbidden_modules = {
            "urllib",
            "urllib.request",
            "urllib.parse",
            "requests",
            "httpx",
            "subprocess",
            "dotenv",
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
                f"Forbidden module '{forbidden}' imported in run_virustotal_smoke.py",
            )

    def test_no_forbidden_function_calls(self) -> None:
        """Smoke script must not call eval, exec, or os.system."""
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

    def test_no_forbidden_project_imports(self) -> None:
        """Smoke script must not import from orchestrator, policy, approval, simulator, router, or jira."""
        forbidden_project_modules = {
            "investigator.orchestrator",
            "investigator.policy",
            "investigator.approval",
            "investigator.simulator",
            "investigator.tool_router",
            "investigator.ticketing",
            "investigator.providers.jira_provider",
            "investigator.incident_record",
        }
        imported_modules: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module)

        for forbidden in forbidden_project_modules:
            self.assertNotIn(
                forbidden,
                imported_modules,
                f"Forbidden internal module '{forbidden}' imported in run_virustotal_smoke.py",
            )

    def test_filesystem_isolation_and_pathlib_usage(self) -> None:
        """pathlib may be used only for deterministic repository-root path resolution; zero file I/O."""
        forbidden_fs_calls: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    forbidden_fs_calls.append("open")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "read_text",
                    "read_bytes",
                    "write_text",
                    "write_bytes",
                    "iterdir",
                    "glob",
                    "rglob",
                }:
                    forbidden_fs_calls.append(node.func.attr)

        self.assertEqual(
            forbidden_fs_calls,
            [],
            f"Forbidden filesystem I/O calls detected: {forbidden_fs_calls}",
        )


if __name__ == "__main__":
    unittest.main()
