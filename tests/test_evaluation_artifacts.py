"""Tests for evaluation artifact persistence and CLI workflow.

TDD RED PHASE ONLY - Milestone 10G.
Exercises deterministic JSON/Markdown persistence to repository artifact paths,
safe write semantics, sanitization, and failure handling.
"""

import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

from evaluation.harness import EvaluationHarnessError
from evaluation.runner import EvaluationObservation, EvaluationRunnerError
from scripts.run_security_evaluation import (
    EvaluationArtifactError,
    main,
    write_security_evaluation_artifacts,
)


class TestWriteSecurityEvaluationArtifacts(unittest.TestCase):
    """Tests for write_security_evaluation_artifacts() contract and deterministic writing."""

    def test_writes_both_artifacts_to_specified_directory(self) -> None:
        """Writer executes harness and saves JSON + Markdown to output directory."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            output_dir = Path(temp_dir_str)
            json_path, md_path = write_security_evaluation_artifacts(output_dir=output_dir)

            # 1. Path invariants
            self.assertEqual(json_path, output_dir / "security-evaluation.json")
            self.assertEqual(md_path, output_dir / "security-evaluation.md")
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())

            # 2. JSON artifact content validation
            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(data.get("report_type"), "ai_native_soc_agent_security_evaluation")
            self.assertEqual(data["metrics"]["total_scenarios"], 7)
            self.assertEqual(data["metrics"]["passed"], 7)
            self.assertEqual(data["metrics"]["failed"], 0)
            self.assertEqual(data["metrics"]["pass_rate"], 1.0)
            self.assertEqual(data["metrics"]["unsafe_tool_executions"], 0)
            self.assertEqual(data["metrics"]["approval_bypasses"], 0)
            self.assertEqual(data["metrics"]["arbitrary_query_executions"], 0)
            self.assertEqual(data["metrics"]["runtime_guard_bypasses"], 0)
            self.assertEqual(data["metrics"]["audit_leakage_findings"], 0)
            self.assertEqual(data["metrics"]["policy_override_findings"], 0)

            expected_scenario_ids = [
                "eval-10c-prompt-injection",
                "eval-10c-arbitrary-spl",
                "eval-10c-runtime-guard",
                "eval-11d-ti-private-ip",
                "eval-11d-ti-argument-smuggling",
                "eval-11d-ti-prompt-injection",
                "eval-11d-ti-provider-failure",
            ]
            actual_ids = [res["scenario_id"] for res in data["results"]]
            self.assertEqual(actual_ids, expected_scenario_ids)

            # 3. Markdown artifact content validation
            md_content = md_path.read_text(encoding="utf-8")
            self.assertIn("# AI SOC Agent Security Evaluation Report", md_content)
            self.assertIn("controlled lab environment", md_content.lower())
            self.assertIn("Total Scenarios: 7", md_content)
            self.assertIn("Passed: 7", md_content)
            self.assertIn("Failed: 0", md_content)
            self.assertIn("Pass Rate: 100.0%", md_content)
            for sc_id in expected_scenario_ids:
                self.assertIn(sc_id, md_content)
            self.assertNotIn("FAIL", md_content)

    def test_creates_directory_if_missing(self) -> None:
        """Writer creates non-existent parent/output directories safely."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            nested_output_dir = Path(temp_dir_str) / "nested" / "artifacts" / "eval"
            self.assertFalse(nested_output_dir.exists())

            json_path, md_path = write_security_evaluation_artifacts(output_dir=nested_output_dir)
            self.assertTrue(nested_output_dir.exists())
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())

    def test_overwrites_existing_artifacts_deterministically(self) -> None:
        """Writer completely overwrites existing artifact files rather than appending."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            output_dir = Path(temp_dir_str)
            json_file = output_dir / "security-evaluation.json"
            md_file = output_dir / "security-evaluation.md"

            # Pre-seed with stale content
            json_file.write_text('{"stale": true}', encoding="utf-8")
            md_file.write_text("# Stale Report", encoding="utf-8")

            write_security_evaluation_artifacts(output_dir=output_dir)

            data = json.loads(json_file.read_text(encoding="utf-8"))
            self.assertNotIn("stale", data)
            self.assertEqual(data.get("report_type"), "ai_native_soc_agent_security_evaluation")

            md_content = md_file.read_text(encoding="utf-8")
            self.assertNotIn("Stale Report", md_content)

    def test_deterministic_byte_for_byte_persistence(self) -> None:
        """Consecutive runs in distinct output locations produce byte-identical files."""
        with tempfile.TemporaryDirectory() as dir1_str, tempfile.TemporaryDirectory() as dir2_str:
            dir1 = Path(dir1_str)
            dir2 = Path(dir2_str)

            j1, m1 = write_security_evaluation_artifacts(output_dir=dir1)
            j2, m2 = write_security_evaluation_artifacts(output_dir=dir2)

            self.assertEqual(j1.read_bytes(), j2.read_bytes())
            self.assertEqual(m1.read_bytes(), m2.read_bytes())


class TestArtifactFailureHandling(unittest.TestCase):
    """Tests ensuring writer fails closed without leaving partial or misleading artifacts."""

    def test_failing_harness_fails_closed_and_leaves_no_artifacts(self) -> None:
        """If evaluation harness fails, writer must fail closed and leave no misleading artifacts."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            output_dir = Path(temp_dir_str)
            faulty_executors = {
                "eval-10c-prompt-injection": lambda scenario: (_ for _ in ()).throw(
                    RuntimeError("Simulated infrastructure crash")
                ),
            }

            with self.assertRaises((EvaluationArtifactError, EvaluationRunnerError, EvaluationHarnessError)):
                write_security_evaluation_artifacts(
                    output_dir=output_dir,
                    executors=faulty_executors,
                )

            # Ensure no PASS artifacts were emitted
            json_file = output_dir / "security-evaluation.json"
            md_file = output_dir / "security-evaluation.md"
            self.assertFalse(json_file.exists())
            self.assertFalse(md_file.exists())


class TestArtifactSanitizationAndBoundedContent(unittest.TestCase):
    """Tests ensuring persisted artifacts contain no secrets or raw telemetry."""

    def test_persisted_artifacts_contain_no_secrets_or_traces(self) -> None:
        """Persisted files must be strictly bounded to allowlisted report schemas."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            output_dir = Path(temp_dir_str)
            json_path, md_path = write_security_evaluation_artifacts(output_dir=output_dir)

            for path in (json_path, md_path):
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("sk-proj-", content)
                self.assertNotIn("OPENAI_API_KEY", content)
                self.assertNotIn("AZURE_OPENAI_API_KEY", content)
                self.assertNotIn("Traceback (most recent call last)", content)
                self.assertNotIn("PATH=", content)
                self.assertNotIn("rm -rf", content)


class TestEvaluationScriptCli(unittest.TestCase):
    """Tests for thin CLI execution wrapper."""

    def test_cli_main_success(self) -> None:
        """CLI main() exits with 0 and creates artifacts."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            exit_code = main(argv=["--output-dir", temp_dir_str])
            self.assertEqual(exit_code, 0)

            out_dir = Path(temp_dir_str)
            self.assertTrue((out_dir / "security-evaluation.json").exists())
            self.assertTrue((out_dir / "security-evaluation.md").exists())

    def test_cli_main_handles_failure(self) -> None:
        """CLI main() returns non-zero exit code if execution fails."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            with patch("scripts.run_security_evaluation.run_security_evaluation") as mock_run:
                mock_run.side_effect = EvaluationHarnessError("Simulated failure")
                exit_code = main(argv=["--output-dir", temp_dir_str])
                self.assertNotEqual(exit_code, 0)


class TestThreatIntelEvaluationArtifactExpectations(unittest.TestCase):
    """Milestone 11D: Future artifact expectations when 7 scenarios are integrated."""

    def test_artifacts_contain_seven_scenarios_and_threat_intel_metadata(self) -> None:
        """Future security-evaluation artifacts must contain all 7 scenarios and 100% pass rate."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            output_dir = Path(temp_dir_str)
            json_path, md_path = write_security_evaluation_artifacts(output_dir=output_dir)

            data = json.loads(json_path.read_text(encoding="utf-8"))
            if data["metrics"]["total_scenarios"] != 7:
                self.fail(
                    f"RED PHASE: expected 7 scenarios in evaluation artifact, got {data['metrics']['total_scenarios']}"
                )

            self.assertEqual(data["metrics"]["passed"], 7)
            self.assertEqual(data["metrics"]["failed"], 0)
            self.assertEqual(data["metrics"]["pass_rate"], 1.0)

            expected_scenario_ids = [
                "eval-10c-prompt-injection",
                "eval-10c-arbitrary-spl",
                "eval-10c-runtime-guard",
                "eval-11d-ti-private-ip",
                "eval-11d-ti-argument-smuggling",
                "eval-11d-ti-prompt-injection",
                "eval-11d-ti-provider-failure",
            ]
            actual_ids = [res["scenario_id"] for res in data["results"]]
            self.assertEqual(actual_ids, expected_scenario_ids)

            md_content = md_path.read_text(encoding="utf-8")
            self.assertIn("Total Scenarios: 7", md_content)
            self.assertIn("Passed: 7", md_content)
            for sc_id in expected_scenario_ids:
                self.assertIn(sc_id, md_content)


if __name__ == "__main__":
    unittest.main()
