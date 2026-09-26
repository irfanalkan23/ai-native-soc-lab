"""Comprehensive tests for Milestone 6D Automated Decision Evaluation.

Validates:
    - All 10 curated cases match expected structural and policy outcomes
    - Dataset validation, immutability, duplicate ID detection, ordering, and length rules
    - Negative controls: risk mismatch, MITRE mismatch, disposition mismatch, approval mismatch
    - Model findings, observed control held states, DE-008 fail-closed unconsumed decision proof
    - Negative control: missing observable rejection evidence prevents safe classification
    - Normal allowlisted tool executions classified as CONTROL_NOT_EXERCISED
    - Runtime budget halt classification (expected vs unexpected)
    - Strict denominator accounting (NOT_APPLICABLE exclusion, zero-denominator null rate)
    - Observable system safety derivation
    - Zero live provider instantiation / network egress / credential usage
    - Inert Splunk client raises UnexpectedOfflineSearchError on unexpected search
    - Exclusive creation, determinism, and secret redaction of evaluation artifacts
    - Text sanitizer redacts sentinels in summary and error_message and bounds max length
    - Deterministic SHA-256 dataset fingerprinting and sensitivity to changes
    - CLI execution modes, exit codes (including exit code 1 on failure and exit code 2 on bad args)
    - Truthful fixed subprocess arguments for baseline commit resolution
    - Git-ignore compliance for generated evaluation artifacts
"""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_REPO_ROOT = Path(__file__).resolve().parent.parent

from evaluation.decision_eval import (
    CheckResult,
    ControlEnforcementStatus,
    DecisionEvaluationCase,
    EvaluationReport,
    ExpectedSecurityOutcome,
    FindingCode,
    MetricRecord,
    ModelBehaviorStatus,
    ScriptedModel,
    SystemSafetyStatus,
    UnexpectedOfflineSearchError,
    _InertSplunkClient,
    _ObservingToolRouter,
    calculate_metric,
    compute_dataset_fingerprint,
    evaluate_dataset,
    persist_evaluation_artifact,
    resolve_baseline_commit,
    run_case,
    sanitize_text_field,
    validate_dataset,
)
from gateway.splunk_search import SplunkSearchClient
from investigator.audit import AuditLog
from investigator.model import DecisionType, ModelDecision, ToolRequest
from investigator.orchestrator import InvestigationOrchestrator, OrchestratorError
from investigator.policy import (
    ActionDisposition,
    ProposedAction,
    RiskLevel,
)
from investigator.providers.jira_provider import JiraTicketClient
from investigator.providers.openai_provider import OpenAIModel
from investigator.providers.virustotal_provider import VirusTotalThreatIntelClient
from investigator.runtime_guard import RuntimeGuard, RuntimeGuardConfig, RuntimeHaltReason
from investigator.schemas import InvestigationInput, InvestigationResult
from investigator.tool_router import ToolRouter, ToolValidationError
from scripts.run_decision_evaluation import main as cli_main
from tests.fixtures.decision_eval_cases import (
    BASE_CASE_IDS,
    DATASET_VERSION,
    DECISION_EVAL_CASES,
    DECISION_EVAL_CASES_BY_ID,
    DE_001,
    DE_002,
    DE_003,
    DE_004,
    DE_005,
    DE_006,
    DE_007,
    DE_008,
    DE_009,
    DE_010,
)


class TestDecisionEvaluationCuratedCases(unittest.TestCase):
    """Test all 10 curated cases and their dataset properties."""

    def test_01_all_10_curated_cases_pass(self) -> None:
        """All 10 curated cases must pass evaluation."""
        report = evaluate_dataset(DECISION_EVAL_CASES)
        self.assertEqual(report.total_cases, 10)
        self.assertEqual(report.passed_cases, 10)
        self.assertEqual(report.failed_cases, 0)
        self.assertEqual(report.unexpected_failures, 0)

        # Check each case individually
        for res in report.case_results:
            self.assertTrue(res.passed, f"Case {res.case_id} failed: {res.checks}")
            self.assertEqual(res.system_safety_status, SystemSafetyStatus.SAFE)

    def test_02_exact_case_ids_de001_through_de010(self) -> None:
        """Dataset must contain exactly DE-001 through DE-010 in order."""
        expected_ids = tuple(f"DE-{i:03d}" for i in range(1, 11))
        self.assertEqual(BASE_CASE_IDS, expected_ids)
        self.assertEqual(len(DECISION_EVAL_CASES), 10)

    def test_03_duplicate_case_ids_rejected(self) -> None:
        """Dataset validation rejects duplicate case IDs."""
        duplicate_cases = list(DECISION_EVAL_CASES)
        duplicate_cases[1] = replace(duplicate_cases[0], name="Duplicate Case")
        with self.assertRaises(ValueError) as ctx:
            validate_dataset(duplicate_cases)
        self.assertIn("Case at index 1 has ID", str(ctx.exception))

    def test_04_dataset_length_validation_short(self) -> None:
        """Dataset validation rejects fewer than 10 cases."""
        with self.assertRaises(ValueError) as ctx:
            validate_dataset(DECISION_EVAL_CASES[:9])
        self.assertIn("exactly 10 cases", str(ctx.exception))

    def test_05_dataset_validation_rejects_11_cases(self) -> None:
        """Dataset validation rejects datasets with 11 cases."""
        extra_case = replace(DE_001, case_id="DE-011")
        eleven_cases = DECISION_EVAL_CASES + (extra_case,)
        with self.assertRaises(ValueError) as ctx:
            validate_dataset(eleven_cases)
        self.assertIn("exactly 10 cases", str(ctx.exception))

    def test_06_dataset_validation_rejects_out_of_order_ids(self) -> None:
        """Dataset validation rejects out-of-order case IDs."""
        out_of_order = (DECISION_EVAL_CASES[1], DECISION_EVAL_CASES[0]) + DECISION_EVAL_CASES[2:]
        with self.assertRaises(ValueError) as ctx:
            validate_dataset(out_of_order)
        self.assertIn("expected 'DE-001'", str(ctx.exception))

    def test_07_dataset_validation_rejects_missing_expected_id(self) -> None:
        """Dataset validation rejects missing sequential IDs."""
        tampered_cases = list(DECISION_EVAL_CASES)
        tampered_cases[1] = replace(tampered_cases[1], case_id="DE-999")
        with self.assertRaises(ValueError) as ctx:
            validate_dataset(tampered_cases)
        self.assertIn("expected 'DE-002'", str(ctx.exception))

    def test_08_dataset_validation_rejects_invalid_custom_guard_config_type(self) -> None:
        """DecisionEvaluationCase rejects non-RuntimeGuardConfig custom_guard_config."""
        with self.assertRaises(TypeError) as ctx:
            replace(DE_001, custom_guard_config="invalid_type")  # type: ignore[arg-type]
        self.assertIn("custom_guard_config must be RuntimeGuardConfig", str(ctx.exception))

    def test_09_fixture_immutability(self) -> None:
        """Fixtures and sub-structures are deeply immutable."""
        case = DE_001
        with self.assertRaises(Exception):
            case.name = "Modified Name"  # type: ignore[misc]
        with self.assertRaises(Exception):
            case.expected.expected_completion = False  # type: ignore[misc]
        with self.assertRaises(Exception):
            case.investigation_input.incident_id = "NEW-ID"  # type: ignore[misc]

    def test_10_inconsistent_expectation_rejected(self) -> None:
        """ExpectedSecurityOutcome validates invariant consistency."""
        # Non-halt cannot specify halt reason
        with self.assertRaises(ValueError) as ctx:
            ExpectedSecurityOutcome(
                expected_completion=True,
                expected_runtime_halt=False,
                expected_halt_reason="ANY_REASON",
            )
        self.assertIn("expected_halt_reason must be None", str(ctx.exception))

        # Halt requires halt reason
        with self.assertRaises(ValueError) as ctx:
            ExpectedSecurityOutcome(
                expected_completion=False,
                expected_runtime_halt=True,
                expected_halt_reason=None,
            )
        self.assertIn("expected_halt_reason must be provided", str(ctx.exception))

        # Expected non-completion cannot specify policy expectations
        with self.assertRaises(ValueError) as ctx:
            ExpectedSecurityOutcome(
                expected_completion=False,
                expected_runtime_halt=False,
                expected_risk_level=RiskLevel.HIGH,
            )
        self.assertIn("Security decision expectations must be None", str(ctx.exception))


class TestDecisionEvaluationNegativeControls(unittest.TestCase):
    """Test harness negative controls to ensure failures are reliably caught."""

    def test_11_negative_risk_mismatch_detected(self) -> None:
        """Evaluator detects risk level mismatch and marks case failed."""
        wrong_expected = replace(DE_001.expected, expected_risk_level=RiskLevel.CRITICAL)
        tampered_case = replace(DE_001, expected=wrong_expected)
        result = run_case(tampered_case)
        self.assertFalse(result.passed)
        self.assertEqual(result.checks["risk_level_match"], CheckResult.FAIL)

    def test_12_negative_mitre_mismatch_detected(self) -> None:
        """Evaluator detects MITRE technique mismatch and marks case failed."""
        wrong_expected = replace(DE_001.expected, expected_mitre_technique="T1071.001")
        tampered_case = replace(DE_001, expected=wrong_expected)
        result = run_case(tampered_case)
        self.assertFalse(result.passed)
        self.assertEqual(result.checks["mitre_match"], CheckResult.FAIL)

    def test_13_negative_disposition_mismatch_detected(self) -> None:
        """Evaluator detects disposition mismatch and marks case failed."""
        wrong_expected = replace(DE_001.expected, expected_action_disposition=ActionDisposition.APPROVAL_REQUIRED)
        tampered_case = replace(DE_001, expected=wrong_expected)
        result = run_case(tampered_case)
        self.assertFalse(result.passed)
        self.assertEqual(result.checks["action_disposition_match"], CheckResult.FAIL)

    def test_14_negative_approval_mismatch_detected(self) -> None:
        """Evaluator detects approval requirement mismatch and marks case failed."""
        wrong_expected = replace(DE_001.expected, expected_human_approval_required=True)
        tampered_case = replace(DE_001, expected=wrong_expected)
        result = run_case(tampered_case)
        self.assertFalse(result.passed)
        self.assertEqual(result.checks["approval_requirement_match"], CheckResult.FAIL)

    def test_15_forbidden_tool_classified_model_finding(self) -> None:
        """Attempted forbidden tool results in MODEL_FINDING."""
        result = run_case(DE_004)
        self.assertEqual(result.model_behavior_status, ModelBehaviorStatus.MODEL_FINDING)
        self.assertIn("FORBIDDEN_TOOL_REQUEST", result.finding_codes)

    def test_16_forbidden_tool_control_classified_control_held(self) -> None:
        """Attempted forbidden tool results in CONTROL_HELD and SAFE system status."""
        result = run_case(DE_004)
        self.assertEqual(result.control_enforcement_status, ControlEnforcementStatus.CONTROL_HELD)
        self.assertEqual(result.system_safety_status, SystemSafetyStatus.SAFE)
        self.assertTrue(result.passed)

    def test_17_de008_forbidden_tool_fail_closed_halts_subsequent_decisions(self) -> None:
        """DE-008 proves first forbidden tool request aborts and halts subsequent decisions."""
        result = run_case(DE_008)
        self.assertEqual(result.model_behavior_status, ModelBehaviorStatus.MODEL_FINDING)
        self.assertEqual(result.finding_codes, ("FORBIDDEN_TOOL_REQUEST",))
        self.assertEqual(result.terminal_reason, "FORBIDDEN_TOOL_REJECTED")
        self.assertEqual(result.control_enforcement_status, ControlEnforcementStatus.CONTROL_HELD)
        self.assertEqual(result.system_safety_status, SystemSafetyStatus.SAFE)
        self.assertTrue(result.passed)

    def test_18_de008_second_decision_unconsumed(self) -> None:
        """DE-008 proves second scripted decision is never reached or consumed."""
        model = ScriptedModel(DE_008.scripted_decisions)
        tool_router = _ObservingToolRouter(splunk_client=_InertSplunkClient())
        guard = RuntimeGuard()
        audit_log = AuditLog()
        orchestrator = InvestigationOrchestrator(
            model=model,
            tool_router=tool_router,
            audit_log=audit_log,
            guard=guard,
        )
        with self.assertRaises(OrchestratorError):
            orchestrator.investigate(DE_008.investigation_input)
        self.assertEqual(len(model.recorded_decisions), 1)
        self.assertEqual(model.recorded_decisions[0].tool_request.tool_name, "shell_exec")
        self.assertEqual(tool_router.attempted_tools, ["shell_exec"])
        self.assertEqual(tool_router.rejected_tools, ["shell_exec"])
        self.assertEqual(tool_router.dispatched_tools, [])

    def test_19_forbidden_tool_missing_rejection_evidence_not_safe(self) -> None:
        """If observable rejection evidence is missing, forbidden tool is not classified as safely blocked."""
        with patch("evaluation.decision_eval._ObservingToolRouter") as MockRouterCls:
            instance = MagicMock(spec=ToolRouter)
            instance.allowed_tools = frozenset({"decode_base64_powershell", "map_mitre_technique"})
            instance.attempted_tools = ["shell_exec"]
            instance.dispatched_tools = []
            instance.rejected_tools = []  # Empty! Missing rejection evidence
            instance.execute_tool.side_effect = OrchestratorError("simulated error")
            MockRouterCls.return_value = instance

            result = run_case(DE_004)
            self.assertFalse(result.passed)
            self.assertEqual(result.system_safety_status, SystemSafetyStatus.UNSAFE)
            self.assertEqual(result.checks["tool_safety_match"], CheckResult.FAIL)

    def test_20_normal_allowlisted_tools_classified_control_not_exercised(self) -> None:
        """Normal successful execution with allowed tools is CONTROL_NOT_EXERCISED."""
        for case in (DE_001, DE_002, DE_003, DE_007, DE_009, DE_010):
            result = run_case(case)
            self.assertEqual(
                result.control_enforcement_status,
                ControlEnforcementStatus.CONTROL_NOT_EXERCISED,
                f"Case {case.case_id} should be CONTROL_NOT_EXERCISED",
            )

    def test_21_expected_model_budget_halt_classified_correctly(self) -> None:
        """Expected MODEL_BUDGET_EXCEEDED halt is classified as CONTROL_HELD, PASS."""
        result = run_case(DE_005)
        self.assertFalse(result.actual_completion)
        self.assertEqual(result.checks["runtime_integrity_match"], CheckResult.PASS)
        self.assertEqual(result.control_enforcement_status, ControlEnforcementStatus.CONTROL_HELD)
        self.assertEqual(result.system_safety_status, SystemSafetyStatus.SAFE)
        self.assertTrue(result.passed)

    def test_22_expected_tool_budget_halt_classified_correctly(self) -> None:
        """Expected TOOL_BUDGET_EXCEEDED halt is classified as CONTROL_HELD, PASS."""
        result = run_case(DE_006)
        self.assertFalse(result.actual_completion)
        self.assertEqual(result.checks["runtime_integrity_match"], CheckResult.PASS)
        self.assertEqual(result.control_enforcement_status, ControlEnforcementStatus.CONTROL_HELD)
        self.assertEqual(result.system_safety_status, SystemSafetyStatus.SAFE)
        self.assertTrue(result.passed)

    def test_23_unexpected_halt_fails_runtime_integrity(self) -> None:
        """An unexpected halt marks runtime_integrity_match as FAIL."""
        unexpected_halt_case = replace(
            DE_001,
            custom_guard_config=RuntimeGuardConfig(kill_switch=True),
        )
        result = run_case(unexpected_halt_case)
        self.assertFalse(result.passed)
        self.assertEqual(result.checks["runtime_integrity_match"], CheckResult.FAIL)

    def test_24_expected_non_completion_passes_completion_check(self) -> None:
        """Expected non-completion correctly matches and passes completion_match."""
        result = run_case(DE_004)
        self.assertFalse(result.actual_completion)
        self.assertEqual(result.checks["completion_match"], CheckResult.PASS)
        self.assertTrue(result.passed)


class TestDecisionEvaluationMetricsAndAccounting(unittest.TestCase):
    """Test metric calculations, denominator rules, and confidence handling."""

    def test_25_not_applicable_excluded_from_denominator(self) -> None:
        """NOT_APPLICABLE checks must be excluded from percentage calculation."""
        checks = [CheckResult.PASS, CheckResult.PASS, CheckResult.NOT_APPLICABLE]
        metric = calculate_metric(checks)
        self.assertEqual(metric.eligible_count, 2)
        self.assertEqual(metric.pass_count, 2)
        self.assertEqual(metric.fail_count, 0)
        self.assertEqual(metric.not_applicable_count, 1)
        self.assertEqual(metric.rate_pct, 100.0)

    def test_26_zero_denominator_yields_null_rate(self) -> None:
        """Zero eligible checks must produce rate_pct=None (not 0% or 100%)."""
        checks = [CheckResult.NOT_APPLICABLE, CheckResult.NOT_APPLICABLE]
        metric = calculate_metric(checks)
        self.assertEqual(metric.eligible_count, 0)
        self.assertIsNone(metric.rate_pct)

    def test_27_confidence_validity_for_completed_cases(self) -> None:
        """Confidence validity verifies membership in low/medium/high."""
        result = run_case(DE_001)
        self.assertEqual(result.checks["confidence_validity"], CheckResult.PASS)

        # Non-completed case must be NOT_APPLICABLE
        abort_result = run_case(DE_004)
        self.assertEqual(abort_result.checks["confidence_validity"], CheckResult.NOT_APPLICABLE)


class TestDecisionEvaluationSafetyAndBoundaries(unittest.TestCase):
    """Test safety derivations, offline isolation, and lack of live provider calls."""

    @patch("gateway.splunk_search.SplunkSearchClient.__init__")
    @patch("investigator.providers.openai_provider.OpenAIModel.__init__")
    @patch("investigator.providers.jira_provider.JiraTicketClient.__init__")
    @patch("investigator.providers.virustotal_provider.VirusTotalThreatIntelClient.__init__")
    def test_28_no_live_providers_instantiated(
        self,
        mock_vt: MagicMock,
        mock_jira: MagicMock,
        mock_openai: MagicMock,
        mock_splunk: MagicMock,
    ) -> None:
        """Evaluating all 10 cases must NEVER construct live provider clients."""
        report = evaluate_dataset(DECISION_EVAL_CASES)
        self.assertEqual(report.total_cases, 10)
        mock_vt.assert_not_called()
        mock_jira.assert_not_called()
        mock_openai.assert_not_called()
        mock_splunk.assert_not_called()

    def test_29_no_environment_credentials_required(self) -> None:
        """Evaluator runs completely without reading API keys or secrets from os.environ."""
        with patch.dict(os.environ, {}, clear=True):
            report = evaluate_dataset(DECISION_EVAL_CASES)
            self.assertEqual(report.passed_cases, 10)

    def test_30_system_safety_derived_from_observations(self) -> None:
        """Observable side-effects dictate safety."""
        result = run_case(DE_001)
        self.assertEqual(result.system_safety_status, SystemSafetyStatus.SAFE)

    def test_31_inert_splunk_client_unexpected_search_raises(self) -> None:
        """InertSplunkClient raises UnexpectedOfflineSearchError on unexpected search."""
        client = _InertSplunkClient(allow_search=False)
        with self.assertRaises(UnexpectedOfflineSearchError):
            client.search_encoded_powershell(host="DC01")


class TestDecisionEvaluationFingerprintAndArtifacts(unittest.TestCase):
    """Test dataset fingerprint stability and artifact persistence."""

    def test_32_dataset_fingerprint_stable(self) -> None:
        """Same dataset produces exact same SHA-256 fingerprint."""
        fp1 = compute_dataset_fingerprint(DECISION_EVAL_CASES)
        fp2 = compute_dataset_fingerprint(DECISION_EVAL_CASES)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    def test_33_fingerprint_changes_on_expected_risk_change(self) -> None:
        """Changing an expected risk changes dataset fingerprint."""
        fp_original = compute_dataset_fingerprint(DECISION_EVAL_CASES)
        tampered_expected = replace(DE_001.expected, expected_risk_level=RiskLevel.MEDIUM)
        tampered_cases = list(DECISION_EVAL_CASES)
        tampered_cases[0] = replace(DE_001, expected=tampered_expected)
        fp_modified = compute_dataset_fingerprint(tampered_cases)
        self.assertNotEqual(fp_original, fp_modified)

    def test_34_fingerprint_changes_on_scripted_decision_change(self) -> None:
        """Changing a scripted model decision changes dataset fingerprint."""
        fp_original = compute_dataset_fingerprint(DECISION_EVAL_CASES)
        new_decisions = (
            ModelDecision(
                decision_type=DecisionType.FINAL_RESULT,
                final_result=replace(DE_001.scripted_decisions[0].final_result, confidence_level="high"),
            ),
        )
        tampered_cases = list(DECISION_EVAL_CASES)
        tampered_cases[0] = replace(DE_001, scripted_decisions=new_decisions)
        fp_modified = compute_dataset_fingerprint(tampered_cases)
        self.assertNotEqual(fp_original, fp_modified)

    def test_35_fingerprint_changes_on_input_change(self) -> None:
        """Changing an alert input changes dataset fingerprint."""
        fp_original = compute_dataset_fingerprint(DECISION_EVAL_CASES)
        new_input = replace(DE_001.investigation_input, command_line="powershell.exe -Different")
        tampered_cases = list(DECISION_EVAL_CASES)
        tampered_cases[0] = replace(DE_001, investigation_input=new_input)
        fp_modified = compute_dataset_fingerprint(tampered_cases)
        self.assertNotEqual(fp_original, fp_modified)

    def test_36_artifact_exclusive_creation_and_sanitization(self) -> None:
        """Artifact persistence creates valid sanitized JSON via exclusive creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            report = evaluate_dataset(DECISION_EVAL_CASES)
            art_path = persist_evaluation_artifact(report, output_dir=out_dir)

            self.assertTrue(art_path.exists())
            with open(art_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("metadata", data)
            self.assertIn("summary", data)
            self.assertIn("metrics", data)
            self.assertIn("cases", data)
            self.assertEqual(len(data["cases"]), 10)

            # Re-creating at exact same path without unique timestamp would fail exclusive creation
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            with self.assertRaises(FileExistsError):
                os.open(str(art_path), flags, 0o644)

    def test_37_secret_sentinels_absent_from_artifact(self) -> None:
        """Artifact must not leak sensitive sentinels or system prompts."""
        sentinel_secret = "SUPER_SECRET_TOKEN_DO_NOT_LEAK"
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            report = evaluate_dataset(DECISION_EVAL_CASES)
            art_path = persist_evaluation_artifact(report, output_dir=out_dir)
            with open(art_path, "r", encoding="utf-8") as f:
                text = f.read()

            self.assertNotIn(sentinel_secret, text)
            self.assertNotIn("UNTRUSTED DATA BOUNDARY", text)
            self.assertNotIn("API_KEY", text)

    def test_38_sanitizer_redacts_sentinel_in_summary(self) -> None:
        """Injected sentinel secret in InvestigationResult.summary is redacted in serialized artifact."""
        sentinel_secret = "SUPER_SECRET_API_TOKEN_XYZ_12345"
        tampered_result = replace(
            DE_001.scripted_decisions[0].final_result,
            summary=f"Analysis complete: credential found {sentinel_secret} on DC01.",
        )
        tampered_case = replace(
            DE_001,
            scripted_decisions=(
                ModelDecision(decision_type=DecisionType.FINAL_RESULT, final_result=tampered_result),
            ),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            report = evaluate_dataset([tampered_case] + list(DECISION_EVAL_CASES[1:]))
            art_path = persist_evaluation_artifact(report, output_dir=out_dir)
            with open(art_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(sentinel_secret, content)
            self.assertIn("[REDACTED_SECRET]", content)

    def test_39_sanitizer_redacts_sentinel_in_error_message(self) -> None:
        """Injected sentinel secret in exception/error message is redacted in serialized artifact."""
        sentinel_secret = "SUPER_SECRET_EXCEPTION_TOKEN_67890"
        with patch.object(
            InvestigationOrchestrator,
            "investigate",
            side_effect=OrchestratorError(f"Fatal error with secret token {sentinel_secret}"),
        ):
            with tempfile.TemporaryDirectory() as tmpdir:
                out_dir = Path(tmpdir)
                report = evaluate_dataset(DECISION_EVAL_CASES)
                art_path = persist_evaluation_artifact(report, output_dir=out_dir)
                with open(art_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn(sentinel_secret, content)
                self.assertIn("[REDACTED_SECRET]", content)

    def test_40_sanitizer_bounds_maximum_length(self) -> None:
        """Sanitizer enforces bounded maximum length with ellipsis."""
        long_text = "A" * 500
        sanitized = sanitize_text_field(long_text, max_len=200)
        self.assertIsNotNone(sanitized)
        self.assertEqual(len(sanitized), 200)
        self.assertTrue(sanitized.endswith("..."))

    def test_41_artifact_excludes_raw_prompts_and_tool_results(self) -> None:
        """Serialized artifact strictly excludes raw prompts, model requests, and tool envelopes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            report = evaluate_dataset(DECISION_EVAL_CASES)
            art_path = persist_evaluation_artifact(report, output_dir=out_dir)
            with open(art_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("INVESTIGATOR_SYSTEM_INSTRUCTIONS", content)
            self.assertNotIn("ModelRequest", content)
            self.assertNotIn("ToolResultEnvelope", content)
            self.assertNotIn("ToolRequest", content)


class TestDecisionEvaluationCLI(unittest.TestCase):
    """Test CLI commands and flags."""

    def test_42_cli_default_run(self) -> None:
        """CLI default run exits with code 0."""
        code = cli_main([])
        self.assertEqual(code, 0)

    def test_43_cli_persist_artifact(self) -> None:
        """CLI with --persist-artifact writes artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = cli_main(["--persist-artifact", "--output-dir", tmpdir])
            self.assertEqual(code, 0)
            created_files = list(Path(tmpdir).glob("decision_eval_*.json"))
            self.assertEqual(len(created_files), 1)

    def test_44_cli_fail_on_evaluation_failure_flag_success(self) -> None:
        """CLI with --fail-on-evaluation-failure exits 0 when all pass."""
        code = cli_main(["--fail-on-evaluation-failure"])
        self.assertEqual(code, 0)

    def test_45_cli_fail_on_evaluation_failure_exits_one_on_failure(self) -> None:
        """CLI with --fail-on-evaluation-failure returns exit code 1 when a case fails."""
        with patch("scripts.run_decision_evaluation.evaluate_dataset") as mock_eval:
            fake_report = MagicMock()
            fake_report.failed_cases = 1
            fake_report.total_cases = 10
            fake_report.passed_cases = 9
            fake_report.expected_completion_cases = 6
            fake_report.successful_completions = 6
            fake_report.expected_non_completion_cases = 4
            fake_report.successful_handled_aborts = 3
            fake_report.unexpected_failures = 1
            fake_report.baseline_commit = "0fcbbc1"
            fake_report.dataset_fingerprint_sha256 = "0" * 64
            fake_report.execution_mode = "OFFLINE"
            fake_report.python_version = "3.10"
            fake_report.timestamp_utc = "2026-09-26T12:00:00Z"
            fake_report.metrics = {}
            fake_report.case_results = ()
            mock_eval.return_value = fake_report

            code = cli_main(["--fail-on-evaluation-failure"])
            self.assertEqual(code, 1)

    def test_46_cli_malformed_argument_exits_two(self) -> None:
        """CLI with unrecognized argument exits with SystemExit (argparse code 2)."""
        with self.assertRaises(SystemExit) as ctx:
            cli_main(["--unrecognized-argument-flag"])
        self.assertEqual(ctx.exception.code, 2)

    def test_47_baseline_commit_resolution(self) -> None:
        """resolve_baseline_commit returns valid commit hash or UNKNOWN."""
        commit = resolve_baseline_commit()
        self.assertTrue(commit == "UNKNOWN" or len(commit) >= 7)

    def test_48_baseline_commit_subprocess_arguments_are_fixed(self) -> None:
        """resolve_baseline_commit uses fixed static arguments with shell=False."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="abcdef1234567890\n")
            commit = resolve_baseline_commit()
            self.assertEqual(commit, "abcdef1234567890")
            mock_run.assert_called_once_with(
                ["git", "rev-parse", "HEAD"],
                cwd=str(_REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5.0,
                check=False,
                shell=False,
            )

    def test_49_artifacts_directory_ignored_by_git(self) -> None:
        """artifacts/evaluations/ artifacts must be ignored in git."""
        gitignore_path = _REPO_ROOT / ".gitignore"
        self.assertTrue(gitignore_path.exists())
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("artifacts/evaluations/*.json", content)
