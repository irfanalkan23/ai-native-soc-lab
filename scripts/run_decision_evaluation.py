"""CLI entrypoint for Milestone 6D Automated Decision Evaluation (Offline).

Architecture Principles:
    - 100% Offline execution: zero network egress, zero live credentials.
    - No incident-response shell/process execution and no network provider execution occur.
      The evaluator may run one fixed local 'git rev-parse HEAD' subprocess to record repository metadata.
    - Measures model behavior, deterministic control enforcement, and system safety independently.
    - Strict denominator accounting: NOT_APPLICABLE checks excluded from percentage calculation.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evaluation.decision_eval import evaluate_dataset, persist_evaluation_artifact
from tests.fixtures.decision_eval_cases import DATASET_VERSION, DECISION_EVAL_CASES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run automated decision evaluation (offline) against curated SOC test cases.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--dataset-version",
        type=str,
        default=DATASET_VERSION,
        help=f"Dataset version to evaluate (default: {DATASET_VERSION})",
    )
    parser.add_argument(
        "--persist-artifact",
        action="store_true",
        help="Persist sanitized evaluation report JSON to artifacts/evaluations/",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional custom output directory for persisted evaluation artifacts",
    )
    parser.add_argument(
        "--fail-on-evaluation-failure",
        action="store_true",
        help="Exit with non-zero code if any evaluation case fails",
    )

    args = parser.parse_args(argv)

    print("=" * 72)
    print("  AUTOMATED DECISION EVALUATION HARNESS (OFFLINE)")
    print(f"  Dataset: {args.dataset_version} ({len(DECISION_EVAL_CASES)} cases)")
    print("=" * 72)

    report = evaluate_dataset(DECISION_EVAL_CASES, dataset_version=args.dataset_version)

    print(f"\nMetadata:")
    print(f"  Baseline Commit: {report.baseline_commit}")
    print(f"  Dataset Fingerprint (SHA256): {report.dataset_fingerprint_sha256[:16]}...")
    print(f"  Execution Mode:  {report.execution_mode}")
    print(f"  Python Version:  {report.python_version}")
    print(f"  Timestamp UTC:   {report.timestamp_utc}")

    print(f"\nLifecycle & Completion Accounting:")
    print(f"  Expected Completions:         {report.expected_completion_cases}")
    print(f"  Successful Completions:       {report.successful_completions}")
    print(f"  Expected Non-Completions:     {report.expected_non_completion_cases}")
    print(f"  Successful Handled Aborts:    {report.successful_handled_aborts}")
    print(f"  Unexpected Failures:          {report.unexpected_failures}")

    print(f"\nAggregate Metric Performance:")
    print(f"  {'Metric Name':<28} {'Eligible':<10} {'Pass':<8} {'Fail':<8} {'N/A':<6} {'Rate %':<8}")
    print(f"  {'-'*28} {'-'*10} {'-'*8} {'-'*8} {'-'*6} {'-'*8}")
    for mname, mrec in report.metrics.items():
        rate_str = f"{mrec.rate_pct:.1f}%" if mrec.rate_pct is not None else "N/A"
        print(
            f"  {mname:<28} {mrec.eligible_count:<10} {mrec.pass_count:<8} "
            f"{mrec.fail_count:<8} {mrec.not_applicable_count:<6} {rate_str:<8}"
        )

    print(f"\nPer-Case Results:")
    print(f"  {'Case ID':<8} {'Category':<22} {'Model Status':<16} {'Control Status':<22} {'Safety':<8} {'Verdict':<8}")
    print(f"  {'-'*8} {'-'*22} {'-'*16} {'-'*22} {'-'*8} {'-'*8}")
    for res in report.case_results:
        verdict = "PASS" if res.passed else "FAIL"
        print(
            f"  {res.case_id:<8} {res.category:<22} {res.model_behavior_status.value:<16} "
            f"{res.control_enforcement_status.value:<22} {res.system_safety_status.value:<8} {verdict:<8}"
        )

    print("\n" + "=" * 72)
    print(f"  OVERALL RESULT: {report.passed_cases}/{report.total_cases} CASES PASSED")
    print("=" * 72)

    if args.persist_artifact:
        artifact_path = persist_evaluation_artifact(report, output_dir=args.output_dir)
        print(f"\n[+] Sanitized evaluation artifact persisted to:\n    {artifact_path}")

    if args.fail_on_evaluation_failure and report.failed_cases > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
