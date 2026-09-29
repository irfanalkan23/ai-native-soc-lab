"""Deterministic evaluation artifact generation script and CLI entrypoint.

Executes the end-to-end security evaluation harness and persists deterministic
JSON and Markdown reports to repository artifact paths.
"""

import argparse
from pathlib import Path
import sys
from typing import Callable, Mapping, Optional, Sequence, Tuple

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evaluation.harness import (
    EvaluationHarnessError,
    run_security_evaluation,
)
from evaluation.reporting import (
    render_json_report,
    render_markdown_report,
)
from evaluation.runner import (
    EvaluationObservation,
    EvaluationRunnerError,
)
from evaluation.schema import EvaluationScenario


class EvaluationArtifactError(ValueError):
    """Raised when artifact directory validation or safe persistence fails."""
    pass


def write_security_evaluation_artifacts(
    output_dir: Path = Path("artifacts/evaluation"),
    executors: Optional[
        Mapping[str, Callable[[EvaluationScenario], EvaluationObservation]]
    ] = None,
) -> Tuple[Path, Path]:
    """Execute evaluation harness and persist deterministic artifacts.

    Stages rendered JSON and Markdown reports in memory before writing to disk
    to prevent emitting partial or misleading artifacts if execution fails.

    Args:
        output_dir: Destination directory for artifacts.
        executors: Optional mapping to override scenario executors.

    Returns:
        Tuple of (json_file_path, markdown_file_path).

    Raises:
        EvaluationArtifactError: If output directory specification is invalid.
        EvaluationHarnessError: If scenario execution or harness invariants fail.
        EvaluationRunnerError: If runner contracts are violated.
    """
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)
    elif not isinstance(output_dir, Path):
        raise EvaluationArtifactError("output_dir must be a Path or string")

    json_path = output_dir / "security-evaluation.json"
    md_path = output_dir / "security-evaluation.md"

    # 1. Execute harness and render reports in memory
    report = run_security_evaluation(executors=executors)
    json_text = render_json_report(report)
    markdown_text = render_markdown_report(report)

    # 2. Persist to disk deterministically only after all steps succeed
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json_text, encoding="utf-8")
        md_path.write_text(markdown_text, encoding="utf-8")
    except Exception as exc:
        raise EvaluationArtifactError("Failed to write evaluation artifacts") from exc

    return json_path, md_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint for running evaluation harness and persisting artifacts.

    Args:
        argv: Optional command line arguments. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 on success, non-zero on failure.
    """
    parser = argparse.ArgumentParser(
        description="Run security evaluation harness and write deterministic artifacts."
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/evaluation",
        help="Directory to write security-evaluation.json and security-evaluation.md",
    )

    args = parser.parse_args(argv)

    try:
        json_path, md_path = write_security_evaluation_artifacts(
            output_dir=Path(args.output_dir)
        )
        print(f"[+] Security evaluation artifacts persisted successfully:")
        print(f"    JSON:     {json_path}")
        print(f"    Markdown: {md_path}")
        return 0
    except (EvaluationArtifactError, EvaluationHarnessError, EvaluationRunnerError) as err:
        print(f"[-] Evaluation harness failed: {err}", file=sys.stderr)
        return 1
    except Exception:
        print("[-] Unexpected error occurred during evaluation artifact generation", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
