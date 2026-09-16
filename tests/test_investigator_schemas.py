"""Unit tests for investigation input and output schemas."""

import unittest

from investigator.schemas import (
    ConfidenceLevel,
    InvestigationInput,
    InvestigationResult,
    SchemaValidationError,
    MAX_SUMMARY_LENGTH,
    MAX_RECOMMENDED_STEP_LENGTH,
    MAX_OBSERVATIONS,
    MAX_OBSERVATION_LENGTH,
    MAX_SUSPICIOUS_INDICATORS,
    MAX_EVIDENCE_REFS,
)


class TestInvestigationSchemas(unittest.TestCase):
    """Test validation boundaries and immutability of investigation schemas."""

    def test_valid_investigation_input(self) -> None:
        """Verify successful creation of compliant InvestigationInput."""
        inp = InvestigationInput(
            incident_id="INC-2026-001",
            timestamp="2026-09-15T17:05:00Z",
            host="DC01",
            user="SOCLAB\\Administrator",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -NoProfile -EncodedCommand VwBy...",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line='"C:\\Windows\\system32\\cmd.exe"',
            detection_name="Suspicious Encoded PowerShell Execution",
            detection_id="4e4f13c0-89a9-4f0e-a08f-b70b9c19e729",
        )
        self.assertEqual(inp.incident_id, "INC-2026-001")
        self.assertEqual(inp.host, "DC01")
        self.assertEqual(inp.detection_id, "4e4f13c0-89a9-4f0e-a08f-b70b9c19e729")

    def test_investigation_input_empty_or_missing_fields_fail(self) -> None:
        """Proof: Empty or whitespace-only strings fail validation."""
        valid_kwargs = {
            "incident_id": "INC-001",
            "timestamp": "2026-09-15T17:05:00Z",
            "host": "DC01",
            "user": "SOCLAB\\Administrator",
            "image": "powershell.exe",
            "command_line": "powershell.exe -enc test",
            "parent_image": "cmd.exe",
            "parent_command_line": "cmd.exe",
            "detection_name": "Suspicious Encoded PowerShell",
            "detection_id": "rule-001",
        }

        # Each field must reject empty string
        for field in valid_kwargs.keys():
            bad_kwargs = dict(valid_kwargs)
            bad_kwargs[field] = ""
            with self.subTest(field=field, value="empty"):
                with self.assertRaises(SchemaValidationError):
                    InvestigationInput(**bad_kwargs)

            bad_kwargs[field] = "   "
            with self.subTest(field=field, value="whitespace"):
                with self.assertRaises(SchemaValidationError):
                    InvestigationInput(**bad_kwargs)

            bad_kwargs[field] = None  # type: ignore[assignment]
            with self.subTest(field=field, value="None"):
                with self.assertRaises(SchemaValidationError):
                    InvestigationInput(**bad_kwargs)

    def test_valid_investigation_result(self) -> None:
        """Verify successful creation of compliant InvestigationResult."""
        res = InvestigationResult(
            summary="Benign controlled encoded PowerShell execution observed on DC01.",
            observations=[
                "Parent process is cmd.exe",
                "Command line decoded to Write-Host test banner",
            ],
            decoded_command="Write-Host 'AI-NativeSOC-LAB-TEST'",
            mitre_techniques=["T1059.001"],
            suspicious_indicators=["EncodedCommand flag present"],
            recommended_next_step="Close alert as verified benign test",
            confidence_level="high",
            evidence_refs=["DC01:Sysmon:EventID1:Record-101"],
        )
        self.assertEqual(res.confidence_level, "high")
        self.assertEqual(res.decoded_command, "Write-Host 'AI-NativeSOC-LAB-TEST'")

    def test_investigation_result_invalid_confidence_level_fails(self) -> None:
        """Proof: confidence_level must be strictly 'low', 'medium', or 'high'."""
        invalid_levels = ["critical", "none", "very_high", "0.95", "", 10]
        for level in invalid_levels:
            with self.subTest(level=level):
                with self.assertRaises(SchemaValidationError):
                    InvestigationResult(
                        summary="Test summary",
                        observations=["obs1"],
                        decoded_command=None,
                        mitre_techniques=["T1059.001"],
                        suspicious_indicators=["ind1"],
                        recommended_next_step="step1",
                        confidence_level=level,  # type: ignore[arg-type]
                        evidence_refs=["ref1"],
                    )

    def test_investigation_result_empty_required_text_fails(self) -> None:
        """Proof: summary and recommended_next_step cannot be empty."""
        with self.assertRaises(SchemaValidationError):
            InvestigationResult(
                summary="",
                observations=[],
                decoded_command=None,
                mitre_techniques=[],
                suspicious_indicators=[],
                recommended_next_step="step",
                confidence_level="low",
                evidence_refs=[],
            )

        with self.assertRaises(SchemaValidationError):
            InvestigationResult(
                summary="Valid summary",
                observations=[],
                decoded_command=None,
                mitre_techniques=[],
                suspicious_indicators=[],
                recommended_next_step="   ",
                confidence_level="low",
                evidence_refs=[],
            )

    def test_investigation_result_deep_immutability(self) -> None:
        """Proof: InvestigationResult collections are normalized to immutable tuples."""
        obs_input = ["Parent process is cmd.exe", "PowerShell executed"]
        mitre_input = ["T1059.001"]
        suspicious_input = ["EncodedCommand flag"]
        evidence_input = ["EventID:1"]

        res = InvestigationResult(
            summary="Controlled test execution",
            observations=obs_input,
            decoded_command=None,
            mitre_techniques=mitre_input,
            suspicious_indicators=suspicious_input,
            recommended_next_step="Close alert",
            confidence_level="high",
            evidence_refs=evidence_input,
        )

        # Stored collections must be immutable tuples
        self.assertIsInstance(res.observations, tuple)
        self.assertIsInstance(res.mitre_techniques, tuple)
        self.assertIsInstance(res.suspicious_indicators, tuple)
        self.assertIsInstance(res.evidence_refs, tuple)

        # Caller mutating the original lists cannot alter the InvestigationResult
        obs_input.append("Injected observation")
        mitre_input.append("T9999")
        suspicious_input.append("Injected indicator")
        evidence_input.append("Injected evidence")

        self.assertEqual(len(res.observations), 2)
        self.assertEqual(len(res.mitre_techniques), 1)
        self.assertEqual(len(res.suspicious_indicators), 1)
        self.assertEqual(len(res.evidence_refs), 1)

        # In-place mutations on stored collections must fail
        with self.assertRaises(AttributeError):
            res.observations.append("Injected")  # type: ignore[attr-defined]

        with self.assertRaises(TypeError):
            res.observations[0] = "Overwritten"  # type: ignore[index]

    def test_investigation_result_collection_element_validation(self) -> None:
        """Proof: Every collection element must be a non-empty string exactly."""
        collection_fields = [
            "observations",
            "mitre_techniques",
            "suspicious_indicators",
            "evidence_refs",
        ]
        invalid_elements = [
            123,
            {"nested": "dict"},
            None,
            "",
            "   ",
            ["nested_list"],
            ("nested_tuple",),
            True,
            1.5,
        ]

        for field in collection_fields:
            for invalid_elem in invalid_elements:
                with self.subTest(field=field, invalid_elem=repr(invalid_elem)):
                    kwargs = {
                        "summary": "Valid summary",
                        "observations": ["valid obs"],
                        "decoded_command": None,
                        "mitre_techniques": ["T1059.001"],
                        "suspicious_indicators": ["valid ind"],
                        "recommended_next_step": "Close alert",
                        "confidence_level": "high",
                        "evidence_refs": ["valid ref"],
                    }
                    kwargs[field] = [invalid_elem]  # type: ignore[list-item]

                    with self.assertRaises(SchemaValidationError):
                        InvestigationResult(**kwargs)


class TestInvestigationResultSizeBounds(unittest.TestCase):
    """Test output size bounds on InvestigationResult to prevent unbounded model output."""

    def _valid_kwargs(self) -> dict:
        """Return a base set of valid kwargs for InvestigationResult construction."""
        return {
            "summary": "Valid summary.",
            "observations": ["obs1"],
            "decoded_command": None,
            "mitre_techniques": ["T1059.001"],
            "suspicious_indicators": ["indicator1"],
            "recommended_next_step": "Close alert.",
            "confidence_level": "high",
            "evidence_refs": ["ref1"],
        }

    def test_summary_too_long_fails(self) -> None:
        """Proof: summary exceeding MAX_SUMMARY_LENGTH fails closed."""
        kw = self._valid_kwargs()
        kw["summary"] = "x" * (MAX_SUMMARY_LENGTH + 1)
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("exceeds maximum", str(ctx.exception))

    def test_summary_at_max_length_passes(self) -> None:
        """Verify summary of exactly MAX_SUMMARY_LENGTH characters is accepted."""
        kw = self._valid_kwargs()
        kw["summary"] = "x" * MAX_SUMMARY_LENGTH
        result = InvestigationResult(**kw)
        self.assertEqual(len(result.summary), MAX_SUMMARY_LENGTH)

    def test_recommended_step_too_long_fails(self) -> None:
        """Proof: recommended_next_step exceeding MAX_RECOMMENDED_STEP_LENGTH fails closed."""
        kw = self._valid_kwargs()
        kw["recommended_next_step"] = "x" * (MAX_RECOMMENDED_STEP_LENGTH + 1)
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("exceeds maximum", str(ctx.exception))

    def test_observations_count_too_many_fails(self) -> None:
        """Proof: more than MAX_OBSERVATIONS items in observations fails closed."""
        kw = self._valid_kwargs()
        kw["observations"] = [f"obs{i}" for i in range(MAX_OBSERVATIONS + 1)]
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("maximum", str(ctx.exception))

    def test_observation_element_too_long_fails(self) -> None:
        """Proof: individual observation string exceeding MAX_OBSERVATION_LENGTH fails closed."""
        kw = self._valid_kwargs()
        kw["observations"] = ["x" * (MAX_OBSERVATION_LENGTH + 1)]
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("exceeds maximum", str(ctx.exception))

    def test_suspicious_indicators_count_too_many_fails(self) -> None:
        """Proof: more than MAX_SUSPICIOUS_INDICATORS items fails closed."""
        kw = self._valid_kwargs()
        kw["suspicious_indicators"] = [f"ind{i}" for i in range(MAX_SUSPICIOUS_INDICATORS + 1)]
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("maximum", str(ctx.exception))

    def test_evidence_refs_count_too_many_fails(self) -> None:
        """Proof: more than MAX_EVIDENCE_REFS items fails closed."""
        kw = self._valid_kwargs()
        kw["evidence_refs"] = [f"ref{i}" for i in range(MAX_EVIDENCE_REFS + 1)]
        with self.assertRaises(SchemaValidationError) as ctx:
            InvestigationResult(**kw)
        self.assertIn("maximum", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
