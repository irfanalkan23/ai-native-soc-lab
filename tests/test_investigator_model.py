"""Regression tests for model prompt contracts and instructions."""

import unittest

from investigator.model import INVESTIGATOR_SYSTEM_INSTRUCTIONS


class TestInvestigatorModelPrompt(unittest.TestCase):
    """Verify system instructions communicate strict tool boundaries and parameter types."""

    def test_investigator_system_instructions_bounded_splunk_contract(self) -> None:
        """Verify bounded_splunk_search instructions explicitly specify required types and constraints."""
        instructions = INVESTIGATOR_SYSTEM_INSTRUCTIONS
        self.assertIn("bounded_splunk_search", instructions)
        self.assertIn('host: string, must equal "DC01"', instructions)
        self.assertIn("minutes: integer, 1-60 (do not pass string)", instructions)
        self.assertIn("limit: integer, 1-50 (do not pass string)", instructions)
        self.assertIn("no additional arguments allowed", instructions)

    def test_investigator_system_instructions_bounded_splunk_query_type_contract(self) -> None:
        """Verify bounded_splunk_search instructions expose query_type with exactly the allowed values."""
        instructions = INVESTIGATOR_SYSTEM_INSTRUCTIONS
        self.assertIn("query_type", instructions)
        self.assertIn("encoded_powershell_matches", instructions)
        self.assertIn("powershell_network_retrieval_matches", instructions)


    def test_investigator_system_instructions_map_mitre_technique_contract(self) -> None:
        """Verify map_mitre_technique instructions specify exact detection_ref and fail_closed false."""
        instructions = INVESTIGATOR_SYSTEM_INSTRUCTIONS
        self.assertIn("map_mitre_technique", instructions)
        mitre_section = instructions[instructions.index("map_mitre_technique"):]

        self.assertIn("detection_ref", mitre_section)
        self.assertIn("investigation_input.detection_name", mitre_section)
        self.assertTrue(
            "exactly" in mitre_section.lower(),
            msg="map_mitre_technique instructions must require using investigation_input.detection_name exactly",
        )
        self.assertIn("T1105", mitre_section)
        self.assertIn("fail_closed", mitre_section)
        self.assertTrue(
            "false" in mitre_section.lower(),
            msg="map_mitre_technique instructions must state fail_closed must be false",
        )
        self.assertTrue(
            "no additional arguments" in mitre_section.lower(),
            msg="map_mitre_technique instructions must forbid additional arguments",
        )

    def test_investigator_system_instructions_map_mitre_required_terms(self) -> None:
        """Verify all Milestone 8L required terms are explicitly present in the model prompt."""
        instructions = INVESTIGATOR_SYSTEM_INSTRUCTIONS
        for term in (
            "detection_ref",
            "investigation_input.detection_name",
            "T1105",
            "fail_closed",
        ):
            self.assertIn(term, instructions)

        self.assertTrue(
            "exactly" in instructions.lower(),
            msg="Prompt must contain 'exactly'",
        )
        self.assertTrue(
            "false" in instructions.lower(),
            msg="Prompt must contain 'false'",
        )


if __name__ == "__main__":
    unittest.main()
