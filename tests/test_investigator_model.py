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


if __name__ == "__main__":
    unittest.main()
