"""Regression tests for Analyzer LLM function-reference matching."""

import unittest

from llm_agents.agents.analyzer import AnalyzerAgent


class AnalyzerFunctionMatchingTests(unittest.TestCase):
    def test_normalizes_llm_function_references_for_lookup(self):
        cases = [
        ("withdraw", "withdraw(uint256)"),
        ("withdraw()", "withdraw(uint256)"),
        ("withdraw(uint256)", "withdraw(uint256)"),
        ("Contract.withdraw", "withdraw(uint256)"),
        ("Contract.withdraw()", "withdraw(uint256)"),
        ("Contract.withdraw(uint256)", "withdraw(uint256)"),
        ("withdraw(uint256)_0x6d9485e7", "withdraw(uint256)"),
        ("withdraw_0x1234abcd", "withdraw(uint256)"),
        ("withdraw(uint256)_42", "withdraw(uint256)"),
        ("withdraw(uint256)_compiler_7", "withdraw(uint256)"),
        ("Contract.withdraw(uint256)_deadbeef", "withdraw(uint256)"),
        ]
        for reference, expected in cases:
            with self.subTest(reference=reference):
                self.assertEqual(
                    AnalyzerAgent._normalize_function_reference_for_lookup(
                        reference, {"withdraw(uint256)"}
                    ),
                    expected,
                )

    def test_does_not_resolve_ambiguous_overloaded_bare_name(self):
        allowed = {"withdraw()", "withdraw(uint256)"}

        self.assertIsNone(AnalyzerAgent._normalize_function_reference_for_lookup("withdraw", allowed))
        self.assertIsNone(AnalyzerAgent._normalize_function_reference_for_lookup("withdraw_0x1234abcd", allowed))

    def test_validation_keeps_original_llm_function_name_when_normalized_lookup_exists(self):
        original_name = "withdraw(uint256)_0x6d9485e7"
        findings = [{"vulnerability_type": "reentrancy", "affected_functions": [original_name]}]
        contract_info = {
            "function_details": [{"function": "withdraw", "function_id": "withdraw(uint256)"}]
        }

        validated = AnalyzerAgent._validate_findings(findings, contract_info)

        self.assertEqual(validated, findings)
        self.assertEqual(validated[0]["affected_functions"], [original_name])

    def test_attaches_snippet_for_function_with_generated_suffix(self):
        original_name = "withdraw(uint256)_0x6d9485e7"
        findings = [{"vulnerability_type": "reentrancy", "affected_functions": [original_name]}]
        contract_info = {
            "function_details": [{
                "contract": "Contract",
                "function": "withdraw",
                "function_id": "withdraw(uint256)",
                "content": "function withdraw(uint256 amount) external { /* vulnerable */ }",
            }]
        }

        AnalyzerAgent._attach_code_snippets(AnalyzerAgent, findings, contract_info)

        self.assertEqual(findings[0]["affected_functions"], [original_name])
        self.assertEqual(
            findings[0]["code_snippet"],
            "function withdraw(uint256 amount) external { /* vulnerable */ }",
        )
