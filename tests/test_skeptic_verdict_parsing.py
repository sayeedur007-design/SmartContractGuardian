import unittest

from llm_agents.agents.skeptic import SkepticAgent


class SkepticVerdictParsingTests(unittest.TestCase):
    def test_markdown_fenced_json_is_parsed(self):
        agent = SkepticAgent.__new__(SkepticAgent)
        response = '''```json
        {"rechecked_vulnerabilities": [{"original_idx": 0, "skeptic_confidence": 0.7,
        "validity_reasoning": "source evidence", "evidence_lines": [], "verdict": "LIKELY"}]}
        ```'''
        self.assertEqual(agent._parse_response(response)[0]["verdict"], "LIKELY")

    def test_string_index_and_incomplete_response_preserve_unverified_finding(self):
        findings = [{"vulnerability_type": "timestamp_dependence", "affected_functions": ["draw()"], "confidence_score": 0.6}]
        parsed = [{"original_index": "0", "skeptic_confidence": 0.7, "verdict": "NEEDS_REVIEW"}]
        merged = SkepticAgent._merge_verdicts("", findings, parsed, [])
        self.assertEqual(merged[0]["skeptic_status"], "NEEDS_REVIEW")
        self.assertFalse(merged[0]["confirmed"])

        incomplete = SkepticAgent._merge_verdicts("", findings, [], [])
        self.assertEqual(incomplete[0]["skeptic_status"], "INSUFFICIENT_EVIDENCE")
        self.assertFalse(incomplete[0]["confirmed"])
