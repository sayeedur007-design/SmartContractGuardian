# ==============================
# File: llm_agents/agents/skeptic.py
# ==============================
import os
import json
from openai import OpenAI
import re
from pathlib import Path
from utils.print_utils import create_progress_spinner, print_warning
from utils.function_identifiers import known_function_ids, normalize_affected_functions

class SkepticAgent:
    """
    The SkepticAgent re-checks each vulnerability to confirm whether it truly applies.
    It outputs a re-ranked or filtered list of vulnerabilities, sorted from highest to lowest confidence.
    """

    def __init__(self, model_config=None):
        from ..config import ModelConfig

        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("skeptic")

        # Get provider info for the selected model
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)

        # Initialize OpenAI client with the correct settings
        self.client = OpenAI(
            api_key=os.getenv(api_key_env),
            **self.model_config.get_openai_args(self.model_name)
        )

    def audit_vulnerabilities(self, contract_source: str, vulnerabilities: list, function_details: list = None) -> list:
        if not vulnerabilities:
            return []

        original_findings = [dict(finding) for finding in vulnerabilities]
        allowed = known_function_ids(function_details or [])
        if allowed:
            vulnerabilities = [
                {**finding, "affected_functions": normalize_affected_functions(finding.get("affected_functions", []), allowed)}
                for finding in vulnerabilities
            ]
            vulnerabilities = [finding for finding in vulnerabilities if finding["affected_functions"]]
        if not vulnerabilities:
            print_warning("Skeptic input validation removed every finding; preserving Analyzer findings for review.")
            vulnerabilities = original_findings

        self._log_findings("Skeptic input", vulnerabilities)

        with create_progress_spinner("Re-checking vulnerabilities") as progress:
            task = progress.add_task("Analyzing...")

            # Build prompts
            system_prompt = """You are a skeptical Smart Contract Security Auditor. 
Your job is to verify findings from a previous analyzer.
Be extremely critical. Most findings might be false positives.

For each finding:
1. Examine the contract source code carefully.
2. Check if the vulnerability actually exists and is exploitable.
3. Reject if the reasoning is flawed or the code handles the issue correctly.
4. Provide a confidence score (0.0-1.0).
5. Provide reasoning for your verdict.

Return ONLY valid JSON in this format:
{
  "rechecked_vulnerabilities": [
    {
      "original_idx": 0,
      "skeptic_confidence": 0.9,
      "validity_reasoning": "Detailed reason why it is valid or invalid",
      "evidence_lines": ["code snippet from contract"],
      "verdict": "accepted"
    }
  ]
}"""
            user_prompt = f"=== CONTRACT SOURCE CODE ===\n{contract_source}\n\n=== REPORTED VULNERABILITIES ===\n"
            for idx, vuln in enumerate(vulnerabilities):
                user_prompt += (
                    f"#{idx} => type={vuln.get('vulnerability_type')}\n"
                    f"affected_functions={vuln.get('affected_functions', [])}\n"
                    f"analyzer_reasoning={vuln.get('reasoning', '')}\n"
                    f"analyzer_impact={vuln.get('impact', '')}\n"
                    "evidence_code:\n"
                )
                code_snippet = vuln.get("code_snippet") or "(no snippet)"
                user_prompt += f"{code_snippet}\n\n"

            user_prompt += """Please re-check each vulnerability from #0, #1, #2, etc.
    You may reject a finding only when you cite exact Solidity evidence that disproves its analyzer reasoning.
    A missing, irrelevant, or empty evidence_lines field is not a valid rejection.
    Return one verdict for every input index.
    Return a JSON object with the final verdict.
    """
            # Call LLM with appropriate message structure
            if self.model_config.supports_reasoning(self.model_name):
                messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
            else:
                messages = [{"role": "user", "content": system_prompt + user_prompt}]

            # Import token tracker
            from utils.token_tracker import token_tracker
            
            try:
                if self.model_name == "claude-3-7-sonnet-latest":
                    resp = self.client.chat.completions.create(model=self.model_name, messages=messages, max_tokens=64000, extra_body={"thinking": {"type": "enabled", "budget_tokens": 5000}})
                else:
                    resp = self.client.chat.completions.create(model=self.model_name, messages=messages)
            except Exception as exc:
                # Analyzer findings backed by a deterministic source rule are
                # still valid evidence; do not turn an Ollama outage into an
                # empty audit report.
                print_warning(f"Local skeptic unavailable; retaining analyzer confidence: {exc}")
                fallback = []
                for finding in vulnerabilities:
                    item = dict(finding)
                    item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                    item["validity_reasoning"] = "Retained because the local skeptic was unavailable."
                    item["skeptic_status"] = "fallback_llm_unavailable"
                    fallback.append(item)
                progress.update(task, completed=True)
                return fallback
                
            # Track token usage
            if hasattr(resp, 'usage') and resp.usage:
                token_tracker.log_tokens(
                    agent_name="skeptic",
                    model_name=self.model_name,
                    prompt_tokens=resp.usage.prompt_tokens,
                    completion_tokens=resp.usage.completion_tokens,
                    total_tokens=resp.usage.total_tokens
                )
                
            text_out = resp.choices[0].message.content.strip()
            self._write_raw_response(text_out)
            print("\n========== RAW SKEPTIC RESPONSE ==========")
            print(text_out[:2000])
            print("... (full response saved to reports/raw_skeptic_response.txt)")
            print("==========================================\n")

            # Parse results
            progress.update(task, description="Processing results...")
            rechecked = self._parse_response(text_out)

            if rechecked is None:
                print_warning("Skeptic response was malformed; using Analyzer findings unchanged.")
                fallback = []
                for finding in vulnerabilities:
                    item = dict(finding)
                    item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                    item["validity_reasoning"] = "Skeptic JSON could not be parsed; retained Analyzer finding."
                    item["skeptic_status"] = "fallback_parse_failure"
                    fallback.append(item)
                self._log_findings("Skeptic fallback output", fallback)
                progress.update(task, completed=True)
                return fallback

            # Merge each verdict by its original index. Missing verdicts are
            # preserved rather than silently deleted; explicit rejections are
            # logged and removed only when the model actually returned one.
            verdicts = {}
            for item in rechecked:
                idx = item.get("original_idx")
                if idx is not None and 0 <= idx < len(vulnerabilities):
                    verdicts[idx] = item

            accepted = []
            for idx, finding in enumerate(vulnerabilities):
                verdict = verdicts.get(idx)
                if verdict is None:
                    item = dict(finding)
                    item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                    item["validity_reasoning"] = "Skeptic did not return a verdict for this finding; retained Analyzer finding."
                    item["skeptic_status"] = "fallback_missing_verdict"
                    accepted.append(item)
                    continue
                try:
                    confidence = float(verdict.get("skeptic_confidence"))
                except (TypeError, ValueError):
                    confidence = None
                reasoning = str(verdict.get("validity_reasoning", ""))
                evidence = verdict.get("evidence_lines", [])
                if isinstance(evidence, str):
                    evidence = [evidence]
                has_evidence = any(str(line).strip() for line in evidence)
                if confidence is None:
                    print_warning(f"Skeptic verdict #{idx} has no numeric confidence; retaining Analyzer finding.")
                    item = dict(finding)
                    item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                    item["validity_reasoning"] = "Skeptic verdict had no valid confidence; retained Analyzer finding."
                    item["skeptic_status"] = "fallback_invalid_verdict"
                    accepted.append(item)
                elif confidence <= 0.0:
                    if not has_evidence:
                        print_warning(f"Skeptic rejected {finding.get('vulnerability_type')} without Solidity evidence; retaining Analyzer finding.")
                        item = dict(finding)
                        item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                        item["validity_reasoning"] = "Skeptic rejection lacked required Solidity evidence; retained Analyzer finding."
                        item["skeptic_status"] = "fallback_unsupported_rejection"
                        accepted.append(item)
                    else:
                        print_warning(f"Skeptic rejected {finding.get('vulnerability_type')}: {reasoning or 'no reason supplied'} | evidence={evidence}")
                else:
                    item = dict(finding)
                    item["skeptic_confidence"] = max(0.0, min(1.0, confidence))
                    item["validity_reasoning"] = reasoning
                    item["skeptic_evidence_lines"] = evidence
                    item["skeptic_status"] = "verified"
                    accepted.append(item)

            progress.update(task, completed=True)

        self._log_findings("Skeptic merged output", accepted)
        return sorted(accepted, key=lambda x: x.get("skeptic_confidence", 0), reverse=True)

    def _parse_response(self, text_out: str):
        from utils.json_cleaner import parse_json_safely

        data = parse_json_safely(text_out, default_fallback={}, log_failure=False)
        verdicts = data.get("rechecked_vulnerabilities") if isinstance(data, dict) else None
        if isinstance(verdicts, list):
            return verdicts
        # Recover individually valid verdict objects from a malformed array.
        recovered = self._extract_verdict_objects(text_out)
        return recovered if recovered else None

    @staticmethod
    def _extract_verdict_objects(text_out: str) -> list:
        from utils.json_cleaner import parse_json_safely
        marker = re.search(r'"rechecked_vulnerabilities"\s*:\s*\[', text_out)
        if not marker:
            return []
        objects, start, depth, in_string, escaped = [], None, 0, False, False
        for index, char in enumerate(text_out[marker.end():], start=marker.end()):
            if in_string:
                if char == '"' and not escaped:
                    in_string = False
                escaped = char == "\\" and not escaped
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                if depth == 0:
                    start = index
                depth += 1
            elif char == "}" and depth:
                depth -= 1
                if depth == 0 and start is not None:
                    item = parse_json_safely(text_out[start:index + 1], default_fallback=None, log_failure=False)
                    if isinstance(item, dict) and "original_idx" in item:
                        objects.append(item)
            elif char == "]" and depth == 0:
                break
        return objects

    @staticmethod
    def _log_findings(stage: str, findings: list) -> None:
        print(f"\n{stage}: {len(findings)} finding(s)")
        for finding in findings:
            print(
                f"  - {finding.get('vulnerability_type')} | "
                f"confidence={finding.get('skeptic_confidence', finding.get('confidence_score', 0))} | "
                f"functions={finding.get('affected_functions', [])}"
            )

    @staticmethod
    def _write_raw_response(response: str) -> None:
        reports = Path.cwd() / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "raw_skeptic_response.txt").write_text(response, encoding="utf-8")
