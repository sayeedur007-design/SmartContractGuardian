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
            system_prompt = """You are an objective, source-grounded Smart Contract Security Auditor.
Verify each reported finding using only the supplied contract source, affected function, and attached code snippet. Do not invent Solidity code or infer omitted checks.

For each finding:
1. Identify concrete source evidence that supports or explicitly disproves the reported condition.
2. If evidence is insufficient, return INSUFFICIENT_EVIDENCE; do not reject it merely because proof is absent.
3. Reject only when exact Solidity evidence disproves the analyzer reasoning.
4. Provide a confidence score (0.0-1.0) for your independent assessment and concise evidence-grounded reasoning.
5. Use one verdict: VERIFIED, LIKELY, NEEDS_REVIEW, WEAK, REJECTED, or INSUFFICIENT_EVIDENCE.

Return ONLY valid JSON in this format:
{
  "rechecked_vulnerabilities": [
    {
      "original_idx": 0,
      "skeptic_confidence": 0.9,
      "validity_reasoning": "Detailed reason why it is valid or invalid",
      "evidence_lines": ["code snippet from contract"],
      "verdict": "LIKELY"
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
    If evidence is missing or inconclusive, use INSUFFICIENT_EVIDENCE or NEEDS_REVIEW.
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
                reasoning = self._ground_execution_order(finding, reasoning, contract_source)
                evidence = verdict.get("evidence_lines", [])
                if isinstance(evidence, str):
                    evidence = [evidence]
                has_evidence = any(str(line).strip() for line in evidence)
                verdict_name = str(verdict.get("verdict", "INSUFFICIENT_EVIDENCE")).upper()
                if confidence is None:
                    print_warning(f"Skeptic verdict #{idx} has no numeric confidence; retaining Analyzer finding.")
                    item = dict(finding)
                    item["skeptic_confidence"] = float(item.get("confidence_score", 0.0))
                    item["validity_reasoning"] = "Skeptic verdict had no valid confidence; retained Analyzer finding."
                    item["skeptic_status"] = "fallback_invalid_verdict"
                    accepted.append(item)
                elif verdict_name == "REJECTED" and self._explicit_disproof(evidence, reasoning, contract_source):
                    print_warning(f"Skeptic rejected {finding.get('vulnerability_type')}: {reasoning or 'explicit source disproof'}")
                else:
                    item = dict(finding)
                    calibrated = self._calibrate_confidence(finding, confidence, evidence, contract_source, verdict_name)
                    item["skeptic_confidence"] = calibrated
                    item["confidence_score"] = calibrated
                    item["validity_reasoning"] = reasoning or "INSUFFICIENT_EVIDENCE: retained without an explicit Solidity disproof."
                    item["skeptic_evidence_lines"] = evidence
                    item["skeptic_status"] = verdict_name if verdict_name in {"VERIFIED", "LIKELY", "NEEDS_REVIEW", "WEAK", "INSUFFICIENT_EVIDENCE"} else "INSUFFICIENT_EVIDENCE"
                    item["confidence_level"] = self._confidence_level(calibrated, item["skeptic_status"])
                    accepted.append(item)

            progress.update(task, completed=True)

        self._log_findings("Skeptic merged output", accepted)
        return sorted(accepted, key=lambda x: x.get("skeptic_confidence", 0), reverse=True)

    @staticmethod
    def _explicit_disproof(evidence: list, reasoning: str, contract_source: str) -> bool:
        """Only a source-backed protective condition can justify rejection."""
        joined = "\n".join(str(line) for line in evidence if str(line).strip())
        if not joined or not all(line.strip() in contract_source for line in evidence if str(line).strip()):
            return False
        return bool(re.search(
            r"onlyOwner|onlyRole|nonReentrant|revert\s+Unauthorized|"
            r"require\s*\([^;]*(?:msg\.sender\s*==\s*(?:owner|admin)|hasRole|owner\s*==\s*msg\.sender)",
            joined + "\n" + reasoning, re.I,
        ))

    @staticmethod
    def _calibrate_confidence(finding: dict, skeptic_confidence: float, evidence: list,
                              contract_source: str, verdict: str) -> float:
        analyzer_confidence = max(0.0, min(1.0, float(finding.get("confidence_score", 0.0) or 0.0)))
        source_evidence = any(str(line).strip() and str(line).strip() in contract_source for line in evidence)
        deterministic = str(finding.get("reasoning", "")).startswith("Deterministic source evidence")
        evidence_score = 1.0 if deterministic and source_evidence else (0.75 if source_evidence else 0.45)
        calibrated = 0.45 * analyzer_confidence + 0.40 * max(0.0, min(1.0, skeptic_confidence)) + 0.15 * evidence_score
        if verdict in {"INSUFFICIENT_EVIDENCE", "NEEDS_REVIEW"}:
            calibrated = min(calibrated, 0.69)
        elif verdict == "WEAK":
            calibrated = min(calibrated, 0.49)
        return round(max(0.0, min(1.0, calibrated)), 3)

    @staticmethod
    def _confidence_level(confidence: float, status: str) -> str:
        if status == "INSUFFICIENT_EVIDENCE":
            return "Needs Review"
        if confidence >= 0.80:
            return "Verified"
        if confidence >= 0.65:
            return "Likely"
        if confidence >= 0.40:
            return "Needs Review"
        return "Weak"

    @staticmethod
    def _ground_execution_order(finding: dict, reasoning: str, contract_source: str) -> str:
        """Prevent a reentrancy assessment from contradicting observable order."""
        if "reentrancy" not in str(finding.get("vulnerability_type", "")).lower():
            return reasoning
        snippet = str(finding.get("code_snippet", "")) or contract_source
        external_call = re.search(r"\.call\s*\{[^}]*value\s*:", snippet, re.I)
        state_update = re.search(r"(?:balances|\w+)\s*\[[^\]]+\]\s*[-+]?=", snippet)
        if external_call and state_update and external_call.start() < state_update.start():
            contradiction = re.search(r"(?:correctly\s+follows|follows)\s+checks[-\s]?effects[-\s]?interactions", reasoning, re.I)
            if contradiction:
                return (
                    "Source execution order shows an external value call before the state update; "
                    "this does not follow checks-effects-interactions. "
                    "The prior reasoning contradicted the supplied Solidity snippet."
                )
        return reasoning

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
