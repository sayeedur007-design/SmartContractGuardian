"""Reliable Foundry execution and compiler-diagnostic repair loop."""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from openai import OpenAI
from ..config import ModelConfig
from utils.print_utils import print_warning
from .generator import GeneratorAgent


class ExploitRunner:
    def __init__(self, model_config=None):
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)
        self.client = OpenAI(api_key=os.getenv(api_key_env), **self.model_config.get_openai_args(self.model_name))
        self.max_retries = self.model_config.poc_max_retries
        self.project_root = Path.cwd()
        self.exploit_root = self.project_root / "exploit"
        # Reuse one validator/client across all repairs; do not create one per attempt.
        self.validator = GeneratorAgent(self.model_config)

    def run_and_fix_exploit(self, poc_data: Dict) -> Dict:
        path = Path(poc_data.get("exploit_file", ""))
        if not path.is_file():
            return {"success": False, "error": poc_data.get("generation_error", "Exploit file not found"), "output": "", "retries": 0, "diagnostics": []}
        diagnostics, output, success = [], "", False
        previous_attempt = ""
        for attempt in range(self.max_retries + 1):
            success, output = self._execute_test(path, attempt)
            diagnostic = self._diagnose(output)
            diagnostics.append(diagnostic)
            if success:
                return {"success": True, "output": output, "error": "", "file_path": str(path), "retries": attempt, "diagnostics": diagnostics}
            if attempt == self.max_retries:
                break
            current = path.read_text(encoding="utf-8")
            candidate = self._fix_test_code(current, output, diagnostic, previous_attempt)
            previous_attempt = current
            if not candidate:
                continue
            candidate = GeneratorAgent._clean_solidity(candidate)
            # Repairs are accepted only after structural validation and Forge compilation.
            target = poc_data.get("target_contract", {"filename": "VulnerableContract.sol", "contract_name": "VulnerableContract", "functions": []})
            errors = self.validator.validate_contract(candidate, {}, target)
            review = self.validator._self_review(candidate, {}, target) if not errors else ""
            compiled, compile_output = self.validator.compile_candidate(candidate) if not errors and not review else (False, "Compilation skipped due to validation failure")
            self._write_repair_log(path, attempt, "build", compile_output)
            if errors or review or not compiled:
                if review:
                    errors.append(f"Self-review: {review}")
                diagnostics.append({"categories": ["RepairValidationError"], "output": "; ".join(errors) or compile_output})
                continue
            path.write_text(candidate, encoding="utf-8")
        return {"success": False, "output": output, "error": output, "file_path": str(path), "retries": self.max_retries, "diagnostics": diagnostics}

    def _execute_test(self, path: Path, attempt: int) -> Tuple[bool, str]:
        relative = path.resolve().relative_to(self.exploit_root.resolve()).as_posix()
        try:
            command = ["forge", "test", "-vv", "--no-cache", "--match-path", f"./{relative}"]
            solc = shutil.which("solc")
            if solc:
                command.extend(["--use", solc])
            result = subprocess.run(
                command,
                cwd=self.exploit_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.model_config.forge_test_timeout,
                env=GeneratorAgent._forge_env(),
            )
            output = (result.stdout or "") + ("\n" if result.stdout and result.stderr else "") + (result.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            output, result = f"Unable to execute forge test: {exc}", None
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        log = reports / f"forge_{path.stem}_{int(time.time() * 1000)}_attempt{attempt}.log"
        log.write_text(output, encoding="utf-8")
        return bool(result and result.returncode == 0 and "FAIL" not in output), output

    def _write_repair_log(self, path: Path, attempt: int, stage: str, output: str) -> None:
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        (reports / f"repair_{path.stem}_{int(time.time() * 1000)}_attempt{attempt}_{stage}.log").write_text(output, encoding="utf-8")

    @staticmethod
    def _diagnose(output: str) -> Dict:
        categories = [label for label, pattern in {
            "ParserError": r"ParserError", "TypeError": r"TypeError", "DeclarationError": r"DeclarationError",
            "CompilerError": r"(?:CompilerError|Error \(\d+\))", "Revert": r"\brevert(?:ed)?\b",
            "RuntimeFailure": r"(?:runtime error|Execution failed)", "OutOfGas": r"out of gas",
            "Panic": r"\bPanic\b", "MissingImport": r"(?:not found|No such file|failed to resolve import)",
            "MissingContract": r"(?:Identifier not found|not a contract)", "FailedAssertion": r"(?:AssertionFailed|assert(?:Eq|True|False)|FAIL)",
        }.items() if re.search(pattern, output, re.I)]
        return {"categories": categories or ["UnknownFailure"], "output": output}

    def _fix_test_code(self, current: str, output: str, diagnostic: Dict, previous: str) -> Optional[str]:
        prompt = f"""Rewrite this complete Foundry test to repair the reported failure. Do not regenerate blindly: preserve the intended exploit and directly address every compiler/runtime diagnostic. Return only complete Solidity.

CURRENT SOLIDITY:
{current}

COMPLETE FORGE OUTPUT:
{output}

DIAGNOSTICS: {diagnostic}
PREVIOUS ATTEMPT: {previous or 'none'}
"""
        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.client.chat.completions.create(model=self.model_name, messages=messages)
            return response.choices[0].message.content or None
        except Exception as exc:
            print_warning(f"Unable to request PoC repair: {exc}")
            return None
