"""Foundry PoC generation with deterministic validation and compile gating."""
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from openai import OpenAI

from utils.print_utils import print_success, print_warning
from utils.function_identifiers import canonical_function_id


class GeneratorAgent:
    """Generate only PoCs that pass structural, semantic, and Forge checks."""

    MAX_ATTEMPTS = 3

    def __init__(self, model_config=None):
        from ..config import ModelConfig

        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)
        self.client = OpenAI(
            api_key=os.getenv(api_key_env),
            **self.model_config.get_openai_args(self.model_name),
        )
        self.project_root = Path.cwd()
        self.exploit_root = self.project_root / "exploit"
        # Keep generated tests in Foundry's dedicated test directory.  Putting
        # them below ``src`` makes every old PoC part of all future builds.
        self.test_dir = self.exploit_root / "test"

    def generate(self, exploit_data: Dict) -> Dict:
        """Generate, validate, self-review, compile, then persist a PoC."""
        vulnerability = exploit_data.get("vulnerability", {})
        plan = exploit_data.get("exploit_plan", {}) or {}
        target = self._resolve_target(exploit_data)
        failures: List[str] = []

        self.generate_basetest_file() if not (self.test_dir / "basetest.sol").exists() else None
        for attempt in range(1, self.model_config.poc_generation_attempts + 1):
            code = self.generate_poc_contract(vulnerability, plan, target, failures, attempt)
            errors = self.validate_contract(code, vulnerability, target)
            if errors:
                failures = errors
                print_warning(f"Generator attempt {attempt} rejected: {'; '.join(errors)}")
                continue

            review = self._self_review(code, vulnerability, target)
            if review:
                failures = [f"Self-review: {review}"]
                print_warning(f"Generator attempt {attempt} self-review rejected the contract: {review}")
                continue

            compiled, forge_output = self.compile_candidate(code)
            self._write_generation_log(attempt, "build", forge_output)
            if not compiled:
                failures = [f"Forge build failed:\n{forge_output}"]
                print_warning(f"Generator attempt {attempt} did not compile.")
                continue

            filename = self.save_poc_locally(code, vulnerability.get("vulnerability_type", "unknown"))
            relative = Path(filename).resolve().relative_to(self.exploit_root.resolve()).as_posix()
            return {
                "exploit_code": code,
                "exploit_file": filename,
                "execution_command": f'forge test -vv --match-path "./{relative}"',
                "target_contract": target,
                "compile_output": forge_output,
            }

        return {
            "exploit_code": "",
            "exploit_file": "",
            "execution_command": "",
            "target_contract": target,
            "generation_error": "PoC generation failed after deterministic validation and Forge compilation.",
            "validation_errors": failures,
        }

    def generate_poc_contract(
        self, vulnerability: Dict, plan: Dict, target: Dict, failures: List[str], attempt: int
    ) -> str:
        affected = ", ".join(self._extract_relevant_functions(vulnerability)) or "not specified"
        previous_failures = "None (first attempt)." if not failures else "\n".join(f"- {item}" for item in failures)
        target_import = f'import "../src/{target["filename"]}";'
        target_type = target["contract_name"]
        if target_type == "Test":
            # forge-std exports Test, so importing a target contract named Test
            # without an alias makes every generated PoC uncompilable.
            target_import = f'import {{Test as VulnerableBankTarget}} from "../src/{target["filename"]}";'
            target_type = "VulnerableBankTarget"
        prompt = f"""
You are an expert Solidity security researcher specializing in Foundry proof-of-concept generation.

Your task is to generate ONE complete Forge test that compiles successfully.

Return ONLY Solidity code.

==============================
TARGET CONTRACT
==============================

File:
{target["filename"]}

Contract:
{target["contract_name"]}

Available functions:

{chr(10).join(target.get("functions", []))}

==============================
VULNERABILITY
==============================

Type:
{vulnerability.get("vulnerability_type","")}

Confidence:
{vulnerability.get("confidence_score","")}

Reasoning:
{vulnerability.get("reasoning","")}

Affected Functions:

{affected}

Relevant Solidity snippet:

{vulnerability.get("code_snippet","")}

==============================
EXPLOIT PLAN
==============================

Setup Steps:
{chr(10).join(plan.get("setup_steps", []))}

Execution Steps:
{chr(10).join(plan.get("execution_steps", []))}

Validation Steps:
{chr(10).join(plan.get("validation_steps", []))}

==============================
PREVIOUS FAILURES
==============================

{previous_failures}

==============================
STRICT RULES
==============================

1. Return ONLY Solidity.

2. Do NOT return JSON.

3. Do NOT explain anything.

4. Do NOT include markdown except optional ```solidity``` fences.

5. Import exactly:

import "./basetest.sol";
{target_import}

6. Inherit:

contract PocTest is BaseTestWithBalanceLog

7. Include BOTH functions:

function setUp()

function testExploit() public balanceLog

8. Instantiate the target exactly as:

{target_type} target;

9. Deploy using:

target = new {target_type}();

10. Use vm.deal(...)

11. Use vm.prank(...) or vm.startPrank(...)

12. Include at least ONE Foundry assertion.

13. Call ONLY functions that exist in the Available functions list.

14. Never invent functions.

15. Never call:

balanceOf
approve
transfer
transferFrom
mint
burn

unless they appear in Available functions.

16. If the contract handles ETH, use:

address(target).balance

or

address(attacker).balance

instead of ERC20 APIs.

17. Generate a Forge test that compiles without modification.

18. Use the affected function directly in the exploit.

19. Never use placeholder code.

20. Never reference contracts or state variables that do not exist.

Return ONLY the Solidity source.
"""
        return self._clean_solidity(self._chat(prompt))

    def validate_contract(self, code: str, vulnerability: Dict, target: Dict) -> List[str]:
        """Deterministic checks; this is deliberately independent of model judgement."""
        errors: List[str] = []
        if not re.search(r"^\s*//\s*SPDX-License-Identifier:\s*\S+", code, re.M):
            errors.append("missing SPDX license")
        if not re.search(r"\bpragma\s+solidity\s+[^;]+;", code):
            errors.append("missing pragma")
        imports = re.findall(r"^\s*import\s+(?:[^\"']+from\s+)?[\"']([^\"']+)[\"']\s*;", code, re.M)
        if "./basetest.sol" not in imports:
            errors.append("missing basetest import")
        expected_import = f"../src/{target['filename']}"
        if expected_import not in imports:
            errors.append(f"missing target import {expected_import}")
        if re.search(r"\b(TODO|placeholder|fill\s+here)\b|\.\.\.", code, re.I):
            errors.append("contains placeholder content")
        if not self._braces_match(code):
            errors.append("malformed braces")
        contract_match = re.search(
            r"\bcontract\s+\w+\s+is\s+[^\{]*\bBaseTestWithBalanceLog\b[^\{]*\{", code
        )
        if not contract_match:
            errors.append("missing BaseTestWithBalanceLog test contract")
        setup = self._function_body(code, "setUp")
        test = self._function_body(code, "testExploit")
        if not setup or not re.search(r"\S", self._without_comments(setup)):
            errors.append("missing or empty setUp")
        if not test or not re.search(r"\S", self._without_comments(test)):
            errors.append("missing or empty testExploit")
        # Solidity permits modifiers before or after visibility.  The old
        # expression accepted only one ordering and rejected valid generated
        # tests before Forge could compile them.
        test_signature = re.search(r"function\s+testExploit\s*\([^)]*\)\s*([^\{]*)\{", code)
        if not test_signature or not re.search(r"\bbalanceLog\b", test_signature.group(1)):
            errors.append("testExploit does not use balanceLog")
        if "vm.deal" not in code:
            errors.append("missing vm.deal")
        if not re.search(r"\bvm\.(?:prank|startPrank)\s*\(", code):
            errors.append("missing vm.prank or vm.startPrank")
        if not re.search(r"\bassert(?:Eq|True|False|Gt|Lt|Ge|Le)\s*\(", code):
            errors.append("missing Foundry assertion")
        if not re.search(rf"\b{re.escape(target['contract_name'])}\b", code):
            errors.append("target contract name is not used")
        source_functions = set(target.get("functions", []))
        affected = self._extract_relevant_functions(vulnerability)
        for forbidden in [
            "balanceOf(",
            "approve(",
            "transfer(",
            "transferFrom(",
            "mint(",
            "burn("
        ]:
            if forbidden in code:
                if not any(
                    fn.startswith(forbidden[:-1])
                    for fn in source_functions
                ):
                    errors.append(
                        f"PoC calls nonexistent function {forbidden[:-1]}"
                    )
        for function in affected:
            if source_functions and function not in source_functions:
                errors.append(f"reported affected function does not exist: {function}")
            elif source_functions:
                function_name = function.split("(", 1)[0]
                if not re.search(rf"\.\s*{re.escape(function_name)}\s*\(", code):
                    errors.append(f"PoC does not call affected function: {function}")
        return errors

    def compile_candidate(self, code: str) -> Tuple[bool, str]:
        """Compile a temporary test and never leave it in the persisted test suite."""
        self.test_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.test_dir / f".poc_validation_{uuid.uuid4().hex}.t.sol"
        try:
            temporary.write_text(code, encoding="utf-8")
            relative = temporary.relative_to(self.exploit_root).as_posix()
            # `forge build --contracts` still writes compiler signatures on
            # some Windows nightly builds, even with --no-cache.  Running the
            # isolated test path validates the same compilation unit without
            # touching the global Foundry cache.
            command = ["forge", "test", "--no-cache", "--match-path", f"./{relative}"]
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
                timeout=self.model_config.forge_build_timeout,
                env=self._forge_env(),
            )
            output = (result.stdout or "") + ("\n" if result.stdout and result.stderr else "") + (result.stderr or "")
            return result.returncode == 0, output
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"Unable to run forge build: {exc}"
        finally:
            temporary.unlink(missing_ok=True)

    def _write_generation_log(self, attempt: int, stage: str, output: str) -> None:
        """Keep each generation diagnostic; never overwrite a prior investigation log."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        filename = reports / f"generator_{int(time.time() * 1000)}_attempt{attempt}_{stage}.log"
        filename.write_text(output, encoding="utf-8")

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        self.test_dir.mkdir(parents=True, exist_ok=True)
        safe_vuln = re.sub(r"[^A-Za-z0-9_]", "_", vuln_type) or "unknown"
        filename = self.test_dir / f"PoC_{safe_vuln}_{int(time.time() * 1000)}.t.sol"
        filename.write_text(poc_code, encoding="utf-8")
        print_success(f"PoC saved to {filename}")
        return str(filename)

    def _resolve_target(self, exploit_data: Dict) -> Dict:
        configured = exploit_data.get("target_contract", {})
        candidates = []
        if configured.get("path"):
            candidates.append(self.exploit_root / "src" / configured["path"])
        candidates.extend(path for path in (self.exploit_root / "src").glob("*.sol") if path.name != "basetest.sol")
        for path in candidates:
            if path.exists():
                source = path.read_text(encoding="utf-8")
                contract = configured.get("name") or self._contract_name(source)
                if contract:
                    return {"filename": path.name, "contract_name": contract, "functions": self._source_functions(source)}
        raise RuntimeError("Unable to resolve target contract.")

    @staticmethod
    def _contract_name(source: str) -> Optional[str]:
        match = re.search(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", source)
        return match.group(1) if match else None

    @staticmethod
    def _source_functions(source: str) -> List[str]:
        functions = []
        for name, raw_params in re.findall(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", source):
            types = []
            for raw_param in filter(None, (part.strip() for part in raw_params.split(","))):
                tokens = [token for token in raw_param.split() if token not in {"memory", "storage", "calldata", "payable"}]
                if tokens:
                    types.append(tokens[0])
            functions.append(canonical_function_id(name, types))
        return functions

    @staticmethod
    def _extract_relevant_functions(vulnerability: Dict) -> List[str]:
        values = vulnerability.get("affected_functions", []) or []
        return [str(value).split(".")[-1] for value in values if str(value).strip()]

    def _self_review(self, code: str, vulnerability: Dict, target: Dict) -> str:
        prompt = f"""Review this Solidity Foundry test. Answer exactly PASS, or FAIL: followed by one concrete compilation/rule violation. It must import ./basetest.sol and ../src/{target['filename']}, inherit BaseTestWithBalanceLog, use balanceLog and vm.deal, and exercise {target['contract_name']} for {self._extract_relevant_functions(vulnerability)}.\n\n{code}"""
        try:
            response = self._chat(prompt).strip()
        except Exception as exc:
            return f"review request failed: {exc}"
        return "" if response.upper().startswith("PASS") else response[:2000]

    def _chat(self, prompt: str) -> str:
        messages = ([{"role": "system", "content": "Return precise Solidity engineering output."}, {"role": "user", "content": prompt}]
                    if self.model_config.supports_reasoning(self.model_name) else [{"role": "user", "content": prompt}])
        kwargs = {"model": self.model_name, "messages": messages}
        if self.model_name == "claude-3-7-sonnet-latest":
            kwargs.update(max_tokens=64000, extra_body={"thinking": {"type": "enabled", "budget_tokens": 2000}})
        response = self.client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    @staticmethod
    def _forge_env() -> Dict[str, str]:
        """Give Foundry a Windows home directory when invoked from a service."""
        env = os.environ.copy()
        home = env.get("HOME") or env.get("USERPROFILE") or str(Path.home())
        # svm-rs uses the Windows profile variables while other Foundry
        # components use HOME.  A service process can omit either set.
        env["HOME"] = home
        env["USERPROFILE"] = home
        drive, tail = os.path.splitdrive(home)
        if drive:
            env["HOMEDRIVE"] = drive
            env["HOMEPATH"] = tail or "\\"
        return env

    @staticmethod
    def _clean_solidity(response: str) -> str:
        match = re.search(r"```(?:solidity)?\s*([\s\S]*?)\s*```", response)
        return (match.group(1) if match else response).strip()

    @staticmethod
    def _without_comments(text: str) -> str:
        return re.sub(r"//.*?$|/\*[\s\S]*?\*/", "", text, flags=re.M).strip()

    @staticmethod
    def _braces_match(code: str) -> bool:
        stripped = GeneratorAgent._without_comments(re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', code))
        depth = 0
        for char in stripped:
            if char == "{": depth += 1
            elif char == "}":
                depth -= 1
                if depth < 0: return False
        return depth == 0

    @staticmethod
    def _function_body(code: str, name: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*{{", code)
        if not match: return ""
        start, depth = match.end(), 1
        for index in range(start, len(code)):
            if code[index] == "{": depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0: return code[start:index]
        return ""

    def generate_basetest_file(self) -> str:
        self.test_dir.mkdir(parents=True, exist_ok=True)
        filename = self.test_dir / "basetest.sol"
        if not filename.exists():
            filename.write_text("""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;
import \"forge-std/Test.sol\";
contract BaseTestWithBalanceLog is Test {
    modifier balanceLog() { _; }
}
""", encoding="utf-8")
        return str(filename)
