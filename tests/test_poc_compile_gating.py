from pathlib import Path
from types import SimpleNamespace

from llm_agents.agents.generator import GeneratorAgent
from llm_agents.agents.runner import ExploitRunner


def _generator(tmp_path, attempts=3):
    agent = GeneratorAgent.__new__(GeneratorAgent)
    agent.model_config = SimpleNamespace(poc_generation_attempts=attempts)
    agent.project_root = tmp_path
    agent.exploit_root = tmp_path / "exploit"
    agent.workspace_root = agent.exploit_root / "tmp"
    agent.test_dir = agent.exploit_root / "test"
    agent.test_dir.mkdir(parents=True)
    (agent.test_dir / "basetest.sol").write_text("// test helper", encoding="utf-8")
    return agent


def _target():
    return {
        "filename": "Target.sol",
        "contract_name": "Target",
        "functions": ["withdraw(uint256)"],
        "public_members": ["balances"],
        "pragma": "^0.8.20",
        "constructor": "constructor()",
    }


def _compile_failure(returncode=1):
    return {
        "compiled": False,
        "compile_error": "Error (9640): invalid conversion",
        "stdout": "forge stdout",
        "stderr": "forge stderr",
        "output": "forge stdout\nforge stderr",
        "returncode": returncode,
        "compile_time": 0.01,
    }


def test_generator_stops_after_compilation_failures_without_runner_candidate(tmp_path):
    agent = _generator(tmp_path)
    agent._resolve_target = lambda _: _target()
    agent.generate_poc_contract = lambda *_: "contract PocTest {}"
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compile_calls = []

    def compile_candidate(code, attempt):
        compile_calls.append((code, attempt))
        return _compile_failure()

    agent.compile_candidate = compile_candidate
    result = agent.generate({"vulnerability": {"vulnerability_type": "reentrancy"}})

    assert len(compile_calls) == 1
    assert result["poc_status"] == "COMPILATION_FAILED"
    assert result["compiled"] is False
    assert result["exploit_file"] == ""
    assert result["compile_returncode"] == 1
    assert result["compile_stderr"] == "forge stderr"


def test_next_generation_attempt_receives_diagnostic_and_recompiles_repaired_source(tmp_path):
    agent = _generator(tmp_path, attempts=2)
    agent._resolve_target = lambda _: _target()
    seen_failures = []

    def generate_source(_, __, ___, failures, attempt, ____):
        seen_failures.append((attempt, failures))
        return "first source" if attempt == 1 else "repaired source"

    agent.generate_poc_contract = generate_source
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compiled_sources = []

    def compile_candidate(code, attempt):
        compiled_sources.append((code, attempt))
        if attempt == 1:
            return _compile_failure()
        return {"compiled": True, "stdout": "", "stderr": "", "output": "", "returncode": 0, "compile_time": 0.01}

    agent.compile_candidate = compile_candidate
    plan = {
        "setup_steps": ["Fund target and deploy receiver"],
        "execution_steps": ["Call withdraw and re-enter"],
        "validation_steps": ["Assert receiver balance exceeds its deposit"],
    }
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}, "exploit_plan": plan})

    assert "Error (9640): invalid conversion" in seen_failures[1][1][0]
    assert compiled_sources == [("first source", 1), ("repaired source", 2)]
    assert result["compiled"] is True
    assert result["exploit_plan"] == plan
    assert Path(result["exploit_file"]).read_text(encoding="utf-8") == "repaired source"


def test_failed_deterministic_template_falls_back_with_compile_diagnostic(tmp_path):
    agent = _generator(tmp_path, attempts=2)
    agent._resolve_target = lambda _: _target()
    deterministic = "contract DeterministicPoc {}"
    agent._deterministic_poc = lambda *_: deterministic
    prompts = []
    agent._chat = lambda prompt: prompts.append(prompt) or "contract ModelRepair {}"
    agent._clean_solidity = lambda code: code
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compiled_sources = []

    def compile_candidate(code, attempt):
        compiled_sources.append((code, attempt))
        return _compile_failure() if attempt == 1 else {
            "compiled": True, "stdout": "", "stderr": "", "output": "",
            "returncode": 0, "compile_time": 0.01,
        }

    agent.compile_candidate = compile_candidate
    result = agent.generate({
        "vulnerability": {"vulnerability_type": "access_control", "reasoning": "missing authorization"},
        "exploit_plan": {"execution_steps": ["call target"]},
    })

    assert compiled_sources == [(deterministic, 1), ("contract ModelRepair {}\n", 2)]
    assert "Error (9640): invalid conversion" in prompts[0]
    assert deterministic in prompts[0]
    assert result["compiled"] is True


def test_supported_compiler_error_repairs_and_recompiles_candidate(tmp_path):
    agent = _generator(tmp_path, attempts=1)
    agent._resolve_target = lambda _: _target()
    source = "uint256 actorId; address actor = address(actorId);"
    agent.generate_poc_contract = lambda *_: source
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compiled = []

    def compile_candidate(code, attempt):
        compiled.append(code)
        if len(compiled) == 1:
            return {**_compile_failure(), "compile_error": 'TypeError: Explicit type conversion not allowed from "uint256" to "address".'}
        return {"compiled": True, "stdout": "", "stderr": "", "output": "", "returncode": 0, "compile_time": 0.01}

    agent.compile_candidate = compile_candidate
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert compiled == [source, "uint256 actorId; address actor = address(uint160(actorId));"]
    assert result["compiled"] is True


def test_invalid_super_setup_compiler_error_removes_only_the_invalid_parent_call():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    source = """contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    function setUp() public {
        super.setUp();
        target = new VulnerableBank();
        vm.deal(address(target), 1 ether);
    }
}"""
    diagnostic = (
        'Error (9582): Member "setUp" not found or not visible after argument-dependent '
        'lookup in type(contract super VulnerableBankTest).'
    )

    repaired = agent._repair_compiler_error(source, diagnostic, {})
    unchanged = agent._repair_compiler_error(source, "ParserError: unrelated", {})

    assert "super.setUp()" not in repaired
    assert "target = new VulnerableBank();" in repaired
    assert "vm.deal(address(target), 1 ether);" in repaired
    assert unchanged == source


def test_auto_repair_funds_vm_addr_attacker_before_payable_prank():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = _target()
    vulnerability = {"vulnerability_type": "reentrancy"}
    source = '''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/Target.sol";
contract VulnerableBankTest is BaseTestWithBalanceLog {
    Target target;
    function setUp() public { target = new Target(); }
    function testExploit() public balanceLog {
        address attacker = vm.addr(1);
        vm.startPrank(attacker);
        target.deposit{value: 1 ether}();
        assertEq(target.balances(attacker), 1 ether);
    }
}'''

    repaired = agent._auto_repair_contract(source, vulnerability, target)

    assert "vm.deal(vm.addr(1), 10 ether);" in agent._function_body(repaired, "setUp")
    assert "target.deposit{value: 1 ether}();" in repaired
    assert "assertEq(target.balances(attacker), 1 ether);" in repaired


def test_diagnostics_remain_paired_with_original_and_repaired_candidates(tmp_path):
    agent = _generator(tmp_path, attempts=1)
    agent._resolve_target = lambda _: _target()
    source = "uint256 actorId; address actor = address(actorId);"
    agent.generate_poc_contract = lambda *_: source
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compile_calls = []

    def compile_candidate(code, attempt):
        compile_calls.append(code)
        if len(compile_calls) == 1:
            return {**_compile_failure(), "compile_error": 'Explicit type conversion not allowed from "uint256" to "address"'}
        return {**_compile_failure(), "compile_error": "ParserError: repaired source still has a syntax error"}

    agent.compile_candidate = compile_candidate
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert len(result["validation_errors"]) == 2
    assert source in result["validation_errors"][0]
    assert 'Explicit type conversion' in result["validation_errors"][0]
    assert "address(uint160(actorId))" in result["validation_errors"][1]
    assert "ParserError: repaired source still has a syntax error" in result["validation_errors"][1]


def test_unsupported_compiler_error_reaches_constrained_fallback(tmp_path):
    agent = _generator(tmp_path, attempts=2)
    agent._resolve_target = lambda _: _target()
    original = "candidate that failed"
    seen = []
    agent.generate_poc_contract = lambda _, __, ___, failures, attempt, previous: (
        seen.append((attempt, list(failures), previous)) or (original if attempt == 1 else "fallback candidate")
    )
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compiled = []

    def compile_candidate(code, attempt):
        compiled.append(code)
        return {**_compile_failure(), "compile_error": "ParserError: unsupported syntax error"} if attempt == 1 else {
            "compiled": True, "stdout": "", "stderr": "", "output": "", "returncode": 0, "compile_time": 0.01,
        }

    agent.compile_candidate = compile_candidate
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert compiled == [original, "fallback candidate"]
    assert "ParserError: unsupported syntax error" in seen[1][1][0]
    assert seen[1][2] == original
    assert result["compiled"] is True


def test_unchanged_candidate_is_not_recompiled_after_failure(tmp_path):
    agent = _generator(tmp_path, attempts=2)
    agent._resolve_target = lambda _: _target()
    source = "same failed candidate"
    agent.generate_poc_contract = lambda *_: source
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda *_: []
    agent._self_review = lambda *_: ""
    compiled = []
    agent.compile_candidate = lambda code, attempt: compiled.append(code) or _compile_failure()

    agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert compiled == [source]


def test_compiler_repair_rejected_by_validation_falls_back(tmp_path):
    agent = _generator(tmp_path, attempts=2)
    agent._resolve_target = lambda _: _target()
    original = "uint256 actorId; address actor = address(actorId);"
    seen = []
    agent.generate_poc_contract = lambda _, __, ___, failures, attempt, previous: (
        seen.append((attempt, list(failures), previous)) or (original if attempt == 1 else "validated fallback")
    )
    agent._replace_placeholders = lambda code: code
    agent._auto_repair_contract = lambda code, *_: code
    agent.validate_contract = lambda code, *_: ["repaired candidate rejected"] if "uint160" in code else []
    agent._self_review = lambda *_: ""
    compiled = []

    def compile_candidate(code, attempt):
        compiled.append(code)
        return {**_compile_failure(), "compile_error": 'Explicit type conversion not allowed from "uint256" to "address"'} if attempt == 1 else {
            "compiled": True, "stdout": "", "stderr": "", "output": "", "returncode": 0, "compile_time": 0.01,
        }

    agent.compile_candidate = compile_candidate
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert compiled == [original, "validated fallback"]
    assert "Explicit type conversion" in seen[1][1][0]
    assert result["compiled"] is True


def test_runner_rejects_previously_uncompiled_poc_without_execution():
    runner = ExploitRunner.__new__(ExploitRunner)
    states = []
    result = runner.run_and_fix_exploit(
        {
            "compiled": False,
            "compile_error": "Error: parser failure",
            "compile_stdout": "stdout",
            "compile_stderr": "stderr",
            "compile_output": "stdout\nstderr",
        },
        status_callback=lambda state, detail: states.append((state, detail)),
    )

    assert states[-1] == ("COMPILATION_FAILED", "Error: parser failure")
    assert result["runner_state"] == "COMPILATION_FAILED"
    assert result["compiled"] is False
    assert result["executed"] is False
    assert result["stderr"] == "stderr"
