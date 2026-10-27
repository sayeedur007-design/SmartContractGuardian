from pathlib import Path
from types import SimpleNamespace

from llm_agents.agents.runner import ExploitRunner


def _runner(tmp_path, retries=1):
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = retries
    runner.project_root = tmp_path
    runner.exploit_root = tmp_path / "exploit"
    runner.validator = SimpleNamespace(
        compile_candidate=lambda code, attempt=0: {
            "compiled": True, "compile_error": "", "stdout": "", "stderr": "",
            "output": "", "compile_time": 0.01,
        },
        validate_contract=lambda code, vulnerability, target: [],
        _function_body=lambda code, name: code,
        _has_meaningful_impact_assertion=lambda code: True,
    )
    runner._cleanup_job_workspace = lambda _path: None
    runner._write_repair_artifacts = lambda *_args: None
    return runner


def _execution(output, *, success=False, timeout=False, returncode=1, failure_reason="Revert"):
    return {
        "executed": not timeout,
        "success": success,
        "is_timeout": timeout,
        "runtime_error": "Execution timed out" if timeout else output,
        "stdout": output,
        "stderr": "",
        "output": output,
        "execution_time": 0.01,
        "gas_used": None,
        "execution_trace": output,
        "failure_reason": "TIMEOUT" if timeout else failure_reason,
        "returncode": None if timeout else returncode,
        "command": ["forge", "test"],
        "workspace": "mock-workspace",
    }


def _poc(path, source="original candidate"):
    path.write_text(source, encoding="utf-8")
    return {
        "exploit_file": str(path),
        "compiled": True,
        "poc_strategy": "executable",
        "target_contract": {
            "filename": "Vault.sol", "contract_name": "Vault", "pragma": "^0.8.20",
            "constructor": "constructor(address owner)", "functions": ["withdraw(uint256)"],
            "public_members": ["balances"],
        },
        "vulnerability": {
            "vulnerability_type": "reentrancy", "reasoning": "external call precedes state update",
            "affected_functions": ["withdraw(uint256)"],
        },
        "exploit_plan": {"execution_steps": ["withdraw twice"]},
    }


def test_forge_output_classifies_runtime_revert_and_assertion_failure():
    assert "Revert" in ExploitRunner._diagnose("[FAIL: EvmError: Revert] testExploit()") ["categories"]
    assert ExploitRunner._failure_reason("[FAIL: assertion failed] testExploit()", 1) == "FailedAssertion"


def test_repair_prompt_receives_full_output_objective_and_target_metadata(tmp_path):
    runner = _runner(tmp_path)
    prompts = []
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="repaired"))])
    runner.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **kwargs: prompts.append(kwargs["messages"][0]["content"]) or response
    )))
    runner.model_name = "test-model"
    output = "[FAIL: assertion failed] testExploit()\nrevert data 0x1234"
    target = _poc(tmp_path / "unused.t.sol")["target_contract"]

    result = runner._fix_test_code(
        "failed source", output, runner._diagnose(output), "previous source", target,
        {"vulnerability_type": "reentrancy", "reasoning": "state update is late"},
        {"execution_steps": ["withdraw twice"]},
    )

    assert result == "repaired"
    prompt = prompts[0]
    for expected in (output, "failed source", "Vault.sol", "constructor(address owner)", "state update is late", "withdraw twice"):
        assert expected in prompt


def test_changed_repair_is_validated_recompiled_and_executed(tmp_path):
    runner = _runner(tmp_path)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    compiled, validated, repaired_calls = [], [], []
    repair_context = []
    runner.validator.compile_candidate = lambda code, attempt=0: compiled.append(code) or {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "", "output": "", "compile_time": 0.01,
    }
    runner.validator.validate_contract = lambda code, vulnerability, target: validated.append((code, vulnerability, target)) or []
    runner._execute_test = lambda _path, attempt, code: (
        repaired_calls.append(code) or (_execution("[FAIL: EvmError: Revert]", failure_reason="Revert") if attempt == 0
                                       else _execution("[PASS] testExploit()", success=True, returncode=0, failure_reason=""))
    )
    runner._fix_test_code = lambda *args: repair_context.append(args) or "meaningfully repaired candidate"

    result = runner.run_and_fix_exploit(poc)

    assert compiled == ["original candidate", "meaningfully repaired candidate"]
    assert repaired_calls == compiled
    assert validated[0][0] == "meaningfully repaired candidate"
    assert validated[0][1] == poc["vulnerability"]
    assert repair_context[0][4] == poc["target_contract"]
    assert repair_context[0][5] == poc["vulnerability"]
    assert repair_context[0][6] == poc["exploit_plan"]
    assert result["runner_state"] == "PASSED"
    assert result["impact_verified"] is True


def test_unchanged_repair_is_not_recompiled(tmp_path):
    runner = _runner(tmp_path, retries=2)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    compile_calls, fix_calls = [], []
    runner.validator.compile_candidate = lambda code, attempt=0: compile_calls.append(code) or {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "", "output": "", "compile_time": 0.01,
    }
    runner._execute_test = lambda *_args: _execution("[FAIL: assertion failed] testExploit()", failure_reason="FailedAssertion")
    runner._fix_test_code = lambda current, *_args: fix_calls.append(current) or current

    runner.run_and_fix_exploit(poc)

    assert compile_calls == ["original candidate"]
    assert fix_calls == ["original candidate"]


def test_execution_timeout_stops_without_repair_retry(tmp_path):
    runner = _runner(tmp_path, retries=2)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    fix_calls = []
    runner._execute_test = lambda *_args: _execution("", timeout=True)
    runner._fix_test_code = lambda *_args: fix_calls.append(True) or "repaired"

    result = runner.run_and_fix_exploit(poc)

    assert result["runner_state"] == "TIMEOUT"
    assert result["is_timeout"] is True
    assert fix_calls == []


def test_forge_launch_error_is_not_sent_for_llm_repair(tmp_path):
    runner = _runner(tmp_path, retries=2)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    runner._execute_test = lambda *_args: {
        **_execution("Unable to execute forge test: executable not found", returncode=None, failure_reason="ForgeLaunchError"),
        "executed": False,
    }
    fix_calls = []
    runner._fix_test_code = lambda *_args: fix_calls.append(True) or "should not be used"

    result = runner.run_and_fix_exploit(poc)

    assert result["runner_state"] == "ERROR"
    assert result["failure_reason"] == "ForgeLaunchError"
    assert fix_calls == []


def test_repair_rejected_by_validation_is_never_compiled_or_executed(tmp_path):
    runner = _runner(tmp_path, retries=2)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    compile_calls, execution_calls = [], []
    runner.validator.compile_candidate = lambda code, attempt=0: compile_calls.append(code) or {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "", "output": "", "compile_time": 0.01,
    }
    runner.validator.validate_contract = lambda *_args: ["security-impact assertion missing"]
    runner._execute_test = lambda *_args: execution_calls.append(True) or _execution(
        "[FAIL: assertion failed]", failure_reason="FailedAssertion"
    )
    runner._fix_test_code = lambda *_args: "candidate rejected by validation"

    result = runner.run_and_fix_exploit(poc)

    assert compile_calls == ["original candidate"]
    assert execution_calls == [True]
    assert any("RepairValidationError" in item["categories"] for item in result["diagnostics"])


def test_successful_forge_execution_without_impact_is_not_demonstrated(tmp_path):
    runner = _runner(tmp_path, retries=2)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    runner.validator.validate_contract = lambda *_args: [
        "PoC does not demonstrate the selected vulnerability impact"
    ]
    execution_calls, fix_calls = [], []
    runner._execute_test = lambda *_args: execution_calls.append(True) or _execution(
        "[PASS] testExploit()", success=True, returncode=0, failure_reason=""
    )
    runner._fix_test_code = lambda *_args: fix_calls.append(True) or "changed"

    result = runner.run_and_fix_exploit(poc)

    assert result["runner_state"] == "NOT_DEMONSTRATED"
    assert result["executed"] is True
    assert result["impact_verified"] is False
    assert result["success"] is False
    assert "selected vulnerability impact" in result["runtime_error"]
    assert execution_calls == [True]
    assert fix_calls == []


def test_final_compile_failure_does_not_retain_previous_candidate_execution_status(tmp_path):
    runner = _runner(tmp_path, retries=1)
    path = tmp_path / "PoC.t.sol"
    poc = _poc(path)
    compile_count = []

    def compile_candidate(code, attempt=0):
        compile_count.append(code)
        if len(compile_count) == 1:
            return {"compiled": True, "compile_error": "", "stdout": "", "stderr": "", "output": "", "compile_time": 0.01}
        return {"compiled": False, "compile_error": "ParserError: broken repair", "stdout": "", "stderr": "", "output": "ParserError: broken repair", "compile_time": 0.01}

    runner.validator.compile_candidate = compile_candidate
    runner._execute_test = lambda *_args: _execution("[FAIL: assertion failed]", failure_reason="FailedAssertion")
    runner._fix_test_code = lambda *_args: "repaired candidate"

    result = runner.run_and_fix_exploit(poc)

    assert compile_count == ["original candidate", "repaired candidate"]
    assert result["compiled"] is False
    assert result["executed"] is False
    assert result["final_candidate"] == "repaired candidate"
    assert result["final_attempt"] == 2
