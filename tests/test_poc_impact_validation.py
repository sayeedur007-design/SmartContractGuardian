from llm_agents.agents.generator import GeneratorAgent
from llm_agents.agents.runner import ExploitRunner
from pathlib import Path
from types import SimpleNamespace


def _target():
    return {
        "filename": "VulnerableBank.sol",
        "contract_name": "VulnerableBank",
        "functions": ["unsafeSend(address,uint256)"],
        "public_members": [],
        "pragma": "^0.8.20",
        "constructor": "constructor()",
    }


def _vulnerability():
    return {
        "vulnerability_type": "unchecked_low_level_calls",
        "affected_functions": ["unsafeSend(address,uint256)"],
    }


def test_unchecked_call_template_measures_unauthorized_value_transfer():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    code = agent._unchecked_call_poc(_target(), _vulnerability())

    assert "vm.deal(address(target), 1 ether)" in code
    assert "attackerBalanceBefore" in code
    assert "assertEq(attacker.balance, attackerBalanceBefore + 1 ether)" in code
    assert agent.validate_contract(code, _vulnerability(), _target()) == []


def test_executable_poc_rejects_tautological_success_assertion():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    code = agent._unchecked_call_poc(_target(), _vulnerability()).replace(
        "assertEq(attacker.balance, attackerBalanceBefore + 1 ether);",
        "assertTrue(true);",
    )

    assert any("security-impact assertion" in error for error in agent.validate_contract(code, _vulnerability(), _target()))


def test_runner_does_not_report_exploit_success_without_impact_verification():
    runner = ExploitRunner.__new__(ExploitRunner)
    result = runner._result(
        compile_result={"compiled": True},
        execution_result={"executed": True, "success": True, "impact_verified": False},
    )

    assert result["compiled"] is True
    assert result["executed"] is True
    assert result["impact_verified"] is False
    assert result["success"] is False


def test_runner_reports_verified_executable_impact_only_after_test_success():
    runner = ExploitRunner.__new__(ExploitRunner)
    result = runner._result(
        compile_result={"compiled": True},
        execution_result={"executed": True, "success": True, "impact_verified": True},
        runner_state="PASSED",
    )

    assert result["runner_state"] == "PASSED"
    assert result["compiled"] is True
    assert result["executed"] is True
    assert result["impact_verified"] is True
    assert result["success"] is True


def test_runner_keeps_passing_regression_separate_from_verified_exploit():
    runner = ExploitRunner.__new__(ExploitRunner)
    result = runner._result(
        compile_result={"compiled": True},
        execution_result={"executed": True, "success": True, "impact_verified": False},
        runner_state="NOT_DEMONSTRATED",
    )

    assert result["runner_state"] == "NOT_DEMONSTRATED"
    assert result["success"] is False


def test_runner_preserves_failed_regression_without_llm_repairs(tmp_path):
    poc_path = Path(tmp_path) / "PoC_reentrancy.t.sol"
    poc_path.write_text("contract PocTest {}", encoding="utf-8")
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = 3
    runner.validator = SimpleNamespace(compile_candidate=lambda *_args, **_kwargs: {
        "compiled": True, "compile_error": "", "stdout": "compile output", "stderr": "",
        "output": "compile output", "compile_time": 0.01,
    })
    runner._execute_test = lambda *_args: {
        "executed": True, "success": False, "is_timeout": False,
        "runtime_error": "[FAIL: assertion failed] testDemonstration()",
        "stdout": "[FAIL: assertion failed] testDemonstration()", "stderr": "",
        "output": "[FAIL: assertion failed] testDemonstration()", "execution_time": 0.01,
        "gas_used": None, "execution_trace": "[FAIL: assertion failed] testDemonstration()",
        "failure_reason": "FailedAssertion", "returncode": 1, "command": ["forge", "test"], "workspace": "temporary",
    }
    runner._cleanup_job_workspace = lambda _path: None
    runner._fix_test_code = lambda *_args: (_ for _ in ()).throw(AssertionError("must not repair regression"))
    states = []

    result = runner.run_and_fix_exploit(
        {"exploit_file": str(poc_path), "compiled": True, "poc_strategy": "regression"},
        status_callback=lambda state, detail: states.append((state, detail)),
    )

    assert states[-1][0] == "TEST_FAILED"
    assert result["runner_state"] == "TEST_FAILED"
    assert result["executed"] is True
    assert result["success"] is False
    assert result["execution_returncode"] == 1


def test_checked_arithmetic_reentrancy_template_is_a_non_exploit_regression():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = {
        "filename": "ReentrancyVulnerable.sol",
        "contract_name": "ReentrancyVulnerable",
        "functions": ["deposit()", "withdraw(uint256)"],
        "public_members": ["balances"],
        "pragma": "^0.8.20",
        "constructor": "constructor()",
        "source": "function withdraw(uint256 amount) external { (bool ok,) = msg.sender.call{value: amount}(\"\"); balances[msg.sender] -= amount; }",
    }
    vulnerability = {"vulnerability_type": "reentrancy", "affected_functions": ["withdraw(uint256)"]}
    code = agent._deterministic_poc(vulnerability, target)

    assert agent._validation_mode(vulnerability, target) == "regression"
    assert "testDemonstration" in code
    assert "assertFalse(succeeded);" in code
    assert "assertEq(target.balances(address(receiver)), 1 ether);" in code
    assert "vm.expectRevert" not in code


def test_unchecked_reentrancy_template_requires_excess_withdrawal_assertion():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = {
        "filename": "UncheckedVault.sol",
        "contract_name": "UncheckedVault",
        "functions": ["deposit()", "withdraw(uint256)"],
        "public_members": ["balances"],
        "pragma": "^0.8.20",
        "constructor": "constructor()",
        "source": "function withdraw(uint256 amount) external { (bool ok,) = msg.sender.call{value: amount}(\"\"); unchecked { balances[msg.sender] -= amount; } }",
    }
    vulnerability = {"vulnerability_type": "reentrancy", "affected_functions": ["withdraw(uint256)"]}
    code = agent._deterministic_poc(vulnerability, target)

    assert agent._validation_mode(vulnerability, target) == "executable"
    assert "function testExploit" in code
    assert "assertTrue(succeeded);" in code
    assert "assertGt(address(receiver).balance, initialDeposit);" in code
    assert agent.validate_contract(code, vulnerability, target) == []
