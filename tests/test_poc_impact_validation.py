import pytest

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


def _ownership_target():
    return {
        "filename": "OwnershipBug.sol",
        "contract_name": "OwnershipBug",
        "functions": ["transferOwnership(address)", "destroy()"],
        "public_members": ["owner"],
        "pragma": "^0.8.20",
        "constructor": "constructor()",
        "source": """pragma solidity ^0.8.20;
contract OwnershipBug {
    address public owner;
    constructor() { owner = msg.sender; }
    function transferOwnership(address newOwner) external { owner = newOwner; }
    function destroy() external { selfdestruct(payable(msg.sender)); }
}""",
    }


def _ownership_finding():
    return {
        "vulnerability_type": "access_control",
        "affected_functions": ["transferOwnership(address)"],
    }


def _ownership_poc():
    return """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/OwnershipBug.sol";
contract PocTest is BaseTestWithBalanceLog {
    OwnershipBug target;
    address attacker = address(0xBAD);
    function setUp() public { target = new OwnershipBug(); vm.deal(attacker, 1 ether); }
    function testExploit() public balanceLog {
        vm.prank(attacker);
        target.transferOwnership(attacker);
        assertEq(target.owner(), attacker);
    }
}"""


def _funded_destroy_poc():
    return """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/OwnershipBug.sol";
contract PocTest is BaseTestWithBalanceLog {
    OwnershipBug target;
    address attacker = address(0xBAD);
    function setUp() public { target = new OwnershipBug(); vm.deal(attacker, 1 ether); }
    function testExploit() public balanceLog {
        assertTrue(target.owner() != attacker);
        vm.deal(address(target), 1 ether);
        uint256 targetBalanceBefore = address(target).balance;
        uint256 attackerBalanceBefore = attacker.balance;
        vm.prank(attacker);
        target.destroy();
        assertEq(attacker.balance, attackerBalanceBefore + targetBalanceBefore);
        assertEq(address(target).balance, 0);
    }
}"""


def _unfunded_destroy_poc(make_attacker_owner=False):
    setup = "target.transferOwnership(attacker);" if make_attacker_owner else ""
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/OwnershipBug.sol";
contract PocTest is BaseTestWithBalanceLog {{
    OwnershipBug target;
    address attacker = address(0xBAD);
    function setUp() public {{ target = new OwnershipBug(); }}
    function testExploit() public balanceLog {{
        {setup}
        vm.prank(attacker);
        target.destroy();
        assertEq(address(target).balance, 0);
    }}
}}"""


def _run_with_real_objective_validator(tmp_path, source, finding):
    candidate = tmp_path / "Candidate.t.sol"
    candidate.write_text(source, encoding="utf-8")
    validator = GeneratorAgent.__new__(GeneratorAgent)
    validator.compile_candidate = lambda *_args, **_kwargs: {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "",
        "output": "", "compile_time": 0.01,
    }
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = 0
    runner.validator = validator
    runner._cleanup_job_workspace = lambda _path: None
    runner._execute_test = lambda *_args: {
        "executed": True, "success": True, "is_timeout": False,
        "runtime_error": "", "stdout": "1 passed", "stderr": "", "output": "1 passed",
        "execution_time": 0.01, "gas_used": None, "execution_trace": "1 passed",
        "failure_reason": "", "returncode": 0,
    }
    return runner.run_and_fix_exploit({
        "exploit_file": str(candidate), "exploit_code": source, "compiled": True,
        "poc_strategy": "executable", "vulnerability": finding,
        "target_contract": _ownership_target(),
    })


def test_unchecked_call_template_measures_unauthorized_value_transfer():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    code = agent._unchecked_call_poc(_target(), _vulnerability())

    assert "vm.deal(address(target), 1 ether)" in code
    assert "attackerBalanceBefore" in code
    assert "assertEq(attacker.balance, attackerBalanceBefore + 1 ether)" in code
    assert agent.validate_contract(code, _vulnerability(), _target()) == []


def test_owner_transfer_requires_caller_and_asserted_new_owner_to_match():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    code = _ownership_poc()
    assert agent.validate_contract(code, _ownership_finding(), _ownership_target()) == []

    mismatched = code.replace(
        "target.transferOwnership(attacker);",
        "target.transferOwnership(address(this));",
    )
    errors = agent.validate_contract(mismatched, _ownership_finding(), _ownership_target())
    assert any("same attacker becomes owner" in error for error in errors)


@pytest.mark.parametrize(
    "vulnerability",
    [
        {"vulnerability_type": "access_control", "affected_functions": ["destroy()"]},
        {"vulnerability_type": "dangerous_selfdestruct", "affected_functions": ["destroy()"]},
    ],
)
def test_destroy_impact_requires_funded_attacker_value_gain(vulnerability):
    agent = GeneratorAgent.__new__(GeneratorAgent)
    assert agent.validate_contract(_funded_destroy_poc(), vulnerability, _ownership_target()) == []

    zero_balance_only = _funded_destroy_poc()
    for line in (
        "        vm.deal(address(target), 1 ether);\n",
        "        uint256 targetBalanceBefore = address(target).balance;\n",
        "        uint256 attackerBalanceBefore = attacker.balance;\n",
        "        vm.prank(attacker);\n",
        "        assertEq(attacker.balance, attackerBalanceBefore + targetBalanceBefore);\n",
        "        assertEq(address(target).balance, 0);\n",
    ):
        zero_balance_only = zero_balance_only.replace(line, "")
    errors = agent.validate_contract(zero_balance_only, vulnerability, _ownership_target())
    assert any("fund the target" in error for error in errors)


@pytest.mark.parametrize(
    "vulnerability",
    [
        {"vulnerability_type": "dangerous_selfdestruct", "affected_functions": ["destroy()"]},
        {"vulnerability_type": "access_control", "affected_functions": ["destroy()"]},
    ],
)
def test_deterministic_destroy_template_proves_attacker_receives_funded_balance(vulnerability):
    agent = GeneratorAgent.__new__(GeneratorAgent)
    code = agent._selfdestruct_poc(_ownership_target(), vulnerability)

    assert "vm.deal(address(target), 1 ether);" in code
    assert "vm.prank(attacker);\n        target.destroy();" in code
    assert "assertEq(attacker.balance, attackerBalanceBefore + targetBalanceBefore);" in code
    assert "assertEq(address(target).balance, 0);" in code
    if vulnerability["vulnerability_type"] == "access_control":
        assert "assertTrue(target.owner() != attacker);" in code
    assert agent.validate_contract(code, vulnerability, _ownership_target()) == []


def test_destroy_template_does_not_claim_attacker_funds_when_owner_is_beneficiary():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = _ownership_target()
    target["source"] = target["source"].replace(
        "selfdestruct(payable(msg.sender));",
        "selfdestruct(payable(owner));",
    )
    vulnerability = {"vulnerability_type": "dangerous_selfdestruct", "affected_functions": ["destroy()"]}

    assert agent._selfdestruct_poc(target, vulnerability) == ""
    candidate = _funded_destroy_poc()
    assert any(
        "does not selfdestruct to msg.sender" in error
        for error in agent.validate_contract(candidate, vulnerability, target)
    )


def test_generated_balance_logger_call_is_removed_without_removing_impact_assertion():
    source = """contract PocTest {
    function testExploit() public {
        assertEq(attacker.balance, 1 ether);
        balanceLog.logBalance(address(this), 0);
    }
}"""

    agent = GeneratorAgent.__new__(GeneratorAgent)
    agent._chat = lambda _prompt: source
    generated = agent.generate_poc_contract(
        {"vulnerability_type": "business_logic", "affected_functions": []},
        {},
        {
            "filename": "OwnershipBug.sol", "contract_name": "OwnershipBug",
            "functions": [], "public_members": [],
            "pragma": "^0.8.20", "constructor": "constructor()",
        },
        [], 1,
    )

    assert "balanceLog.logBalance" not in generated
    assert "assertEq(attacker.balance, 1 ether);" in generated


def test_access_control_destroy_requires_attacker_to_be_non_owner():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    vulnerability = {"vulnerability_type": "access_control", "affected_functions": ["destroy()"]}
    code = _funded_destroy_poc().replace("        assertTrue(target.owner() != attacker);\n", "")

    errors = agent.validate_contract(code, vulnerability, _ownership_target())

    assert any("not the target owner" in error for error in errors)


def test_runner_accepts_owner_takeover_only_after_successful_forge_assertions(tmp_path):
    result = _run_with_real_objective_validator(tmp_path, _ownership_poc(), _ownership_finding())

    assert result["runner_state"] == "PASSED"
    assert result["compiled"] is True and result["executed"] is True
    assert result["impact_verified"] is True and result["success"] is True


@pytest.mark.parametrize(
    "vulnerability, make_attacker_owner",
    [
        ({"vulnerability_type": "access_control", "affected_functions": ["destroy()"]}, True),
        ({"vulnerability_type": "dangerous_selfdestruct", "affected_functions": ["destroy()"]}, False),
    ],
)
def test_runner_rejects_zero_balance_destroy_assertion_as_impact(
    tmp_path, vulnerability, make_attacker_owner
):
    result = _run_with_real_objective_validator(
        tmp_path,
        _unfunded_destroy_poc(make_attacker_owner),
        vulnerability,
    )

    assert result["runner_state"] == "NOT_DEMONSTRATED"
    assert result["compiled"] is True and result["executed"] is True
    assert result["impact_verified"] is False and result["success"] is False
    assert "fund the target" in result["runtime_error"]


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


def test_runner_does_not_verify_source_assertions_when_forge_execution_fails(tmp_path):
    poc_path = Path(tmp_path) / "PoC.t.sol"
    poc_path.write_text("contract PocTest { function testExploit() public { assertTrue(true); } }", encoding="utf-8")
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = 0
    runner.validator = SimpleNamespace(compile_candidate=lambda *_args, **_kwargs: {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "",
        "output": "", "compile_time": 0.01,
    })
    runner._execute_test = lambda *_args: {
        "executed": True, "success": False, "is_timeout": False,
        "runtime_error": "Forge assertion failed", "stdout": "Forge assertion failed",
        "stderr": "", "output": "Forge assertion failed", "execution_time": 0.01,
        "gas_used": None, "execution_trace": "Forge assertion failed",
        "failure_reason": "FailedAssertion", "returncode": 1,
    }
    runner._cleanup_job_workspace = lambda _path: None

    result = runner.run_and_fix_exploit({
        "exploit_file": str(poc_path), "compiled": True, "poc_strategy": "executable",
        "vulnerability": _vulnerability(), "target_contract": _target(),
    })

    assert result["runner_state"] == "FAILED"
    assert result["executed"] is True
    assert result["impact_verified"] is False
    assert result["success"] is False


def test_runner_reports_not_demonstrated_when_passing_test_lacks_valid_objective(tmp_path):
    poc_path = Path(tmp_path) / "PoC.t.sol"
    poc_path.write_text("contract PocTest { function testExploit() public { assertTrue(true); } }", encoding="utf-8")
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = 0
    runner.validator = SimpleNamespace(
        compile_candidate=lambda *_args, **_kwargs: {
            "compiled": True, "compile_error": "", "stdout": "", "stderr": "",
            "output": "", "compile_time": 0.01,
        },
        validate_contract=lambda *_args: ["PoC does not exercise the selected vulnerability impact"],
    )
    runner._execute_test = lambda *_args: {
        "executed": True, "success": True, "is_timeout": False,
        "runtime_error": "", "stdout": "1 passed", "stderr": "", "output": "1 passed",
        "execution_time": 0.01, "gas_used": None, "execution_trace": "1 passed",
        "failure_reason": "", "returncode": 0,
    }
    runner._cleanup_job_workspace = lambda _path: None

    result = runner.run_and_fix_exploit({
        "exploit_file": str(poc_path), "compiled": True, "poc_strategy": "executable",
        "vulnerability": _vulnerability(), "target_contract": _target(),
    })

    assert result["runner_state"] == "NOT_DEMONSTRATED"
    assert result["compiled"] is True and result["executed"] is True
    assert result["impact_verified"] is False and result["success"] is False
    assert "selected vulnerability impact" in result["runtime_error"]


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


def test_executable_reentrancy_rejects_normal_balance_and_revert_assertions():
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
    code = code.replace("assertEq(withdrawn, 2 ether);", "assertEq(target.balances(address(receiver)), 1 ether);")
    code = code.replace("        assertGt(address(receiver).balance, initialDeposit);", "")

    errors = agent.validate_contract(code, vulnerability, target)

    assert any("attacker receives more than its initial deposit" in error for error in errors)
