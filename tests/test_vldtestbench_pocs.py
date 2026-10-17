from pathlib import Path

from llm_agents.agents.generator import GeneratorAgent
from llm_agents.agents.analyzer import AnalyzerAgent
from static_analysis.parse_contract import analyze_contract


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "uploads" / "edb3526f-1f9e-4713-9adb-14c5a55cbb2c_PastedContract.sol"


def _target():
    source = SOURCE.read_text(encoding="utf-8")
    return {
        "filename": SOURCE.name,
        "contract_name": "VLDTestBench",
        "functions": GeneratorAgent._source_functions(source),
        "public_members": GeneratorAgent._public_members(source),
        "pragma": GeneratorAgent._pragma(source),
        "constructor": GeneratorAgent._constructor_signature(source),
        "source": source,
    }


def test_reentrancy_regression_uses_actual_vulnerable_entrypoint():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    finding = {"vulnerability_type": "reentrancy", "affected_functions": ["withdrawVulnerable(uint256)"]}
    code = agent._deterministic_poc(finding, _target())

    assert "target.withdrawVulnerable(amount)" in code
    assert "contract ReentrancyReceiver" in code
    assert "bool succeeded = receiver.attack{value: 1 ether}();" in code
    assert "assertFalse(succeeded);" in code
    assert "vm.expectRevert" not in code
    assert "testDemonstration" in code
    assert agent.validate_contract(code, finding, _target()) == []


def test_randomness_poc_uses_local_controls_without_contract_name_collision():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    finding = {"vulnerability_type": "bad_randomness", "affected_functions": ["guessNumber(uint256)"]}
    code = agent._deterministic_poc(finding, _target())

    assert "contract PocTest" in code
    assert "contract VLDTestBench is BaseTestWithBalanceLog" not in code
    assert "vm.warp" in code and "vm.prevrandao" in code
    assert "target.guessNumber{value: 1 ether}(predicted)" in code
    assert agent.validate_contract(code, finding, _target()) == []


def test_vldtestbench_detects_only_unprotected_emergency_withdrawal_and_tx_origin():
    source = SOURCE.read_text(encoding="utf-8")
    details, _, _ = analyze_contract(str(SOURCE))
    findings = AnalyzerAgent._add_deterministic_findings([], {"source_code": source, "function_details": details})
    by_function = {function for finding in findings for function in finding["affected_functions"]}
    assert "emergencyWithdrawVulnerable(address)" in by_function
    assert "emergencyWithdrawSecure(address)" not in by_function
    assert "txOriginAuthentication()" in by_function


def test_access_control_poc_checks_secure_counterpart_when_available():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    finding = {"vulnerability_type": "access_control", "affected_functions": ["changeOwnerVulnerable(address)"]}
    code = agent._deterministic_poc(finding, _target())
    assert "target.changeOwnerSecure(attacker)" in code
    assert "vm.expectRevert()" in code
    assert "target.changeOwnerVulnerable(attacker)" in code
