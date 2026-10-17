from llm_agents.agents.generator import GeneratorAgent
from llm_agents.agents.analyzer import AnalyzerAgent
import shutil
import subprocess
import tempfile
from pathlib import Path


def test_auto_repair_uses_mapping_getter_and_safe_address_cast():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = {"contract_name": "Vault", "public_members": ["balances"], "functions": []}
    code = """pragma solidity ^0.8.20;
import \"./basetest.sol\";
contract Vault is BaseTestWithBalanceLog {
 function testExploit() public { address actor = address(i); target.balanceOf(actor); }
}"""
    repaired = agent._auto_repair_contract(code, {"vulnerability_type": "access_control"}, target)
    assert "contract PocTest is BaseTestWithBalanceLog" in repaired
    assert "address(uint160(i))" in repaired
    assert "target.balances(actor)" in repaired
    assert "assertTrue(true)" not in repaired


def test_auto_repair_preserves_contract_instance_address_casts():
    agent = GeneratorAgent.__new__(GeneratorAgent)
    target = {"contract_name": "Vault", "public_members": [], "functions": []}
    code = """pragma solidity ^0.8.20;
import \"./basetest.sol\";
contract Receiver {}
contract PocTest is BaseTestWithBalanceLog {
 Vault target;
 Receiver receiver;
 function testDemonstration() public { address targetAddress = address(target); address receiverAddress = address(receiver); }
}"""

    repaired = agent._auto_repair_contract(code, {"vulnerability_type": "reentrancy"}, target)

    assert "address(target)" in repaired
    assert "address(receiver)" in repaired
    assert "address(uint160(target))" not in repaired
    assert "address(uint160(receiver))" not in repaired


def test_contract_instance_address_casts_compile_with_solc():
    if not shutil.which("solc"):
        return
    source = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
contract Target {}
contract Receiver {}
contract Poc {
    Target target;
    Receiver receiver;
    function addresses() external view returns (address, address) {
        return (address(target), address(receiver));
    }
}
"""
    with tempfile.TemporaryDirectory() as temporary_directory:
        source_path = Path(temporary_directory) / "Poc.sol"
        source_path.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [shutil.which("solc"), "--bin", str(source_path)],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode == 0, result.stderr


def test_slippage_finding_rejects_ordinary_eth_withdrawal():
    finding = [{"vulnerability_type": "no_slippage_limit_check", "affected_functions": ["withdraw(uint256)"]}]
    contract = {"function_details": [{
        "function": "withdraw", "function_id": "withdraw(uint256)", "visibility": "external",
        "content": "function withdraw(uint256 amount) external { payable(msg.sender).transfer(amount); }",
    }]}
    assert AnalyzerAgent._validate_findings(finding, contract) == []
