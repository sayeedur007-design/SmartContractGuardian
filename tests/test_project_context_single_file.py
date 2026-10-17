import re

from llm_agents.agents.project_context_llm import ProjectContextLLMAgent


def _agent():
    agent = ProjectContextLLMAgent.__new__(ProjectContextLLMAgent)
    agent.contract_pattern = re.compile(r'\b(contract|interface|library)\s+(\w+)(?:\s+is\s+([^\{]+))?\s*\{', re.MULTILINE)
    agent.import_pattern = re.compile(r'\bimport\s+(?:[^;]*?\s+from\s+)?["\']([^"\']+)["\']\s*;', re.MULTILINE)
    return agent


def test_single_file_context_extracts_unprotected_owner_change(tmp_path):
    source = tmp_path / "UnprotectedAdmin.sol"
    source.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract UnprotectedAdmin {
    address public owner;
    constructor() { owner = msg.sender; }
    function changeOwner(address newOwner) external { owner = newOwner; }
}
""",
        encoding="utf-8",
    )

    result = _agent().analyze_project(str(source))

    detail = result["contract_details"][0]
    assert detail["name"] == "UnprotectedAdmin"
    assert detail["state_variables"] == [{"type": "address", "visibility": "public", "name": "owner"}]
    assert {function["signature"] for function in detail["functions"]} == {"constructor()", "changeOwner(address newOwner)"}
    assert detail["generated_getters"] == ["owner()"]
    assert result["dependencies"] == []
    assert result["important_functions"] == ["UnprotectedAdmin.changeOwner(address newOwner)"]
    assert result["stats"]["total_vulnerabilities"] == 1
    assert result["stats"]["total_recommendations"] == 1
    assert "UnprotectedAdmin" in result["mermaid_diagram"]


def test_single_file_context_does_not_invent_owner_risk(tmp_path):
    source = tmp_path / "SecureValue.sol"
    source.write_text(
        """pragma solidity ^0.8.20;
contract SecureValue {
    uint256 public value;
    function setValue(uint256 nextValue) external { value = nextValue; }
}
""",
        encoding="utf-8",
    )

    result = _agent().analyze_project(str(source))

    assert result["dependencies"] == []
    assert result["vulnerabilities"] == []
    assert result["recommendations"] == []
    assert result["important_functions"] == []


def test_single_file_context_tracks_interface_mapping_and_call_relationship(tmp_path):
    source = tmp_path / "ContextAnalysisTest.sol"
    source.write_text(
        """pragma solidity ^0.8.20;
interface IPriceOracle { function getPrice() external view returns (uint256); }
contract ContextAnalysisTest {
    address public owner;
    address public treasury;
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;
    IPriceOracle public priceOracle;
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event TreasuryUpdated(address indexed newTreasury);
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    constructor(address oracle, address initialTreasury) { owner = msg.sender; priceOracle = IPriceOracle(oracle); treasury = initialTreasury; }
    function deposit() external payable { balances[msg.sender] += msg.value; totalDeposits += msg.value; emit Deposited(msg.sender, msg.value); }
    function withdraw(uint256 amount) external { balances[msg.sender] -= amount; totalDeposits -= amount; (bool sent,) = payable(msg.sender).call{value: amount}(""); require(sent); emit Withdrawn(msg.sender, amount); }
    function updateTreasury(address nextTreasury) external onlyOwner { treasury = nextTreasury; emit TreasuryUpdated(nextTreasury); }
    function getOraclePrice() external view returns (uint256) { return priceOracle.getPrice(); }
    function emergencyWithdraw() external onlyOwner { (bool sent,) = payable(treasury).call{value: address(this).balance}(""); require(sent); }
}
""",
        encoding="utf-8",
    )

    result = _agent().analyze_project(str(source))

    interface, contract = result["contract_details"]
    assert interface["type"] == "interface"
    assert interface["functions"][0]["signature"] == "getPrice()"
    assert contract["type"] == "contract"
    assert {item["name"] for item in contract["state_variables"]} == {"owner", "treasury", "totalDeposits", "balances", "priceOracle"}
    assert next(item for item in contract["state_variables"] if item["name"] == "balances")["type"] == "mapping(address => uint256)"
    assert {item["name"] for item in contract["events"]} == {"Deposited", "Withdrawn", "TreasuryUpdated"}
    assert contract["modifiers"] == [{"name": "onlyOwner", "parameters": ""}]
    assert "ContextAnalysisTest calls IPriceOracle.getPrice via priceOracle" in result["dependencies"]
    assert "ContextAnalysisTest.getOraclePrice()" in result["important_functions"]
    assert result["vulnerabilities"] == []
    assert result["recommendations"] == []
    assert 'n1 -->|calls getPrice via priceOracle| n0' in result["mermaid_diagram"]
