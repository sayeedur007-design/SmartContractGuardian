from types import SimpleNamespace

import pytest

from llm_agents.agents.generator import GeneratorAgent


def _generator(tmp_path):
    agent = GeneratorAgent.__new__(GeneratorAgent)
    agent.exploit_root = tmp_path / "exploit"
    (agent.exploit_root / "src").mkdir(parents=True)
    return agent


def test_resolves_explicit_valid_target_and_its_metadata(tmp_path):
    agent = _generator(tmp_path)
    (agent.exploit_root / "src" / "Targets.sol").write_text(
        """pragma solidity ^0.8.20;
contract Sibling { function unrelated() external {} }
contract Vault is Base { constructor(address owner_) {} function withdraw(uint256 amount) external {} }
""",
        encoding="utf-8",
    )

    target = agent._resolve_target({"target_contract": {"path": "Targets.sol", "name": "Vault"}})

    assert target["contract_name"] == "Vault"
    assert target["filename"] == "Targets.sol"
    assert target["functions"] == ["withdraw(uint256)"]
    assert target["constructor"] == "constructor(address owner_)"


def test_missing_explicit_path_does_not_fall_back(tmp_path):
    agent = _generator(tmp_path)
    (agent.exploit_root / "src" / "Other.sol").write_text("contract Other {}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Invalid target path 'Missing.sol'"):
        agent._resolve_target({"target_contract": {"path": "Missing.sol"}})


def test_requested_contract_must_be_declared_in_explicit_file(tmp_path):
    agent = _generator(tmp_path)
    (agent.exploit_root / "src" / "Targets.sol").write_text("contract Actual {}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="'Wanted'.*not declared in 'Targets.sol'"):
        agent._resolve_target({"target_contract": {"path": "Targets.sol", "name": "Wanted"}})


def test_multiple_contracts_selects_requested_contract_and_keeps_legacy_first_default(tmp_path):
    agent = _generator(tmp_path)
    source = """contract First { function first() external {} }
contract Second { constructor(uint256 value) {} function second() external {} }
"""
    (agent.exploit_root / "src" / "Targets.sol").write_text(source, encoding="utf-8")

    selected = agent._resolve_target({"target_contract": {"path": "Targets.sol", "name": "Second"}})
    default = agent._resolve_target({"target_contract": {"path": "Targets.sol"}})

    assert selected["contract_name"] == "Second"
    assert selected["functions"] == ["second()"]
    assert selected["constructor"] == "constructor(uint256 value)"
    assert default["contract_name"] == "First"
    assert default["functions"] == ["first()"]
