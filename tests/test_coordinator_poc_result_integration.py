import pytest
from pathlib import Path
from types import SimpleNamespace

from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.agents.runner import ExploitRunner


@pytest.mark.parametrize(
    "run_result, expected_state",
    [
        ({"runner_state": "COMPILATION_FAILED", "compiled": False, "executed": False}, "COMPILATION_FAILED"),
        ({"runner_state": "TIMEOUT", "compiled": True, "executed": True, "is_timeout": True}, "TIMEOUT"),
        ({"runner_state": "ERROR", "compiled": True, "executed": False, "failure_reason": "ForgeLaunchError"}, "ERROR"),
        ({"runner_state": "FAILED", "compiled": True, "executed": True, "failure_reason": "Revert"}, "FAILED"),
        ({"runner_state": "NOT_DEMONSTRATED", "compiled": True, "executed": True, "success": False}, "NOT_DEMONSTRATED"),
    ],
)
def test_coordinator_preserves_runner_failure_states(run_result, expected_state):
    poc = {"exploit_code": "generated source"}

    recorded = AgentCoordinator._record_runner_result(poc, run_result)

    assert recorded["runner_state"] == expected_state
    assert recorded["success"] is False
    assert recorded["impact_verified"] is False


def test_coordinator_requires_explicit_impact_verification_for_success():
    contradictory = {
        "runner_state": "PASSED", "compiled": True, "executed": True, "success": True,
    }

    recorded = AgentCoordinator._record_runner_result({}, contradictory)

    assert recorded["success"] is False
    assert recorded["impact_verified"] is False


def test_coordinator_accepts_only_verified_pass_and_syncs_final_candidate():
    poc = {"exploit_code": "initial candidate"}
    runner_result = {
        "runner_state": "PASSED", "compiled": True, "executed": True,
        "success": True, "impact_verified": True,
        "final_candidate": "repaired candidate", "final_attempt": 2,
        "is_timeout": False, "failure_reason": "",
    }

    recorded = AgentCoordinator._record_runner_result(poc, runner_result)

    assert recorded["success"] is True
    assert recorded["impact_verified"] is True
    assert recorded["final_attempt"] == 2
    assert poc["exploit_code"] == "repaired candidate"


def test_passing_regression_stays_not_demonstrated_through_coordinator(tmp_path):
    candidate = Path(tmp_path) / "PoC.t.sol"
    source = "contract PocTest { function testDemonstration() public { assertTrue(true); } }"
    candidate.write_text(source, encoding="utf-8")
    runner = ExploitRunner.__new__(ExploitRunner)
    runner.max_retries = 0
    runner.validator = SimpleNamespace(compile_candidate=lambda *_args, **_kwargs: {
        "compiled": True, "compile_error": "", "stdout": "", "stderr": "",
        "output": "", "compile_time": 0.01,
    })
    runner._execute_test = lambda *_args: {
        "executed": True, "success": True, "is_timeout": False,
        "runtime_error": "", "stdout": "1 passed", "stderr": "", "output": "1 passed",
        "execution_time": 0.01, "gas_used": None, "execution_trace": "1 passed",
        "failure_reason": "", "returncode": 0,
    }
    runner._cleanup_job_workspace = lambda _path: None
    poc = {
        "exploit_file": str(candidate), "exploit_code": source, "compiled": True,
        "poc_strategy": "regression", "vulnerability": {"vulnerability_type": "reentrancy"},
        "exploit_plan": {"validation_steps": ["Check attacker gain"]},
        "target_contract": {"contract_name": "Vault"},
    }

    runner_result = runner.run_and_fix_exploit(poc)
    recorded = AgentCoordinator._record_runner_result(poc, runner_result)

    assert runner_result["runner_state"] == recorded["runner_state"] == "NOT_DEMONSTRATED"
    assert runner_result["compiled"] is True and runner_result["executed"] is True
    assert runner_result["impact_verified"] is False
    assert runner_result["success"] is recorded["success"] is False
    assert "reverted before a security impact" in recorded["runtime_error"]


def test_coordinator_does_not_preserve_positive_impact_on_not_demonstrated_result():
    recorded = AgentCoordinator._record_runner_result({}, {
        "runner_state": "NOT_DEMONSTRATED", "compiled": True, "executed": True,
        "success": True, "impact_verified": True,
        "runtime_error": "Impact evidence did not match the finding.",
    })

    assert recorded["runner_state"] == "NOT_DEMONSTRATED"
    assert recorded["impact_verified"] is False
    assert recorded["success"] is False
    assert recorded["runtime_error"] == "Impact evidence did not match the finding."


def test_coordinator_does_not_print_generated_demonstration_for_compile_failure(capsys):
    finding = {
        "vulnerability_type": "dangerous_selfdestruct",
        "affected_functions": ["destroy()"],
        "confidence_score": 0.9,
        "skeptic_confidence": 0.9,
    }
    coordinator = AgentCoordinator.__new__(AgentCoordinator)
    coordinator.model_config = SimpleNamespace(skip_poc_generation=False)
    coordinator.runner = SimpleNamespace(max_retries=0)
    coordinator.analyzer = SimpleNamespace(
        analyze=lambda _contract: {"vulnerabilities": [finding]},
        _deduplicate_vulnerabilities=lambda items: items,
    )
    coordinator.skeptic = SimpleNamespace(audit_vulnerabilities=lambda *_args: [finding])
    coordinator.exploiter = SimpleNamespace(
        generate_exploit_plan=lambda _finding: {"exploit_plan": {"execution_steps": ["call destroy"]}},
    )
    coordinator.generator = SimpleNamespace(generate=lambda _data: {
        "exploit_file": "",
        "exploit_code": "",
        "generation_error": "Forge compilation failed",
        "poc_strategy": "compilation_failed",
        "compiled": False,
    })

    coordinator.analyze_contract(
        {"source_code": "contract Target {}", "function_details": [], "target_contract": {}},
        auto_run_config={"auto_run": True, "max_retries": 0},
    )

    output = capsys.readouterr().out
    assert "PoC rejected: Forge compilation failed" in output
    assert "Generated demonstration" not in output


def test_coordinator_passes_selected_finding_and_plan_to_generator_and_result(capsys):
    finding = {
        "vulnerability_type": "access_control",
        "affected_functions": ["transferOwnership(address)"],
        "confidence_score": 1.0,
        "skeptic_confidence": 1.0,
    }
    plan = {
        "setup_steps": ["Deploy OwnershipBug"],
        "execution_steps": ["Call transferOwnership as an unauthorized account"],
        "validation_steps": ["Assert the unauthorized account becomes owner"],
    }
    target = {"path": "OwnershipBug.sol"}
    generated_input = {}

    coordinator = AgentCoordinator.__new__(AgentCoordinator)
    coordinator.model_config = SimpleNamespace(skip_poc_generation=False)
    final_lifecycle = {
        "generated": True, "source_validated": True, "compiled": True,
        "executed": True, "impact_demonstrated": True,
    }
    runner_input = {}

    def run_poc(data):
        runner_input.update(data)
        return {
            "runner_state": "PASSED", "compiled": True, "executed": True,
            "success": True, "impact_verified": True, "lifecycle": final_lifecycle,
            "retries": 0, "compile_time": 0.01, "execution_time": 0.01,
        }

    coordinator.runner = SimpleNamespace(max_retries=0, run_and_fix_exploit=run_poc)
    coordinator.analyzer = SimpleNamespace(
        analyze=lambda _contract: {"vulnerabilities": [finding]},
        _deduplicate_vulnerabilities=lambda items: items,
    )
    coordinator.skeptic = SimpleNamespace(
        audit_vulnerabilities=lambda *_args: [finding],
    )
    coordinator.exploiter = SimpleNamespace(
        generate_exploit_plan=lambda _finding: {"exploit_plan": plan},
    )

    def generate(data):
        generated_input.update(data)
        return {
            "exploit_code": "generated candidate",
            "exploit_file": "candidate.t.sol",
            "vulnerability": data["vulnerability"],
            "exploit_plan": data["exploit_plan"],
            "compiled": True,
            "poc_strategy": "executable",
            "lifecycle": {
                "generated": True, "source_validated": True, "compiled": True,
                "executed": False, "impact_demonstrated": False,
            },
        }

    coordinator.generator = SimpleNamespace(generate=generate)
    result = coordinator.analyze_contract(
        {
            "source_code": "contract OwnershipBug {}",
            "function_details": [],
            "target_contract": target,
        },
        auto_run_config={"auto_run": True, "max_retries": 0},
    )

    assert generated_input["vulnerability"] == finding
    assert generated_input["exploit_plan"] == plan
    assert generated_input["target_contract"] == target
    assert runner_input["vulnerability"] == finding
    assert runner_input["exploit_plan"] == plan
    poc = result["generated_pocs"][0]
    assert poc["vulnerability"] == finding
    assert poc["exploit_plan"] == plan
    assert poc["poc_data"]["vulnerability"] == finding
    assert "Generated demonstration for access_control" in capsys.readouterr().out
    assert poc["poc_data"]["exploit_plan"] == plan
    assert poc["poc_data"]["lifecycle"] == final_lifecycle
    assert poc["poc_data"]["execution_results"]["lifecycle"] == final_lifecycle
