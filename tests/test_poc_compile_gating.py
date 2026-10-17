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

    assert len(compile_calls) == 3
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
    result = agent.generate({"vulnerability": {"vulnerability_type": "access_control"}})

    assert "Error (9640): invalid conversion" in seen_failures[1][1][0]
    assert compiled_sources == [("first source", 1), ("repaired source", 2)]
    assert result["compiled"] is True
    assert Path(result["exploit_file"]).read_text(encoding="utf-8") == "repaired source"


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
