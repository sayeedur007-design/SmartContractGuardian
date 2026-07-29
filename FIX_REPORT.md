# Production-Readiness Fix Report

## Scope and verification status

This maintenance pass focused on the execution-critical analysis path: Slither parsing, finding identity, agent handoff, and Foundry PoC validation. Python modules compile successfully. Static analysis was executed against the current `VulnerableBank.sol` and now reports the ten declarations actually present in the target source.

The final live LLM/frontend end-to-end retest is currently blocked by an external dependency: Ollama is not listening on `http://127.0.0.1:11434` (`WinError 10061`). Start it with `ollama serve`, confirm both required models with `ollama list`, then rerun the commands in `RUNNER.md`.

## Issues found and fixes

### 1. Parser counted inherited and dependency functions as target functions

**Root cause:** `static_analysis/parse_contract.py` iterated `contract.functions`, which includes inherited `forge-std` methods. Imported contracts were also included once Foundry remapping was available. This produced thousands of irrelevant functions for a test file.

**Fix:** parsing now limits contracts to the analyzed file/directory scope and iterates `contract.functions_declared`. The current target verification returns these exact IDs:

`constructor()`, `deposit()`, `withdraw(uint256)`, `transferOwnership(address)`, `emergencyWithdraw()`, `setBalance(address,uint256)`, `destroy()`, `random()`, `unsafeSend(address,uint256)`, and `receive()`.

### 2. Reported locations were character offsets, not source lines

**Root cause:** Slither `source_mapping.start` and `end` are byte/character offsets.

**Fix:** the parser now derives `start_line`/`end_line` from `source_mapping.lines`, preserving true report locations.

### 3. Function references varied across agents and deterministic rules invented names

**Root cause:** parser details used bare names while generators used bare source regex names, and analyzer fallback rules emitted fixed names such as `withdraw` or `destroy` even when absent.

**Fix:** added `utils/function_identifiers.py`, which supplies the canonical ABI-style ID `name(type,...)`. Parser, analyzer prompt, analyzer validation, skeptic validation, and generator source-function validation now use it. Deterministic rules locate the matching analyzed function instead of emitting a guessed identifier.

### 4. Hallucinated analyzer findings could enter the pipeline

**Root cause:** model JSON was accepted without proving that each affected function existed in the parsed target.

**Fix:** `AnalyzerAgent._validate_findings` drops any finding that lacks an exact canonical affected-function ID. It does not silently map a guessed name to a real function.

### 5. Skeptic retained rejected findings as low-confidence records

**Root cause:** the skeptic mutated the original list and retained entries even when the LLM assigned a near-zero score. The coordinator then accepted `0.2` as an exploitation threshold.

**Fix:** SkepticAgent now accepts only returned, source-validated records with confidence `>= 0.6`; rejected/unknown records are removed. The coordinator uses the same `0.6` threshold before ExploiterAgent is called.

### 6. Generator validation and source identifiers were inconsistent

**Root cause:** generator source-function extraction returned bare names, while downstream findings now need overload-safe IDs. Generated tests also were not explicitly required to use an attacker prank and assertion.

**Fix:** generator derives canonical source IDs and checks an affected function call by the ID’s function name. The prompt and deterministic validator require `vm.deal`, `vm.prank`/`vm.startPrank`, `balanceLog`, and a Foundry assertion in addition to imports, setup, target use, braces, and compile execution.

### 7. Slither could not resolve Foundry test imports

**Root cause:** Slither did not receive a local `forge-std` remapping.

**Fix:** parser conditionally adds the checked-in `exploit/lib/forge-std/src` remapping. The multi-contract reentrancy example compiles through Slither and returns its directly declared functions.

## Files changed

- `utils/function_identifiers.py` — new shared canonical-ID and validation helpers.
- `static_analysis/parse_contract.py` — scoped/direct function extraction, correct source lines, modifiers, function IDs, and local Foundry remapping.
- `llm_agents/agents/analyzer.py` — exact-function prompt contract, deterministic rule mapping, hallucination gate, and canonical snippet lookup input.
- `llm_agents/agents/skeptic.py` — invalid-finding removal and production confidence gate.
- `llm_agents/agent_coordinator.py` — passes function details to Skeptic and uses the same exploitation threshold.
- `llm_agents/agents/generator.py` — canonical target function validation and stronger required test semantics.
- `RUNNER.md` — Windows setup/runbook created in the earlier maintenance pass.

## Tests performed

- `python -m compileall -q static_analysis llm_agents utils` — passed.
- Slither parser on `examples/ReentrancyTest.sol` — passed; returned only the seven declarations in the example source, not inherited `forge-std` helpers.
- Slither parser on current `VulnerableBank.sol` — passed; returned the ten functions listed above, with source line numbers and modifiers.
- Analyzer hallucination gate — verified with a synthetic invalid `invented()` reference: it was removed; an exact `withdraw(uint256)` reference was retained.
- Existing Foundry generator compile-gate validation from the previous pass — passed a targeted temporary Forge test using `--no-cache` and local `solc`.
- `python main.py --no-rag --skip-poc --export-json reports/hardened_no_rag.json` — static analysis and report export completed; LLM call could not proceed because Ollama was down.

## Remaining limitations / required external actions

1. Start Ollama before a live agent or UI retest:

   ```powershell
   ollama serve
   ollama list
   ```

   Required models: `qwen2.5-coder:7b` and `nomic-embed-text`.

2. The React/Flask Socket.IO/UI path requires a live Ollama service for a full asynchronous analysis test. It was not falsely marked successful while the service was unavailable.

3. LLM-generated PoCs remain intentionally rejected unless they pass all structural checks and Forge. This is a safety gate, not a feature disablement; valid reports can legitimately produce no PoC when the skeptic rejects the finding or the contract is not demonstrably exploitable.

4. The current repository has pre-existing modified files and generated report artifacts. This pass did not discard unrelated user changes.
