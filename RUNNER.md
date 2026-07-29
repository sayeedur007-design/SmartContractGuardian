# SmartContractGuardian / VLD Windows Runbook

This is a local smart-contract vulnerability-analysis system. It combines Slither structural analysis, a multi-agent LLM workflow, optional retrieval-augmented generation (RAG), and Foundry proof-of-concept (PoC) validation. The supported local model provider is Ollama through its OpenAI-compatible endpoint.

The default target is `VulnerableBank.sol`; therefore `python main.py` works from the repository root without a contract argument.

## Architecture and repository map

| Area | Location | Purpose |
| --- | --- | --- |
| CLI/backend pipeline | `main.py` | Parses arguments, copies the target to `exploit/src`, runs static analysis and agents, and writes reports. |
| Static analysis | `static_analysis/` | Slither parsing, detector registration, function details, and call graph. |
| Agents | `llm_agents/` | Analyzer, Skeptic, Exploiter, Generator, Foundry runner, and model configuration. |
| RAG | `rag/doc_db.py` | Builds/reuses local Chroma vectors from `known_vulnerabilities/contract_vulns.json`. |
| Knowledge corpus | `known_vulnerabilities/` | Solidity examples and vulnerability metadata used by RAG. |
| Foundry project | `exploit/` | `src/` receives the target, `test/` receives new PoCs, and `lib/forge-std` is the test library. |
| Flask/UI server | `frontend_poc/app.py` | REST API and Socket.IO server on port 3000. |
| React UI | `frontend_poc/client/` | React application; its production build is served by Flask. |
| Runtime output | `reports/`, `uploads/`, `performance_analysis/` | Reports, fetched/uploaded source files, generated Foundry diagnostics, and metrics. |

The agent sequence is: **AnalyzerAgent** proposes findings from source and Slither data; **SkepticAgent** rechecks them; **ExploiterAgent** plans an exploit for findings that remain above the confidence threshold; **GeneratorAgent** produces and compile-gates a Foundry test; **ExploitRunner** runs and repairs a generated test up to the configured retry limit.

## Prerequisites

Use a 64-bit Windows machine and PowerShell. The checked-in virtual environment used Python 3.11; use Python 3.11 for a reproducible installation.

- Git. Git LFS is not referenced by `.gitattributes` or this run path, so it is not required by this repository.
- Python 3.11 and `pip`.
- Node.js and npm for the React client. The repository does not state a pinned Node release; use a current Node.js LTS release compatible with `react-scripts` 5.
- Ollama for generation and embeddings.
- Foundry: `forge`, `anvil`, and `cast`.
- Solidity compiler (`solc`). The supplied Foundry project compiles Solidity `0.8.20`; install that compiler or let Foundry manage matching versions.
- Slither. It is pinned in `requirements.txt` and uses `solc`/`solc-select` underneath.
- Internet access is needed the first time packages, Foundry, Ollama models, or explorer-fetched contracts are downloaded.

Useful Windows installers (choose the one appropriate for your workstation):

```powershell
winget install Python.Python.3.11
winget install OpenJS.NodeJS.LTS
winget install Ollama.Ollama
winget install Git.Git
```

Foundry’s Windows installation method is published by Foundry. After installing its bootstrapper, run:

```powershell
foundryup
forge --version
anvil --version
cast --version
```

The project does not require Visual Studio Build Tools itself. Install them only if pip has to build a native dependency rather than using an available wheel.

## First-time Python setup

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m slither --version
python -c "import chromadb, langchain_chroma, langchain_ollama, flask, openai; print('Python dependencies OK')"
```

If PowerShell blocks activation, use the current-session command below, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

`requirements.txt` includes Flask, Flask-SocketIO, ChromaDB, LangChain, LangChain-Chroma, LangChain-Ollama, OpenAI SDK, Slither, `solc-select`, and `python-dotenv`; no separate Python requirements file exists for the frontend server.

## Environment variables

Copy the template, then add the local settings used by this project. Never commit `.env`.

```powershell
Copy-Item .env.example .env
```

| Variable | Use | Example / requirement |
| --- | --- | --- |
| `OPENAI_API_KEY` | Required by the OpenAI SDK client even when it targets Ollama. A non-empty local placeholder is sufficient for typical Ollama configurations. | `OPENAI_API_KEY=ollama` |
| `OPENAI_BASE_URL` | Present in the local `.env`; the configured qwen provider defaults to `http://localhost:11434/v1`. The CLI can override it with `--api-base`. | `http://localhost:11434/v1` |
| `OLLAMA_MODEL` | Present in the local `.env`; documents the generation model. The current `ModelConfig` defaults are explicit in code. | `qwen2.5-coder:7b` |
| `EMBEDDING_MODEL` | Present in the local `.env`; documents the embedding model. RAG currently requests `nomic-embed-text` directly. | `nomic-embed-text` |
| `USE_PINECONE` | Present in the local `.env`; no current CLI/RAG code path reads it. Local Chroma is used. | `false` |
| `CHROMA_DB_DIR` | Present in the local `.env`; the current coordinator passes `<repo>/chroma_db` explicitly. | `./chroma_db` |
| `ANTHROPIC_API_KEY` | Optional, only when choosing an Anthropic model. | provider API key |
| `DEEPSEEK_API_KEY` | Optional, only when choosing a DeepSeek model. | provider API key |
| `ETHERSCAN_API_KEY` | Optional contract fetching from Ethereum. | explorer API key |
| `BSCSCAN_API_KEY` | Optional contract fetching from BSC. | explorer API key |
| `BASESCAN_API_KEY` | Optional contract fetching from Base. | explorer API key |
| `ARBISCAN_API_KEY` | Optional contract fetching from Arbitrum. | explorer API key |
| `PINECONE_API_KEY`, `PINECONE_ENV` | Listed in `.env.example`; no active local-Chroma path uses them. | only for future/alternate Pinecone work |

`.env` is loaded by `main.py`, RAG, source fetching, and shared agent configuration.

## Ollama setup

Install/start Ollama, then ensure the API listens on `http://127.0.0.1:11434` (the OpenAI-compatible URL used by agents is `http://localhost:11434/v1`).

```powershell
ollama serve
```

In another PowerShell window:

```powershell
ollama pull qwen2.5-coder:7b
ollama pull nomic-embed-text
ollama list
ollama ps
ollama run qwen2.5-coder:7b "Reply with OK"
Invoke-WebRequest http://127.0.0.1:11434/api/tags | Select-Object -Expand Content
```

`qwen2.5-coder:7b` is the default model for Analyzer, Skeptic, Exploiter, Generator, and project-context agents. `nomic-embed-text` creates Chroma embeddings. Do not start analysis until both are listed.

## ChromaDB / RAG

The persistent local database is `chroma_db/`. RAG creates a LangChain Chroma collection with Ollama embeddings. On the first RAG run it loads `known_vulnerabilities/contract_vulns.json`, reads the referenced corpus files, chunks them, embeds them, and persists the vectors. On later runs it reuses existing vectors.

Run with RAG:

```powershell
python main.py
```

Run without RAG:

```powershell
python main.py --no-rag
```

To force a rebuild, stop all analysis processes first, then delete only the repository database directory and run with RAG:

```powershell
Remove-Item -LiteralPath .\chroma_db -Recurse
python main.py
```

This is destructive: it removes only cached vectors, not the corpus under `known_vulnerabilities/`.

## Foundry and Solidity setup

Verify the toolchain from the repository root:

```powershell
forge --version
anvil --version
cast --version
solc --version
```

The Foundry project is `exploit/` with `src = 'src'` and `test = 'test'` in `exploit/foundry.toml`. The CLI copies the analyzed contract to `exploit/src/<original-name>.sol`. GeneratorAgent writes current PoCs to `exploit/test/`, validates structure, and invokes a targeted Forge test. The runner executes that targeted test and writes Forge/repair logs into `reports/`.

For a manual project check:

```powershell
Set-Location .\exploit
forge test -vv --no-cache
Set-Location ..
```

On Windows, the agent code supplies `HOME`, `USERPROFILE`, `HOMEDRIVE`, and `HOMEPATH` to Foundry subprocesses and uses a `solc` executable from `PATH` when available. This avoids a Foundry-nightly home/cache failure seen in service-launched processes.

## Slither setup

Slither is installed with the Python requirements and invoked by `static_analysis/parse_contract.py` before LLM analysis. It must be able to compile the target Solidity version.

```powershell
.\.venv\Scripts\Activate.ps1
python -m slither --version
solc --version
```

If Slither reports a compiler-version mismatch, install/select the version required by the contract pragma (the default target uses `^0.8.20`) and retry. `solc-select` is included in the Python requirements, but no automatic selection command is performed by this repository.

## Node and frontend setup

The Flask server serves the production React build from `frontend_poc/client/build`. Build it once after installing Node dependencies:

```powershell
Set-Location .\frontend_poc\client
npm install
npm run build
Set-Location ..\..
```

`npm audit fix` is not part of the project’s required run path; run it only after reviewing dependency changes, because it can alter the lockfile.

For React development-server work, use:

```powershell
Set-Location .\frontend_poc\client
npm start
```

The checked-in client API URL is `http://localhost:3000/api`, which is also the Flask/Socket.IO port. For the supported integrated UI, build the client and run Flask rather than running both servers on the same port.

## Starting the backend and frontend

### CLI analysis backend

From the repository root with the virtual environment activated and Ollama running:

```powershell
python main.py
python main.py --no-rag
```

Expected CLI milestones are `Environment loaded`, `Static analysis complete`, `AnalyzerAgent`, `SkepticAgent`, and report export. Exploiter, Generator, and ExploitRunner run only for findings that remain above the Skeptic confidence threshold.

### Flask + React interface

Build the React client first, then run:

```powershell
.\.venv\Scripts\python.exe .\frontend_poc\app.py
```

Expected output includes `Static folder: ...frontend_poc\client\build` and `Running on http://127.0.0.1:3000`. Open `http://127.0.0.1:3000/`.

The API provides `POST /api/upload-contract`, `POST /api/fetch-contract`, `POST /api/analyze`, `GET /api/status/<jobId>`, and `GET /api/results/<jobId>`. Uploading a Solidity file stores it in `uploads/`; address fetching also writes there.

## Running analysis

Analyze the default local target:

```powershell
python main.py
python main.py --no-rag
```

Analyze a different local contract, a directory of Solidity files, or a chain address:

```powershell
python main.py --contract .\path\Contract.sol
python main.py --contract .\path\to\project-directory
python main.py --contract-address 0xYourAddress --network ethereum
python main.py --contract-address 0xYourAddress --network bsc --save-separate
```

Supported network values in the CLI are `ethereum`, `bsc`, `base`, and `arbitrum`. Explorer keys are needed where the explorer API requires them. Useful output controls are:

```powershell
python main.py --export-md --export-json .\reports\analysis.json
python main.py --skip-poc
python main.py --no-auto-run
python main.py --max-retries 3
python main.py --all-models qwen2.5-coder:7b --api-base http://localhost:11434/v1
```

In the UI, upload a `.sol` file or submit an address/network, then start analysis. The job API and Socket.IO events update the interface while the same static-analysis/agent flow runs.

## Reports and generated files

- `reports/analysis_report_<contract>_<timestamp>.html`: always written by the CLI and opened by the CLI where supported.
- `reports/analysis_report_<contract>_<timestamp>.md`: written when `--export-md` is supplied.
- Path passed to `--export-json`: machine-readable result export.
- `reports/generator_*_attempt*_build.log`: compile-gate diagnostics.
- `reports/forge_*_attempt*.log` and `reports/repair_*`: Foundry execution and repair diagnostics.
- `performance_metrics_<timestamp>.json`: run metrics emitted in the working directory.
- `performance_analysis/`: retained analysis/benchmark metric data.
- `uploads/`: UI uploads and flattened/fetched contracts.
- `exploit/src/`: copied analysis target; `exploit/test/`: generated current PoCs.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Connection refused` / `openai.APIConnectionError` | Ollama is not listening at port 11434. | Run `ollama serve`, then check `/api/tags`; ensure `OPENAI_BASE_URL`/`--api-base` points to `http://localhost:11434/v1`. |
| `model ... not found` | Required generator or embedding model was not pulled. | Run `ollama pull qwen2.5-coder:7b` and `ollama pull nomic-embed-text`; confirm with `ollama list`. |
| Chroma initialization or embedding error | Ollama embedding endpoint is unavailable, database is corrupt, or package installation is incomplete. | Start Ollama, verify `nomic-embed-text`, then remove `chroma_db` as described above and rerun. |
| `No module named ...` | Virtual environment is inactive or incomplete. | Activate `.venv`; run `python -m pip install -r requirements.txt`. |
| Slither import/compiler error | Slither or the Solidity compiler is unavailable/mismatched. | Run `python -m slither --version` and `solc --version`; install/select the pragma-compatible compiler. |
| `forge` / `anvil` not recognized | Foundry is not installed or not on `PATH`. | Install Foundry, run `foundryup`, open a new shell, then verify versions. |
| Foundry cannot detect home/cache directory on Windows | A service/noninteractive process omitted Windows home variables; some nightly builds are sensitive to this. | Run from a normal user PowerShell. The generator/runner set these variables for their own subprocesses. Use `forge test -vv --no-cache` for a direct diagnostic. |
| `solc` not found or Forge cannot download it | Compiler is absent or network is restricted. | Install the contract’s required `solc`, put it on `PATH`, and verify `solc --version`. |
| `Address already in use` on 3000 | Flask or another local server already owns the UI port. | Stop the process using 3000 or run the other application on a different port; this Flask app itself is configured for port 3000. |
| Flask serves no UI / missing `index.html` | React build has not been created. | In `frontend_poc/client`, run `npm install` then `npm run build`; restart Flask. |
| React dev server cannot call API | Both the checked-in client API and Flask use port 3000. | Use the integrated production build served by Flask, or deliberately change the client API configuration and dev-server port as a development change. |
| OpenTelemetry/telemetry warning | A dependency’s optional telemetry/exporter integration is unavailable. | Chroma is initialized with `anonymized_telemetry=False`; confirm Python requirements are installed. Treat unrelated optional telemetry warnings separately from the analysis result. |
| Windows path / permission failure | Command was launched outside the repo root or a tool lacks write access. | `Set-Location` to the clone root, avoid protected folders, and use absolute paths for diagnostics. |

LLM JSON can occasionally be malformed. The analyzer has recovery logic for valid individual findings; inspect `raw_llm_response.txt` and the generated report when a model response looks suspicious. A rejected PoC is deliberate safety behavior: it means deterministic Foundry/structure validation did not accept the generated Solidity.

## Verification checklist

- [ ] `.venv` is active and `python -m pip install -r requirements.txt` completed.
- [ ] `python -m slither --version` and `solc --version` work.
- [ ] `forge --version`, `anvil --version`, and `cast --version` work.
- [ ] `ollama serve` is running.
- [ ] `ollama list` shows `qwen2.5-coder:7b` and `nomic-embed-text`.
- [ ] `python main.py` completes and produces an HTML report.
- [ ] `python main.py --no-rag` completes and produces an HTML report.
- [ ] A RAG run reports local Chroma initialization/reuse.
- [ ] `npm install` and `npm run build` complete in `frontend_poc/client`.
- [ ] `python frontend_poc/app.py` responds at `http://127.0.0.1:3000/`.
- [ ] Requested Markdown/JSON exports appear in `reports/`.

## Daily Startup

1. Open PowerShell at the repository root and activate Python:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. Start Ollama in a separate PowerShell:

   ```powershell
   ollama serve
   ```

3. Verify models:

   ```powershell
   ollama list
   ```

4. Run an analysis:

   ```powershell
   python main.py
   # or
   python main.py --no-rag
   ```

5. To use the web UI, start the Flask server in another PowerShell:

   ```powershell
   .\.venv\Scripts\python.exe .\frontend_poc\app.py
   ```

6. Open `http://127.0.0.1:3000/`.

## Shutdown

- Stop a CLI run, Flask, React dev server, or `ollama serve` with `Ctrl+C` in its own terminal.
- If a server was started in the background, identify its PID with `Get-Process python,node,ollama` and stop the exact intended process with `Stop-Process -Id <PID>`.
- Foundry unit tests run their own local EVM; stop an explicitly started Anvil instance with `Ctrl+C`.

## Developer maintenance

```powershell
# Reinstall Python dependencies
.\.venv\Scripts\python.exe -m pip install --upgrade -r requirements.txt

# Reinstall frontend dependencies and rebuild
Set-Location .\frontend_poc\client
npm install
npm run build
Set-Location ..\..

# Rebuild only the local RAG cache (destructive to cached vectors)
Remove-Item -LiteralPath .\chroma_db -Recurse
python main.py

# Update Foundry
foundryup

# Update/pull local models
ollama pull qwen2.5-coder:7b
ollama pull nomic-embed-text

# Clear generated reports only after preserving anything needed
Get-ChildItem .\reports
```

There is no repository command that automatically deletes reports, uploads, or the Chroma database. Review exact paths before using destructive PowerShell commands.
