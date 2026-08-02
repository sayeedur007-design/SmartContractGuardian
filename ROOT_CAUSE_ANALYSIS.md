# Web UI blank-page root cause analysis

## Root cause

The analysis backend was completing correctly. The blank page was a React render-time exception in `PerformanceMetricsPanel` after the completed-job response was applied.

The component checked only that a top-level metrics section existed, then dereferenced nested fields such as `metrics.token_usage.total.total_tokens`, `metrics.time_metrics.stage_times`, `metrics.code_metrics.files.map`, and `metrics.run_info.config`. A partial metrics payload (or a polling completion that had not yet supplied all nested fields) therefore threw `TypeError`. There was no React error boundary, so React removed the affected application tree and presented a white page.

## Request lifecycle traced

1. `ContractInput` posts the selected `.sol` file to `POST /api/upload-contract`.
2. The backend creates a job and `App` stores its id/status.
3. `POST /api/analyze` starts `analyze_thread`.
4. The analyzer and agent coordinator finish; the job stores `results` and `performance_metrics`.
5. The backend emits `analysis_complete`; it also exposes results through `GET /api/results/<job_id>`.
6. The frontend can receive completion through Socket.IO or status polling. Previously only the Socket.IO path assigned metrics; the polling path assigned results but omitted metrics.
7. The render path displayed results and passed metrics directly to the unsafe renderer.

## Verified live result

With Flask on port 3000, Ollama available at `127.0.0.1:11434`, and RAG enabled, uploading and analyzing `VulnerableBank.sol` completed successfully. The results API returned 2 verified vulnerabilities, 2 PoCs, and a performance-metrics payload with token, timing, code, and derived sections.

## Secondary integration defects fixed

- Completion and polling errors were only written to the browser console; users saw no error UI.
- `GET /api/status/<job_id>` did not include the backend failure message.
- Upload/fetch responses and analysis result responses were trusted without validating their required fields.
- Drag/drop handlers dereferenced refs without checking whether they were mounted.
- Findings/PoC list renderers accepted arbitrary array elements and could dereference malformed elements.

## Deliberately unchanged

The analyzer, RAG, agent prompts, report generation, PoC functionality, routes, and backend analysis behavior were not refactored or reduced.
