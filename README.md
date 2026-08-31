# SecureAI Automated Test Suite

Automated test suite validating **SecureAiService**, a Windows endpoint service that detects AI workloads (cloud, local, containerized, and embedded) via ETW instrumentation, and reports them to a central controller.

Each test case corresponds to a SAVR ticket ID and checks a specific detection behavior — process confidence scoring, DNS/TCP correlation, TLS metadata capture, container detection, registration, and more — against live log output and `detected_agents.json` from a real service run.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Running the Suite](#running-the-suite)
  - [Automated Setup](#automated-setup)
  - [Manual Run](#manual-run)
- [Output Files](#output-files)
- [Test Cases Covered](#test-cases-covered)
- [Roster Configuration](#roster-configuration)
- [Reading the Results](#reading-the-results)
- [Known Product Bugs (Current Build)](#known-product-bugs-current-build)
- [Known Environment Limitations](#known-environment-limitations)

## Prerequisites

- SecureAiService must be installed and running
- Python 3.x with `requests`, `torch` packages installed
- PowerShell available (for Schannel fixture)
- Docker Desktop installed and running (for container detection tests)
- `curl` available on PATH (for OpenAI fixture)
- Run as Administrator (required for service restart via `net stop/start`)
- At least 7GB RAM allocated to Docker Desktop's Hyper-V VM (configure in Docker Desktop → Settings → Resources → Memory)
- `C:\models\tinyllama.gguf` present on disk (download from HuggingFace `TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF`)

## Running the Suite

### Automated Setup

The suite is fully automated via `setup.py`. A single command handles service restart, fixture launch, roster patching, and suite execution:

```
python setup.py
```

Optional flag:

- `--typeperf Yes` — capture SecureAiService CPU and working-set memory to `perf_metrics.csv` (sampled every 5 seconds) for the full run duration. Default is `No`.

`setup.py` performs the following steps in order:

1. Records the start timestamp (intentionally before service restart, to capture the full shutdown/startup lifecycle)
2. Restarts SecureAiService (`net stop` then `net start`) to exercise the registration sequence and ETW session startup
3. Launches the httpbin fixture as a background process and patches `roster.json` with the live PID
4. Launches the chatgpt fixture for DNS/TCP correlation testing
5. Patches `roster.json` with the live httpbin PID
6. Launches the python+torch fixture as a background process for library detection and module enumeration tests, and patches `roster.json` with the live PID
7. Launches the OpenAI curl fixture for TCP connect testing and patches `roster.json` with the live PID
8. Launches the Anthropic fixture for IPv6 TCP testing
9. Waits for Docker to be ready, then pulls required images (`ollama/ollama`, `nginx`, `python:3.11`, `n8nio/n8n`)
10. Launches five Docker containers: `ollama_mount_test` (with model volume), `nginx_test`, `langchain_test`, `n8n_test`, `pyai_test`
11. Waits 240 seconds for scanner poll cycles, registration attempts, DNS cache refresh, and container detection
12. Runs two Schannel fixtures via PowerShell (`copilot.microsoft.com`, `chat.openai.com`)
13. Waits 20 seconds for TLS events to appear in the log
14. Invokes `overall.py` with the recorded start timestamp
15. Terminates all fixtures and cleans up Docker containers

Total runtime is approximately 280 seconds.

### Manual Run

If running `overall.py` directly without `setup.py`:

1. Launch httpbin fixture and note the PID:
```
python -c "import requests, time, os; print(f'PID: {os.getpid()}', flush=True); [requests.get('https://httpbin.org/get') or time.sleep(30) for _ in range(20)]"
```
2. Launch python+torch fixture and note the PID:
```
python -c "import torch, time, os; print(f'PID: {os.getpid()}', flush=True); time.sleep(300)"
```
3. Launch curl fixture and note the PID:
```
curl https://openai.com
```
4. Update `roster.json` — `SAVR14.by_pid` with the httpbin PID, `SAVR12.by_pid` with the curl PID, and `SAVR17.expected_agents[0].pid` with the python PID
5. Launch Docker containers:
```
docker run -d --name ollama_mount_test -v C:\models:/models ollama/ollama
docker run -d --name nginx_test nginx
docker run -d --name langchain_test python:3.11 python -c "import time; time.sleep(300)  # langchain"
docker run -d --name n8n_test n8nio/n8n
docker run -d --name pyai_test -e OPENAI_API_KEY=sk-test1234567890abcdef python:3.11 python -c "import time; time.sleep(300)  # langchain"
```
6. Run Schannel fixtures in PowerShell:
```powershell
Invoke-WebRequest -Uri "https://copilot.microsoft.com" -UseBasicParsing
Invoke-WebRequest -Uri "https://chat.openai.com" -UseBasicParsing
```
7. Wait 120 seconds then run:
```
python overall.py --start "YYYY-MM-DD HH:MM:SS.000" --roster roster.json --out results.csv
```
Set `--start` to just before you launched your fixtures.

## Output Files

- **`results.csv`** — one row per assertion, with columns `test, subject, expected, actual, result, comments`. This is the primary output; see [Reading the Results](#reading-the-results) for verdict meanings.
- **`perf_metrics.csv`** — only produced when `setup.py --typeperf Yes` is used. Contains sampled `% Processor Time` and `Working Set` for SecureAiService every 5 seconds across the run.
- **`log.snapshot`** / **`agents.snapshot`** — local copies of the service log and `detected_agents.json` taken at run time, used as the source data for the test window. Safe to delete between runs.

## Test Cases Covered

> **File paths below reflect the actual module names imported in `overall.py` and present in `tests/`.**

### DNS Cache and Localhost Resolution (SAVR-5)
Look for the DNS cache thread running, IP-to-domain mappings being inserted, localhost connections being correctly resolved, and ollama's endpoint being identified as localhost.

- **File:** `tests/SAVR5.py`
- **Roster key:** `SAVR5` (empty object `{}` is sufficient)
- **What it checks:**
  - `DnsCache::TimerCallback` line present in log confirming the cache thread is running (fires every ~5 minutes; window must be long enough to capture a cycle)
  - `DnsCache::Insert` lines present confirming IP-to-domain mappings are being cached (currently absent — known gap in this build)
  - TCP connect line to `127.0.0.1` with `domain=localhost` confirming localhost mapping works
  - ollama's `endpoint` field in `detected_agents.json` contains `localhost:11434`
  - `DnsCacheLookup` lines with `source=ip_cache` confirming cache is used for domain correlation (currently absent — known gap in this build)
- **Known limitations:** DNS cache insert and IP cache lookup checks will FAIL on this build as the feature is not logging these operations

### AI Module Enumeration (SAVR-6)
Look for each detected AI process having its loaded DLL libraries correctly enumerated and recorded in the agent database.

- **File:** `tests/SAVR2SAVR6.py`
- **Roster key:** `SAVR6`
- **What it checks:**
  - For each process in `expected_agents`: verifies an entry exists in `detected_agents.json` and that `loaded_ai_libraries` contains the expected library names (matched by `lib_name` field)
  - For processes with no expected libraries (e.g. native binaries like ollama.exe): verifies the field is present
  - For processes with expected libraries (e.g. python+torch): verifies `detection_method` is `LibraryAnalysis`
  - Flags any agent in `detected_agents.json` with a non-empty `loaded_ai_libraries` not covered by the roster
- **Fixture required:** python+torch fixture must be running during the scanner poll cycle

### AI Process Confidence Scoring (SAVR-7)
Look for whether known AI programs get correct confidence scores, are persisted to the agent database, and that non-AI system processes are correctly excluded.

- **File:** `tests/SAVR2SAVR7.py`
- **Roster key:** `SAVR7`
- **Config dependency:** reads `config.json` at runtime for whitelist confidence values, service types, and system process exclusions
- **What it checks:**
  - For each process in `expected_agents`: verifies scanner assigns a confidence score within the configured range, and that the entry is correctly persisted to `detected_agents.json`
  - For each process in `library_processes`: verifies the scanner detects the process via LibraryAnalysis
  - Cross-checks each JSON entry's confidence against the whitelist configured value in `config.json`
  - Verifies no processes from `exclusions.system_processes` in `config.json` appear in `detected_agents.json`
  - Verifies all JSON entries are above `minimum_confidence_threshold` from `config.json`
  - Flags unexpected entries in `detected_agents.json` not covered by the roster, with prefix-based exclusion for known container processes (`/bin/`, `python -c`) and deduplication across accumulated runs
- **Roster note:** add `"known_container_processes": ["/bin/", "python -c"]` to suppress expected Docker fixture entries from the unexpected entries check

### Process Token Properties (SAVR-9)
Look for each detected AI process having correct user SID, token type, privileges, integrity level, and elevation status recorded in sysinfo.

- **File:** `tests/SAVR9.py`
- **Roster key:** `SAVR9`
- **What it checks:**
  - For each process in `expected_agents`: finds the matching entry in the latest `sysinfo.jsonl` snapshot's `agent_process_info` array
  - Verifies `user_sid` is non-empty, `privileges` is non-empty, `token_type` is `Primary`
  - Verifies `integrity_level` and `is_elevated` match expected values from the roster
  - Reports PASS/PARTIAL/FAIL based on how many fields match

### TCP Connect Fixture (SAVR-12)
Look for a TCP connection from a specific PID to a specific domain being logged correctly.

- **File:** `tests/SAVR12.py`
- **Roster key:** `SAVR12`
- **What it checks:** For the PID and domain configured in `by_pid`, verifies a TCP connect line appears in the log with matching PID and domain
- **Setup:** `setup.py` automatically patches `by_pid` with the live curl PID each run

### Scan Speed / Responsiveness (SAVR-13)
Look for the engine reacting to a new AI process within 50ms, instead of waiting for its next scheduled scan.

- **File:** `tests/SAVR2SAVR13.py`
- **Roster key:** `SAVR13` (no roster configuration required)
- **What it checks:** Measures the time gap between an AI process ETW event and the next scan. Also profiles the overall scan interval pattern to distinguish event-driven dispatch (sub-5-second gaps) from a fixed polling loop (25–40 second gaps). Acceptance threshold: latency under 50ms.
- **Known limitations:** event-driven dispatch is not implemented in the current build; all three checks will FAIL

### Network Connection Stats (SAVR-14)
Look for accurate data-sent, data-received, and connection-speed numbers logged for an AI program's network connections.

- **File:** `tests/SAVR2SAVR14.py`
- **Roster key:** `SAVR14`
- **What it checks:** For each expected process (matched by name or PID), verifies at least one logged TCP connection snapshot has non-zero bytes sent, non-zero bytes received, and a non-zero round-trip time simultaneously.
- **Known limitations:** RTT is always 0 in the current build — the test will FAIL on the RTT check regardless of fixture behavior. Bytes are captured correctly on connections with actual data transfer.

### Encrypted Connection Detection (SAVR-15)
Look for the domain, TLS version, and cipher being correctly captured for a secure connection made by an AI program.

- **File:** `tests/SAVR2SAVR15.py`
- **Roster key:** `SAVR15`
- **What it checks:** For each domain in the roster, verifies the captured TLS event includes SNI, TLS version, and cipher. Key exchange method and ALPN are checked as secondary fields.
- **Known limitations:** `kex` field returns `?(255)` (unresolved) and `alpn` is never captured in the current build. Both domains will produce PARTIAL rather than PASS until these are fixed. Requires PowerShell/.NET fixtures — Chrome/Edge use their own TLS stack and bypass Schannel.

### File Monitoring & Filtering (SAVR-16)
Look for the file-monitoring component only capturing activity from AI-related programs and staying within its resource limits.

- **File:** `tests/SAVR2SAVR16.py`
- **Roster key:** `SAVR16`
- **What it checks:** Confirms the monitoring session starts correctly, session statistics are logged with zero lost events, event rate stays under the configured limit, CPU and memory usage stay within budget, and the session only stops after the parent service begins shutting down.
- **Known limitations:** feature is not present in all builds. If no `SecureAIKernelFileMonitor` lines appear in the full log (not just the window), the feature is compiled out of the current build and all rows will show NOT_DETECTED.

### AI Library and Module Detection (SAVR-17)
Look for the process module scanner and main scanner agreeing on the number of AI libraries loaded by a process.

- **File:** `tests/SAVR17.py`
- **Roster key:** `SAVR17`
- **What it checks:**
  - Finds the target process in `detected_agents.json` by `process_name` and `library_name`
  - Searches the log for `[PROCMOD]` and `[SCANNER]` lines matching the PID from the roster
  - Verifies both lines are present and that the module counts match
- **Setup:** `setup.py` automatically patches `expected_agents[0].pid` with the live python+torch fixture PID each run

### Domain Lookup Correlation (SAVR-18)
Look for a domain lookup (DNS query) being correctly linked to the connection that follows it.

- **File:** `tests/SAVR2SAVR18.py`
- **Roster key:** `SAVR18`
- **What it checks:** For each domain in the roster, confirms a successful DNS resolution is followed by a TCP connection line with `source=dns_etw` and a populated URL field.
- **Known limitations:** `chatgpt.com` consistently produces PARTIAL — DNS resolution is captured but the TCP connect is not correlated, likely due to CDN redirection. This is a product-side IP-to-domain cache gap.

### Container Detection (SAVR-27/28)
Look for Docker containers running AI workloads being correctly detected, classified, and distinguished from non-AI containers.

- **File:** `tests/SAVR27a28.py`
- **Roster key:** `SAVR27a28`
- **What it checks:**
  - `ollama_mount_test` — detected via `ContainerAnalysis`, `service_type=LocalModel`, `confidence>=0.85`, `.gguf` volume mount present in `model_mounts`
  - `nginx_test` — correctly NOT forwarded to the detection engine
  - `langchain_test` — `cmd_match=1` confirmed in log via `[DOCKER]` line with `pattern=langchain`
  - `n8n_test` — `service_type=WorkflowAutomation`, `confidence>=0.60`
  - `pyai_test` — `service_type=PythonAIAgent`, `env_api_keys_mask!=0` confirming `OPENAI_API_KEY` env var was detected
- **Known limitations:**
  - `model_mounts` is never populated even when a `.gguf` file is present and actively loaded — confirmed product gap
  - n8n confidence is 0.50 without active OpenAI API calls, below the 0.60 threshold — tabled pending fixture complexity
  - `cmd_match` and `image_match` flags are logged but not persisted to `detected_agents.json` — known gap

### Anomaly Pipeline (SAVR-29)
Look for the full anomaly detection pipeline firing in order: rule triggered, dispatched, and output sent.

- **File:** `tests/SAVR29.py`
- **Roster key:** `SAVR29`
- **What it checks:** For each anomaly segment observed in the log, verifies the pipeline stages appear in order — `AnomalyPipeline` rule fired, `dispatchFlow` called, `OutputModule` batch sent. Reports FAIL if the pipeline breaks before the output stage.
- **Known limitations:** the OUTPUT_MODULE batch send stage is not firing in the current build after dispatchFlow — the pipeline breaks before JSON output.

### Performance Baseline (SAVR-40)
Look for the service staying within CPU, memory, and I/O budgets during normal operation.

- **File:** `tests/SAVR40.py`
- **Roster key:** `SAVR40`
- **What it checks:** Samples the service's resource usage across the run window and verifies average CPU stays below 3%, total I/O reads stay below 100MB, and memory growth slope stays below 500 KB/hr.
- **Known limitations:** memory slope may exceed threshold during startup as the service initializes its data structures. The current build shows ~1727 KB/hr slope which exceeds the 500 KB/hr threshold.

### Device Registration (SAVR-43, Issue 1)
Look for a device completing registration and authentication in the correct order, even when no AI activity has been detected yet.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `SAVR43_1`
- **What it checks:** Confirms six milestones occur in order — fingerprint generated, registration request sent, registration accepted, authentication request sent, authentication accepted, first heartbeat sent — and that every process scan completed before registration reported zero AI processes found.
- **Known limitations:** currently blocked by license limit exceeded on the controller. Registration returns `success=false` which prevents auth and heartbeat from running.

### Status Report Contents (SAVR-43, Issue 2)
Look for each periodic status report containing all required fields.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `SAVR43_2`
- **What it checks:** Verifies the heartbeat payload includes all required fields, a valid stats block, a correctly formatted last-scan timestamp, and a successful server response.
- **Known limitations:** currently blocked by license limit exceeded — heartbeat never fires if registration fails.

### Detection Record Completeness (SAVR-43, Issue 3)
Look for a detection record on an AI program that's also using the network to include both process details and network details together.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `SAVR43_3`
- **What it checks:** For each detected-agent record in the run window, verifies all 13 required process- and network-level fields are present and non-empty.
- **Known limitations:** all 13 combined fields are absent from every agent entry in the current build — confirmed Issue 3 regression. Additionally, `event_type` field is not persisted to `detected_agents.json`. The test produces many rows due to accumulated entries from repeated runs; this will be addressed by filtering on `first_detected` in a future update.

## Roster Configuration

The roster (`roster.json`) controls which processes, domains, and fields each test asserts on. It is the single place to configure expected values for a given environment.

Each test has its own top-level key in the roster, matching the test class's `name` attribute (e.g. `SAVR5`, `SAVR12`, `SAVR27a28`). If a key is absent, that test is skipped entirely. An empty object `{}` enables the test with default settings.

The following fields are automatically patched by `setup.py` on every run — do not manually edit them as they will be overwritten:

- `SAVR14.by_pid` — httpbin fixture PID
- `SAVR12.by_pid` — curl/openai fixture PID
- `SAVR17.expected_agents[0].pid` — python+torch fixture PID

Fields that are environment-specific and may need updating between VMs or builds:

- `SAVR7.config_path` — path to `config.json` on the target machine
- `SAVR7.expected_agents` — processes expected to be running and detected; add or remove entries to match what is installed
- `SAVR7.known_container_processes` — list of process name prefixes to exclude from the unexpected entries check (e.g. `["/bin/", "python -c"]`)
- `SAVR18.domains` — domains to verify DNS+TCP correlation for
- `SAVR15.domains` — TLS domains to verify; must be reachable via PowerShell/.NET
- `SAVR43_2` — required fields and stats keys; update if the heartbeat payload schema changes
- `SAVR16` — provider GUID and event ID; update if the ETW provider changes
- `SAVR6.expected_agents` — processes to check for library enumeration
- `SAVR27a28.expect_container_name` — name of the ollama Docker container to check (default: `ollama_mount_test`)
- `SAVR27a28.expect_model_mount` — expected `.gguf` mount path (default: `/models/tinyllama.gguf`)

## Reading the Results

Each row in `results.csv` gets one of these verdicts:

- **PASS** — worked as expected
- **FAIL** — did not work as expected (a real finding)
- **PARTIAL** — mostly worked, but part of it is missing or incomplete
- **NOT_DETECTED** — the activity we needed to check never happened during this run (usually means rerun with the right setup, not a product problem)
- **INCONCLUSIVE** — not enough information in this run to make a call either way
