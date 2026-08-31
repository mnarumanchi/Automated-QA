# Anomaly Detection Engine — Test Case Documentation

## Setup And Running the Suite

### Prerequisites
- SecureAiService must be installed and running
- Python 3.x with `requests` and `torch` packages installed
- PowerShell available (for Schannel fixture)
- Run as Administrator (required for service restart via `net stop/start`)

### Automated Setup
The suite is fully automated via `setup.py`. A single command handles service restart, fixture launch, roster patching, and suite execution: python setup.py

`setup.py` performs the following steps in order:

1. Records the start timestamp
2. Restarts SecureAiService (`net stop` then `net start`) to exercise the registration sequence and ETW session startup
3. Launches the httpbin fixture as a background process and patches `roster.json` with the live PID
4. Launches the python+torch fixture as a background process for library detection and module enumeration tests
5. Waits 180 seconds for scanner poll cycles, registration attempts, DNS cache refresh, and heartbeat to fire
6. Runs the Schannel fixture via PowerShell
7. Waits 20 seconds for the TLS event to appear in the log
8. Invokes `overall.py` with the recorded start timestamp
9. Terminates fixtures and cleans up

Total runtime is approximately 200 seconds.

### Manual Run
If running `overall.py` directly without `setup.py`:

1. Launch httpbin fixture and note the PID:
python -c "import requests, time, os; print(f'PID: {os.getpid()}', flush=True); [requests.get('https://httpbin.org/get') or time.sleep(30) for _ in range(20)]"
2. Launch python+torch fixture:
python -c "import torch, time; time.sleep(300)"
3. Update `roster.json` `tcp_stats_test.by_pid` with the httpbin PID
4. Run Schannel fixture in PowerShell:
```powershell
   Invoke-WebRequest -Uri "https://copilot.microsoft.com" -UseBasicParsing
```
5. Wait 60 seconds then run:
python overall.py --start "YYYY-MM-DD HH:MM:SS.000" --roster roster.json --out results.csv
   Set `--start` to just before you launched your fixtures.

### Known Environment Limitations
- **License limit exceeded** — the controller is rejecting registration with `"License limit exceeded"`. This blocks `registration_test` auth milestones and `heartbeat_payload_test` entirely until resolved on the controller side.
- **kernel_file_monitor_test statistics** — stats, CPU, memory, and stop rows only appear when a service shutdown occurs within the run window. The current setup captures session startup (PASS) but not shutdown. These rows will show NOT_DETECTED on normal runs.

## Test Cases Covered

### AI Module Enumeration (SAVR-6)
Look for each detected AI process having its loaded DLL libraries correctly enumerated and recorded in the agent database.

- **File:** `tests/SAVR2SAVR11.py`
- **Roster key:** `module_enum_test`
- **What it checks:**
  - For each process in `expected_agents`: verifies an entry exists in `detected_agents.json` and that `loaded_ai_libraries` contains the expected library names
  - For processes with no expected libraries (e.g. native binaries like ollama.exe): verifies the field is present and notes any libraries found as informational.
  - For processes with expected libraries (e.g. python+torch): verifies `detection_method` is `LibraryAnalysis`, confirming the process was detected via file monitoring rather than name matching alone
  - Flags any agent in `detected_agents.json` with a non-empty `loaded_ai_libraries` that is not covered by the roster
- **Known limitations:** python.exe entries will produce NOT_DETECTED until SAVR-16 (ETW kernel file monitor) is fixed — the monitor session starts correctly (provider EDD08927, event ID 12) but `BuffersWritten=0` means no file events are captured, so LibraryAnalysis never fires and python.exe is never written to `detected_agents.json`
- **Fixture required:** run `python -c "import torch; time.sleep(300)"` before invoking the suite so python.exe is alive during the scanner poll cycle

### AI Process Confidence Scoring (SAVR-7)
Look for whether known AI programs get correct confidence scores, are persisted to the agent database, and that non-AI system processes are correctly excluded.

- **File:** `tests/SAVR2SAVR7.py`
- **Roster key:** `confidence_test`
- **Config dependency:** reads `config.json` at runtime for whitelist 
  confidence values, service types, and system process exclusions
- **What it checks:**
  - For each process in `expected_agents`: verifies the scanner assigns a confidence score within the configured range, and that the entry is correctly persisted to `detected_agents.json` with the right confidence and `service_type`
  - For each process in `library_processes`: verifies the scanner detects the process via LibraryAnalysis and persists it to `detected_agents.json` with `loaded_ai_libraries` populated
  - Cross-checks each JSON entry's confidence against the whitelist configured value in `config.json`
  - Verifies no processes from `exclusions.system_processes` in `config.json` appear in `detected_agents.json`
  - Verifies all JSON entries are above `minimum_confidence_threshold` (0.6) from `config.json`
  - Flags any unexpected entries in `detected_agents.json` not covered by the roster
- **Known limitations:** `library_processes` entries will produce NOT_DETECTED until SAVR-16 (ETW kernel file monitor) is fixed, as LibraryAnalysis depends on file event capture to populate `loaded_ai_libraries`

### Scan Speed / Responsiveness (SAVR-13)
Look for the engine reacting to a new AI process within 50ms, instead of waiting for its next scheduled scan.

- **File:** `tests/SAVR2SAVR13.py`
- **Roster key:** `scan_latency_test` (no roster configuration required)
- **What it checks:** Measures the time gap between an AI process being flagged (ETW event) and the next scan actually running. Also profiles the overall scan interval pattern to distinguish event-driven dispatch (short, sub-5-second gaps) from a fixed polling loop (25–40 second gaps). Acceptance threshold: latency under 50ms (per TC-DET-09).

### Network Connection Stats (SAVR-14)
Look for accurate data-sent, data-received, and connection-speed numbers logged for an AI program's network connections.

- **File:** `tests/SAVR2SAVR14.py`
- **Roster key:** `tcp_stats_test`
- **What it checks:** For each expected process (matched by name or PID), verifies at least one logged TCP connection snapshot has non-zero bytes sent, non-zero bytes received, and a non-zero round-trip time simultaneously.

### Encrypted Connection Detection (SAVR-15)
Look for the domain, TLS version, and cipher being correctly captured for a secure connection made by an AI program.

- **File:** `tests/SAVR2SAVR15.py`
- **Roster key:** `schannel_test`
- **What it checks:** For each domain in the roster, verifies the captured TLS event includes a matching server name (SNI), a non-empty TLS version, and a non-empty cipher. Key exchange method and protocol list are checked as secondary fields. Requires the test traffic to be generated via PowerShell/.NET rather than Chrome/Edge, since those browsers use their own TLS stack rather than the OS Schannel provider.

### Domain Lookup Correlation (SAVR-18)
Look for a domain lookup (DNS query) being correctly linked to the connection that follows it, rather than logged as two unrelated events.

- **File:** `tests/SAVR2SAVR18.py`
- **Roster key:** `dns_correlation_test`
- **What it checks:** For each domain in the roster, confirms a successful DNS resolution (status 0, at least one answer) is followed by a TCP connection line attributing its domain source to that DNS lookup, and that the resulting URL field is populated rather than empty.

### Device Registration (SAVR-43, Issue 1)
Look for a device completing registration and authentication in the correct order, even when no AI activity has been detected yet.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `registration_test`
- **What it checks:** Confirms six milestones occur in order — fingerprint generated, registration request sent, registration accepted, authentication request sent, authentication accepted, first status report sent — and that every process scan completed before registration reported zero AI processes found.

### Status Report Contents (SAVR-43, Issue 2)
Look for each periodic status report containing all required fields (IP address, hostname, device token, stats, etc.).

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `heartbeat_payload_test`
- **What it checks:** Verifies the status report payload includes all required top-level fields, a valid stats block (CPU, memory, disk usage, uptime), a correctly formatted last-scan timestamp, and a successful server response.

### Detection Record Completeness (SAVR-43, Issue 3)
Look for a detection record on an AI program that's also using the network to include both the process details and the network details together, with nothing missing.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `combined_fields_test`
- **What it checks:** For each detected-agent record in the run window, verifies the event type and detection method are correct, and that all 13 required process- and network-level fields (OS details, logged-in user, network adapters, route table, process metrics, and flow/connection details) are present and non-empty.

### File Monitoring & Filtering (SAVR-16)
Look for the file-monitoring component only capturing activity from AI-related programs (ignoring everything else) and staying within its event-rate, CPU, and memory limits.

- **File:** `tests/SAVR2SAVR16.py`
- **Roster key:** `kernel_file_monitor_test`
- **What it checks:** Confirms the monitoring session starts correctly with the expected provider, that session statistics are logged with zero lost events or buffers, that the event rate stays under the configured limit, that CPU and memory usage stay within budget, that matched (AI-relevant) and dropped (non-AI) file events meet configured expectations, and that the session only stops after the parent service begins shutting down.

## Roster Configuration

The roster (`roster.json`) controls which processes, domains, and fields each test asserts on. It is the single place to configure expected values for a given environment.

Each test has its own top-level key in the roster. If a key is absent, that test is skipped entirely. An empty object `{}` enables the test with default settings.

`setup.py` automatically patches `tcp_stats_test.by_pid` on every run with the live httpbin fixture PID — do not manually edit that field as it will be overwritten.

Fields that are environment-specific and may need updating between VMs or builds:

- `confidence_test.config_path` — path to `config.json` on the target machine
- `confidence_test.expected_agents` — processes expected to be running and detected; add or remove entries to match what is installed
- `tcp_stats_test.by_pid` — managed automatically by `setup.py`
- `dns_correlation_test.domains` — domains to verify DNS+TCP correlation for; `httpbin.org` requires the fixture, `chatgpt.com` resolves automatically from the service's DNS cache refresh
- `schannel_test.domains` — TLS domains to verify; must be reachable via PowerShell/.NET (not Chrome/Edge)
- `heartbeat_payload_test` — required fields and stats keys; update if the heartbeat payload schema changes between builds
- `kernel_file_monitor_test` — provider GUID and event ID; update if the ETW provider changes between builds
- `module_enum_test.expected_agents` — processes to check for library enumeration. Set `expected_libraries` to `[]` for native binaries like ollama.exe. For python+torch, list expected DLL names — entries will produce NOT_DETECTED until SAVR-16 is fixed.

## Reading the Results

Each row in the results output gets one of these verdicts:

- **PASS** — worked as expected
- **FAIL** — did not work as expected (a real finding)
- **PARTIAL** — mostly worked, but part of it is missing or incomplete
- **NOT_DETECTED** — the activity we needed to check never happened during this run (usually means rerun with the right setup, not a product problem)
- **INCONCLUSIVE** — not enough information in this run to make a call either way
