import re
import json
from pathlib import Path

CONF_RE = re.compile(
    r"\[SCANNER\]\s+Trusted AI process:\s+(?P<name>\S+)\s+\(PID\s+(?P<pid>\d+),"
    r".*?conf\s+(?P<conf>[0-9.]+)\)"
)

class SAVR7:
    name = "SAVR7"
    link = ""

    def __init__(self, cfg, agents, sysinfo):
        self.agents = agents or []
        self.config_path = Path(cfg.get("config_path", ""))
        self.expected_agents = cfg.get("expected_agents", [])
        self.library_processes = cfg.get("library_processes", [])

        # load config.json
        self.policy = {}
        self.exclusions = []
        self.min_threshold = 0.6
        self.whitelist = []
        if self.config_path.exists():
            try:
                policy = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.policy = policy
                self.exclusions = [
                    p.lower() for p in
                    policy.get("exclusions", {}).get("system_processes", [])
                ]
                self.min_threshold = policy.get(
                    "confidence_modifiers", {}
                ).get("minimum_threshold", 0.6)
                self.whitelist = policy.get(
                    "whitelists", {}
                ).get("legitimate_ai_processes", [])
            except (json.JSONDecodeError, ValueError):
                pass

        # per process name -> list of (pid, conf) seen in log
        self.log_hits = {}

    def offer(self, line, i, window):
        m = CONF_RE.search(line)
        if not m:
            return
        name = m.group("name")
        pid  = m.group("pid")
        conf = float(m.group("conf"))
        if name not in self.log_hits:
            self.log_hits[name] = []
        # dedupe by pid -- keep highest conf seen for this pid
        existing_pids = [p for p, c in self.log_hits[name]]
        if pid not in existing_pids:
            self.log_hits[name].append((pid, conf))

    def _whitelist_entry(self, process_name):
        name_lower = process_name.lower().replace(".exe", "")
        for entry in self.whitelist:
            for pattern in entry.get("patterns", []):
                if re.search(pattern, name_lower, re.IGNORECASE):
                    return entry
        return None

    def resolve(self):
        self.results = []

        # --- Part 1: log confidence checks for expected_agents ---
        for ea in self.expected_agents:
            pname  = ea["process_name"]
            lo, hi = ea["confidence_range"]
            expect_stype = ea.get("expect_service_type")

            hits = self.log_hits.get(pname, [])
            if not hits:
                self.results.append((
                    f"{pname} (log)",
                    f"conf {lo}-{hi}",
                    "", "NOT_DETECTED",
                    f"no SCANNER confidence line for {pname} in run window",
                ))
                continue

            # use best (highest) confidence seen
            best_pid, best_conf = max(hits, key=lambda x: x[1])
            ok = lo <= best_conf <= hi
            self.results.append((
                f"{pname} (PID {best_pid}) (log)",
                f"conf {lo}-{hi}",
                str(best_conf),
                "PASS" if ok else "FAIL",
                "" if ok else
                f"confidence {best_conf} outside expected range {lo}-{hi}",
            ))

        # --- Part 2: JSON persistence checks for expected_agents ---
        for ea in self.expected_agents:
            pname        = ea["process_name"]
            lo, hi       = ea["confidence_range"]
            expect_stype = ea.get("expect_service_type")

            json_entry = next(
                (a for a in self.agents
                 if a.get("process_name", "").lower() == pname.lower()),
                None
            )

            if json_entry is None:
                # check if it was seen in log -- if yes, persistence is the bug
                seen_in_log = pname in self.log_hits
                self.results.append((
                    f"{pname} (JSON)",
                    "present in detected_agents.json",
                    "absent",
                    "FAIL" if seen_in_log else "NOT_DETECTED",
                    f"detected in log (conf {max(c for p,c in self.log_hits[pname]):.2f}) "
                    f"but not persisted to detected_agents.json"
                    if seen_in_log else
                    f"{pname} not seen in log or JSON this window",
                ))
                continue

            failures = []
            conf = json_entry.get("confidence", 0)
            if not (lo <= conf <= hi):
                failures.append(f"confidence {conf:.2f} outside {lo}-{hi}")

            if expect_stype:
                actual_stype = json_entry.get("service_type", "")
                if actual_stype != expect_stype:
                    failures.append(
                        f"service_type='{actual_stype}' expected '{expect_stype}'"
                    )

            # cross-check against whitelist
            wl = self._whitelist_entry(pname)
            if wl:
                wl_conf = wl.get("confidence", 0)
                if abs(conf - wl_conf) > 0.05:
                    failures.append(
                        f"JSON confidence {conf:.2f} diverges from "
                        f"whitelist configured value {wl_conf}"
                    )

            actual_str = (
                f"conf={conf:.2f} service_type={json_entry.get('service_type')}"
            )
            self.results.append((
                f"{pname} (JSON)",
                f"conf {lo}-{hi}, service_type={expect_stype}",
                actual_str,
                "PASS" if not failures else "FAIL",
                "; ".join(failures),
            ))

        # --- Part 3: library_processes ---
        for lp in self.library_processes:
            pname  = lp["process_name"]
            lo, hi = lp["confidence_range"]
            note   = lp.get("note", "")

            hits = self.log_hits.get(pname, [])
            if not hits:
                self.results.append((
                    f"{pname} library detection (log)",
                    f"conf >= {lo}",
                    "", "NOT_DETECTED",
                    f"no SCANNER line for {pname} -- "
                    f"process not running or not detected",
                ))
            else:
                best_pid, best_conf = max(hits, key=lambda x: x[1])
                ok = lo <= best_conf <= hi
                self.results.append((
                    f"{pname} (PID {best_pid}) library detection (log)",
                    f"conf {lo}-{hi}",
                    str(best_conf),
                    "PASS" if ok else "FAIL",
                    "" if ok else
                    f"confidence {best_conf} outside expected range {lo}-{hi}",
                ))

            json_entry = next(
                (a for a in self.agents
                 if a.get("process_name", "").lower() == pname.lower()),
                None
            )
            if json_entry is None:
                self.results.append((
                    f"{pname} library detection (JSON)",
                    "present in detected_agents.json",
                    "absent",
                    "NOT_DETECTED",
                    f"not in detected_agents.json -- {note}" if note
                    else f"not in detected_agents.json",
                ))
            else:
                conf = json_entry.get("confidence", 0)
                libs = json_entry.get("loaded_ai_libraries", [])
                ok   = lo <= conf <= hi and len(libs) > 0
                self.results.append((
                    f"{pname} library detection (JSON)",
                    f"conf {lo}-{hi}, loaded_ai_libraries non-empty",
                    f"conf={conf:.2f} libraries={libs}",
                    "PASS" if ok else "FAIL",
                    "" if ok else
                    "loaded_ai_libraries empty (SAVR-16)" if not libs
                    else f"confidence {conf:.2f} outside {lo}-{hi}",
                ))

        # --- Part 4: exclusions check ---
        if self.exclusions:
            unexpected = [
                a for a in self.agents
                if a.get("process_name", "").lower() in self.exclusions
            ]
            if unexpected:
                for a in unexpected:
                    self.results.append((
                        f"{a['process_name']} (JSON exclusion)",
                        "must not appear in detected_agents.json",
                        f"present (conf={a.get('confidence', '?')})",
                        "FAIL",
                        f"excluded process found in detected_agents.json "
                        f"-- confidence scorer or exclusion list not applied",
                    ))
            else:
                self.results.append((
                    "exclusions check",
                    "no system_processes in detected_agents.json",
                    f"0 excluded processes found ({len(self.exclusions)} checked)",
                    "PASS",
                    "",
                ))

        # --- Part 5: minimum threshold check ---
        below_threshold = [
            a for a in self.agents
            if a.get("confidence", 1.0) < self.min_threshold
        ]
        if below_threshold:
            for a in below_threshold:
                self.results.append((
                    f"{a['process_name']} (threshold)",
                    f"confidence >= {self.min_threshold}",
                    f"{a.get('confidence', '?')}",
                    "FAIL",
                    f"entry below minimum_confidence_threshold "
                    f"{self.min_threshold} in detected_agents.json",
                ))
        else:
            self.results.append((
                "minimum threshold check",
                f"all JSON entries >= {self.min_threshold}",
                f"all {len(self.agents)} agent(s) above threshold",
                "PASS" if self.agents else "INCONCLUSIVE",
                "" if self.agents else "no agents in window to check",
            ))

        # --- Part 6: unexpected JSON entries ---
        expected_names = {
            ea["process_name"].lower() for ea in self.expected_agents
        } | {
            lp["process_name"].lower() for lp in self.library_processes
        }
        unexpected_json = [
            a for a in self.agents
            if a.get("process_name", "").lower() not in expected_names
            and a.get("process_name", "").lower() not in self.exclusions
        ]
        if unexpected_json:
            for a in unexpected_json:
                self.results.append((
                    f"{a['process_name']} (unexpected JSON entry)",
                    "not in expected_agents or library_processes",
                    f"conf={a.get('confidence', '?')} "
                    f"service_type={a.get('service_type', '?')}",
                    "FAIL",
                    "unexpected process in detected_agents.json -- "
                    "verify this is a legitimate detection",
                ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
