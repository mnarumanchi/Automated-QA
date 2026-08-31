import re
import json

PROCMOD_RE = re.compile(r"\[PROCMOD\] PID (\d+): (\d+) AI module\(s\) found")
SCANNER_RE = re.compile(r"\[SCANNER\] AI process: (\S+) \(PID (\d+), (\d+) lib\(s\), conf ([0-9.]+)\)")

def _has_library(agent, lib_name):
    libs = agent.get("loaded_ai_libraries", [])
    return any(lib.get("lib_name") == lib_name for lib in libs)

class SAVR17:
    name = "SAVR17"

    def __init__(self, cfg, agents, sysinfo):
        self.results = []
        self.targets = {}

        for ea in cfg.get("expected_agents", []):
            pname    = ea["process_name"]
            lib_name = ea.get("library_name")

            matched_agent = None
            for agent in agents:
                if agent.get("process_name") != pname:
                    continue
                if lib_name and not _has_library(agent, lib_name):
                    continue
                matched_agent = agent
                break

            key = f"{pname}+{lib_name}" if lib_name else pname
            self.targets[key] = {
                "pname":           pname,
                "lib_name":        lib_name,
                "pids":            [str(p) for p in matched_agent.get("pids", [])] if matched_agent else [],
                "found_in_agents": matched_agent is not None,
                "procmod_modules": None,
                "scanner_modules": None,
                "scanner_conf":    None,
            }

    def offer(self, line, i, window):
        for key, t in self.targets.items():
            if not t["pids"]:
                continue

            m = PROCMOD_RE.search(line)
            if m and m.group(1) in t["pids"]:
                t["procmod_modules"] = int(m.group(2))
                continue

            m = SCANNER_RE.search(line)
            if m and m.group(2) in t["pids"]:
                t["scanner_modules"] = int(m.group(3))
                t["scanner_conf"]    = float(m.group(4))

    def resolve(self):
        for key, t in self.targets.items():
            pname    = t["pname"]
            lib_name = t["lib_name"]
            label    = f"{pname} ({lib_name})" if lib_name else pname

            if not t["found_in_agents"]:
                self.results.append((
                    label,
                    f"present in detected_agents.json with {lib_name}",
                    "absent",
                    "NOT_DETECTED",
                    f"{pname} with library {lib_name} not found in detected_agents.json"
                ))
                continue

            expected = f"PROCMOD and SCANNER entries found in log for PIDs {t['pids']}"
            actual_parts = []
            failures = []

            if t["procmod_modules"] is None:
                failures.append("PROCMOD line not found")
                actual_parts.append("PROCMOD: absent")
            else:
                actual_parts.append(f"PROCMOD: {t['procmod_modules']} module(s)")

            if t["scanner_modules"] is None:
                failures.append("SCANNER line not found")
                actual_parts.append("SCANNER: absent")
            else:
                actual_parts.append(f"SCANNER: {t['scanner_modules']} lib(s), conf {t['scanner_conf']}")

            if t["procmod_modules"] is not None and t["scanner_modules"] is not None:
                if t["procmod_modules"] != t["scanner_modules"]:
                    failures.append(
                        f"module count mismatch: PROCMOD={t['procmod_modules']} vs SCANNER={t['scanner_modules']}"
                    )

            actual = ", ".join(actual_parts)

            if not failures:
                result  = "PASS"
                comment = "PROCMOD and SCANNER lines found with matching module counts"
            elif t["procmod_modules"] is None and t["scanner_modules"] is None:
                result  = "NOT_DETECTED"
                comment = "neither PROCMOD nor SCANNER lines found in log"
            else:
                result  = "FAIL"
                comment = "; ".join(failures)

            self.results.append((label, expected, actual, result, comment))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)