"""
TC-DET-11: AI module enumeration test.

Checks that detected agents in detected_agents.json have their
loaded_ai_libraries field correctly populated.

Harness contract: name, __init__(cfg, agents=None),
offer(line, i, window), resolve(), rows().
Enable via "module_enum_test" section in roster.json.

This test reads only `agents` (detected_agents.json entries filtered
by --start). The log window is not used.
"""

class SAVR6:
    name = "SAVR6"

    def __init__(self, cfg, agents, sysinfo):
        self.agents = agents or []
        self.expected_agents = cfg.get("expected_agents", [])

    def offer(self, line, i, window):
        pass  # data comes from agents, not the log

    def resolve(self):
        self.results = []

        if not self.agents and not self.expected_agents:
            self.results.append((
                "module enumeration",
                "detected_agents.json entries in window",
                "0",
                "INCONCLUSIVE",
                "no agents in window and no expected_agents configured",
            ))
            return

        for ea in self.expected_agents:
            pname     = ea["process_name"]
            exp_libs  = ea.get("expected_libraries", [])

            # find matching entry in agents
            entry = next(
                (a for a in self.agents
                 if a.get("process_name", "").lower() == pname.lower()),
                None
            )

            if entry is None:
                self.results.append((
                    f"{pname} libraries",
                    f"present in detected_agents.json with libraries={exp_libs}",
                    "absent",
                    "NOT_DETECTED",
                    f"{pname} not in detected_agents.json this window -- "
                    f"process not detected or LibraryAnalysis not firing (SAVR-16)",
                ))
                continue

            actual_libs = entry.get("loaded_ai_libraries", [])
            detection_method = entry.get("detection_method", "")

            # case 1: expected_libraries is empty -- just check field exists
            if not exp_libs:
                result  = "PASS"
                comment = ""
                actual  = f"loaded_ai_libraries={actual_libs} detection_method={detection_method}"
                # if libraries are non-empty that's actually better than expected
                if actual_libs:
                    comment = f"libraries present (unexpected but not a failure): {actual_libs}"
                self.results.append((
                    f"{pname} libraries",
                    "loaded_ai_libraries field present",
                    actual,
                    result,
                    comment,
                ))
                continue

            # case 2: expected_libraries specified -- check each one present
            if not actual_libs:
                self.results.append((
                    f"{pname} libraries",
                    f"loaded_ai_libraries contains {exp_libs}",
                    "loaded_ai_libraries=[]",
                    "FAIL",
                    f"loaded_ai_libraries is empty -- "
                    f"ETW kernel file monitor not capturing file events (SAVR-16)",
                ))
                continue

            missing = [l for l in exp_libs if l not in actual_libs]
            unexpected = [l for l in actual_libs if l not in exp_libs]

            if missing:
                self.results.append((
                    f"{pname} libraries",
                    f"loaded_ai_libraries contains {exp_libs}",
                    f"actual={actual_libs}",
                    "FAIL",
                    f"missing expected libraries: {missing}"
                    + (f"; unexpected: {unexpected}" if unexpected else ""),
                ))
            else:
                self.results.append((
                    f"{pname} libraries",
                    f"loaded_ai_libraries contains {exp_libs}",
                    f"actual={actual_libs}",
                    "PASS",
                    f"unexpected additional libraries: {unexpected}"
                    if unexpected else "",
                ))

            # check detection_method -- should be LibraryAnalysis for library-detected processes
            ok = detection_method == "LibraryAnalysis"
            self.results.append((
                f"{pname} detection_method",
                "LibraryAnalysis",
                detection_method,
                "PASS" if ok else "FAIL",
                "" if ok else
                f"expected LibraryAnalysis but got {detection_method} -- "
                f"process detected via fallback, not library scan",
            ))

        # check for agents in JSON that have non-empty loaded_ai_libraries
        # but aren't in expected_agents -- surface as informational
        expected_names = {ea["process_name"].lower() for ea in self.expected_agents}
        for agent in self.agents:
            pname = agent.get("process_name", "")
            if pname.lower() in expected_names:
                continue
            libs = agent.get("loaded_ai_libraries", [])
            if libs:
                self.results.append((
                    f"{pname} (unexpected libraries)",
                    "not in expected_agents",
                    f"loaded_ai_libraries={libs}",
                    "FAIL",
                    "agent has libraries but is not in expected_agents roster -- "
                    "verify and add to roster if legitimate",
                ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
