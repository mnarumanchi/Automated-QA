"""
SAVR-43 test classes.

  Issue 1 - Device registration completes without any agent detection   (RegistrationTest)
  Issue 2 - Heartbeat payload contains ip_address (+ schema alignment)  (HeartbeatPayloadTest)
  Issue 3 - Combined (process+network) detection events carry both
            process fields and flow fields                              (CombinedFieldsTest)

Harness contract (matches overall.py): name, __init__(cfg, agents=None),
offer(line, i, window), resolve(), rows(). Enable each test by adding
its section to roster.json.

CombinedFieldsTest reads `agents` - the list overall.py builds from
detected_agents.json, already filtered to entries whose last_seen is
at/after --start. Each entry is one detected-agent record (the same
shape as a Process-Data.txt export). No manual file export needed;
event_files/event_dir in the roster remain as an optional supplement
for replaying older captures.
"""

import json
from pathlib import Path

# ---------------------------------------------------------------- helpers

def _extract_json(line: str, marker: str):
    """Pull the JSON that follows `marker` in a log line.
    Requests are logged with doubled braces {{...}}; responses as [ {...} ].
    """
    idx = line.find(marker)
    if idx < 0:
        return None
    payload = line[idx + len(marker):].strip()
    if payload.startswith("{{"):
        payload = payload[1:]
    if payload.endswith("}}"):
        payload = payload[:-1]
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        return parsed[0]
    return parsed if isinstance(parsed, dict) else None


import re
_EPOCH_RE = re.compile(r"^\d{9,11}$")
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SCAN_COMPLETE_RE = re.compile(
    r"\[SCANNER\]\s+Scan complete:\s*(?P<n>\d+)\s+AI process\(es\) found")


# =====================================================================
# Issue 1 - device registration with zero agent detections
# =====================================================================
class SAVR43_1:
    name = "SAVR43_1"

    _MILESTONES = [
        ("fingerprint",   "Successfully generated device fingerprint"),
        ("reg_request",   "Registration Request data"),
        ("reg_response",  "Registration response"),
        ("auth_request",  "Authentication Request data"),
        ("auth_response", "Authentication response"),
        ("heartbeat_ok",  "Successfully sent heartbeat request"),
    ]

    def __init__(self, cfg, agents, sysinfo):
        self.require_zero_agents = bool(cfg.get("require_zero_agents", True))
        self.seen = {}
        self.scan_counts = []
        self.reg_success = None
        self.auth_success = None

    def offer(self, line, i, window):
        for key, needle in self._MILESTONES:
            if key not in self.seen and needle in line:
                self.seen[key] = (i, line)
                if key == "reg_response":
                    d = _extract_json(line, "Registration response :")
                    self.reg_success = bool(d and d.get("success"))
                elif key == "auth_response":
                    d = _extract_json(line, "Authentication response :")
                    self.auth_success = bool(d and d.get("success"))
        m = _SCAN_COMPLETE_RE.search(line)
        if m:
            self.scan_counts.append((i, int(m.group("n"))))

    def resolve(self):
        self.results = []
        prev_idx, in_order, missing = -1, True, []
        for key, _needle in self._MILESTONES:
            if key not in self.seen:
                missing.append(key)
                continue
            idx = self.seen[key][0]
            if idx < prev_idx:
                in_order = False
            prev_idx = idx
        if missing:
            self.results.append((
                "registration sequence", "all 6 milestones",
                f"missing: {', '.join(missing)}", "NOT_DETECTED",
                "registration/auth sequence not (fully) in run window; "
                "start the window at service install/restart to exercise it",
            ))
        else:
            self.results.append((
                "registration sequence", "all 6 milestones in order",
                "complete" if in_order else "out of order",
                "PASS" if in_order else "FAIL",
                "" if in_order else "milestones appeared out of expected order",
            ))

        for label, key, ok in (
                ("registration accepted", "reg_response", self.reg_success),
                ("authentication accepted", "auth_response", self.auth_success)):
            seen = key in self.seen
            result = "PASS" if ok else ("FAIL" if seen else "NOT_DETECTED")
            self.results.append((
                label, "success=true",
                "true" if ok else ("false/unparsed" if seen else "not seen"),
                result,
                "" if ok else ("server did not confirm success" if seen
                               else "response line not in run window"),
            ))

        if self.require_zero_agents:
            if "reg_response" in self.seen:
                reg_idx = self.seen["reg_response"][0]
                pre = [n for i, n in self.scan_counts if i <= reg_idx]
                nonzero = [n for n in pre if n > 0]
                if not pre:
                    self.results.append((
                        "zero-agent precondition", "0 AI processes in all scans",
                        "no scans in window", "NOT_DETECTED",
                        "no [SCANNER] Scan complete lines before registration",
                    ))
                else:
                    ok = not nonzero
                    self.results.append((
                        "zero-agent precondition",
                        "0 AI processes in all scans before registration",
                        f"{len(pre)} scan(s), max count {max(pre)}",
                        "PASS" if ok else "FAIL",
                        "" if ok else
                        "an AI process was detected before registration; "
                        "this run does not exercise Issue 1",
                    ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)


# =====================================================================
# Issue 2 - heartbeat payload contents (schema-configurable)
# =====================================================================
class SAVR43_2:
    name = "SAVR43_2"

    def __init__(self, cfg, agents, sysinfo):
        self.required = cfg.get("required_fields", ["ip_address"])
        self.forbidden = cfg.get("forbidden_fields", [])
        self.stats_key = cfg.get("stats_key", "sys_stats")
        self.stats_required = cfg.get("stats_required", [])
        self.lst_format = cfg.get("last_scan_time_format")
        self.require_resp = bool(cfg.get("require_response_success", True))
        self.payload = None
        self.resp_success = None

    def offer(self, line, i, window):
        if self.payload is None and "Heartbeat Request data" in line:
            d = _extract_json(line, "Heartbeat Request data :")
            if isinstance(d, dict):
                self.payload = d
        if self.resp_success is None and "Heartbeat response" in line:
            d = _extract_json(line, "Heartbeat response :")
            if isinstance(d, dict):
                self.resp_success = bool(d.get("success"))

    def resolve(self):
        self.results = []
        p = self.payload
        if p is None:
            self.results.append((
                "heartbeat request", "parseable JSON payload", "", "NOT_DETECTED",
                "no parseable Heartbeat Request data line in the run window",
            ))
            return

        for f in self.required:
            val = p.get(f, None)
            ok = val is not None and val != ""
            self.results.append((
                f"heartbeat field '{f}'", "present, non-empty",
                repr(val) if f != "device_token" else ("<set>" if ok else repr(val)),
                "PASS" if ok else "FAIL",
                "" if ok else "field missing or empty in heartbeat payload",
            ))

        for f in self.forbidden:
            ok = f not in p
            self.results.append((
                f"heartbeat field '{f}'", "absent",
                "absent" if ok else "present",
                "PASS" if ok else "FAIL",
                "" if ok else "legacy/forbidden field still in heartbeat payload",
            ))

        if self.stats_key:
            stats = p.get(self.stats_key)
            if not isinstance(stats, dict):
                self.results.append((
                    f"stats block '{self.stats_key}'", "present (object)",
                    "missing", "FAIL",
                    "expected stats object not found "
                    "(check sys_stats vs system_stats naming)",
                ))
            else:
                for f in self.stats_required:
                    ok = f in stats
                    self.results.append((
                        f"{self.stats_key}.{f}", "present",
                        repr(stats.get(f)) if ok else "missing",
                        "PASS" if ok else "FAIL",
                        "" if ok else "stat field missing "
                        "(check cpu_percent/cpu_usage, memory_mb/memory_usage)",
                    ))

        if self.lst_format:
            raw = p.get("last_scan_time")
            s = str(raw) if raw is not None else ""
            if self.lst_format == "epoch":
                ok = bool(_EPOCH_RE.match(s))
            elif self.lst_format == "iso8601":
                ok = bool(_ISO8601_RE.match(s))
            else:
                ok = False
            self.results.append((
                "last_scan_time format", self.lst_format, repr(raw),
                "PASS" if ok else "FAIL",
                "" if ok else f"value does not match {self.lst_format} format",
            ))

        if self.require_resp:
            ok = bool(self.resp_success)
            self.results.append((
                "heartbeat response", "success=true",
                "true" if ok else ("false" if self.resp_success is not None
                                   else "not seen"),
                "PASS" if ok else "FAIL",
                "" if ok else "no successful heartbeat response in run window",
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)


# =====================================================================
# Issue 3 - combined detection events carry process + flow fields
# =====================================================================
class SAVR43_3:
    """Primary source: `agents` - the detected_agents.json entries overall.py
    already loaded and filtered by --start. Optionally supplemented by
    roster-listed event_files/event_dir (useful for replaying older,
    manually captured records, e.g. from a Slack/Jira attachment).

    roster section:
      "combined_fields_test": {
        "event_files": [],          # optional extra records (manual captures)
        "event_dir": null,
        "required_fields": ["os_name", "os_version", "logged_in_user",
                            "network_adapters", "route_table",
                            "working_set_bytes", "thread_count",
                            "handle_count", "process_start_time",
                            "flow_id", "src_ip", "dst_ip", "bytes_out"],
        "expect_event_type": "agent_detected",
        "expect_detection_method": "Combined",
        "require_min_records": 1     # fail loudly if nothing to check
      }
    """

    name = "SAVR43_3"

    DEFAULT_REQUIRED = [
        "os_name", "os_version", "logged_in_user", "network_adapters",
        "route_table", "working_set_bytes", "thread_count", "handle_count",
        "process_start_time", "flow_id", "src_ip", "dst_ip", "bytes_out",
    ]

    def __init__(self, cfg, agents, sysinfo):
        self.agents = agents or []
        self.files = [Path(f) for f in cfg.get("event_files", [])]
        event_dir = cfg.get("event_dir")
        if event_dir:
            d = Path(event_dir)
            if d.is_dir():
                self.files += sorted(
                    p for p in d.iterdir()
                    if p.suffix.lower() in (".json", ".txt"))
        self.required = cfg.get("required_fields", self.DEFAULT_REQUIRED)
        self.expect_type = cfg.get("expect_event_type", "agent_detected")
        self.expect_method = cfg.get("expect_detection_method")
        self.require_min = int(cfg.get("require_min_records", 0))

    def offer(self, line, i, window):
        pass  # data comes from `agents` (+ optional files), not the log

    def _check_record(self, subject, ev):
        rows = []
        if self.expect_type:
            ok = ev.get("event_type") == self.expect_type
            rows.append((
                subject, f"event_type={self.expect_type}",
                repr(ev.get("event_type")), "PASS" if ok else "FAIL",
                "" if ok else "unexpected event type",
            ))
        if self.expect_method:
            ok = ev.get("detection_method") == self.expect_method
            rows.append((
                subject, f"detection_method={self.expect_method}",
                repr(ev.get("detection_method")), "PASS" if ok else "FAIL",
                "" if ok else "event is not a combined detection",
            ))
        bad = [f for f in self.required
              if ev.get(f, None) in (None, "", [])]
        ok = not bad
        rows.append((
            subject, f"{len(self.required)} combined fields non-null",
            "all present" if ok else f"missing/null: {', '.join(bad)}",
            "PASS" if ok else "FAIL",
            "" if ok else "process/flow fields absent from combined event "
            "(Issue 3 regression)",
        ))
        return rows

    def resolve(self):
        self.results = []

        records = []
        for ev in self.agents:
            agent = ev.get("agent_name") or ev.get("process_name") or "?"
            last_seen = ev.get("last_seen", "")
            records.append((f"agent: {agent} ({last_seen})", ev))

        for path in self.files:
            if not path.exists():
                self.results.append((
                    path.name, "file exists", "missing", "NOT_DETECTED",
                    "captured event file not found on disk",
                ))
                continue
            try:
                ev = json.loads(path.read_text(encoding="utf-8",
                                               errors="replace"))
            except (json.JSONDecodeError, ValueError) as e:
                self.results.append((
                    path.name, "valid JSON", "parse error", "FAIL",
                    f"could not parse event file: {e}",
                ))
                continue
            agent = ev.get("agent_name") or ev.get("process_name") or "?"
            records.append((f"{path.name} ({agent})", ev))

        if not records:
            self.results.append((
                "combined detections", f">= {max(self.require_min, 1)} record(s)",
                "0", "NOT_DETECTED" if self.require_min == 0 else "FAIL",
                "no detected_agents entries in window and no event files "
                "configured; trigger a combined detection (AI process that "
                "also makes a network connection) inside the run window",
            ))
            return

        if len(records) < self.require_min:
            self.results.append((
                "combined detections", f">= {self.require_min} record(s)",
                str(len(records)), "FAIL",
                "fewer combined-detection records in window than required",
            ))

        for subject, ev in records:
            self.results.extend(self._check_record(subject, ev))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
