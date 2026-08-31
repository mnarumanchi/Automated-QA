"""
SAVR-16 test class - ETW Kernel-File monitor: AI library/model detection
with PID allowlist volume control.

Ticket requirements covered (Tasks 3.4-3.7):
  - session created ('SecureAIKernelFileMonitor')
  - provider enabled with GUID EDD08927, Event 12
  - trace started and events processed (worker thread)
  - session statistics logged; no event/buffer drops
  - session stopped on service shutdown
  - performance: CPU / memory within limits
  - acceptance: event rate < 1000/sec under full workload
  - PID allowlist + path/extension filters observable through the
    'Dropped (PID filter)' and 'Matched (path+ext)' counters

Harness contract (matches overall.py): name, __init__(cfg, agents=None),
offer(line, i, window), resolve(), rows(). Enable via a
"kernel_file_monitor_test" section in roster.json.
This test reads only the log window; `agents` is accepted for contract
compatibility but not used.
"""

import re
from datetime import datetime

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")

_SESSION_RE = re.compile(
    r"\[ETW_SESSION_MGR\]\s+Session '(?P<name>SecureAIKernelFileMonitor)' started"
    r"\s*\(handle=(?P<handle>\S+), max_buffers=(?P<maxbuf>\d+), buffer_kb=(?P<bufkb>\d+)\)")

_STARTED_RE = re.compile(
    r"\[ETW_FILE_MONITOR\]\s+Started\s*\(provider=(?P<provider>[0-9A-Fa-f]+),"
    r"\s*keyword=(?P<keyword>0x[0-9A-Fa-f]+),\s*eventId=(?P<eventid>\d+)\)")

_STOPPED_RE = re.compile(r"\[ETW_FILE_MONITOR\]\s+Stopped\b")

_STAT_RE = re.compile(
    r"\[ETW_FILE_MONITOR\]\s+(?P<key>Events Processed|Events Received\(\d+\)|"
    r"Dropped \(PID filter\)|Matched \(path\+ext\)|Buffers Written|"
    r"Events Lost|RT Buffers Lost)\s*:\s*(?P<val>\d+)")

_CPU_RE = re.compile(r"\[ETW_FILE_MONITOR\]\s+CPU Usage\s*:\s*(?P<pct>[0-9.]+)%")
_MEM_RE = re.compile(r"\[ETW_FILE_MONITOR\]\s+Memory Working Set\s*:\s*(?P<kb>\d+)\s*KB")

_SVC_STOP_MARKERS = ("Stopping ETW monitors", "Svc stop in progress")


def _ts(line):
    m = _TS_RE.match(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")


class SAVR16:
    """roster section:
      "kernel_file_monitor_test": {
        "expected_provider": "EDD08927",
        "expected_event_id": 12,
        "max_event_rate_per_sec": 1000,
        "require_zero_lost": true,
        "max_cpu_pct": 5.0,             # null to skip
        "max_memory_kb": 51200,         # null to skip
        "expect_matched_min": 0,        # set >=1 for AI-workload runs
        "expect_dropped_min": 0         # set >=1 for allowlist-drop runs
      }
    """

    name = "SAVR16"

    def __init__(self, cfg, agents, sysinfo):
        self.expected_provider = cfg.get("expected_provider", "EDD08927")
        self.expected_event_id = int(cfg.get("expected_event_id", 12))
        self.max_rate = cfg.get("max_event_rate_per_sec", 1000)
        self.require_zero_lost = bool(cfg.get("require_zero_lost", True))
        self.max_cpu = cfg.get("max_cpu_pct")
        self.max_mem_kb = cfg.get("max_memory_kb")
        self.matched_min = int(cfg.get("expect_matched_min", 0))
        self.dropped_min = int(cfg.get("expect_dropped_min", 0))

        self.session_line = None
        self.started = None
        self.stopped_idx = None
        self.svc_stop_idx = None
        self.stats = {}
        self.stats_ts = None
        self.cpu_pct = None
        self.mem_kb = None

    def offer(self, line, i, window):
        if self.session_line is None:
            m = _SESSION_RE.search(line)
            if m:
                self.session_line = (i, line)
                return

        if self.started is None:
            m = _STARTED_RE.search(line)
            if m:
                self.started = {
                    "i": i,
                    "ts": _ts(line),
                    "provider": m.group("provider"),
                    "event_id": int(m.group("eventid")),
                    "keyword": m.group("keyword"),
                }
                return

        m = _STAT_RE.search(line)
        if m:
            key = m.group("key")
            key = re.sub(r"\(\d+\)$", "", key).strip()
            self.stats[key] = int(m.group("val"))
            self.stats_ts = _ts(line) or self.stats_ts
            return

        m = _CPU_RE.search(line)
        if m:
            self.cpu_pct = float(m.group("pct"))
            return
        m = _MEM_RE.search(line)
        if m:
            self.mem_kb = int(m.group("kb"))
            return

        if _STOPPED_RE.search(line):
            self.stopped_idx = i
            return
        if self.svc_stop_idx is None and any(k in line for k in _SVC_STOP_MARKERS):
            self.svc_stop_idx = i

    def resolve(self):
        self.results = []
        R = self.results.append

        if (self.session_line is None and self.started is None
                and not self.stats):
            R(("kernel-file monitor", "activity in window", "none",
               "NOT_DETECTED",
               "no SecureAIKernelFileMonitor lines in the run window; "
               "start the window at a service (re)start on a build with "
               "the feature enabled"))
            return

        ok = self.session_line is not None
        R(("session created", "'SecureAIKernelFileMonitor' started",
           "seen" if ok else "not seen",
           "PASS" if ok else "NOT_DETECTED",
           "" if ok else "session-start line not in run window"))

        if self.started is None:
            R(("provider enabled",
               f"provider={self.expected_provider}, "
               f"eventId={self.expected_event_id}",
               "not seen", "NOT_DETECTED",
               "[ETW_FILE_MONITOR] Started line not in run window"))
        else:
            ok = (self.started["provider"].upper()
                  == self.expected_provider.upper())
            R(("provider GUID", self.expected_provider,
               self.started["provider"],
               "PASS" if ok else "FAIL",
               "" if ok else "wrong Kernel-File provider configured"))
            ok = self.started["event_id"] == self.expected_event_id
            R(("subscribed event id", str(self.expected_event_id),
               str(self.started["event_id"]),
               "PASS" if ok else "FAIL",
               "" if ok else "monitor subscribed to wrong event id"))

        expected_keys = ["Events Processed", "Events Received",
                         "Dropped (PID filter)", "Matched (path+ext)",
                         "Buffers Written", "Events Lost", "RT Buffers Lost"]
        missing = [k for k in expected_keys if k not in self.stats]
        if missing:
            R(("statistics block", "all 7 counters logged",
               f"missing: {', '.join(missing)}", "NOT_DETECTED",
               "stats are logged at monitor stop; make sure the window "
               "includes a service stop/restart"))
        else:
            R(("statistics block", "all 7 counters logged", "complete",
               "PASS", ""))

            if self.require_zero_lost:
                lost = self.stats["Events Lost"]
                rt_lost = self.stats["RT Buffers Lost"]
                ok = lost == 0 and rt_lost == 0
                R(("event/buffer loss", "Events Lost=0, RT Buffers Lost=0",
                   f"lost={lost}, rt_lost={rt_lost}",
                   "PASS" if ok else "FAIL",
                   "" if ok else "ETW session dropped events/buffers "
                   "(volume control insufficient?)"))

            received = self.stats["Events Received"]
            if self.started and self.started["ts"] and self.stats_ts:
                dur = (self.stats_ts - self.started["ts"]).total_seconds()
                if dur > 0:
                    rate = received / dur
                    ok = rate < self.max_rate
                    R(("event rate", f"< {self.max_rate}/sec",
                       f"{rate:.2f}/sec ({received} events / {dur:.0f}s)",
                       "PASS" if ok else "FAIL",
                       "" if ok else "event rate exceeds acceptance limit"))
                else:
                    R(("event rate", f"< {self.max_rate}/sec",
                       f"{received} events / 0s window", "NOT_DETECTED",
                       "start and stats timestamps identical; "
                       "cannot compute rate"))
            else:
                R(("event rate", f"< {self.max_rate}/sec",
                   "no start/stats timestamps", "NOT_DETECTED",
                   "cannot compute rate without both timestamps"))

            matched = self.stats["Matched (path+ext)"]
            ok = matched >= self.matched_min
            R(("AI path events fired (path+ext filter)",
               f">= {self.matched_min}", str(matched),
               "PASS" if ok else "FAIL",
               "" if ok else "expected AI file activity was not matched; "
               "check path/extension filters and that the writing process "
               "is in the AI allowlist"))

            dropped = self.stats["Dropped (PID filter)"]
            ok = dropped >= self.dropped_min
            R(("PID allowlist drop (first-line filter)",
               f">= {self.dropped_min}", str(dropped),
               "PASS" if ok else "FAIL",
               "" if ok else "expected non-AI file activity was not "
               "dropped; PID allowlist first-line check may not be "
               "filtering"))

        if self.max_cpu is not None:
            if self.cpu_pct is None:
                R(("CPU usage", f"<= {self.max_cpu}%", "not logged",
                   "NOT_DETECTED", "CPU Usage line not in run window"))
            else:
                ok = self.cpu_pct <= float(self.max_cpu)
                R(("CPU usage", f"<= {self.max_cpu}%", f"{self.cpu_pct}%",
                   "PASS" if ok else "FAIL",
                   "" if ok else "monitor CPU above limit under workload"))
        if self.max_mem_kb is not None:
            if self.mem_kb is None:
                R(("memory working set", f"<= {self.max_mem_kb} KB",
                   "not logged", "NOT_DETECTED",
                   "Memory Working Set line not in run window"))
            else:
                ok = self.mem_kb <= int(self.max_mem_kb)
                R(("memory working set", f"<= {self.max_mem_kb} KB",
                   f"{self.mem_kb} KB",
                   "PASS" if ok else "FAIL",
                   "" if ok else "monitor memory above limit under workload"))

        if self.stopped_idx is None:
            R(("monitor stop", "[ETW_FILE_MONITOR] Stopped", "not seen",
               "NOT_DETECTED",
               "no Stopped line; include a service stop in the window"))
        else:
            if self.svc_stop_idx is not None:
                ok = self.stopped_idx >= self.svc_stop_idx
                R(("stop follows service status",
                   "Stopped after service shutdown began",
                   "yes" if ok else "Stopped before shutdown began",
                   "PASS" if ok else "FAIL",
                   "" if ok else "monitor stopped while the service was "
                   "still running (unexpected early stop)"))
            else:
                R(("stop follows service status",
                   "Stopped after service shutdown began",
                   "Stopped seen, but no service-shutdown marker in window",
                   "FAIL",
                   "monitor stopped without a service stop in the window "
                   "(unexpected early stop)"))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
