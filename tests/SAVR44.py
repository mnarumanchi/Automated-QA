import re

# SAVR-44 Step 1 checklist only: OUTPUT_MODULE batch/replay, heartbeat,
# ProcessScanner-detection-to-Push correlation, ERROR/failed-POST capture.
# Steps 2-7 (controller payload checks, code tracing, race conditions,
# written deliverables) are manual work, not automatable here.

OUTPUT_SENT_RE = re.compile(
    r"\[OUTPUT_MODULE\].*?Sent batch of (?P<n>\d+) events", re.IGNORECASE
)
OUTPUT_REPLAYED_RE = re.compile(
    r"\[OUTPUT_MODULE\].*?Replayed (?P<n>\d+) unsynced agents from disk",
    re.IGNORECASE,
)
HEARTBEAT_SENT_RE = re.compile(
    r"\[HEARTBEAT\].*?Heartbeat sent", re.IGNORECASE
)
SCANNER_HIT_RE = re.compile(
    r"\[SCANNER\]\s+Trusted AI process:\s+(?P<name>\S+)\s+\(PID\s+(?P<pid>\d+)"
)
PUSH_RE = re.compile(
    r"\[OUTPUT_MODULE\](?!.*will start after).*?push", re.IGNORECASE
)

ERROR_PATTERNS = [
    re.compile(r"\[HEARTBEAT\].*?Registration response.*?\"success\":false.*", re.IGNORECASE),
    re.compile(r"\[HEARTBEAT\].*?Failed to register device\.?", re.IGNORECASE),
    re.compile(r"\[HEARTBEAT\].*?Runtime error.*", re.IGNORECASE),
    re.compile(r"\bERROR\b.*", re.IGNORECASE),
    re.compile(r".*failed.*POST.*|.*POST.*failed.*", re.IGNORECASE),
]


class SAVR44:
    name = "SAVR44"

    def __init__(self, cfg, agents, sysinfo):
        self.output_sent_hits = []
        self.output_replayed_hits = []
        self.heartbeat_sent_hits = []
        self.scanner_hits = []
        self.push_hits = []
        self.error_lines = set()

    def offer(self, line, i, window):
        m = OUTPUT_SENT_RE.search(line)
        if m:
            self.output_sent_hits.append((i, int(m.group("n"))))

        m = OUTPUT_REPLAYED_RE.search(line)
        if m:
            self.output_replayed_hits.append((i, int(m.group("n"))))

        if HEARTBEAT_SENT_RE.search(line):
            self.heartbeat_sent_hits.append(i)

        m = SCANNER_HIT_RE.search(line)
        if m:
            self.scanner_hits.append((i, m.group("name"), m.group("pid")))

        if PUSH_RE.search(line):
            self.push_hits.append((i, line.strip()))

        for pat in ERROR_PATTERNS:
            m = pat.search(line)
            if m:
                self.error_lines.add(m.group(0).strip())
                break

    def resolve(self):
        self.results = []

        if self.output_sent_hits:
            idx, n = self.output_sent_hits[0]
            self.results.append((
                "OUTPUT_MODULE sent batch",
                "'[OUTPUT_MODULE] Sent batch of N events' appears at least once",
                f"first seen at line {idx}, N={n} ({len(self.output_sent_hits)} total)",
                "PASS", "",
            ))
        else:
            self.results.append((
                "OUTPUT_MODULE sent batch",
                "'[OUTPUT_MODULE] Sent batch of N events' appears at least once",
                "absent", "NOT_DETECTED",
                "sender thread never posted a batch in this window",
            ))

        if self.output_replayed_hits:
            idx, n = self.output_replayed_hits[0]
            self.results.append((
                "OUTPUT_MODULE replay on startup",
                "'[OUTPUT_MODULE] Replayed N unsynced agents from disk' appears",
                f"first seen at line {idx}, N={n}",
                "PASS", "",
            ))
        else:
            self.results.append((
                "OUTPUT_MODULE replay on startup",
                "'[OUTPUT_MODULE] Replayed N unsynced agents from disk' appears",
                "absent", "NOT_DETECTED",
                "ReconcileFromFile() replay line never seen in this window",
            ))

        if self.heartbeat_sent_hits:
            self.results.append((
                "Heartbeat sent",
                "'[HEARTBEAT] Heartbeat sent' appears at configured interval",
                f"{len(self.heartbeat_sent_hits)} occurrence(s), "
                f"first at line {self.heartbeat_sent_hits[0]}",
                "PASS", "",
            ))
        else:
            self.results.append((
                "Heartbeat sent",
                "'[HEARTBEAT] Heartbeat sent' appears at configured interval",
                "absent", "NOT_DETECTED",
                "no line matching '[HEARTBEAT] Heartbeat sent' found -- "
                "existing HEARTBEAT lines use different wording, confirm "
                "with dev whether this text exists under another name",
            ))

        if not self.scanner_hits:
            self.results.append((
                "ProcessScanner detection -> OutputModule::Push()",
                "at least one SCANNER detection followed by a Push",
                "", "NOT_DETECTED",
                "no SCANNER detection lines found in this window",
            ))
        else:
            first_idx, first_name, first_pid = self.scanner_hits[0]
            push_after = [p for p in self.push_hits if p[0] > first_idx]
            if push_after:
                push_idx, push_line = push_after[0]
                self.results.append((
                    "ProcessScanner detection -> OutputModule::Push()",
                    "at least one SCANNER detection followed by a Push",
                    f"detection: {first_name} (PID {first_pid}) at line "
                    f"{first_idx}; push at line {push_idx}",
                    "PASS", "",
                ))
            else:
                self.results.append((
                    "ProcessScanner detection -> OutputModule::Push()",
                    "at least one SCANNER detection followed by a Push",
                    f"{len(self.scanner_hits)} SCANNER detection(s) found "
                    f"(e.g. {first_name} PID {first_pid} at line {first_idx}) "
                    f"but 0 Push-related OUTPUT_MODULE lines in window",
                    "PARTIAL",
                    "ProcessScanner works but OutputModule::Push() is never "
                    "called from that path -- matches SAVR-29 finding",
                ))

        if self.error_lines:
            for err in sorted(self.error_lines):
                self.results.append((
                    "ERROR / failed registration line",
                    "no ERROR or failed POST/registration lines in window",
                    err, "FAIL",
                    "captured verbatim per Step 1 -- attach to ticket",
                ))
        else:
            self.results.append((
                "ERROR / failed registration line",
                "no ERROR or failed POST/registration lines in window",
                "0 matching lines found", "PASS", "",
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
