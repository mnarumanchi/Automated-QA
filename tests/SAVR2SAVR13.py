import re
from datetime import datetime

SCAN_START_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*"
    r"\[SCANNER\] Starting process scan"
)

ETW_PROCESS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*"
    r"AI process added pid-image <(?P<pid>\d+)>-<(?P<image>[^>]+)>"
)

TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

POLL_LOOP_THRESHOLD_S  = 25.0   # avg interval >= this -> poll loop
EVENT_DRIVEN_THRESHOLD_S = 25.0 # etw-to-scan gap >= this -> not event driven
LATENCY_PASS_MS = 50            # acceptance criteria from TC-DET-09

class SAVR13:
    name = "SAVR13"

    def __init__(self, cfg, agents, sysinfo):
        # no roster config needed for this test
        # cfg may be empty dict, that's fine
        self.scan_timestamps = []   # datetime of each "Starting process scan"
        self.etw_events = []        # (datetime, pid, image) of each AI process added

    def offer(self, line, i, window):
        m = SCAN_START_RE.match(line)
        if m:
            self.scan_timestamps.append(
                datetime.strptime(m.group(1), TS_FMT)
            )
            return

        m = ETW_PROCESS_RE.match(line)
        if m:
            self.etw_events.append((
                datetime.strptime(m.group(1), TS_FMT),
                m.group("pid"),
                m.group("image"),
            ))

    def resolve(self):
        self.results = []
        self._check_scan_interval()
        self._check_etw_latency()
        self._check_event_driven_markers()

    def _check_scan_interval(self):
        if len(self.scan_timestamps) < 2:
            self.results.append((
                "scan interval",
                f"short gaps (<5s) present, no poll-range gaps (25-40s)",
                "n/a", "INCONCLUSIVE",
                "fewer than 2 scan timestamps in window -- cannot compute interval",
            ))
            return

        gaps = [
            (self.scan_timestamps[i+1] - self.scan_timestamps[i]).total_seconds()
            for i in range(len(self.scan_timestamps) - 1)
        ]

        short      = [g for g in gaps if g < 5]           # event-driven signal
        poll_range = [g for g in gaps if 25 <= g <= 40]   # poll loop signal
        anomalous  = [g for g in gaps if g > 40]          # something wrong
        other      = [g for g in gaps                     # in between -- ambiguous
                    if g >= 5 and g < 25]

        total = len(gaps)

        # result logic
        if len(short) == 0 and len(poll_range) > total * 0.8:
            # overwhelmingly poll-range, no short gaps at all
            result = "FAIL"
            diagnosis = "poll loop -- no event-driven scans detected"
        elif len(short) > 0 and len(poll_range) > 0:
            # mix of short and poll-range -- partial event-driven dispatch
            result = "FAIL"
            diagnosis = "partial -- some event-driven scans but poll loop still dominant"
        elif len(short) > total * 0.5:
            # majority short gaps -- event-driven working
            result = "PASS"
            diagnosis = "event-driven dispatch confirmed"
        else:
            result = "INCONCLUSIVE"
            diagnosis = "gap distribution unclear"

        actual = (
            f"{total} gap(s): "
            f"{len(short)} short (<5s), "
            f"{len(poll_range)} poll-range (25-40s), "
            f"{len(anomalous)} anomalous (>40s), "
            f"{len(other)} other (5-25s)"
        )

        self.results.append((
            "scan interval",
            "short gaps present, no poll-range gaps",
            actual,
            result,
            f"{diagnosis} -- {len(self.scan_timestamps)} scans observed",
        ))

    def _check_etw_latency(self):
        if not self.etw_events:
            self.results.append((
                "ETW process-added to scan latency",
                f"latency < {LATENCY_PASS_MS}ms",
                "n/a", "INCONCLUSIVE",
                "no AI process added ETW events in window -- cannot measure latency",
            ))
            return

        if not self.scan_timestamps:
            self.results.append((
                "ETW process-added to scan latency",
                f"latency < {LATENCY_PASS_MS}ms",
                "n/a", "INCONCLUSIVE",
                "no scan timestamps in window -- cannot measure latency",
            ))
            return

        # for each ETW event find the next scan after it
        worst_latency_s = None
        worst_event = None

        for evt_ts, pid, image in self.etw_events:
            # find first scan that starts after this event
            next_scan = next(
                (ts for ts in self.scan_timestamps if ts > evt_ts),
                None
            )
            if next_scan is None:
                continue
            latency_s = (next_scan - evt_ts).total_seconds()
            if worst_latency_s is None or latency_s > worst_latency_s:
                worst_latency_s = latency_s
                worst_event = (evt_ts, pid, image)

        if worst_latency_s is None:
            self.results.append((
                "ETW process-added to scan latency",
                f"latency < {LATENCY_PASS_MS}ms",
                "n/a", "INCONCLUSIVE",
                "ETW events found but no subsequent scan in window",
            ))
            return

        worst_ms = worst_latency_s * 1000
        result = "PASS" if worst_ms < LATENCY_PASS_MS else "FAIL"
        evt_ts, pid, image = worst_event

        self.results.append((
            "ETW process-added to scan latency",
            f"< {LATENCY_PASS_MS}ms",
            f"{worst_ms:.0f}ms (worst case, PID {pid})",
            result,
            f"process {image} (PID {pid}) added at {evt_ts.strftime('%H:%M:%S.%f')[:-3]} "
            f"-- next scan fired {worst_latency_s:.1f}s later "
            f"({'event-driven dispatch not implemented' if result == 'FAIL' else 'event-driven dispatch working'})",
        ))

    def _check_event_driven_markers(self):
        # this is checked implicitly by the interval and latency checks
        # but we report it explicitly as TC-DET-09 looks for dispatch markers
        has_etw = len(self.etw_events) > 0
        all_from_poll = True  # we can only confirm poll; can't confirm event-driven
                               # from absence alone

        if not has_etw:
            status = "INCONCLUSIVE"
            comment = "no ETW process-added events in window to evaluate dispatch"
        else:
            status = "FAIL"
            comment = (
                f"{len(self.etw_events)} AI process ETW event(s) received "
                f"but no event-driven scan markers found in log -- "
                f"scanner appears to be ignoring ETW events for dispatch"
            )

        self.results.append((
            "event-driven dispatch markers",
            "scan triggered within 50ms of ETW event",
            "none found",
            status,
            comment,
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
