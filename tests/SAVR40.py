"""
perf_csv_check.py
-----------------
Analyzes a PDH-format CSV (e.g. from Windows Performance Monitor) for a
single process and checks three health criteria:

  1. CPU idle average < 3 % processor time
  2. Total I/O reads < 100 MB over the monitored window
  3. Memory (Working Set) is flat  (no sustained upward drift)

Usage (standalone):
    python perf_csv_check.py secureai_perf.csv

Usage (imported):
    from perf_csv_check import PerfCSVCheck

    checker = PerfCSVCheck(cfg={}, agents=None, sysinfo=None)
    checker.load("/path/to/secureai_perf.csv")
    checker.resolve()
    for row in checker.rows():
        print(row)

cfg keys (all optional):
    cpu_idle_max_pct      float   default 3.0
    io_read_max_mb        float   default 100.0
    memory_slope_max_kb   float   default 500.0   (KB/hr; flat = low slope)
    label                 str     default "secureai_perf"
"""

import csv
import statistics
from datetime import datetime
from pathlib import Path

PATH1800 = "secureai_perf.csv" #relative to overall.py


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _parse_float(val: str) -> float | None:
    """Return float or None for blank / non-numeric cells."""
    v = val.strip()
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _parse_dt(val: str) -> datetime | None:
    """Parse the PDH timestamp column."""
    v = val.strip()
    for fmt in ("%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            pass
    return None


# ---------------------------------------------------------------------------
# main class
# ---------------------------------------------------------------------------

class SAVR40:
    """
    Checks a PDH performance-monitor CSV against three thresholds.

    Columns expected (by position, matching the secureai_perf.csv layout):
        0  timestamp
        1  % Processor Time
        2  Working Set          (bytes)
        3  Private Bytes        (bytes)
        4  Handle Count
        5  Thread Count
        6  IO Read Bytes/sec
        7  IO Write Bytes/sec
    """

    name = "SAVR40"

    # column indices in the PDH CSV
    _COL_TS        = 0
    _COL_CPU       = 1
    _COL_WS        = 2   # Working Set (bytes)
    _COL_IO_READ   = 6   # IO Read Bytes/sec

    def __init__(self, cfg: dict, agents, sysinfo):
        self.cfg     = cfg or {}
        self.results = []

        # thresholds (caller can override via cfg)
        self.cpu_idle_max_pct    = float(self.cfg.get("cpu_idle_max_pct",    3.0))
        self.io_read_max_mb      = float(self.cfg.get("io_read_max_mb",    100.0))
        self.memory_slope_max_kb = float(self.cfg.get("memory_slope_max_kb", 500.0))

        self.label = self.cfg.get("label", "secureai")

        # raw samples collected by load() / offer()
        self._cpu_samples:    list[float]   = []
        self._io_read_series: list[tuple]   = []  # (datetime, bytes_per_sec)
        self._mem_series:     list[tuple]   = []  # (datetime, bytes)

        with open(PATH1800, newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            next(reader, None)          # skip header row
            for row in reader:
                self._ingest_row(row)

    def offer(self, line, i, window):
        pass  # data comes from CSV file, not the log

    def _ingest_row(self, row: list[str]) -> None:
        if len(row) < 8:
            return

        ts  = _parse_dt(row[self._COL_TS])
        cpu = _parse_float(row[self._COL_CPU])
        ws  = _parse_float(row[self._COL_WS])
        ior = _parse_float(row[self._COL_IO_READ])

        if cpu is not None:
            self._cpu_samples.append(cpu)

        if ts is not None:
            if ior is not None:
                self._io_read_series.append((ts, ior))
            if ws is not None:
                self._mem_series.append((ts, ws))

    # ------------------------------------------------------------------
    # checks (return (actual_str, result, comment))
    # ------------------------------------------------------------------

    def _check_cpu(self):
        """Average CPU usage should be below cpu_idle_max_pct."""
        expected = f"avg CPU < {self.cpu_idle_max_pct}%"
        if not self._cpu_samples:
            return expected, "0 CPU samples", "NOT_DETECTED", "no CPU data found"

        avg = statistics.mean(self._cpu_samples)
        actual = f"avg CPU = {avg:.3f}%"
        if avg < self.cpu_idle_max_pct:
            return expected, actual, "PASS", f"CPU idle average {avg:.3f}% is below threshold {self.cpu_idle_max_pct}%"
        else:
            return expected, actual, "FAIL", f"CPU idle average {avg:.3f}% exceeds threshold {self.cpu_idle_max_pct}%"

    def _check_io_reads(self):
        """Total I/O read volume over the window should be < io_read_max_mb MB."""
        expected = f"total IO reads < {self.io_read_max_mb} MB"
        if not self._io_read_series:
            return expected, "no IO data", "NOT_DETECTED", "no IO read samples found"

        # Integrate: for each sample, multiply rate (bytes/sec) by interval (sec)
        total_bytes = 0.0
        for idx, (ts, rate) in enumerate(self._io_read_series):
            if idx == 0:
                # use 2-second default for first sample (PDH polls every ~2 s)
                interval = 2.0
            else:
                prev_ts = self._io_read_series[idx - 1][0]
                interval = (ts - prev_ts).total_seconds()
                if interval <= 0:
                    interval = 2.0
            total_bytes += rate * interval

        total_mb = total_bytes / (1024 * 1024)
        actual = f"total IO reads = {total_mb:.2f} MB"
        if total_mb < self.io_read_max_mb:
            return expected, actual, "PASS", f"IO reads {total_mb:.2f} MB are below threshold {self.io_read_max_mb} MB"
        else:
            return expected, actual, "FAIL", f"IO reads {total_mb:.2f} MB exceed threshold {self.io_read_max_mb} MB"

    def _check_memory(self):
        """
        Memory (Working Set) should be flat.
        We compute a simple linear slope (KB/hr) and compare to memory_slope_max_kb.
        """
        expected = f"memory slope < {self.memory_slope_max_kb} KB/hr"
        if len(self._mem_series) < 2:
            return expected, "insufficient memory samples", "NOT_DETECTED", "need at least 2 memory samples"

        t0  = self._mem_series[0][0]
        xs  = [(ts - t0).total_seconds() / 3600.0 for ts, _ in self._mem_series]
        ys  = [ws / 1024.0 for _, ws in self._mem_series]   # → KB

        # least-squares slope
        n     = len(xs)
        sx    = sum(xs)
        sy    = sum(ys)
        sxy   = sum(x * y for x, y in zip(xs, ys))
        sxx   = sum(x * x for x in xs)
        denom = n * sxx - sx * sx
        slope = (n * sxy - sx * sy) / denom if denom != 0 else 0.0

        start_kb = ys[0]
        end_kb   = ys[-1]
        delta_kb = end_kb - start_kb
        actual   = (f"Working Set start={start_kb/1024:.1f} MB "
                    f"end={end_kb/1024:.1f} MB "
                    f"delta={delta_kb:.1f} KB "
                    f"slope={slope:.1f} KB/hr")

        if abs(slope) < self.memory_slope_max_kb:
            return expected, actual, "PASS", f"Memory slope {slope:.1f} KB/hr is within threshold ±{self.memory_slope_max_kb} KB/hr"
        else:
            return expected, actual, "FAIL", f"Memory slope {slope:.1f} KB/hr exceeds threshold ±{self.memory_slope_max_kb} KB/hr"

    # ------------------------------------------------------------------
    # public interface
    # ------------------------------------------------------------------

    def resolve(self) -> None:
        """Evaluate all checks and populate self.results."""
        self.results.clear()

        for check_fn in (self._check_cpu, self._check_io_reads, self._check_memory):
            expected, actual, result, comment = check_fn()
            self.results.append((self.label, expected, actual, result, comment))

    def rows(self):
        """
        Yield (name, subject, expected, actual, result, comment) tuples —
        same shape as SAVR12.rows().
        """
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)


# ---------------------------------------------------------------------------
# standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    checker = SAVR40(cfg={}, agents=None, sysinfo=None)
    checker.resolve()

    header = f"{'TEST':<15} {'SUBJECT':<20} {'RESULT':<12} COMMENT"
    print(header)
    print("-" * len(header))
    for name, subject, expected, actual, result, comment in checker.rows():
        print(f"{name:<15} {subject:<20} {result:<12} {comment}")
        print(f"{'':15} {'expected:':<20} {expected}")
        print(f"{'':15} {'actual:':<20} {actual}")
        print()