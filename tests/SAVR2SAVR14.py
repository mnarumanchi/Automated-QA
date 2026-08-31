import re

TCP_RE = re.compile(
    r"TCP connect:\s+PID=(?P<pid>\d+)\s+\S+\s+"
    r"IPv6=(?P<ipv6>\d)\s+"
    r"bytes_out=(?P<bytes_out>\d+)\s+"
    r"bytes_in=(?P<bytes_in>\d+)\s+"
    r"rtt=(?P<rtt>\d+)ms\s+"
    r"retrans=(?P<retrans>\d+)\s+"
    r"syn=(?P<syn>\d+)\s+"
    r"domain=(?P<domain>\S+)\s+"
    r"source=(?P<source>\S+)"
)

class SAVR14:
    name = "SAVR14"

    def __init__(self, cfg, agents, sysinfo):
        self.by_name = cfg.get("by_name", {})  # {"fixture.exe": "httpbin.org"}
        self.by_pid  = cfg.get("by_pid", {})   # {"1234": {"label":..., "domain":...}}
        self.seen = {}                          # pid -> list of snapshots

    def _get_expected(self, pid, proc):
        # by_pid wins over by_name, same precedence rule as Test1
        if pid in self.by_pid:
            entry = self.by_pid[pid]
            return entry["domain"], entry["label"]
        if proc in self.by_name:
            return self.by_name[proc], proc
        return None, None

    def offer(self, line, i, window):
        m = TCP_RE.search(line)
        if not m:
            return
        pid = m.group("pid")
        if pid not in self.seen:
            self.seen[pid] = []
        self.seen[pid].append({
            "bytes_out": int(m.group("bytes_out")),
            "bytes_in":  int(m.group("bytes_in")),
            "rtt":       int(m.group("rtt")),
            "domain":    m.group("domain"),
            "syn":       int(m.group("syn")),
            "retrans":   int(m.group("retrans")),
        })

    def resolve(self):
        self.results = []
        checked_pids = set()

        # by_pid entries
        for pid, entry in self.by_pid.items():
            checked_pids.add(pid)
            snapshots = [s for s in self.seen.get(pid, [])
                         if s["domain"] == entry["domain"]]
            self._score(f"PID {pid} ({entry['label']})",
                        entry["domain"], snapshots)

        # by_name entries
        for proc, expected_domain in self.by_name.items():
            matched_pids = [pid for pid, snaps in self.seen.items()
                            if pid not in checked_pids
                            and any(s["domain"] == expected_domain for s in snaps)]
            if not matched_pids:
                self.results.append((
                    f"{proc} -> {expected_domain}",
                    "bytes_out>0, bytes_in>0, rtt>0",
                    "", "NOT_DETECTED",
                    f"no TCP connect line found for domain {expected_domain}",
                ))
                continue
            for pid in matched_pids:
                snapshots = [s for s in self.seen[pid]
                             if s["domain"] == expected_domain]
                self._score(f"{proc} (PID {pid}) -> {expected_domain}",
                            expected_domain, snapshots)

    def _score(self, subject, expected_domain, snapshots):
        if not snapshots:
            self.results.append((
                f"{subject} -> {expected_domain}",
                "bytes_out>0, bytes_in>0, rtt>0",
                "", "NOT_DETECTED",
                f"no TCP connect lines to {expected_domain} for this PID",
            ))
            return

        total = len(snapshots)

        # pass condition: any single snapshot with all 3 non-zero simultaneously
        passing = [s for s in snapshots
                   if s["bytes_out"] > 0
                   and s["bytes_in"] > 0
                   and s["rtt"] > 0]

        # partial: bytes non-zero but rtt always 0
        bytes_ok = [s for s in snapshots
                    if s["bytes_out"] > 0 and s["bytes_in"] > 0]

        if passing:
            best = passing[0]
            result  = "PASS"
            comment = (f"bytes_out={best['bytes_out']} "
                       f"bytes_in={best['bytes_in']} "
                       f"rtt={best['rtt']}ms on 1 of {total} snapshot(s)")
        elif bytes_ok:
            result  = "FAIL"
            comment = (f"bytes non-zero on {len(bytes_ok)}/{total} snapshot(s) "
                       f"but rtt=0ms on all.")
        else:
            result  = "FAIL"
            comment = (f"all {total} snapshot(s) have bytes_out=0 and bytes_in=0 "
                       f" connection logged at handshake only, no data captured")

        best_snap = passing[0] if passing else (bytes_ok[0] if bytes_ok else snapshots[0])
        actual = (f"bytes_out={best_snap['bytes_out']} "
                  f"bytes_in={best_snap['bytes_in']} "
                  f"rtt={best_snap['rtt']}ms")

        self.results.append((
            f"{subject} -> {expected_domain}",
            "bytes_out>0, bytes_in>0, rtt>0",
            actual, result, comment,
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
