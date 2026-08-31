import re

TCP_RE = re.compile(
    r"TCP connect: PID=(\d+) \S+ IPv6=\d+ bytes_out=(\d+) bytes_in=(\d+) "
    r"rtt=(\d+)ms retrans=(\d+) syn=(\d+) domain=(\S+) source=(\S+) url=(\S+)"
)

class SAVR12:
    name = "SAVR12"

    def __init__(self, cfg, agents, sysinfo):
        self.results = []
        self.targets = {}

        for pid, info in cfg.get("by_pid", {}).items():
            self.targets[pid] = {
                "pid":        pid,
                "label":      info.get("label", pid),
                "domain":     info.get("domain", ""),
                "found":      None,   # will hold matched line fields if found
            }

    def offer(self, line, i, window):
        if "TCP connect" not in line:
            return

        m = TCP_RE.search(line)
        if not m:
            return

        pid    = m.group(1)
        domain = m.group(7)

        if pid not in self.targets:
            return

        t = self.targets[pid]
        if domain != t["domain"]:
            return

        t["found"] = {
            "pid":        pid,
            "domain":     domain,
            "bytes_out":  int(m.group(2)),
            "bytes_in":   int(m.group(3)),
            "rtt":        int(m.group(4)),
            "retrans":    int(m.group(5)),
            "syn":        int(m.group(6)),
            "source":     m.group(8),
            "url":        m.group(9),
        }

    def resolve(self):
        for pid, t in self.targets.items():
            label    = t["label"]
            expected = f"TCP connect from PID={pid} to domain={t['domain']}"

            if t["found"] is None:
                self.results.append((
                    label,
                    expected,
                    "absent",
                    "NOT_DETECTED",
                    f"no TCP connect line found for PID={pid} domain={t['domain']}"
                ))
                continue

            f = t["found"]
            actual = (
                f"PID={f['pid']} domain={f['domain']} "
                f"bytes_out={f['bytes_out']} bytes_in={f['bytes_in']} "
                f"rtt={f['rtt']}ms retrans={f['retrans']} syn={f['syn']} "
                f"source={f['source']} url={f['url']}"
            )

            self.results.append((
                label,
                expected,
                actual,
                "PASS",
                "TCP connect line found with matching PID and domain"
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)