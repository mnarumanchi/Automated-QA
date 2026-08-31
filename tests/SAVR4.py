import re

# SAVR-4: IPv6 CDN address mapped to domain; chrome.exe QUIC heuristic fires.

TCP_RE = re.compile(
    r"TCP connect: PID=(?P<pid>\d+) \S+ IPv6=(?P<ipv6>\d+) "
    r"bytes_out=(?P<bytes_out>\d+) bytes_in=(?P<bytes_in>\d+) "
    r"rtt=(?P<rtt>\d+)ms retrans=(?P<retrans>\d+) syn=(?P<syn>\d+) "
    r"domain=(?P<domain>\S+) source=(?P<source>\S+) url=(?P<url>\S+)"
)


class SAVR4:
    name = "SAVR4"

    def __init__(self, cfg, agents, sysinfo):
        self.udp_shipped = cfg.get("udp_enumeration_shipped", False)
        self.quic_processes = cfg.get("quic_heuristic_processes", [])
        self.sysinfo = sysinfo or {}
        self.ipv6_hit = None

    def offer(self, line, i, window):
        if "TCP connect" not in line or self.ipv6_hit is not None:
            return
        m = TCP_RE.search(line)
        if not m or m.group("ipv6") != "1":
            return
        self.ipv6_hit = {
            "pid":       m.group("pid"),
            "bytes_out": int(m.group("bytes_out")),
            "bytes_in":  int(m.group("bytes_in")),
            "rtt":       int(m.group("rtt")),
            "domain":    m.group("domain"),
            "source":    m.group("source"),
            "url":       m.group("url"),
        }

    def resolve(self):
        self.results = []

        # Part 1: IPv6 TCP enumeration + domain correlation
        expected = "TCP connect line with IPv6=1 and domain resolved (non-'(none)')"
        if self.ipv6_hit is None:
            self.results.append((
                "IPv6 TCP table enumeration",
                expected,
                "",
                "NOT_DETECTED",
                "no TCP connect line with IPv6=1 seen in run window",
            ))
        else:
            h = self.ipv6_hit
            domain_ok = h["domain"] not in ("", "(none)")
            actual = (
                f"PID={h['pid']} domain={h['domain']} source={h['source']} "
                f"url={h['url']} bytes_out={h['bytes_out']} bytes_in={h['bytes_in']} "
                f"rtt={h['rtt']}ms"
            )
            self.results.append((
                "IPv6 TCP table enumeration",
                expected,
                actual,
                "PASS" if domain_ok else "PARTIAL",
                "" if domain_ok else
                "IPv6 connect captured but domain unresolved -- DNS cache "
                "correlation not working for AF_INET6",
            ))

        # Part 2: UDP table enumeration (sysinfo.jsonl active_tcp_sessions)
        tcp_sessions = self.sysinfo.get("active_tcp_sessions", [])
        udp_sessions = [s for s in tcp_sessions if s.get("transport") == "UDP"]

        if not self.udp_shipped:
            ok = len(udp_sessions) == 0
            self.results.append((
                "UDP table enumeration (sysinfo.jsonl)",
                "0 UDP-transport entries (udp_enumeration_shipped=false)",
                f"{len(udp_sessions)} UDP / {len(tcp_sessions)} total sessions",
                "PASS" if ok else "FAIL",
                "" if ok else
                "UDP entries present despite udp_enumeration_shipped=false "
                "-- roster stale or feature partially shipped",
            ))
        else:
            ok = len(udp_sessions) > 0
            self.results.append((
                "UDP table enumeration (sysinfo.jsonl)",
                "UDP-transport entries present in active_tcp_sessions",
                f"{len(udp_sessions)} UDP / {len(tcp_sessions)} total sessions",
                "PASS" if ok else "NOT_DETECTED",
                "" if ok else
                "udp_enumeration_shipped=true but no UDP entries found -- "
                "still need the log-line-level check too",
            ))

        # Part 3: QUIC heuristic (sysinfo.jsonl agent_process_info)
        agent_info = self.sysinfo.get("agent_process_info", [])
        for pname in self.quic_processes:
            matches = [
                a for a in agent_info
                if a.get("agent_process_name", "").lower() == pname.lower()
            ]
            if not matches:
                self.results.append((
                    f"{pname} QUIC heuristic (sysinfo.jsonl)",
                    "agent_process_is_quic present for this process",
                    "absent",
                    "NOT_DETECTED",
                    f"{pname} not present in agent_process_info snapshot",
                ))
                continue

            quic_vals = {
                str(a.get("agent_pid")): a.get("agent_process_is_quic", False)
                for a in matches
            }
            actual = f"agent_process_is_quic by PID: {quic_vals}"

            if not self.udp_shipped:
                ok = not any(quic_vals.values())
                self.results.append((
                    f"{pname} QUIC heuristic (sysinfo.jsonl)",
                    "agent_process_is_quic=false for all PIDs (unshipped)",
                    actual,
                    "PASS" if ok else "FAIL",
                    "" if ok else
                    "agent_process_is_quic=true despite unshipped UDP -- "
                    "investigate before trusting roster state",
                ))
            else:
                ok = any(quic_vals.values())
                self.results.append((
                    f"{pname} QUIC heuristic (sysinfo.jsonl)",
                    "agent_process_is_quic=true for at least one PID",
                    actual,
                    "PASS" if ok else "NOT_DETECTED",
                    "" if ok else
                    "udp_enumeration_shipped=true but heuristic never fired "
                    "-- still need the log-line-level check too",
                ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
