import re

DNS_TIMER_RE = re.compile(r"DnsCache::TimerCallback.*Refreshing DNS Cache")
DNS_INSERT_RE = re.compile(
    r"DnsCache::Insert.*Inserted: (?P<domain>\S+) \| IP: \[(?P<ip>[^\]]+)\]"
)
DNS_LOOKUP_RE = re.compile(
    r"DnsCacheLookup.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?domain=(?P<domain>\S+).*?source=(?P<source>\S+)"
)
LOCALHOST_TCP_RE = re.compile(
    r"TCP connect: PID=(?P<pid>\d+) (?P<src>127\.0\.0\.1|::1)\S*->(?P<dst>\S+) "
    r".*?domain=(?P<domain>\S+) source=(?P<source>\S+)"
)

class SAVR5:
    name = "SAVR5"

    def __init__(self, cfg, agents, sysinfo):
        self.results        = []
        self.timer_seen     = False
        self.inserts        = []   # list of {domain, ip}
        self.lookups        = []   # list of {ip, domain, source}
        self.localhost_hits = []   # list of {pid, src, dst, domain, source}

        # from agents -- find ollama endpoint
        self.ollama_agent = next(
            (a for a in (agents or [])
             if a.get("process_name", "").lower() == "ollama.exe"),
            None
        )

    def offer(self, line, i, window):
        if DNS_TIMER_RE.search(line):
            self.timer_seen = True
            return

        m = DNS_INSERT_RE.search(line)
        if m:
            self.inserts.append({
                "domain": m.group("domain"),
                "ip":     m.group("ip"),
            })
            return

        m = DNS_LOOKUP_RE.search(line)
        if m:
            self.lookups.append({
                "ip":     m.group("ip"),
                "domain": m.group("domain"),
                "source": m.group("source"),
            })
            return

        m = LOCALHOST_TCP_RE.search(line)
        if m:
            self.localhost_hits.append({
                "pid":    m.group("pid"),
                "src":    m.group("src"),
                "dst":    m.group("dst"),
                "domain": m.group("domain"),
                "source": m.group("source"),
            })

    def resolve(self):
        self._check_timer()
        self._check_inserts()
        self._check_localhost()
        self._check_ollama_endpoint()
        self._check_ip_cache()

    def _check_timer(self):
        self.results.append((
            "DNS cache thread",
            "DnsCache::TimerCallback present in log",
            "present" if self.timer_seen else "absent",
            "PASS" if self.timer_seen else "FAIL",
            "" if self.timer_seen else
            "DNS cache thread not observed -- service may not have started cache thread"
        ))

    def _check_inserts(self):
        if not self.inserts:
            self.results.append((
                "DNS cache inserts",
                "DnsCache::Insert lines present in log",
                "absent",
                "FAIL",
                "no DnsCache::Insert lines found -- "
                "IP-to-domain cache not being populated (known gap)"
            ))
        else:
            self.results.append((
                "DNS cache inserts",
                "DnsCache::Insert lines present in log",
                f"{len(self.inserts)} insert(s) found",
                "PASS",
                ""
            ))

    def _check_localhost(self):
        if not self.localhost_hits:
            self.results.append((
                "localhost domain mapping",
                "TCP connect to 127.0.0.1 with domain=localhost",
                "absent",
                "NOT_DETECTED",
                "no TCP connect lines with domain=localhost found -- "
                "no local connections observed in window"
            ))
            return

        hit = self.localhost_hits[0]
        self.results.append((
            "localhost domain mapping",
            "TCP connect to 127.0.0.1 with domain=localhost",
            f"PID={hit['pid']} src={hit['src']} dst={hit['dst']} "
            f"domain={hit['domain']} source={hit['source']}",
            "PASS" if hit["domain"] == "localhost" else "FAIL",
            "" if hit["domain"] == "localhost" else
            f"domain={hit['domain']} expected localhost"
        ))

    def _check_ollama_endpoint(self):
        if self.ollama_agent is None:
            self.results.append((
                "ollama localhost endpoint",
                "endpoint=localhost:11434 in detected_agents.json",
                "absent",
                "NOT_DETECTED",
                "ollama.exe not found in detected_agents.json"
            ))
            return

        endpoint = self.ollama_agent.get("endpoint", "")
        ok = "localhost" in endpoint
        self.results.append((
            "ollama localhost endpoint",
            "endpoint=localhost:11434 in detected_agents.json",
            f"endpoint={endpoint}",
            "PASS" if ok else "FAIL",
            "" if ok else
            f"endpoint={endpoint} does not contain localhost"
        ))

    def _check_ip_cache(self):
        ip_cache_hits = [l for l in self.lookups if l["source"] == "ip_cache"]
        if not self.lookups:
            self.results.append((
                "IP-to-domain cache lookup",
                "DnsCacheLookup with source=ip_cache in log",
                "absent",
                "FAIL",
                "no DnsCacheLookup lines found in log -- "
                "IP cache lookup not implemented in this build (known gap)"
            ))
        elif not ip_cache_hits:
            self.results.append((
                "IP-to-domain cache lookup",
                "DnsCacheLookup with source=ip_cache in log",
                f"{len(self.lookups)} lookup(s) found but none with source=ip_cache",
                "FAIL",
                "cache lookups found but source=ip_cache never returned -- "
                "cache not being used for domain correlation"
            ))
        else:
            hit = ip_cache_hits[0]
            self.results.append((
                "IP-to-domain cache lookup",
                "DnsCacheLookup with source=ip_cache",
                f"ip={hit['ip']} domain={hit['domain']} source={hit['source']}",
                "PASS",
                ""
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)