import re

DNS_RE = re.compile(
    r"\[ETW_DNS_MONITOR\].*?q=(?P<domain>\S+)\s+"
    r"status=(?P<status>\d+).*?"
    r"type=(?P<type>\d+).*?"
    r"transport=(?P<transport>\S+)\s+"
    r"answers=(?P<answers>\d+)\s+"
    r"latency=(?P<latency>\d+)ms"
)

TCP_RE = re.compile(
    r"TCP connect:.*?"
    r"domain=(?P<domain>\S+)\s+"
    r"source=(?P<source>\S+)\s+"
    r"url=(?P<url>\S+)"
)

class SAVR18:
    name = "SAVR18"

    def __init__(self, cfg, agents, sysinfo):
        self.domains = cfg.get("domains", [])

        # per domain state
        # dns_hit: None or {"index": i, "answers": n, "transport": t, "latency": l}
        # tcp_hit: None or {"domain": d, "source": s, "url": u}
        self.state = {
            d: {"dns_hit": None, "tcp_hit": None}
            for d in self.domains
        }

    def offer(self, line, i, window):
        # --- check DNS lines ---
        m = DNS_RE.search(line)
        if m:
            domain  = m.group("domain")
            status  = int(m.group("status"))
            answers = int(m.group("answers"))
            if domain in self.state and status == 0 and answers >= 1:
                # only record first successful resolution per domain
                if self.state[domain]["dns_hit"] is None:
                    self.state[domain]["dns_hit"] = {
                        "index":     i,
                        "answers":   answers,
                        "transport": m.group("transport"),
                        "latency":   int(m.group("latency")),
                    }
            return

        # --- check TCP lines ---
        m = TCP_RE.search(line)
        if m:
            domain = m.group("domain")
            source = m.group("source")
            url    = m.group("url")
            if domain in self.state and source == "dns_etw":
                ds = self.state[domain]
                # only count if dns was already seen and this line comes after it
                if (ds["dns_hit"] is not None
                        and ds["tcp_hit"] is None
                        and i > ds["dns_hit"]["index"]):
                    ds["tcp_hit"] = {
                        "index":  i,
                        "source": source,
                        "url":    url,
                    }

    def resolve(self):
        self.results = []

        for domain in self.domains:
            ds = self.state[domain]
            dns = ds["dns_hit"]
            tcp = ds["tcp_hit"]

            if dns is None and tcp is None:
                self.results.append((
                    domain,
                    "DNS status=0 + TCP source=dns_etw",
                    "", "NOT_DETECTED",
                    "no successful DNS query or TCP connect line found for this domain",
                ))

            elif dns is not None and tcp is None:
                self.results.append((
                    domain,
                    "DNS status=0 + TCP source=dns_etw",
                    f"DNS captured (answers={dns['answers']} "
                    f"transport={dns['transport']} latency={dns['latency']}ms) "
                    f"but no subsequent TCP connect with source=dns_etw found",
                    "PARTIAL",
                    f"DNS resolution captured at line {dns['index']} "
                    f"but flow correlation missing -- "
                    f"IP-to-domain cache lookup not working for this domain",
                ))

            elif dns is not None and tcp is not None:
                # both found -- check url is not (none)
                url_ok = tcp["url"] != "(none)"
                result = "PASS" if url_ok else "FAIL"
                self.results.append((
                    domain,
                    "DNS status=0 + TCP source=dns_etw",
                    f"DNS answers={dns['answers']} transport={dns['transport']} "
                    f"latency={dns['latency']}ms -- "
                    f"TCP domain={domain} source={tcp['source']} url={tcp['url']}",
                    result,
                    "" if result == "PASS"
                    else "url field is (none) -- domain correlation incomplete",
                ))

            else:
                # tcp found but no dns -- shouldn't happen given our logic
                # but handle gracefully
                self.results.append((
                    domain,
                    "DNS status=0 + TCP source=dns_etw",
                    "", "INCONCLUSIVE",
                    "TCP connect found but no preceding DNS resolution -- unexpected",
                ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
