#First run on powershell: Invoke-WebRequest -Uri "https://copilot.microsoft.com" -UseBasicParsing

import re

SCHANNEL_RE = re.compile(
    r"\[SCHANNEL_DETECTOR\]\s+TLS\s+pid=(?P<pid>\d+)\s+"
    r"sni=(?P<sni>\S+)\s+"
    r"ver=(?P<ver>[^\s]+(?:\s+[^\s]+)?)\s+"
    r"cipher=(?P<cipher>\S+)"
    r"(?:\s+kex=(?P<kex>\S+))?"
)

class SAVR15:
    name = "SAVR15"

    def __init__(self, cfg, agents, sysinfo):
        self.domains = cfg.get("domains", [])
        # domain -> first matching TLS event
        self.seen = {d: None for d in self.domains}

    def offer(self, line, i, window):
        m = SCHANNEL_RE.search(line)
        if not m:
            return
        sni = m.group("sni")
        if sni not in self.seen:
            return
        if self.seen[sni] is not None:
            return  # already have a hit for this domain
        self.seen[sni] = {
            "pid":    m.group("pid"),
            "sni":    sni,
            "ver":    m.group("ver"),
            "cipher": m.group("cipher"),
            "kex":    m.group("kex") or "",
        }

    def resolve(self):
        self.results = []
        for domain in self.domains:
            hit = self.seen[domain]
            if hit is None:
                self.results.append((
                    domain,
                    "sni + ver + cipher present",
                    "", "NOT_DETECTED",
                    "no SCHANNEL_DETECTOR line found for this domain -- "
                    "ensure fixture uses PowerShell/.NET, not Chrome/Edge",
                ))
                continue
            self._score(domain, hit)

    def _score(self, domain, hit):
        failures = []
        partials = []

        # check 1: sni populated and matches domain
        if not hit["sni"] or hit["sni"] != domain:
            failures.append(f"sni mismatch: got '{hit['sni']}' expected '{domain}'")

        # check 2: ver present and non-empty
        if not hit["ver"]:
            failures.append("ver field missing")

        # check 3: cipher present and non-empty
        if not hit["cipher"]:
            failures.append("cipher field missing")

        # check 4: kex -- partial if unresolved ?(255)
        if not hit["kex"]:
            partials.append("kex field absent")
        elif "?" in hit["kex"]:
            partials.append(f"kex unresolved: {hit['kex']}")

        # check 5: alpn -- always absent per Round 2
        partials.append("alpn not captured")

        actual = (
            f"pid={hit['pid']} sni={hit['sni']} "
            f"ver={hit['ver']} cipher={hit['cipher']} "
            f"kex={hit['kex'] or 'absent'}"
        )

        if failures:
            result  = "FAIL"
            comment = "; ".join(failures)
            if partials:
                comment += " | partial: " + "; ".join(partials)
        elif partials:
            result  = "PARTIAL"
            comment = "; ".join(partials)
        else:
            result  = "PASS"
            comment = ""

        self.results.append((
            domain,
            "sni + ver + cipher present",
            actual,
            result,
            comment,
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
