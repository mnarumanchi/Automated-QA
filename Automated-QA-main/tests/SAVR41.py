import re

# SAVR-41: proves specific config.json patterns require real regex
# semantics -- i.e. a literal wstring::find() could never have matched
# them -- and that the product still detects them. Covers ProcessScanner.cpp
# process patterns and confidence modifier alternations only; other
# consumers (library/container/file-path patterns, Dns.cpp tiers) need
# their own fixtures once available.

CONF_RE = re.compile(
    r"\[SCANNER\]\s+Trusted AI process:\s+(?P<name>\S+)\s+\(PID\s+(?P<pid>\d+),"
    r".*?conf\s+(?P<conf>[0-9.]+)\)"
)


def _pattern_is_regex_only(pattern, target_text):
    """True if `pattern` matches `target_text` via regex but could not
    have matched via literal substring search."""
    literal_hit = pattern in target_text
    try:
        regex_hit = re.search(pattern, target_text, re.IGNORECASE) is not None
    except re.error:
        return False
    return regex_hit and not literal_hit


class SAVR41:
    name = "SAVR41"

    def __init__(self, cfg, agents, sysinfo):
        self.agents = agents or []
        self.regex_only_targets = cfg.get("regex_only_targets", [])
        self.confidence_modifier_targets = cfg.get(
            "confidence_modifier_targets", []
        )
        self.log_hits = {}

    def offer(self, line, i, window):
        m = CONF_RE.search(line)
        if not m:
            return
        name = m.group("name")
        pid = m.group("pid")
        conf = float(m.group("conf"))
        self.log_hits.setdefault(name, [])
        existing_pids = [p for p, c in self.log_hits[name]]
        if pid not in existing_pids:
            self.log_hits[name].append((pid, conf))

    def resolve(self):
        self.results = []

        # Part 1: regex-only process pattern fixtures
        for target in self.regex_only_targets:
            pname = target["process_name"]
            pattern = target["pattern"]
            consumer = target.get("consumer", "")
            expected = (
                f"'{pname}' detected via SCANNER using pattern '{pattern}' "
                f"({consumer}) -- literal match is impossible"
            )

            if not _pattern_is_regex_only(pattern, pname):
                self.results.append((
                    f"{pname} (regex-only proof)",
                    expected,
                    "",
                    "INCONCLUSIVE",
                    f"pattern '{pattern}' doesn't isolate regex-vs-literal "
                    f"for '{pname}' -- fix the fixture",
                ))
                continue

            hits = self.log_hits.get(pname, [])
            if not hits:
                self.results.append((
                    f"{pname} (regex-only proof)",
                    expected,
                    "",
                    "NOT_DETECTED",
                    f"no SCANNER line for {pname} in run window",
                ))
                continue

            best_pid, best_conf = max(hits, key=lambda x: x[1])
            self.results.append((
                f"{pname} (regex-only proof)",
                expected,
                f"PID={best_pid} conf={best_conf}",
                "PASS",
                "detection could only come from compiled regex matching",
            ))

        # Part 2: confidence modifier fixtures (reducer/booster)
        for target in self.confidence_modifier_targets:
            pname = target["process_name"]
            pattern = target["pattern"]
            modifier_type = target.get("modifier_type", "reducer")
            multiplier = target.get("expected_multiplier")
            max_confidence = target.get("max_confidence")
            base_lo, base_hi = target.get("base_confidence_range", [0.0, 1.0])

            subject = f"{pname} ({modifier_type} '{pattern}')"
            expected = (
                f"confidence multiplied by {multiplier} "
                f"(base range {base_lo}-{base_hi})"
            )

            if not _pattern_is_regex_only(pattern, pname):
                self.results.append((
                    subject,
                    expected,
                    "",
                    "INCONCLUSIVE",
                    f"pattern '{pattern}' doesn't isolate regex-vs-literal "
                    f"for '{pname}' -- fix the fixture",
                ))
                continue

            hits = self.log_hits.get(pname, [])
            if not hits:
                self.results.append((
                    subject, expected, "", "NOT_DETECTED",
                    f"no SCANNER line for {pname} in run window",
                ))
                continue

            best_pid, best_conf = max(hits, key=lambda x: x[1])
            expected_lo = base_lo * multiplier if multiplier else base_lo
            expected_hi = base_hi * multiplier if multiplier else base_hi
            if modifier_type == "booster" and max_confidence is not None:
                expected_hi = min(expected_hi, max_confidence)
            ok = expected_lo <= best_conf <= expected_hi

            self.results.append((
                subject,
                expected,
                f"PID={best_pid} conf={best_conf}",
                "PASS" if ok else "FAIL",
                "" if ok else
                f"confidence {best_conf} not in expected range "
                f"{expected_lo:.3f}-{expected_hi:.3f} -- modifier likely "
                f"still using literal match",
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
