class SAVR29:
    name = "SAVR29"

    # SAVR-29: 4 field groups from the acceptance criteria, checked against
    # detected_agents.json. Other acceptance bullets (schema key-presence,
    # controller POST 2xx, dns/lib fields null-is-ok) are out of scope.
    TCP_FIELDS = [
        "src_ip", "src_port", "dst_ip", "dst_port",
        "bytes_out", "bytes_in", "bytes_ratio", "packets",
        "rtt", "tcp_syn", "tcp_fin", "tcp_rst",
    ]
    TLS_FIELDS = [
        "sni", "tls_version", "tls_cipher_suite", "tls_key_exchange_algo",
    ]
    PROCESS_FIELDS = [
        "pid", "process_name", "process_path",
        "agent_name", "agent_id", "confidence",
    ]
    DEVICE_FIELDS = [
        "hostname", "os_name", "os_version",
        "network_adapters", "route_table",
    ]

    GROUPS = [
        ("TCP flow fields", TCP_FIELDS),
        ("TLS fields", TLS_FIELDS),
        ("Process fields", PROCESS_FIELDS),
        ("Device snapshot fields", DEVICE_FIELDS),
    ]

    def __init__(self, cfg, agents, sysinfo):
        self.agents = agents or []
        self.process_name = cfg.get("process_name", "Cursor.exe")

    def offer(self, line, i, window):
        return  # grades detected_agents.json state, not the log stream

    def _is_populated(self, value):
        if value is None:
            return False
        if isinstance(value, (str, list, dict)) and len(value) == 0:
            return False
        return True

    def resolve(self):
        self.results = []

        entry = next(
            (a for a in self.agents
             if a.get("process_name", "").lower() == self.process_name.lower()),
            None,
        )

        if entry is None:
            for group_name, fields in self.GROUPS:
                self.results.append((
                    group_name,
                    f"all present + non-null: {', '.join(fields)}",
                    "absent",
                    "NOT_DETECTED",
                    f"no entry for process_name={self.process_name} in "
                    f"detected_agents.json this window",
                ))
            return

        sentinel = object()
        for group_name, fields in self.GROUPS:
            missing = []
            null_or_empty = []
            populated = {}

            for field in fields:
                val = entry.get(field, sentinel)
                if val is sentinel:
                    missing.append(field)
                elif not self._is_populated(val):
                    null_or_empty.append(field)
                else:
                    populated[field] = val

            failures = []
            if missing:
                failures.append(f"missing keys: {', '.join(missing)}")
            if null_or_empty:
                failures.append(f"null/empty: {', '.join(null_or_empty)}")

            actual = (
                f"{len(populated)}/{len(fields)} populated"
                + (f" -- {failures[0]}" if failures else "")
                + (f"; {failures[1]}" if len(failures) > 1 else "")
            )

            self.results.append((
                group_name,
                f"all present + non-null: {', '.join(fields)}",
                actual,
                "PASS" if not failures else "FAIL",
                "" if not failures else "; ".join(failures),
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
