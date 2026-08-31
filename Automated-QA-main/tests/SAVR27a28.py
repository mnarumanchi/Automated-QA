import re

DOCKER_CONTAINER_RE = re.compile(
    r"\[DOCKER\] AI container: (?P<image>\S+) \(id (?P<id>[a-f0-9]+), "
    r"image_match=(?P<image_match>\d), cmd_match=(?P<cmd_match>\d)"
    r"(?:, pattern \"(?P<pattern>[^\"]+)\")?\)"
)

CONTAINER_INSPECTOR_RE = re.compile(
    r"\[CONTAINER_INSPECTOR\] Inspected (?P<id>[a-f0-9]+) \((?P<image>[^)]+)\): "
    r"cmds=(?P<cmds>\d+) mounts=(?P<mounts>\d+) env_mask=(?P<env_mask>\S+) "
    r"ports=\[(?P<ports>[^\]]*)\] conns=(?P<conns>\d+) ip=(?P<ip>\S+) "
    r"service=(?P<service>\S+) confidence=(?P<confidence>\d+)"
)

class SAVR27a28:
    name = "SAVR27a28"

    def __init__(self, cfg, agents, sysinfo):
        self.results = []
        self.expect_stype          = cfg.get("expect_service_type", "LocalModel")
        self.expect_method         = cfg.get("expect_detection_method", "ContainerAnalysis")
        self.expect_mount          = cfg.get("expect_model_mount", "")
        self.expect_container_name = cfg.get("expect_container_name", "ollama_mount_test")
        self.docker_log_hits       = {}    # container_id -> {image, image_match, cmd_match, pattern}
        self.inspector_log_hits    = {}    # container_id -> {image, service, confidence, env_mask, ...}

        self.ollama_agent = next(
            (a for a in (agents or [])
             if a.get("detection_method") == "ContainerAnalysis"
             and a.get("name") == self.expect_container_name),
            None
        )
        self.nginx_agent = next(
            (a for a in (agents or [])
             if a.get("name") == "nginx_test"),
            None
        )
        self.langchain_agent = next(
            (a for a in (agents or [])
             if a.get("detection_method") == "ContainerAnalysis"
             and a.get("name") == "langchain_test"),
            None
        )
        self.n8n_agent = next(
            (a for a in (agents or [])
             if a.get("name") == "n8n_test"),
            None
        )
        self.pyai_agent = next(
            (a for a in (agents or [])
             if a.get("name") == "pyai_test"),
            None
        )

    def offer(self, line, i, window):
        m = DOCKER_CONTAINER_RE.search(line)
        if m:
            cid = m.group("id")
            self.docker_log_hits[cid] = {
                "image":       m.group("image"),
                "image_match": int(m.group("image_match")),
                "cmd_match":   int(m.group("cmd_match")),
                "pattern":     m.group("pattern") or "",
            }
            return

        m = CONTAINER_INSPECTOR_RE.search(line)
        if m:
            cid = m.group("id")
            self.inspector_log_hits[cid] = {
                "image":      m.group("image"),
                "service":    m.group("service"),
                "confidence": int(m.group("confidence")),
                "env_mask":   m.group("env_mask"),
                "cmds":       int(m.group("cmds")),
                "mounts":     int(m.group("mounts")),
                "conns":      int(m.group("conns")),
                "ports":      m.group("ports"),
            }

    def resolve(self):
        self._check_ollama()
        self._check_nginx()
        self._check_langchain()
        self._check_n8n()
        self._check_pyai()

    def _check_ollama(self):
        if self.ollama_agent is None:
            self.results.append((
                "ollama container detection",
                "ContainerAnalysis entry in detected_agents.json",
                "absent",
                "NOT_DETECTED",
                "no ContainerAnalysis entry for ollama found in detected_agents.json"
            ))
            return

        failures = []
        actuals  = []

        actual_method = self.ollama_agent.get("detection_method", "")
        if actual_method != self.expect_method:
            failures.append(f"detection_method={actual_method} expected {self.expect_method}")
        actuals.append(f"detection_method={actual_method}")

        actual_stype = self.ollama_agent.get("service_type", "")
        if actual_stype != self.expect_stype:
            failures.append(f"service_type={actual_stype} expected {self.expect_stype}")
        actuals.append(f"service_type={actual_stype}")

        container = self.ollama_agent.get("container")
        if not isinstance(container, dict):
            failures.append("container block absent")
            model_mounts = []
        else:
            actuals.append(f"container_id={container.get('container_id', '?')}")
            model_mounts = container.get("model_mounts", [])

        confidence = self.ollama_agent.get("confidence", 0)

        if not model_mounts:
            failures.append("model_mounts is empty -- no .gguf volume mount detected")
        else:
            mount_paths = [m.get("path", "") for m in model_mounts]
            gguf_mounts = [p for p in mount_paths if ".gguf" in p]
            if not gguf_mounts:
                failures.append(f"model_mounts present but no .gguf path found: {mount_paths}")
            else:
                actuals.append(f"model_mount={gguf_mounts[0]}")

        if confidence < 0.85:
            failures.append(f"confidence={confidence:.2f} below 0.85")
        actuals.append(f"confidence={confidence:.2f}")

        self.results.append((
            "ollama container detection",
            f"ContainerAnalysis, service_type={self.expect_stype}, "
            f"model_mount={self.expect_mount}, confidence>=0.85",
            ", ".join(actuals),
            "PASS" if not failures else "FAIL",
            "; ".join(failures),
        ))

    def _check_nginx(self):
        if self.nginx_agent is None:
            self.results.append((
                "nginx container",
                "enumerated but not forwarded to detection engine",
                "absent from detected_agents.json",
                "PASS",
                "nginx correctly not detected as AI"
            ))
        else:
            self.results.append((
                "nginx container",
                "enumerated but not forwarded to detection engine",
                f"present in detected_agents.json conf={self.nginx_agent.get('confidence')}",
                "FAIL",
                "nginx incorrectly forwarded to detection engine as AI"
            ))

    def _check_langchain(self):
        if self.langchain_agent is None:
            self.results.append((
                "langchain container",
                "ContainerAnalysis, cmd_match=1 via langchain pattern",
                "absent",
                "NOT_DETECTED",
                "langchain_test not found in detected_agents.json"
            ))
            return

        failures = []
        actuals  = []

        actual_stype = self.langchain_agent.get("service_type", "")
        actuals.append(f"service_type={actual_stype}")

        confidence = self.langchain_agent.get("confidence", 0)
        actuals.append(f"confidence={confidence:.2f}")

        container_id = self.langchain_agent.get("container", {}).get("container_id", "")

        # check docker log hit for cmd_match
        log_hit = self.docker_log_hits.get(container_id)
        if log_hit is None:
            failures.append(f"no [DOCKER] log line found for container_id={container_id}")
        else:
            if log_hit["cmd_match"] != 1:
                failures.append(f"cmd_match={log_hit['cmd_match']} expected 1")
            else:
                actuals.append(f"cmd_match=1 pattern={log_hit['pattern']}")
            actuals.append(f"image_match={log_hit['image_match']}")

        # check inspector log hit
        inspector_hit = self.inspector_log_hits.get(container_id)
        if inspector_hit:
            actuals.append(f"inspector_service={inspector_hit['service']} "
                          f"inspector_confidence={inspector_hit['confidence']}")

        self.results.append((
            "langchain container",
            "ContainerAnalysis, cmd_match=1 via langchain pattern",
            ", ".join(actuals),
            "PASS" if not failures else "FAIL",
            "; ".join(failures) if failures else
            "cmd_match=1 confirmed in log (note: not persisted to detected_agents.json -- known gap)",
        ))

    def _check_n8n(self):
        failures = []
        actuals  = []

        # first check detected_agents.json
        if self.n8n_agent is not None:
            actual_stype = self.n8n_agent.get("service_type", "")
            if actual_stype != "WorkflowAutomation":
                failures.append(f"service_type={actual_stype} expected WorkflowAutomation")
            actuals.append(f"service_type={actual_stype}")

            confidence = self.n8n_agent.get("confidence", 0)
            if confidence < 0.60:
                failures.append(
                    f"confidence={confidence:.2f} below 0.60 "
                    f"(known gap: active OpenAI API calls needed to reach threshold)"
                )
            actuals.append(f"confidence={confidence:.2f}")

            container = self.n8n_agent.get("container", {})
            has_api_calls = container.get("has_external_ai_api_calls", False)
            actuals.append(f"has_external_ai_api_calls={has_api_calls}")

        else:
            # fall back to inspector log
            inspector_hit = next(
                (v for v in self.inspector_log_hits.values()
                 if "n8n" in v.get("image", "").lower()),
                None
            )
            if inspector_hit is None:
                self.results.append((
                    "n8n container",
                    "service_type=WorkflowAutomation, confidence>=0.60",
                    "absent",
                    "NOT_DETECTED",
                    "n8n_test not found in detected_agents.json or inspector log"
                ))
                return

            # found in log only
            if inspector_hit["service"] != "WorkflowAutomation":
                failures.append(
                    f"service={inspector_hit['service']} expected WorkflowAutomation"
                )
            actuals.append(f"service={inspector_hit['service']} (from log)")

            conf_decimal = inspector_hit["confidence"] / 100
            if conf_decimal < 0.60:
                failures.append(
                    f"confidence={conf_decimal:.2f} below 0.60 "
                    f"(known gap: active OpenAI API calls needed to reach threshold)"
                )
            actuals.append(f"confidence={conf_decimal:.2f} (from log)")
            actuals.append(f"ports={inspector_hit['ports']}")

        self.results.append((
            "n8n container",
            "service_type=WorkflowAutomation, confidence>=0.60",
            ", ".join(actuals),
            "FAIL" if failures else "PASS",
            "; ".join(failures),
        ))

    def _check_pyai(self):
        if self.pyai_agent is None:
            self.results.append((
                "python+env key container",
                "service_type=PythonAIAgent, env_api_keys_mask!=0",
                "absent",
                "NOT_DETECTED",
                "pyai_test not found in detected_agents.json"
            ))
            return

        failures = []
        actuals  = []

        actual_stype = self.pyai_agent.get("service_type", "")
        if actual_stype != "PythonAIAgent":
            failures.append(f"service_type={actual_stype} expected PythonAIAgent")
        actuals.append(f"service_type={actual_stype}")

        container = self.pyai_agent.get("container", {})
        env_mask = container.get("env_api_keys_mask", 0)
        if env_mask == 0:
            failures.append("env_api_keys_mask=0 -- OPENAI_API_KEY not detected in env")
        actuals.append(f"env_api_keys_mask={env_mask}")

        confidence = self.pyai_agent.get("confidence", 0)
        actuals.append(f"confidence={confidence:.2f}")

        # also check inspector log for env_mask
        container_id = container.get("container_id", "")
        inspector_hit = self.inspector_log_hits.get(container_id)
        if inspector_hit:
            actuals.append(f"inspector_env_mask={inspector_hit['env_mask']}")

        self.results.append((
            "python+env key container",
            "service_type=PythonAIAgent, env_api_keys_mask!=0",
            ", ".join(actuals),
            "PASS" if not failures else "FAIL",
            "; ".join(failures),
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
