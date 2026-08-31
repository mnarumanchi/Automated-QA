import argparse, shutil, csv, re
from pathlib import Path
import json
import subprocess
from tests.SAVR2SAVR7 import SAVR7 #01
from tests.SAVR2SAVR14 import SAVR14 #08
from tests.SAVR2SAVR13 import SAVR13 #09
from tests.SAVR2SAVR18 import SAVR18 #05
from tests.SAVR2SAVR15 import SAVR15 #07
from tests.SAVR2SAVR43 import SAVR43_1, SAVR43_2, SAVR43_3
from tests.SAVR2SAVR16 import SAVR16
from tests.SAVR2SAVR6 import SAVR6
from tests.SAVR9 import SAVR9
from tests.SAVR17 import SAVR17
from tests.SAVR4 import SAVR4
from tests.SAVR29 import SAVR29
from tests.SAVR12 import SAVR12
from tests.SAVR27a28 import SAVR27a28
from tests.SAVR40 import SAVR40
from tests.SAVR5 import SAVR5
from datetime import datetime, timezone

#python overall.py --start "2026-07-02 16:00:00.049" --roster roster.json --out results.csv

#TEST_CLASSES = [SAVR7, SAVR14, SAVR13, SAVR18, SAVR15, SAVR43_1, SAVR43_2, SAVR43_3,
#SAVR16, SAVR6, SAVR9, SAVR17, SAVR4, SAVR29, SAVR12, SAVR27a28, SAVR40, SAVR5]


TEST_CLASSES = [SAVR4, SAVR5, SAVR6, SAVR7, SAVR9, SAVR12, SAVR13, SAVR14, SAVR15, 
SAVR16, SAVR17, SAVR18, SAVR27a28, SAVR29, SAVR40, SAVR43_1, SAVR43_2, SAVR43_3]


LOG_PATH    = Path(r"C:\Windows\System32\config\systemprofile\AppData\Local\Cybersenz\SecureAiService\Logs\SecureAiService.log")
AGENTS_PATH = Path(r"C:\ProgramData\Cybersenz\config\agents\detected_agents.json")
SYSINFO_PATH = Path(r"C:\ProgramData\Cybersenz\config\sysinfo.jsonl")

def get_pids_by_name(proc_name):
    result = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {proc_name}", "/FO", "CSV", "/NH"],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            pids.append(parts[1])
    return pids

def build_tests(roster_path, agents, sysinfo):
    if roster_path is None:
        return []
    cfg = json.loads(roster_path.read_text())

    # auto-resolve tcp_stats_test by_name entries into by_pid using live tasklist
    if "SAVR14" in cfg:
        tcp_cfg = cfg["SAVR14"]
        for proc_name, domain in tcp_cfg.get("by_name", {}).items():
            pids = get_pids_by_name(proc_name)
            print(f"looked up {proc_name} -> PIDs: {pids}")
            for pid in pids:
                tcp_cfg["by_pid"][pid] = {"label": proc_name, "domain": domain}
        tcp_cfg["by_name"] = {}

    return [cls(cfg[cls.name], agents, sysinfo) for cls in TEST_CLASSES if cls.name in cfg]

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--start", required=True,
                   help="Run-start timestamp, e.g. '2026-06-25 08:13:00.000'")
    p.add_argument("--out", default="results.csv", type=Path)
    p.add_argument("--roster", type=Path,
                   help="JSON of expected subjects -> conf range")
    return p.parse_args()

def snapshot(log_path: Path) -> Path:
    # write locally, not next to the protected log file
    snap = Path("log.snapshot")
    shutil.copy2(log_path, snap)
    return snap

def snapshot_agents(agents_path: Path) -> Path:
    snap = Path("agents.snapshot")
    shutil.copy2(agents_path, snap)
    return snap

timestamp_re = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")

def load_window(snap: Path, start: str) -> list[str]:
    lines = snap.read_text(encoding="utf-8", errors="replace").splitlines()
    out, started = [], False
    for line in lines:
        m = timestamp_re.match(line)
        if not started:
            if m and m.group(1) >= start:   # >= not ==, string compare is safe for this format
                started = True
            else:
                continue
        out.append(line)
    return out   # indexable array; multi-line matchers can peek forward

def load_agents(agents_snap: Path, start: str) -> list[dict]:
    # parse start as local naive datetime then treat as UTC for comparison
    start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=timezone.utc
    )
    data = json.loads(agents_snap.read_text(encoding="utf-8"))
    active = []
    for agent in data.get("agents", []):
        last_seen = agent.get("last_seen", "")
        if not last_seen:
            continue
        try:
            ls_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ls_dt >= start_dt:
            active.append(agent)
    return active

def load_sysinfo(sysinfo_path: Path) -> dict:
    with sysinfo_path.open("rb") as f:
        f.seek(0, 2)          # seek to end of file
        pos = f.tell()
        
        # walk backwards skipping any trailing newlines
        while pos > 0:
            pos -= 1
            f.seek(pos)
            if f.read(1) not in (b"\n", b"\r", b" "):
                break
        
        # now find the start of this last line
        while pos > 0:
            pos -= 1
            f.seek(pos)
            if f.read(1) in (b"\n", b"\r"):
                break
        
        last_line = f.readline().decode("utf-8").strip()
    
    return json.loads(last_line) if last_line else {}

def run(window, tests):
    for i, line in enumerate(window):
        for t in tests:
            t.offer(line, i, window)
    for t in tests:
        t.resolve()

def write_report(tests, out: Path):
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["test", "subject", "expected", "actual",
                    "result", "comments"])
        for t in tests:
            for row in t.rows():
                w.writerow(row)

def main():
    a = parse_args()
    snap        = snapshot(LOG_PATH)
    agents_snap = snapshot_agents(AGENTS_PATH)
    window      = load_window(snap, a.start)
    agents      = load_agents(agents_snap, a.start)  # fixed: use load_agents not raw json.loads
    sysinfo = load_sysinfo(SYSINFO_PATH)
    tests       = build_tests(a.roster, agents, sysinfo)
    run(window, tests)
    write_report(tests, a.out)

if __name__ == "__main__":
    main()
