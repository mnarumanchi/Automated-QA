import subprocess, json, time
from pathlib import Path
from datetime import datetime

ROSTER = Path("roster.json")
OUT    = Path("results.csv")

def wait_for_docker(timeout=60):
    print("[setup] waiting for Docker to be ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[setup] Docker is ready")
            return True
        time.sleep(3)
    print("[setup] WARNING: Docker not ready after timeout")
    return False

def start_container(name, cmd):
    subprocess.run(["docker", "stop", name], capture_output=True)
    subprocess.run(["docker", "rm",   name], capture_output=True)
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", name],
        capture_output=True, text=True
    )
    status = result.stdout.strip()
    if status != "running":
        print(f"[setup] WARNING: {name} status={status}, attempting docker start")
        subprocess.run(["docker", "start", name], capture_output=True)
        time.sleep(3)
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True, text=True
        )
        status = result.stdout.strip()
    print(f"[setup] {name} status={status}")

def main():
    # 1. record start time
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")
    print(f"[setup] start timestamp: {start}")

    # 2. restart service
    print("[setup] restarting SecureAiService...")
    subprocess.run(["net", "stop", "SecureAiService"], capture_output=True)
    time.sleep(3)
    subprocess.run(["net", "start", "SecureAiService"], capture_output=True)
    time.sleep(5)

    # 3. launch httpbin fixture
    httpbin = subprocess.Popen(
        ["python", "-c",
         "import requests, time, os; print(f'fixture PID: {os.getpid()}', flush=True);"
         "[requests.get('https://httpbin.org/get') or time.sleep(30) for _ in range(20)]"],
        stdout=subprocess.PIPE, text=True
    )
    pid_line = httpbin.stdout.readline().strip()
    fixture_pid = pid_line.split("PID:")[-1].strip()
    print(f"[setup] httpbin fixture PID: {fixture_pid}")

    # 4. chatgpt fixture for SAVR18
    chatgpt = subprocess.Popen(
        ["python", "-c",
         "import requests, time; requests.get('https://chatgpt.com', timeout=30); time.sleep(10)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print(f"[setup] chatgpt fixture launched with PID {chatgpt.pid}")

    # 5. patch roster with httpbin PID
    cfg = json.loads(ROSTER.read_text())
    cfg["SAVR14"]["by_pid"] = {
        fixture_pid: {"label": "httpbin fixture", "domain": "httpbin.org"}
    }
    ROSTER.write_text(json.dumps(cfg, indent=2))
    print("[setup] roster patched with httpbin PID")

    # 6. python+torch fixture for library detection
    python_ai = subprocess.Popen(
        ["python", "-c",
         "import torch, time, os; print(f'python fixture PID: {os.getpid()}', flush=True);"
         "time.sleep(300)"],
        stdout=subprocess.PIPE, text=True
    )
    pid_line2 = python_ai.stdout.readline().strip()
    python_pid = pid_line2.split("PID:")[-1].strip()
    print(f"[setup] python+torch fixture PID: {python_pid}")

    # 7. OpenAI fixture for SAVR12
    open_ai = subprocess.Popen(
        ["curl", "https://openai.com"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    cfg = json.loads(ROSTER.read_text())
    cfg["SAVR12"]["by_pid"] = {
        str(open_ai.pid): {"label": "openai fixture", "domain": "openai.com"}
    }
    ROSTER.write_text(json.dumps(cfg, indent=2))
    print(f"[setup] curl launched with PID {open_ai.pid}, roster patched")

    # 8. anthropic fixture for SAVR4
    subprocess.Popen(
        ["python", "-c",
         "import requests, time; requests.get('https://anthropic.com', timeout=10); time.sleep(10)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print("[setup] anthropic fixture launched")

    # 9. wait for Docker to be ready then pull images
    wait_for_docker()
    print("[setup] pulling docker images...")
    subprocess.run(["docker", "pull", "ollama/ollama"], capture_output=True)
    subprocess.run(["docker", "pull", "nginx"],         capture_output=True)
    subprocess.run(["docker", "pull", "python:3.11"],   capture_output=True)
    subprocess.run(["docker", "pull", "n8nio/n8n"],     capture_output=True)
    print("[setup] docker images ready")

    # 10. ollama container with model volume
    start_container("ollama_mount_test", [
        "docker", "run", "--name", "ollama_mount_test",
        "-v", r"C:\models:/models",
        "ollama/ollama"
    ])

    # 11. nginx -- enumerated but not detected as AI
    start_container("nginx_test", [
        "docker", "run", "--name", "nginx_test", "nginx"
    ])

    # 12. langchain -- detected via command match
    start_container("langchain_test", [
        "docker", "run", "--name", "langchain_test",
        "python:3.11", "python", "-c",
        "import time; time.sleep(300)  # langchain"
    ])

    # 13. n8n -- WorkflowAutomation detection
    start_container("n8n_test", [
        "docker", "run", "--name", "n8n_test", "n8nio/n8n"
    ])

    # 14. pyai -- env var + command match detection
    start_container("pyai_test", [
        "docker", "run", "--name", "pyai_test",
        "-e", "OPENAI_API_KEY=sk-test1234567890abcdef",
        "python:3.11", "python", "-c",
        "import time; time.sleep(300)  # langchain"
    ])

    # 15. wait for scanner cycles
    print("[setup] waiting 240 seconds for scanner cycles...")
    time.sleep(240)

    # 16. schannel fixtures
    print("[setup] running schannel fixtures...")
    subprocess.run(
        ["powershell", "-Command",
         "Invoke-WebRequest -Uri 'https://copilot.microsoft.com' -UseBasicParsing"],
        capture_output=True
    )
    subprocess.run(
        ["powershell", "-Command",
         "Invoke-WebRequest -Uri 'https://chat.openai.com' -UseBasicParsing"],
        capture_output=True
    )
    print("[setup] schannel fixtures done")
    time.sleep(20)

    # 17. run the suite
    print("[setup] running suite...")
    subprocess.run([
        "python", "overall.py",
        "--start", start,
        "--roster", str(ROSTER),
        "--out", str(OUT),
    ])

    # 18. clean up
    print("[setup] cleaning up...")
    httpbin.terminate()
    chatgpt.terminate()
    python_ai.terminate()
    for name in ["ollama_mount_test", "nginx_test", "langchain_test",
                 "n8n_test", "pyai_test"]:
        subprocess.run(["docker", "stop", name], capture_output=True)
        subprocess.run(["docker", "rm",   name], capture_output=True)
    print(f"[setup] done -- results in {OUT}")

if __name__ == "__main__":
    main()
