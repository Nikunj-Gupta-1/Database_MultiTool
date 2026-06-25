import os
import shutil
import subprocess
from datetime import datetime
from config import OUTPUT_DIR
from state import scan_state, scan_lock

TOOL_CHECKS = {
    "subfinder":    "subfinder",
    "subdominator": "subdominator",
    "puredns":      "puredns",
    "dnsx":         "dnsx",
    "naabu":        "naabu",
    "nmap":         "nmap",
    "katana":       "katana",
    "gau":          "gau",
    "waybackurls":  "waybackurls",
    "httpx":        "httpx",
    "nuclei":       "nuclei",
}

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "level": level, "msg": msg}
    with scan_lock:
        scan_state["log"].append(entry)
        session_id = scan_state.get("session_id")
    
    if session_id:
        log_file = OUTPUT_DIR / session_id / "activity.log"
        try:
            with open(log_file, "a") as f:
                f.write(f"[{ts}] [{level}] {msg}\n")
        except Exception:
            pass

    prefix = {
        "INFO": "\033[36m[*]",
        "OK":   "\033[32m[+]",
        "WARN": "\033[33m[!]",
        "ERR":  "\033[31m[-]"
    }.get(level, "[?]")
    print(f"{prefix}\033[0m [{ts}] {msg}")

def tool_exists(name):
    return shutil.which(name) is not None

def check_tools():
    return {k: tool_exists(v) for k, v in TOOL_CHECKS.items()}

def run_cmd(cmd, capture=True, timeout=300, shell=False):
    log(f"Running command: {cmd}", "INFO")
    try:
        import shlex
        if isinstance(cmd, str) and not shell:
            cmd_args = shlex.split(cmd)
        else:
            cmd_args = cmd
            
        result = subprocess.run(
            cmd_args, capture_output=capture,
            text=True, timeout=timeout, shell=shell
        )
        if result.returncode != 0:
            log(f"Command returned code {result.returncode}. Error: {result.stderr.strip()[:250]}", "WARN")
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        log(f"Command timed out after {timeout} seconds", "ERR")
        return "", "TIMEOUT", 1
    except Exception as e:
        log(f"Command execution error: {e}", "ERR")
        return "", str(e), 1

def save_lines(filepath, lines):
    with open(filepath, "w") as f:
        f.write("\n".join(str(l) for l in lines))

def read_lines(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath) as f:
        return [l.strip() for l in f if l.strip()]
