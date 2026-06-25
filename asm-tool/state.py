import threading

scan_lock = threading.Lock()

scan_state = {
    "running": False,
    "domain": "",
    "session_id": "",
    "phase": "",
    "progress": 0,
    "log": [],
    "llm": {
        "running": False,
        "done": False,
        "report": "",
        "error": "",
        "model": "",
        "provider": ""
    },
    "results": {
        "subdomains": [],
        "live_hosts": [],
        "open_ports": [],
        "urls": [],
        "vulnerabilities": [],
        "takeover_candidates": [],
        "technologies": {},
        "nmap_output": ""
    }
}

def set_phase(name, progress):
    with scan_lock:
        scan_state["phase"] = name
        scan_state["progress"] = progress
