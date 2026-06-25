# ASM Tool Architecture Map (For AI & Human Developers)

> **Important Instruction to AI Agents**: This file serves as the ground truth for understanding the `asm-tool` architecture. If you make any structural changes (add/remove a file, change a core function signature, or modify global state variables), you **MUST** update this file to reflect the new state to prevent future mismatch failures.

## Directory Structure

The project has been split into a flat, modular structure to improve maintainability and lower token footprint for LLMs:

```
asm-tool/
├── asm.py                 (Main CLI Entrypoint)
├── config.py              (Configuration & Constants)
├── state.py               (Global State & Locks)
├── utils.py               (Shared Helpers & Exec)
├── scanner.py             (Reconnaissance & Vulnerability Phases)
├── llm.py                 (LLM Integration - Ollama/LM Studio)
├── server.py              (Web Dashboard API & Server)
├── AI_ARCHITECTURE_MAP.md (This file)
└── README.md
```

## Module Responsibilities and Connections

### 1. `config.py`
- **Role**: Holds static configuration (`VERSION`, `BASE_DIR`, `OUTPUT_DIR`), the default configuration dictionary, and methods to load/save settings from `config.json`.
- **Connections**: Imported by almost all other modules (`utils`, `scanner`, `llm`, `server`, `asm`) to know where to save outputs and how to talk to LLMs.
- **State**: Exposes a global `config` dictionary that is updated in-place via `update_config(new_config)`.

### 2. `state.py`
- **Role**: Manages the global runtime state of an ongoing scan. This is necessary because the web server runs on one thread while a scan runs on another.
- **Connections**: 
  - `scanner.py` updates the state during the scan.
  - `utils.py` uses it to append log entries.
  - `server.py` reads it to serve `/api/state` and `/api/chat`.
- **State**: Exposes `scan_state` (dictionary) and `scan_lock` (Threading lock).

### 3. `utils.py`
- **Role**: General utility functions.
- **Key Functions**:
  - `run_cmd(cmd)`: Wrapper for `subprocess.run` with built-in logging and error handling. Used heavily by `scanner.py`.
  - `log(msg, level)`: Thread-safe logger that prints to console, appends to `scan_state["log"]`, and writes to `activity.log`.
  - `check_tools()`: Verifies if external binaries (`subfinder`, `nmap`, etc.) exist in the system path.

### 4. `scanner.py`
- **Role**: Executes the main attack surface scanning lifecycle.
- **Key Functions**:
  - `phase_subdomains`, `phase_dns`, `phase_ports`, `phase_tech_detection`, `phase_urls`, `phase_takeover`, `phase_vuln_scan`.
  - `run_scan(domain, options)`: Orchestrator that calls all the phases in sequence. It creates the unique session directory under `output/`.
- **Connections**: Imported by `asm.py` (CLI mode) and `server.py` (Web API mode) to start scans in a background thread.

### 5. `llm.py`
- **Role**: Handles interacting with local LLMs to generate security reports.
- **Key Functions**:
  - `build_llm_prompt(results, domain)`: Condenses massive JSON scan output into a tight prompt.
  - `run_llm_summary(session_id, ...)`: Sends the prompt to Ollama or LM Studio, waits for the response, and saves it to `llm_report.md`.
- **Connections**: Imported by `asm.py` (CLI `--llm`) and `server.py` (Web API `/api/llm`).

### 6. `server.py`
- **Role**: Serves the web dashboard (`/`) and acts as a REST API endpoint (`/api/...`).
- **Connections**: Uses `run_scan` and `run_llm_summary` to execute tasks in background `threading.Thread` instances. Mutates `config` via `config.update_config` on `/api/settings`.
- **Entry**: Called exclusively by `asm.py` when running with `--web` or without arguments.

### 7. `asm.py`
- **Role**: The main executable. It handles `argparse` arguments, prints ASCII art, and routes execution to either `server.py` (Web mode), `scanner.py` (CLI scan mode), or `llm.py` (CLI summary mode).

## Core Data Flow

1. **User Input**: Arrives via `asm.py` arguments or `server.py` HTTP POST.
2. **Execution**: `scanner.py` runs commands via `utils.run_cmd`.
3. **State Updates**: `scanner.py` holds the `state.scan_lock` to mutate `state.scan_state`.
4. **Output Storage**: `utils.log` and `scanner.py` write raw files and logs to `config.OUTPUT_DIR / <session_id>`.
5. **AI Analysis**: `llm.py` reads `full_results.json` from the output directory, queries the API, and outputs `llm_report.md`.

## Verified Import Graph (no circular dependencies)

Verified by static analysis. Dependencies flow strictly downward — **never upward**.

```
asm.py  ──→  config, state, utils, scanner, llm, server
server.py ──→  config, state, utils, scanner, llm
scanner.py ──→  config, state, utils
llm.py ──→  config, state, utils
utils.py ──→  config, state
state.py ──→  (stdlib only: threading)
config.py ──→  (stdlib only: json, pathlib)
```

## Web API Route Reference (server.py)

| Method | Route | Handler | Function Called |
|--------|-------|---------|----------------|
| GET | `/` | `ASMHandler.do_GET` | Serves `templates/dashboard.html` |
| GET | `/api/state` | `ASMHandler.do_GET` | Returns `scan_state` snapshot |
| GET | `/api/tools` | `ASMHandler.do_GET` | `utils.check_tools()` |
| GET | `/api/sessions` | `ASMHandler.do_GET` | Reads `output/*/full_results.json` |
| GET | `/api/session/<id>` | `ASMHandler.do_GET` | Reads `output/<id>/full_results.json` |
| GET | `/api/llm_report/<id>` | `ASMHandler.do_GET` | Reads `output/<id>/llm_report.md` |
| GET | `/api/settings` | `ASMHandler.do_GET` | `config.load_config()` |
| POST | `/api/scan` | `ASMHandler.do_POST` | `scanner.run_scan()` in thread |
| POST | `/api/llm` | `ASMHandler.do_POST` | `llm.run_llm_summary()` in thread |
| POST | `/api/chat` | `ASMHandler.do_POST` | Direct LLM call (Ollama/LM Studio) |
| POST | `/api/settings` | `ASMHandler.do_POST` | `config.update_config()` |

## Session Output Files

Each scan writes to `output/<session_id>/`:

| File | Written By | Purpose |
|------|-----------|---------|
| `subdomains_raw.txt` | `scanner.phase_subdomains` | All unique subdomains found |
| `resolved.txt` | `scanner.phase_dns` | DNS-resolved live hosts |
| `open_ports.txt` / `open_ports.json` | `scanner.phase_ports` | Naabu/nmap results |
| `httpx_results.json` | `scanner.phase_tech_detection` | Web services, titles, tech stack |
| `nmap_results.txt` | `scanner.phase_tech_detection` | Nmap service banner data |
| `all_urls.txt` / `juicy_urls.txt` | `scanner.phase_urls` | Crawled and archived URLs |
| `takeover_candidates.json` | `scanner.phase_takeover` | Subdomain takeover findings |
| `nuclei_results.json` | `scanner.phase_vuln_scan` | Nuclei vulnerability output |
| `full_results.json` | `scanner.run_scan` | Consolidated results (read by llm.py) |
| `llm_report.md` | `llm.run_llm_summary` | AI-generated security report |
| `activity.log` | `utils.log` | Timestamped activity log (read by /api/chat) |

## Global State Schema (`state.scan_state`)

```python
scan_state = {
    "running": bool,          # True while a scan is in progress
    "domain":  str,           # Target domain of the current scan
    "session_id": str,        # e.g. "20240615_123456_example_com"
    "phase": str,             # Human-readable current phase name
    "progress": int,          # 0–100 percent
    "log": [ {"ts","level","msg"} ],  # In-memory log entries
    "llm": {
        "running": bool,
        "done":    bool,
        "report":  str,       # Full markdown report text
        "error":   str,
        "model":   str,
        "provider": str       # "ollama" or "lmstudio"
    },
    "results": {
        "subdomains":          list[str],
        "live_hosts":          list[dict],  # {url, status, title, tech}
        "open_ports":          list[dict],  # {host, port}
        "urls":                list[str],
        "vulnerabilities":     list[dict],  # {host, template, name, severity, matched, description}
        "takeover_candidates": list[dict],  # {subdomain, cname, service, signature}
        "technologies":        dict,        # {url: [tech,...]}
        "nmap_output":         str
    }
}
```
