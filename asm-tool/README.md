# ⚡ ASM — Attack Surface Manager & Friday AI Security Cockpit

A complete OSINT + vulnerability discovery framework for subdomains, exposed ports, unsafe endpoints, and takeover candidates. Built with a high-fidelity Cyberpunk glassmorphic web dashboard, a custom force-directed interactive network map, and **Friday**, a Tony Stark-inspired AI security assistant.

---

## 🚀 Key Features

*   **Integrated OSINT & Scan Utilities**: Orchestrates `subfinder`, `subdominator`, `dnsx`, `puredns`, `naabu`, `nmap`, `httpx`, `katana`, `gau`, `waybackurls`, and `nuclei`.
*   **Interactive Attack Surface Node Map**: A high-performance, custom HTML5 Canvas-based force-directed physics engine that maps the target domain to subdomains (blue), live web services (green), open ports (purple), and vulnerabilities (red). Hover/drag nodes, double-click subdomains to copy, or select a node to inspect details in the inspection pane.
*   **Friday AI Assistant**: Named after Tony Stark's assistant, Friday automatically summarizes scans, generates comprehensive markdown reports, and powers an interactive security chat. You can ask Friday for vulnerability explanations, exploit steps, remediation advice, or scans diagnostics.
*   **Settings Console**: Save preferred hosts, custom port ranges, and LLM providers directly from the Web UI to `config.json`. Supports both **LM Studio** (default) and **Ollama**.
*   **Activity Logs Telemetry**: Generates an `activity.log` file for each session, recording every subprocess command executed, arguments, timing, stdout/stderr, warnings, and failures. Friday has direct backend access to this file to help debug why specific tools failed.
*   **Cyberpunk Aesthetics**: Transparent glassmorphic panels, real-time glowing indicators, custom animations, and a responsive dashboard layout.
*   **Security & Performance Hardened**: Fully audited and secured against shell injections, path traversals, XSS, and race conditions. Built for robust, performant execution on Linux (e.g. CachyOS).

---

## ⚙️ Configuration & LLM Providers

ASM is built to interface directly with local LLMs to keep data secure and local.

### 1. LM Studio (Default)
1. Install and open **LM Studio**.
2. Download your preferred model (e.g., Llama-3, Mistral).
3. Start the **Local Server** on port `1234` (API endpoint: `http://localhost:1234`).
4. Ensure the dashboard setting is configured to `LM Studio` and target model is set to `local-model` (or your loaded model name).

### 2. Ollama (Fallback/Alternative)
1. Install and start **Ollama**.
2. Run `ollama run llama3` (or your model of choice).
3. Update settings in the **Settings & Tools** dashboard to set provider to `ollama`, host to `http://localhost:11434`, and model name to `llama3`.

---

## 🛠 Quick Start

### Web Dashboard (Recommended)
1. Launch the web server:
   ```bash
   python3 asm.py --web
   ```
2. Navigate to **`http://localhost:7373`** in your browser.
3. Access the **Settings & Tools** tab to verify tool availability and configure LM Studio/Ollama endpoints.
4. Input a target domain on the dashboard and trigger the scan.

### CLI Mode

**Run a Target Scan:**
```bash
# Full automated scan
python3 asm.py -d example.com

# Faster scan skipping vulnerability scanning
python3 asm.py -d example.com --skip-nuclei

# Scan custom ports
python3 asm.py -d example.com --ports "80,443,22,3306"
```

**Generate LLM Summaries from CLI:**
```bash
# Run Friday summary on a past session (uses config.json defaults)
python3 asm.py --llm SESSION_ID

# Override provider, model, and host from the CLI
python3 asm.py --llm SESSION_ID --provider lmstudio --model local-model --llm-host http://localhost:1234
python3 asm.py --llm SESSION_ID --provider ollama --model llama3 --llm-host http://localhost:11434
```

---

## 📁 Directory Structure

The project uses a flat, modular structure to ensure code remains maintainable, readable, and highly optimized for both human developers and AI analysis:

```
asm-tool/
├── asm.py                 # Main CLI Entrypoint
├── config.py              # Configuration & Constants
├── state.py               # Global State & Locks
├── utils.py               # Shared Helpers & Exec
├── scanner.py             # Reconnaissance & Vulnerability Phases
├── llm.py                 # LLM Integration (Ollama/LM Studio)
├── server.py              # Web Dashboard API & Server
├── AI_ARCHITECTURE_MAP.md # AI instructions and architecture map
└── README.md
```

---

## 📂 Session Output Structure

Every scan creates a timestamped session directory under `output/<domain>_<timestamp>/`:

| File Name | Description |
| :--- | :--- |
| `activity.log` | Raw execution telemetry, subprocess commands, warnings, and CLI stderr/stdout. Used by Friday for troubleshooting. |
| `subdomains_raw.txt` | Aggregated raw subdomain list found via passive and active engines. |
| `resolved.txt` | Live/resolved subdomains with IP resolutions. |
| `open_ports.json` | JSON mapping of open ports found per subdomain. |
| `httpx_results.json` | Web service technical details (URLs, status codes, tech stack, titles). |
| `takeover_candidates.json` | Subdomains showing signatures of dangling DNS / takeover potential. |
| `nuclei_results.json` | Detected vulnerabilities and misconfigurations. |
| `llm_report.md` | The security audit report generated by Friday. |
| `full_results.json` | Consolidated data structure containing all session findings. |

---

## 📦 Tool Requirements & Installation

For full functionality, make sure the following tools are installed in your shell path:

```bash
# Go Tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/d3mondev/puredns/v2@latest

# Subdominator (DNS takeover checker)
pip3 install subdominator

# Network Scanner (Nmap)
# Mac:
brew install nmap
# Arch / CachyOS (Recommended):
sudo pacman -S nmap
# Ubuntu/Debian:
sudo apt install nmap
```

*Note: You can check which tools are currently recognized by running `python3 asm.py --check-tools` or viewing the Settings Console in the Web UI.*

---

## ⚠ Legal Notice
Scanning networks or systems without explicit prior permission is strictly illegal. Use this tool only on infrastructure you own or have legal authorization to test. The developers assume no liability for misuse.
