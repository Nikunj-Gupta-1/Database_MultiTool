import json
import threading
import copy
import re as re_module
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from config import config, OUTPUT_DIR, DEFAULT_CONFIG, load_config, save_config, update_config, BASE_DIR
from state import scan_state, scan_lock
from utils import check_tools
from scanner import run_scan
from llm import run_llm_summary

class ASMHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress access logs

    @staticmethod
    def is_valid_session_id(sid):
        """Validate session ID to prevent path traversal."""
        return bool(re_module.match(r'^[a-zA-Z0-9_.-]+$', sid)) and '..' not in sid

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self.serve_file("dashboard.html", "text/html")
        elif path == "/api/state":
            with scan_lock:
                state_snapshot = copy.deepcopy(scan_state)
            self.serve_json(state_snapshot)
        elif path == "/api/tools":
            self.serve_json(check_tools())
        elif path == "/api/sessions":
            sessions = []
            for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
                if d.is_dir():
                    rf = d / "full_results.json"
                    if rf.exists():
                        try:
                            with open(rf) as f:
                                r = json.load(f)
                            has_report = (d / "llm_report.md").exists()
                            sessions.append({
                                "id": d.name,
                                "subdomains": len(r.get("subdomains", [])),
                                "live_hosts":  len(r.get("live_hosts", [])),
                                "vulns":       len(r.get("vulnerabilities", [])),
                                "takeover":    len(r.get("takeover_candidates", [])),
                                "has_report":  has_report,
                            })
                        except Exception:
                            pass
            self.serve_json(sessions)
        elif path.startswith("/api/session/"):
            sid = path.split("/api/session/")[1].rstrip("/")
            if not self.is_valid_session_id(sid):
                self.send_error(400, "Invalid session ID")
                return
            rf = OUTPUT_DIR / sid / "full_results.json"
            if rf.exists():
                with open(rf) as f:
                    self.serve_json(json.load(f))
            else:
                self.send_error(404)
        elif path.startswith("/api/llm_report/"):
            sid = path.split("/api/llm_report/")[1].rstrip("/")
            if not self.is_valid_session_id(sid):
                self.send_error(400, "Invalid session ID")
                return
            rp = OUTPUT_DIR / sid / "llm_report.md"
            if rp.exists():
                with open(rp) as f:
                    self.serve_json({"report": f.read()})
            else:
                self.serve_json({"report": ""})
        elif path == "/api/settings":
            self.serve_json(load_config())
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        if length > 10 * 1024 * 1024:  # 10MB max
            self.send_error(413, "Request body too large")
            return
        body = self.rfile.read(length).decode("utf-8") if length else "{}"

        if path == "/api/scan":
            try:
                data = json.loads(body)
                domain = data.get("domain", "").strip()
                options = data.get("options", {})
                if not domain:
                    self.serve_json({"error": "domain required"}, 400)
                    return
                if scan_state["running"]:
                    self.serve_json({"error": "A scan is already running"}, 409)
                    return
                t = threading.Thread(target=run_scan, args=(domain, options), daemon=True)
                t.start()
                self.serve_json({"status": "started", "domain": domain})
            except Exception as e:
                self.serve_json({"error": str(e)}, 500)

        elif path == "/api/llm":
            try:
                data = json.loads(body)
                session_id = data.get("session_id") or scan_state.get("session_id", "")
                provider   = (data.get("provider", "").strip().lower()) or config.get("provider", "lmstudio")
                model      = data.get("model", "").strip()
                host       = data.get("host", "").strip() or None

                if not session_id:
                    self.serve_json({"error": "No session to summarize"}, 400)
                    return
                if scan_state["llm"]["running"]:
                    self.serve_json({"error": "LLM summary already running"}, 409)
                    return
                if not (OUTPUT_DIR / session_id / "full_results.json").exists():
                    self.serve_json({"error": "Session results not found"}, 404)
                    return

                if provider not in ("ollama", "lmstudio"):
                    self.serve_json({"error": "provider must be 'ollama' or 'lmstudio'"}, 400)
                    return

                if not model:
                    model = "llama3" if provider == "ollama" else "local-model"

                t = threading.Thread(
                    target=run_llm_summary,
                    args=(session_id, provider, model, host),
                    daemon=True
                )
                t.start()
                self.serve_json({
                    "status": "started",
                    "session_id": session_id,
                    "provider": provider,
                    "model": model
                })
            except Exception as e:
                self.serve_json({"error": str(e)}, 500)

        elif path == "/api/chat":
            try:
                data = json.loads(body)
                session_id = data.get("session_id", "")
                history = data.get("history", [])
                message = data.get("message", "").strip()

                if not session_id:
                    self.serve_json({"error": "session_id required"}, 400)
                    return
                if not message:
                    self.serve_json({"error": "message required"}, 400)
                    return

                report_path = OUTPUT_DIR / session_id / "llm_report.md"
                report_content = ""
                if report_path.exists():
                    with open(report_path) as f:
                        report_content = f.read()

                log_path = OUTPUT_DIR / session_id / "activity.log"
                log_content = ""
                if log_path.exists():
                    try:
                        with open(log_path) as f:
                            lines = f.readlines()
                            log_content = "".join(lines[-50:])
                    except Exception:
                        pass

                results_path = OUTPUT_DIR / session_id / "full_results.json"
                counts = {"subdomains": 0, "live_hosts": 0, "open_ports": 0, "vulnerabilities": 0}
                if results_path.exists():
                    try:
                        with open(results_path) as f:
                            r = json.load(f)
                            counts["subdomains"] = len(r.get("subdomains", []))
                            counts["live_hosts"] = len(r.get("live_hosts", []))
                            counts["open_ports"] = len(r.get("open_ports", []))
                            counts["vulnerabilities"] = len(r.get("vulnerabilities", []))
                    except Exception:
                        pass

                sys_prompt = f"""You are Friday, Tony Stark's personal artificial intelligence assistant.
You are helping the user analyze security scan results. You should sound smart, helpful, efficient, and slightly witty, just like Friday.
Refer to the user as Boss or Sir if appropriate, but keep it natural.

=== SESSION CONTEXT ===
Target Session: {session_id}
Summary Stats:
- Subdomains found: {counts['subdomains']}
- Live web hosts: {counts['live_hosts']}
- Open ports: {counts['open_ports']}
- Vulnerabilities: {counts['vulnerabilities']}

=== SECURITY SUMMARY REPORT ===
{report_content if report_content else "No report generated yet."}

=== RECENT ACTIVITY LOGS ===
{log_content if log_content else "No activity logs available."}
"""

                messages = [{"role": "system", "content": sys_prompt}]
                for msg in history:
                    messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
                messages.append({"role": "user", "content": message})

                provider = config.get("provider", "lmstudio")
                if provider == "ollama":
                    host = config.get("ollama_host", "http://localhost:11434")
                    model = config.get("ollama_model", "llama3")
                    url = f"{host}/api/chat"
                    payload = json.dumps({
                        "model": model,
                        "messages": messages,
                        "stream": False
                    }).encode("utf-8")
                else:
                    host = config.get("lmstudio_host", "http://localhost:1234")
                    model = config.get("lmstudio_model", "local-model")
                    url = f"{host}/v1/chat/completions"
                    payload = json.dumps({
                        "model": model,
                        "messages": messages,
                        "temperature": 0.3,
                        "max_tokens": 2048,
                        "stream": False
                    }).encode("utf-8")

                req = Request(url, data=payload, headers={"Content-Type": "application/json"})
                try:
                    with urlopen(req, timeout=300) as resp:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                        if provider == "ollama":
                            reply = resp_data.get("message", {}).get("content", "")
                        else:
                            reply = resp_data["choices"][0]["message"]["content"]
                        self.serve_json({"reply": reply})
                except Exception as e:
                    self.serve_json({"error": f"LLM Connection failed: {e}. Is your LLM server running at {host}?"}, 500)

            except Exception as e:
                self.serve_json({"error": str(e)}, 500)

        elif path == "/api/settings":
            try:
                data = json.loads(body)
                updated_config = load_config()
                for k in DEFAULT_CONFIG.keys():
                    if k in data:
                        updated_config[k] = data[k]
                update_config(updated_config)
                self.serve_json({"status": "success", "config": updated_config})
            except Exception as e:
                self.serve_json({"error": str(e)}, 500)

        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def serve_json(self, data, code=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, filename, content_type):
        filepath = BASE_DIR / "templates" / filename
        if not filepath.exists():
            self.send_error(404)
            return
        with open(filepath, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)
