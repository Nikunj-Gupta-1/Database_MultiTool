import json
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
from config import config, OUTPUT_DIR
from state import scan_state, scan_lock
from utils import log

JUICY_URL_PATTERNS = [
    "redirect", "url=", "next=", "target=", "cmd=", "exec=", "sql",
    "admin", "upload", "token=", "api_key=", "debug=", "shell=", "callback="
]

def build_llm_prompt(results, domain):
    """Build a condensed, focused prompt from scan results."""
    subs     = results.get("subdomains", [])
    live     = results.get("live_hosts", [])
    ports    = results.get("open_ports", [])
    urls     = results.get("urls", [])
    vulns    = results.get("vulnerabilities", [])
    takeover = results.get("takeover_candidates", [])

    juicy = [u for u in urls if any(p in u.lower() for p in JUICY_URL_PATTERNS)][:20]

    # Condense live hosts for prompt
    live_summary = []
    for h in live[:15]:
        tech = ", ".join(h.get("tech", [])) or "unknown"
        live_summary.append({
            "url": h.get("url",""),
            "status": h.get("status",""),
            "title": h.get("title",""),
            "tech": tech
        })

    # Condense ports
    port_summary = [f"{p['host']}:{p['port']}" for p in ports[:30]]

    prompt = f"""You are a senior penetration tester and security analyst.
Below is raw automated attack-surface scan data for the domain: {domain}

Your job is to write a structured, actionable security report based on this data.

=== SCAN RESULTS ===

[Subdomain Enumeration]
Total subdomains found: {len(subs)}
Sample (first 15): {subs[:15]}

[Live Web Services — {len(live)} total]
{json.dumps(live_summary, indent=2)}

[Open Ports — {len(ports)} total]
{port_summary}

[Subdomain Takeover Candidates — {len(takeover)} found]
{json.dumps(takeover, indent=2)}

[Nuclei Vulnerabilities — {len(vulns)} found]
{json.dumps(vulns[:25], indent=2)}

[Juicy/Interesting URLs — {len(juicy)} samples from {len(urls)} total]
{juicy}

=== INSTRUCTIONS ===
Write the following sections:

1. EXECUTIVE SUMMARY
   2-3 clear sentences summarizing the overall risk posture.

2. KEY FINDINGS
   Bullet points: subdomains, exposed services, interesting ports, tech stack observations.

3. SUBDOMAIN TAKEOVER RISK
   For each candidate: explain the risk and how an attacker could exploit it.
   If none found, state clearly.

4. VULNERABILITIES
   Group by severity (Critical → High → Medium → Low).
   For each: name, affected host, what it means in plain English.

5. INTERESTING ENDPOINTS
   From the juicy URLs, flag the most dangerous parameter patterns and why.

6. OVERALL RISK RATING
   One of: CRITICAL / HIGH / MEDIUM / LOW
   Justify in 1-2 sentences.

7. RECOMMENDED NEXT STEPS
   Ordered list of actionable remediation items for the target owner.

Be direct, specific, and technical. Do not repeat raw data verbatim — interpret it.
"""
    return prompt


def call_ollama(prompt, model, host="http://localhost:11434"):
    """Call Ollama's API and return the full response text."""
    url = f"{host}/api/generate"
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False
    }).encode("utf-8")
    req = Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", ""), None
    except URLError as e:
        return "", f"Ollama connection error: {e}. Is Ollama running? (ollama serve)"
    except Exception as e:
        return "", f"Ollama error: {e}"


def call_lmstudio(prompt, model, host="http://localhost:1234"):
    """Call LM Studio's OpenAI-compatible API and return the full response text."""
    url = f"{host}/v1/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior cybersecurity analyst specializing in attack surface management and penetration testing."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "max_tokens": 4096,
        "stream": False
    }).encode("utf-8")
    req = Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"], None
    except URLError as e:
        return "", f"LM Studio connection error: {e}. Is LM Studio running with Local Server enabled?"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return "", f"LM Studio response parse error: {e}"
    except Exception as e:
        return "", f"LM Studio error: {e}"


def check_llm_available(provider, model, host=None):
    """Check if the chosen LLM backend is reachable."""
    if provider == "ollama":
        url = (host or "http://localhost:11434") + "/api/tags"
    else:
        url = (host or "http://localhost:1234") + "/v1/models"
    try:
        req = Request(url)
        with urlopen(req, timeout=5):
            return True
    except Exception:
        return False


def run_llm_summary(session_id, provider="ollama", model=None, host=None):
    """
    Run the LLM summary for a given session.
    This is called from a background thread (web UI) or directly (CLI).
    provider: "ollama" or "lmstudio"
    model: model name string
    host: optional override for API host URL
    """
    # Default models
    if not model:
        model = "llama3" if provider == "ollama" else "local-model"

    # Default hosts
    if not host:
        host = "http://localhost:11434" if provider == "ollama" else "http://localhost:1234"

    with scan_lock:
        scan_state["llm"]["running"] = True
        scan_state["llm"]["done"] = False
        scan_state["llm"]["report"] = ""
        scan_state["llm"]["error"] = ""
        scan_state["llm"]["model"] = model
        scan_state["llm"]["provider"] = provider

    results_file = OUTPUT_DIR / session_id / "full_results.json"
    if not results_file.exists():
        err = f"No results found for session: {session_id}"
        with scan_lock:
            scan_state["llm"]["running"] = False
            scan_state["llm"]["error"] = err
        log(err, "ERR")
        return

    with open(results_file) as f:
        results = json.load(f)

    domain = scan_state.get("domain", session_id)
    log(f"Building LLM prompt for session: {session_id}", "INFO")
    prompt = build_llm_prompt(results, domain)

    log(f"Sending to {provider} (model: {model}) at {host}...", "INFO")

    if provider == "ollama":
        report, error = call_ollama(prompt, model, host)
    else:
        report, error = call_lmstudio(prompt, model, host)

    if error:
        with scan_lock:
            scan_state["llm"]["running"] = False
            scan_state["llm"]["error"] = error
        log(f"LLM error: {error}", "ERR")
        return

    # Save the report
    report_path = OUTPUT_DIR / session_id / "llm_report.md"
    with open(report_path, "w") as f:
        f.write(f"# ASM Security Report — LLM Analysis\n")
        f.write(f"**Session:** {session_id}  \n")
        f.write(f"**Provider:** {provider}  \n")
        f.write(f"**Model:** {model}  \n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        f.write("---\n\n")
        f.write(report)

    with scan_lock:
        scan_state["llm"]["running"] = False
        scan_state["llm"]["done"] = True
        scan_state["llm"]["report"] = report

    log(f"LLM report saved to: {report_path}", "OK")
