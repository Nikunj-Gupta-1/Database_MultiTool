import os
import json
import threading
import traceback
from datetime import datetime
from config import config, OUTPUT_DIR
from state import scan_state, scan_lock, set_phase
from utils import log, run_cmd, tool_exists, save_lines, read_lines

TAKEOVER_SIGNATURES = {
    "github.io":           "There isn't a GitHub Pages site here",
    "amazonaws.com":       "NoSuchBucket",
    "s3.amazonaws.com":    "NoSuchBucket",
    "heroku.com":          "No such app",
    "herokussl.com":       "No such app",
    "azurewebsites.net":   "404 Web Site not found",
    "cloudapp.net":        "404",
    "trafficmanager.net":  "404",
    "wordpress.com":       "Do you want to register",
    "tumblr.com":          "Whatever you were looking for doesn't currently exist",
    "shopify.com":         "Sorry, this shop is currently unavailable",
    "zendesk.com":         "Help Center Closed",
    "surge.sh":            "project not found",
    "bitbucket.io":        "Repository not found",
    "ghost.io":            "The thing you were looking for is no longer here",
    "helpjuice.com":       "We could not find what you're looking for",
    "helpscoutdocs.com":   "No settings were found for this company",
    "cargo.site":          "404",
    "fastly.net":          "Fastly error: unknown domain",
    "pantheon.io":         "The gods are wise",
    "readme.io":           "Project doesnt exist",
    "statuspage.io":       "You are being redirected",
    "uservoice.com":       "This UserVoice subdomain is currently available",
    "desk.com":            "Sorry, We couldn't find your page",
    "cargocollective.com": "404 Not Found",
}

def check_takeover(subdomain):
    stdout, _, rc = run_cmd(["dig", "+short", "CNAME", subdomain], timeout=10)
    if rc != 0 or not stdout:
        return None
    cname = stdout.lower()
    for svc, signature in TAKEOVER_SIGNATURES.items():
        if svc in cname:
            fetch_out, _, _ = run_cmd(
                ["curl", "-sk", "--max-time", "8", "-L", f"http://{subdomain}"], timeout=15
            )
            if signature.lower() in fetch_out.lower():
                return {
                    "subdomain": subdomain,
                    "cname": stdout,
                    "service": svc,
                    "signature": signature
                }
    return None

def phase_subdomains(domain, session_dir):
    set_phase("Subdomain Enumeration", 5)
    log(f"Starting subdomain enumeration for: {domain}")
    all_subs = set()

    if tool_exists("subfinder"):
        log("Running subfinder...")
        out, _, _ = run_cmd(["subfinder", "-d", domain, "-all"], timeout=180)
        found = [l for l in out.splitlines() if l.strip()]
        all_subs.update(found)
        log(f"subfinder found {len(found)} subdomains", "OK")
    else:
        log("subfinder not found, skipping", "WARN")

    if tool_exists("subdominator"):
        log("Running subdominator...")
        sub_out_file = session_dir / "subdominator_raw.txt"
        run_cmd(["subdominator", "-d", domain, "-o", str(sub_out_file)], timeout=180)
        found = read_lines(sub_out_file)
        all_subs.update(found)
        log(f"subdominator found {len(found)} subdomains", "OK")
    else:
        log("subdominator not found, skipping", "WARN")

    if not all_subs and tool_exists("dnsx"):
        log("No subdomains from enum tools; trying dnsx wordlist fallback...", "WARN")
        for wl in [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ]:
            if os.path.exists(wl):
                out, _, _ = run_cmd(
                    ["amass", "enum", "-passive", "-d", domain], timeout=300
                )
                found = [l.strip() for l in out.splitlines() if l.strip()]
                all_subs.update(found)
                log(f"dnsx wordlist found {len(found)} subdomains", "OK")
                break

    all_subs.add(domain)
    all_subs_list = sorted(list(all_subs))
    subs_file = session_dir / "subdomains_raw.txt"
    save_lines(subs_file, all_subs_list)
    log(f"Total unique subdomains: {len(all_subs_list)}", "OK")
    with scan_lock:
        scan_state["results"]["subdomains"] = all_subs_list
    return all_subs_list, subs_file

def phase_dns(subs_list, subs_file, session_dir):
    set_phase("DNS Resolution", 20)
    log("Resolving subdomains with dnsx...")
    resolved_file = session_dir / "resolved.txt"

    if tool_exists("dnsx"):
        # We need a resolver file or just run dnsx. Actually the original code had a bug or assumed variables.
        # But we must preserve the original logic (or roughly) as much as possible, or fix the obvious syntax error in original script.
        # Let's fix the original script bug: all_subs_file -> subs_file, resolver -> missing variable (removing -r resolver)
        run_cmd(
            ["puredns", "resolve", str(subs_file), "-w", str(resolved_file), "--quiet"],
            timeout=300
        )
        resolved = read_lines(resolved_file)
    elif tool_exists("puredns"):
        for wl in [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ]:
            if os.path.exists(wl):
                out, _, _ = run_cmd(
                    ["puredns", "bruteforce", str(wl), scan_state["domain"], "--quiet"], timeout=600
                )
                resolved = [l.strip() for l in out.splitlines() if l.strip()]
                save_lines(resolved_file, resolved)
                break
        else:
            resolved = subs_list
            save_lines(resolved_file, resolved)
    else:
        log("dnsx/puredns not found; using raw subdomain list", "WARN")
        resolved = subs_list
        save_lines(resolved_file, resolved)

    clean = []
    for line in resolved:
        host = line.split()[0].strip()
        if host:
            clean.append(host)

    log(f"Resolved {len(clean)} live subdomains", "OK")
    return clean, resolved_file

def phase_ports(resolved_file, session_dir, port_range=None):
    if port_range is None:
        port_range = config.get("default_ports", "80,443,8080,8443,22,21,25,3306,3389,6379,9200")
    set_phase("Port Scanning", 35)
    log(f"Running Naabu port scan on: {port_range}")
    ports_file = session_dir / "open_ports.txt"
    ports_json = session_dir / "open_ports.json"

    if tool_exists("naabu"):
        run_cmd(
            ["naabu", "-list", str(resolved_file), "-p", str(port_range), "-json", "-o", str(ports_json)],
            timeout=600
        )
        out_plain, _, _ = run_cmd(
            ["naabu", "-list", str(resolved_file), "-p", str(port_range)],
            timeout=600
        )
        save_lines(ports_file, out_plain.splitlines())
        port_lines = [l.strip() for l in out_plain.splitlines() if l.strip()]
    else:
        log("naabu not found; using nmap for quick port scan", "WARN")
        hosts = read_lines(resolved_file)
        hosts_str = " ".join(hosts[:20])
        if tool_exists("nmap") and hosts_str:
            run_cmd(
                ["nmap", "-p", str(port_range), "--open", "-oN", str(ports_file)] + hosts[:20],
                timeout=600
            )
        port_lines = read_lines(ports_file)

    port_entries = []
    if tool_exists("naabu"):
        for line in port_lines:
            if ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    host, port = parts
                    port_entries.append({"host": host.strip(), "port": port.strip()})
    else:
        current_host = None
        for line in port_lines:
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                parts = line.split("for ")
                if len(parts) > 1:
                    host_part = parts[1]
                    if "(" in host_part:
                        current_host = host_part.split("(")[0].strip()
                    else:
                        current_host = host_part.strip()
            elif "/tcp" in line and "open" in line:
                if current_host:
                    port_part = line.split("/")[0].strip()
                    port_entries.append({"host": current_host, "port": port_part})
        
        with open(ports_json, "w") as f:
            json.dump(port_entries, f, indent=2)

    log(f"Found {len(port_entries)} open host:port combinations", "OK")
    with scan_lock:
        scan_state["results"]["open_ports"] = port_entries
    return port_entries, ports_file

def phase_tech_detection(resolved_file, session_dir):
    set_phase("Tech & Service Detection", 50)
    log("Running httpx for web tech detection...")
    httpx_json = session_dir / "httpx_results.json"
    live_hosts = []
    tech_map = {}

    if tool_exists("httpx"):
        run_cmd(
            ["httpx", "-l", str(resolved_file), "-status-code", "-title", "-tech-detect", "-json", "-o", str(httpx_json)],
            timeout=300
        )
        if httpx_json.exists():
            with open(httpx_json) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url   = data.get("url", "")
                        status = data.get("status_code", 0)
                        title  = data.get("title", "")
                        tech   = data.get("tech", [])
                        if url:
                            live_hosts.append({
                                "url": url, "status": status,
                                "title": title, "tech": tech
                            })
                            if tech:
                                tech_map[url] = tech
                    except json.JSONDecodeError:
                        pass
        log(f"httpx found {len(live_hosts)} live web services", "OK")
    else:
        log("httpx not found, skipping web tech detection", "WARN")

    log("Running Nmap service detection (-sV)...")
    nmap_output = ""
    if tool_exists("nmap"):
        hosts = read_lines(resolved_file)
        if hosts:
            targets = " ".join(hosts[:15])
            nmap_out_file = session_dir / "nmap_results.txt"
            run_cmd(
                ["nmap", "-sV", "-O", "--open", "-p", "80,443,22,8080,8443,21,25,3306,3389", "--script=http-title,banner", "-oN", str(nmap_out_file)] + hosts[:15],
                timeout=600
            )
            if nmap_out_file.exists():
                with open(nmap_out_file) as nf:
                    nmap_output = nf.read()
            log("Nmap scan complete", "OK")
    else:
        log("nmap not found, skipping deep service detection", "WARN")

    with scan_lock:
        scan_state["results"]["live_hosts"] = live_hosts
        scan_state["results"]["technologies"] = tech_map
        scan_state["results"]["nmap_output"] = nmap_output

    return live_hosts, tech_map

def phase_urls(domain, live_hosts, session_dir):
    set_phase("URL & Endpoint Discovery", 65)
    log("Starting URL discovery (katana + gau + waybackurls)...")
    all_urls = set()

    if tool_exists("katana") and live_hosts:
        web_roots = [h["url"] for h in live_hosts[:20]]
        roots_file = session_dir / "web_roots.txt"
        save_lines(roots_file, web_roots)
        katana_file = session_dir / "katana_urls.txt"
        log(f"Katana crawling {len(web_roots)} web roots...")
        run_cmd(
            ["katana", "-list", str(roots_file), "-d", "2", "-o", str(katana_file)],
            timeout=300
        )
        found = read_lines(katana_file)
        all_urls.update(found)
        log(f"Katana found {len(found)} URLs", "OK")
    else:
        log("katana not found or no live hosts, skipping", "WARN")

    if tool_exists("gau"):
        gau_file = session_dir / "gau_urls.txt"
        log(f"Running gau on {domain}...")
        run_cmd(f"echo '{domain}' | gau --subs -o {gau_file}", timeout=180, shell=True)
        found = read_lines(gau_file)
        all_urls.update(found)
        log(f"gau found {len(found)} archived URLs", "OK")
    else:
        log("gau not found, skipping", "WARN")

    if tool_exists("waybackurls"):
        wayback_file = session_dir / "wayback_urls.txt"
        log(f"Running waybackurls on {domain}...")
        out, _, _ = run_cmd(f"echo '{domain}' | waybackurls", timeout=180, shell=True)
        found = [l.strip() for l in out.splitlines() if l.strip()]
        save_lines(wayback_file, found)
        all_urls.update(found)
        log(f"waybackurls found {len(found)} archived URLs", "OK")
    else:
        log("waybackurls not found, skipping", "WARN")

    url_list = sorted(list(all_urls))
    save_lines(session_dir / "all_urls.txt", url_list)

    juicy_patterns = [
        "redirect", "url=", "next=", "target=", "rurl=", "dest=", "goto=",
        "sql", "query=", "search=", "id=", "page=", "file=", "path=",
        "token=", "api_key=", "key=", "secret=", "admin", "debug=",
        "upload", "include=", "require=", "cmd=", "exec=", "shell=",
        "callback=", "return=", "open=", "data=", "ref=",
    ]
    juicy = [u for u in url_list if any(p in u.lower() for p in juicy_patterns)]
    save_lines(session_dir / "juicy_urls.txt", juicy)

    log(f"Total unique URLs: {len(url_list)} | Juicy: {len(juicy)}", "OK")
    with scan_lock:
        scan_state["results"]["urls"] = url_list[:2000]
    return url_list

def phase_takeover(subs_list, session_dir):
    set_phase("Subdomain Takeover Check", 80)
    log(f"Checking {min(len(subs_list),100)} subdomains for takeover...")
    results = []
    threads = []
    lock = threading.Lock()

    def check_one(sub):
        res = check_takeover(sub)
        if res:
            with lock:
                results.append(res)
                log(f"[TAKEOVER CANDIDATE] {sub} → {res['service']}", "WARN")

    for sub in subs_list[:100]:
        t = threading.Thread(target=check_one, args=(sub,))
        threads.append(t)
        t.start()
        if len(threads) >= 20:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()

    with open(session_dir / "takeover_candidates.json", "w") as f:
        json.dump(results, f, indent=2)

    log(f"Takeover check done. Candidates: {len(results)}", "OK" if not results else "WARN")
    with scan_lock:
        scan_state["results"]["takeover_candidates"] = results
    return results

def phase_vuln_scan(resolved_file, session_dir):
    set_phase("Vulnerability Scanning", 90)
    log("Running nuclei for vulnerability scanning...")
    vuln_json = session_dir / "nuclei_results.json"
    vulns = []

    if tool_exists("nuclei"):
        # Build comprehensive targets list
        targets = set()
        
        # 1. Add resolved subdomains
        for sub in read_lines(resolved_file):
            targets.add(sub)
            
        with scan_lock:
            # 2. Add live web service URLs
            for host_info in scan_state["results"].get("live_hosts", []):
                url = host_info.get("url")
                if url:
                    targets.add(url)
            
            # 3. Add open ports (host:port)
            for port_info in scan_state["results"].get("open_ports", []):
                host = port_info.get("host")
                port = port_info.get("port")
                if host and port:
                    if port.isdigit():
                        targets.add(f"{host}:{port}")
                        
        targets_file = session_dir / "nuclei_targets.txt"
        save_lines(targets_file, sorted(list(targets)))
        log(f"Nuclei will scan {len(targets)} targets (including subdomains, web services, and open ports).", "INFO")

        run_cmd(
            ["nuclei", "-l", str(targets_file), "-severity", "info,low,medium,high,critical", "-jsonl", "-o", str(vuln_json)],
            timeout=3600
        )
        if vuln_json.exists():
            with open(vuln_json) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        vulns.append({
                            "host":        data.get("host", ""),
                            "template":    data.get("template-id", ""),
                            "name":        data.get("info", {}).get("name", ""),
                            "severity":    data.get("info", {}).get("severity", "unknown"),
                            "matched":     data.get("matched-at", ""),
                            "description": data.get("info", {}).get("description", "")
                        })
                    except json.JSONDecodeError:
                        pass
        log(f"nuclei found {len(vulns)} vulnerabilities", "OK" if not vulns else "WARN")
    else:
        log("nuclei not found, skipping automated vuln scan", "WARN")

    with scan_lock:
        scan_state["results"]["vulnerabilities"] = vulns
    return vulns

def run_scan(domain, options=None):
    if options is None:
        options = {}

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + domain.replace(".", "_")
    session_dir = OUTPUT_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    with scan_lock:
        scan_state["running"] = True
        scan_state["domain"] = domain
        scan_state["session_id"] = session_id
        scan_state["log"] = []
        scan_state["llm"] = {
            "running": False, "done": False,
            "report": "", "error": "", "model": "", "provider": ""
        }
        scan_state["results"] = {
            "subdomains": [], "live_hosts": [], "open_ports": [],
            "urls": [], "vulnerabilities": [], "takeover_candidates": [],
            "technologies": {}, "nmap_output": ""
        }

    log(f"ASM scan started for: {domain}", "OK")
    log(f"Session ID: {session_id}")
    log(f"Output dir: {session_dir}")

    try:
        subs_list, subs_file = phase_subdomains(domain, session_dir)
        resolved, resolved_file = phase_dns(subs_list, subs_file, session_dir)

        if not options.get("skip_ports"):
            phase_ports(
                resolved_file, session_dir,
                options.get("ports") or config.get("default_ports", "80,443,8080,8443,22")
            )
        else:
            log("Port scan skipped (--skip-ports)", "WARN")

        live_hosts, _ = phase_tech_detection(resolved_file, session_dir)
        phase_urls(domain, live_hosts, session_dir)

        if not options.get("skip_takeover"):
            phase_takeover(subs_list, session_dir)
        else:
            log("Takeover check skipped", "WARN")

        if not options.get("skip_nuclei"):
            phase_vuln_scan(resolved_file, session_dir)
        else:
            log("Nuclei scan skipped (--skip-nuclei)", "WARN")

        set_phase("Complete", 100)
        log("All phases complete!", "OK")
        log(f"Results in: {session_dir}", "OK")
        log("You can now run an LLM summary from the web UI or with --llm", "INFO")

        # Save full results JSON
        with open(session_dir / "full_results.json", "w") as f:
            json.dump(scan_state["results"], f, indent=2)

    except Exception as e:
        log(f"Scan error: {e}", "ERR")
        log(traceback.format_exc(), "ERR")
    finally:
        with scan_lock:
            scan_state["running"] = False
