#!/usr/bin/env python3
"""
ASM - Attack Surface Manager
A multi-tool OSINT + vulnerability discovery framework
Integrates: subdominator, subfinder, puredns, dnsx, naabu, nmap,
            katana, gau, waybackurls, httpx, nuclei
LLM Summary: Ollama or LM Studio (OpenAI-compatible API)
"""

import sys
import argparse
from http.server import HTTPServer

from config import VERSION, config, OUTPUT_DIR
from state import scan_state
from utils import check_tools
from scanner import run_scan
from llm import check_llm_available, run_llm_summary
from server import ASMHandler

def main():
    parser = argparse.ArgumentParser(
        description="ASM — Attack Surface Manager v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 asm.py --web                            Launch web UI (http://localhost:7373)
  python3 asm.py -d example.com                   Full scan
  python3 asm.py -d example.com --skip-nuclei     Skip vuln scan
  python3 asm.py -d example.com --ports 1-65535   Full port range
  python3 asm.py --llm SESSION_ID                 Summarize with Ollama (llama3)
  python3 asm.py --llm SESSION_ID --provider lmstudio --model mistral-7b
  python3 asm.py --check-tools                    Show installed tools
        """
    )
    parser.add_argument("-d", "--domain",       help="Target domain to scan")
    parser.add_argument("--web",   action="store_true", help="Launch web dashboard")
    parser.add_argument("--port",  type=int, default=7373, help="Web UI port (default: 7373)")
    parser.add_argument("--ports", default="80,443,8080,8443,22,21,25,3306,3389,6379,9200",
                        help="Ports to scan with naabu")
    parser.add_argument("--skip-ports",    action="store_true")
    parser.add_argument("--skip-nuclei",   action="store_true")
    parser.add_argument("--skip-takeover", action="store_true")
    parser.add_argument("--check-tools",   action="store_true", help="Show tool availability")

    # LLM flags
    parser.add_argument("--llm",      metavar="SESSION_ID",
                        help="Run LLM summary on a completed scan session")
    parser.add_argument("--provider", default="",
                        choices=["", "ollama", "lmstudio"],
                        help="LLM backend: ollama or lmstudio (default: from config or lmstudio)")
    parser.add_argument("--model",    default="",
                        help="Model name. Ollama default: llama3. LM Studio default: loaded model")
    parser.add_argument("--llm-host", default="",
                        help="Override LLM API host (e.g. http://localhost:11434)")
    parser.add_argument("--auto-llm", action="store_true",
                        help="Automatically prompt for LLM summary after scan completes")

    args = parser.parse_args()

    print(f"""\033[36m
 █████╗ ███████╗███╗   ███╗
██╔══██╗██╔════╝████╗ ████║
███████║███████╗██╔████╔██║
██╔══██║╚════██║██║╚██╔╝██║
██║  ██║███████║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝\033[0m
  Attack Surface Manager v{VERSION}
  Integrated OSINT + Vulnerability Discovery + LLM Analysis
""")

    # ── check-tools
    if args.check_tools:
        tools = check_tools()
        print("\033[1mTool Status:\033[0m")
        for name, ok in tools.items():
            s = "\033[32m✓ installed\033[0m" if ok else "\033[31m✗ missing\033[0m"
            print(f"  {name:<20} {s}")
        print()
        return

    # ── llm-only mode (summarize an existing session)
    if args.llm:
        session_id = args.llm
        provider = args.provider or config.get("provider", "lmstudio")
        if provider == "ollama":
            model = args.model or config.get("ollama_model", "llama3")
            host = args.llm_host or config.get("ollama_host", "http://localhost:11434")
        else:
            model = args.model or config.get("lmstudio_model", "local-model")
            host = args.llm_host or config.get("lmstudio_host", "http://localhost:1234")

        print(f"\033[36m[*]\033[0m Checking {provider} availability...")
        if not check_llm_available(provider, model, host):
            print(f"\033[31m[-]\033[0m {provider} is not reachable.")
            if provider == "ollama":
                print("     Make sure Ollama is running: \033[1mollama serve\033[0m")
            else:
                print("     Make sure LM Studio is running with Local Server enabled (port 1234).")
            sys.exit(1)

        print(f"\033[32m[+]\033[0m {provider} is reachable. Using model: \033[1m{model}\033[0m\n")
        run_llm_summary(session_id, provider=provider, model=model, host=host)

        # Print report to terminal
        state = scan_state["llm"]
        if state["error"]:
            print(f"\033[31m[-]\033[0m Error: {state['error']}")
        else:
            print("\n" + "─" * 60)
            print(state["report"])
            print("─" * 60)
            report_file = OUTPUT_DIR / session_id / "llm_report.md"
            print(f"\n\033[32m[+]\033[0m Saved to: {report_file}")
        return

    # ── web mode
    if args.web or not args.domain:
        server = HTTPServer(("127.0.0.1", args.port), ASMHandler)
        print(f"\033[32m[+]\033[0m Web UI → \033[1mhttp://localhost:{args.port}\033[0m")
        print(f"\033[36m[*]\033[0m Press Ctrl+C to stop\n")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n\033[33m[!]\033[0m Shutting down...")
            server.shutdown()
        return

    # ── CLI scan mode
    if args.domain:
        options = {
            "ports":         args.ports,
            "skip_ports":    args.skip_ports,
            "skip_nuclei":   args.skip_nuclei,
            "skip_takeover": args.skip_takeover,
        }
        run_scan(args.domain, options)

        # After scan: optionally prompt for LLM summary
        session_id = scan_state.get("session_id", "")
        if session_id:
            if args.auto_llm:
                do_llm = True
            else:
                try:
                    ans = input(
                        "\n\033[36m[?]\033[0m Run LLM summary on these results? [y/N] "
                    ).strip().lower()
                    do_llm = ans in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    do_llm = False

            if do_llm:
                provider = args.provider or config.get("provider", "lmstudio")
                if provider == "ollama":
                    model = args.model or config.get("ollama_model", "llama3")
                    host = args.llm_host or config.get("ollama_host", "http://localhost:11434")
                else:
                    model = args.model or config.get("lmstudio_model", "local-model")
                    host = args.llm_host or config.get("lmstudio_host", "http://localhost:1234")

                # Let the user choose the model interactively if not given
                if not args.model:
                    try:
                        m = input(
                            f"\033[36m[?]\033[0m Model name? (press Enter for default: \033[1m{model}\033[0m): "
                        ).strip()
                        if m:
                            model = m
                    except (EOFError, KeyboardInterrupt):
                        pass

                print(f"\033[36m[*]\033[0m Checking {provider} availability...")
                if not check_llm_available(provider, model, host):
                    print(f"\033[31m[-]\033[0m {provider} is not reachable. Skipping LLM summary.")
                    if provider == "ollama":
                        print("     Start with: \033[1mollama serve\033[0m")
                    else:
                        print("     Start LM Studio and enable the Local Server.")
                else:
                    run_llm_summary(session_id, provider=provider, model=model, host=host)
                    llm_state = scan_state["llm"]
                    if llm_state["error"]:
                        print(f"\033[31m[-]\033[0m LLM error: {llm_state['error']}")
                    else:
                        print("\n" + "─" * 60)
                        print(llm_state["report"])
                        print("─" * 60)
                        print(f"\n\033[32m[+]\033[0m Report saved: {OUTPUT_DIR / session_id / 'llm_report.md'}")
            else:
                print(
                    f"\033[36m[*]\033[0m LLM skipped. Run later with:\n"
                    f"    python3 asm.py --llm {session_id} --provider ollama --model llama3"
                )

if __name__ == "__main__":
    main()
