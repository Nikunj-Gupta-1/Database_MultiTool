#!/usr/bin/env python3
"""
asm_bridge.py
CYBER_MultiTool Friday ASM Scanner to Central Database Integration Bridge.
Parses nuclei_results.json and full_results.json and populates Plane B tables.
"""

import os
import sys
import json
import re
import argparse
import logging
from datetime import datetime
import psycopg

import sync_cves
import label_engine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("asm_bridge")


def parse_session_metadata(session_dir):
    """
    Parses scan session details from the directory path.
    Example: output/20260623_120010_pentest-ground_com
    """
    dirname = os.path.basename(os.path.normpath(session_dir))
    
    # Try parsing date and target from name
    # Format: YYYYMMDD_HHMMSS_target
    match = re.match(r'^(\d{8})_(\d{6})_(.+)$', dirname)
    if match:
        date_str, time_str, target = match.groups()
        try:
            started_dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
            return dirname, target, started_dt
        except ValueError:
            pass
            
    # Fallbacks if name does not match pattern
    return dirname, "unknown", datetime.now()


def extract_cves_from_finding(finding):
    """Extracts a list of uppercase CVE IDs from a nuclei finding."""
    cves = set()
    info = finding.get("info", {})
    
    # 1. Check classification cve-id
    classification = info.get("classification", {})
    if classification:
        cve_id = classification.get("cve-id")
        if isinstance(cve_id, str):
            cves.add(cve_id.upper().strip())
        elif isinstance(cve_id, list):
            for cid in cve_id:
                if isinstance(cid, str):
                    cves.add(cid.upper().strip())

    # 2. Check tags
    tags = info.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and re.match(r'^cve-\d{4}-\d+$', tag, re.IGNORECASE):
                cves.add(tag.upper().strip())

    # 3. Check template-id
    template_id = finding.get("template-id", "")
    if template_id and re.match(r'^cve-\d{4}-\d+$', template_id, re.IGNORECASE):
        cves.add(template_id.upper().strip())

    # Filter out empty or malformed strings
    return [c for c in cves if re.match(r'^CVE-\d{4}-\d+$', c)]


def upsert_asset(conn, value, asset_type, parent_id=None, metadata=None):
    """Inserts or updates an asset and returns its database ID."""
    if metadata is None:
        metadata = {}

    query = """
        INSERT INTO assets (asset_type, value, parent_id, metadata, source_tool, last_seen_at)
        VALUES (%s, %s, %s, %s, 'asm', now())
        ON CONFLICT (asset_type, value) DO UPDATE SET
            last_seen_at = now(),
            metadata = COALESCE(assets.metadata, '{}'::jsonb) || EXCLUDED.metadata
        RETURNING id
    """
    with conn.cursor() as cur:
        cur.execute(query, (asset_type, value, parent_id, json.dumps(metadata)))
        return cur.fetchone()["id"]


def map_finding_type(finding):
    """Determines finding type from nuclei tags and template ID."""
    info = finding.get("info", {})
    template_id = finding.get("template-id", "")
    tags = info.get("tags", [])

    # Flatten tags
    tags_lower = [t.lower() for t in tags if isinstance(t, str)]

    # Check CVEs
    cves = extract_cves_from_finding(finding)
    if cves:
        return "cve"

    # Exposed secret heuristics
    if any(t in tags_lower for t in ["token", "secret", "private-key", "key", "config", "exposure"]):
        if "exposure" in tags_lower and any(w in template_id.lower() for w in ["git", "env", "backup", "sql"]):
            return "exposed_secret"
        elif "token" in tags_lower or "key" in tags_lower:
            return "exposed_secret"

    # Port checking
    if template_id == "open-port" or "port" in tags_lower:
        return "open_port"

    # Hardening/outdated components
    if "outdated" in tags_lower or "outdated-version" in tags_lower:
        return "outdated_component"

    # Fallback to misconfiguration
    return "misconfiguration"


def ensure_cve_stub_exists(conn, cve_id):
    """Ensures a CVE record exists in the cves table, creating a stub if missing."""
    with conn.cursor() as cur:
        cur.execute("SELECT cve_id, internal_label FROM cves WHERE cve_id = %s", (cve_id,))
        row = cur.fetchone()
        
        if row:
            return row["internal_label"]

        # Insert stub
        logger.info(f"[*] CVE {cve_id} not found in database. Inserting stub...")
        cur.execute("""
            INSERT INTO cves (cve_id, source_of_truth, title, description, vuln_status, last_synced_at)
            VALUES (%s, 'cvelist', %s, 'Stub record inserted by Friday ASM scanner bridge.', 'Awaiting Analysis', now())
            ON CONFLICT (cve_id) DO NOTHING
        """, (cve_id, f"Friday ASM Discovery: {cve_id}"))

        # Generate label for stub
        label = label_engine.generate_label(cve_id, [], [])
        cur.execute("""
            UPDATE cves 
            SET internal_label = %s,
                label_generated_at = now()
            WHERE cve_id = %s
        """, (label, cve_id))
        
        return label


def main():
    parser = argparse.ArgumentParser(description="CYBER_MultiTool Friday ASM Integration Bridge")
    parser.add_argument("--session-dir", required=True, help="Path to Friday ASM session output directory")
    parser.add_argument("--target", help="Override scan target domain/IP")
    args = parser.parse_args()

    session_dir = args.session_dir
    if not os.path.isdir(session_dir):
        logger.error(f"[!] Session directory '{session_dir}' does not exist.")
        sys.exit(1)

    logger.info(f"[*] Starting ASM bridge for: {session_dir}")

    # Parse metadata from session path
    session_id, detected_target, started_at = parse_session_metadata(session_dir)
    target = args.target if args.target else detected_target

    try:
        conn = sync_cves.get_db_connection()
    except Exception as e:
        logger.error(f"[!] Database connection failed: {e}")
        sys.exit(1)

    # Counters
    new_assets = 0
    cve_findings = 0
    misconfig_findings = 0

    try:
        # 1. Create or retrieve Scan Session
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO scan_sessions (session_id, tool, target, started_at, finished_at, status)
                VALUES (%s, 'asm', %s, %s, now(), 'completed')
                ON CONFLICT (session_id) DO UPDATE SET
                    target = EXCLUDED.target,
                    finished_at = EXCLUDED.finished_at
                RETURNING id
            """, (session_id, target, started_at))
            conn.commit()

        # 2. Parse full_results.json (Seeding subdomains, live hosts, open ports)
        full_results_path = os.path.join(session_dir, "full_results.json")
        asset_map = {} # Maps value -> DB ID

        if os.path.exists(full_results_path):
            logger.info("[*] Seeding assets from full_results.json...")
            try:
                with open(full_results_path, "r") as f:
                    full_res = json.load(f)

                # Seed domain/subdomains
                for sub in full_res.get("subdomains", []):
                    # Check if root domain is parent
                    parent_id = None
                    root_domain = target
                    if sub != root_domain and sub.endswith(root_domain):
                        # Ensure root domain exists as asset
                        if root_domain not in asset_map:
                            asset_map[root_domain] = upsert_asset(conn, root_domain, "domain")
                        parent_id = asset_map[root_domain]

                    asset_map[sub] = upsert_asset(conn, sub, "subdomain", parent_id)
                    new_assets += 1

                # Seed live web hosts (URLs) and tech stack
                for host_info in full_res.get("live_hosts", []):
                    url = host_info.get("url")
                    if not url:
                        continue
                    
                    # Parse host name from URL to link parent
                    from urllib.parse import urlparse
                    hostname = urlparse(url).hostname
                    parent_id = None
                    if hostname:
                        if hostname not in asset_map:
                            asset_map[hostname] = upsert_asset(conn, hostname, "subdomain")
                        parent_id = asset_map[hostname]

                    metadata = {
                        "status_code": host_info.get("status"),
                        "title": host_info.get("title"),
                        "tech_stack": host_info.get("tech", [])
                    }
                    asset_map[url] = upsert_asset(conn, url, "url", parent_id, metadata)
                    new_assets += 1

                # Seed open ports
                for port_info in full_res.get("open_ports", []):
                    host = port_info.get("host")
                    port = port_info.get("port")
                    if not host or not port:
                        continue

                    # Parent is host/IP
                    if host not in asset_map:
                        asset_type = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else "subdomain"
                        asset_map[host] = upsert_asset(conn, host, asset_type)

                    port_val = f"{host}:{port}"
                    asset_map[port_val] = upsert_asset(conn, port_val, "port", asset_map[host])
                    new_assets += 1

                conn.commit()
            except Exception as e:
                logger.error(f"[-] Error processing full_results.json: {e}")
                conn.rollback()

        # 3. Parse nuclei_results.json
        nuclei_results_path = os.path.join(session_dir, "nuclei_results.json")
        if os.path.exists(nuclei_results_path):
            logger.info("[*] Importing findings from nuclei_results.json...")
            try:
                with open(nuclei_results_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        # Extract asset target
                        matched_at = finding.get("matched-at")
                        host = finding.get("host")
                        url = finding.get("url")
                        ip = finding.get("ip")

                        # Determine the primary asset value for this finding
                        asset_val = matched_at if matched_at else (url if url else (host if host else ip))
                        if not asset_val:
                            continue

                        # Insert asset if it wasn't seeded in full_results
                        if asset_val not in asset_map:
                            parent_id = None
                            asset_type = "url" if asset_val.startswith(("http://", "https://")) else "subdomain"
                            if ip and asset_type == "url":
                                # Link IP as parent
                                if ip not in asset_map:
                                    asset_map[ip] = upsert_asset(conn, ip, "ip")
                                parent_id = asset_map[ip]
                            asset_map[asset_val] = upsert_asset(conn, asset_val, asset_type, parent_id)
                            new_assets += 1

                        asset_id = asset_map[asset_val]

                        # Check for CVEs
                        cves = extract_cves_from_finding(finding)
                        finding_type = map_finding_type(finding)
                        severity = finding.get("info", {}).get("severity", "info").lower()
                        template_id = finding.get("template-id")

                        with conn.cursor() as cur:
                            if cves:
                                for cve in cves:
                                    # Ensure CVE exists in Plane A and get label
                                    label = ensure_cve_stub_exists(conn, cve)
                                    
                                    cur.execute("""
                                        INSERT INTO findings (
                                            session_id, asset_id, cve_id, internal_label, finding_type, severity,
                                            tool, template_id, status, raw_output, last_confirmed_at
                                        ) VALUES (%s, %s, %s, %s, 'cve', %s, 'nuclei', %s, 'open', %s, now())
                                        ON CONFLICT (session_id, asset_id, template_id, COALESCE(cve_id, ''))
                                        DO UPDATE SET 
                                            last_confirmed_at = now(),
                                            raw_output = EXCLUDED.raw_output
                                    """, (session_id, asset_id, cve, label, severity, template_id, json.dumps(finding)))
                                    cve_findings += 1
                            else:
                                # Non-CVE finding (misconfig/exposure)
                                cur.execute("""
                                    INSERT INTO findings (
                                        session_id, asset_id, cve_id, internal_label, finding_type, severity,
                                        tool, template_id, status, raw_output, last_confirmed_at
                                    ) VALUES (%s, %s, NULL, NULL, %s, %s, 'nuclei', %s, 'open', %s, now())
                                    ON CONFLICT (session_id, asset_id, template_id, COALESCE(cve_id, ''))
                                    DO UPDATE SET 
                                        last_confirmed_at = now(),
                                        raw_output = EXCLUDED.raw_output
                                """, (session_id, asset_id, finding_type, severity, template_id, json.dumps(finding)))
                                misconfig_findings += 1

                conn.commit()
            except Exception as e:
                logger.error(f"[-] Error parsing nuclei findings: {e}")
                conn.rollback()
        else:
            logger.warning(f"[!] nuclei_results.json not found in {session_dir}")

        logger.info("==============================================")
        logger.info("Friday ASM Database Integration Complete")
        logger.info("==============================================")
        logger.info(f"[+] Scan Session ID:           {session_id}")
        logger.info(f"[+] Total New Assets Seeded:   {new_assets}")
        logger.info(f"[+] CVE Findings Integrated:   {cve_findings}")
        logger.info(f"[+] Misconfigs Integrated:     {misconfig_findings}")

    except Exception as e:
        logger.exception(f"[!] Unexpected error integrating ASM session findings: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
