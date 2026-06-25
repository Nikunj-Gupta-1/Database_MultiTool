#!/usr/bin/env python3
"""
sync_cves.py
Central ingestion pipeline for CYBER_MultiTool CVE database.
Ingests from MITRE CVE List, NVD API, CISA KEV, and OSV API.
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
from datetime import datetime, timezone
from dateutil import parser as date_parser
import psycopg
from psycopg.rows import dict_row

# Import labeling engine
import label_engine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sync.log", mode="a")
    ]
)
logger = logging.getLogger("sync_pipeline")


def load_env():
    """Manually parse .env file if it exists, setting environment variables."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("=", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip()
                    # Strip quotes if present
                    if val.startswith(('"', "'")) and val.endswith(('"', "'")):
                        val = val[1:-1]
                    os.environ[key] = val


# Load environment variables
load_env()


def get_db_connection():
    """Establishes connection to the PostgreSQL database."""
    host = os.environ.get("DB_HOST", "127.0.0.1")
    port = os.environ.get("DB_PORT", "5432")
    dbname = os.environ.get("DB_NAME", "cyber_multitool")
    user = os.environ.get("DB_USER", "cyber_admin")
    password = os.environ.get("DB_PASSWORD", "cyber_secure_pass")

    conn_str = f"host={host} port={port} dbname={dbname} user={user} password={password}"
    return psycopg.connect(conn_str, row_factory=dict_row)


def execute_request_with_retry(url, headers=None, params=None, timeout=30):
    """Executes an HTTP request with exponential backoff on rate limits (429)."""
    backoff = 2
    for attempt in range(5):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 200:
                return response
            elif response.status_code == 429:
                logger.warning(f"[!] Rate limit (429) hit on {url}. Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2
            else:
                logger.error(f"[!] HTTP error {response.status_code} requesting {url}.")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"[!] Network failure on {url}: {e}. Retrying in {backoff} seconds...")
            time.sleep(backoff)
            backoff *= 2
    raise RuntimeError(f"Failed to fetch {url} after multiple retries.")


# ==========================================
# SOURCE 1: MITRE CVE LIST
# ==========================================

def sync_cvelist(conn, repo_path):
    """Parses local Mitre cvelistV5 clone recursively and ingests JSON files."""
    if not os.path.exists(repo_path):
        logger.info(f"[*] CVE List path '{repo_path}' not found. Skipping Mitre ingestion.")
        return

    logger.info(f"[*] Starting Mitre CVE List ingestion from {repo_path}...")
    cve_count = 0

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".json") and file.startswith("CVE-"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        record = json.load(f)
                    
                    # Ingest single record
                    upsert_cvelist_record(conn, record)
                    cve_count += 1

                    if cve_count % 1000 == 0:
                        conn.commit()
                        logger.info(f"[+] Ingested {cve_count} Mitre CVE records...")
                except Exception as e:
                    logger.error(f"[-] Error parsing {file_path}: {e}")

    conn.commit()
    logger.info(f"[+] Completed Mitre CVE List ingestion. Total: {cve_count} CVEs.")


def upsert_cvelist_record(conn, record):
    """Parses and upserts a single cvelistV5 record into Plane A tables."""
    cve_meta = record.get("cveMetadata", {})
    cve_id = cve_meta.get("cveId")
    if not cve_id:
        return

    state = cve_meta.get("state")
    published_at = cve_meta.get("datePublished")
    updated_at = cve_meta.get("dateUpdated")
    assigner_org = cve_meta.get("assignerShortName")

    # CNA Container
    containers = record.get("containers", {})
    cna = containers.get("cna", {})

    title = cna.get("title")
    
    # Description (English)
    description = None
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    # Parse timestamps
    pub_dt = date_parser.parse(published_at) if published_at else None
    upd_dt = date_parser.parse(updated_at) if updated_at else None

    with conn.cursor() as cur:
        # 1. Upsert into cves
        cur.execute("""
            INSERT INTO cves (
                cve_id, source_of_truth, title, description, published_at, updated_at, 
                vuln_status, assigner_org, raw_cve_json, last_synced_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (cve_id) DO UPDATE SET
                source_of_truth = EXCLUDED.source_of_truth,
                title = COALESCE(EXCLUDED.title, cves.title),
                description = COALESCE(EXCLUDED.description, cves.description),
                published_at = COALESCE(EXCLUDED.published_at, cves.published_at),
                updated_at = COALESCE(EXCLUDED.updated_at, cves.updated_at),
                vuln_status = COALESCE(EXCLUDED.vuln_status, cves.vuln_status),
                assigner_org = COALESCE(EXCLUDED.assigner_org, cves.assigner_org),
                raw_cve_json = EXCLUDED.raw_cve_json,
                last_synced_at = now()
        """, (cve_id, "cvelist", title, description, pub_dt, upd_dt, state, assigner_org, json.dumps(record)))

        # 2. Ingest Source Documents
        cur.execute("""
            INSERT INTO cve_source_documents (cve_id, source, source_record_id, raw_json)
            VALUES (%s, 'cvelist', %s, %s)
        """, (cve_id, cve_id, json.dumps(record)))

        # 3. References
        references = cna.get("references", [])
        for ref in references:
            ref_url = ref.get("url")
            if ref_url:
                ref_tags = ref.get("tags")
                cur.execute("""
                    INSERT INTO cve_references (cve_id, source, url, tags)
                    VALUES (%s, 'cvelist', %s, %s)
                    ON CONFLICT (cve_id, url) DO UPDATE SET
                        tags = EXCLUDED.tags
                """, (cve_id, ref_url, json.dumps(ref_tags) if ref_tags else None))

        # 4. Metrics & CVSS
        metrics_list = cna.get("metrics", [])
        for metric in metrics_list:
            cwe_id = None
            scenarios = metric.get("scenarios", [])
            for sc in scenarios:
                cwe_id = sc.get("cweId") # Or fallback parsing

            # Check CVSS v3.1
            if "cvssV3_1" in metric:
                cvss = metric["cvssV3_1"]
                cur.execute("""
                    INSERT INTO cve_metrics (
                        cve_id, source, cvss_version, vector_string, base_score, 
                        base_severity, exploitability_score, impact_score, cwe_id
                    ) VALUES (%s, 'cvelist', '3.1', %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                        vector_string = EXCLUDED.vector_string,
                        base_score = EXCLUDED.base_score,
                        base_severity = EXCLUDED.base_severity,
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
                """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"), 
                      cvss.get("exploitabilityScore"), cvss.get("impactScore"), cwe_id))
            
            # Check CVSS v3.0
            elif "cvssV3_0" in metric:
                cvss = metric["cvssV3_0"]
                cur.execute("""
                    INSERT INTO cve_metrics (
                        cve_id, source, cvss_version, vector_string, base_score, 
                        base_severity, exploitability_score, impact_score, cwe_id
                    ) VALUES (%s, 'cvelist', '3.0', %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                        vector_string = EXCLUDED.vector_string,
                        base_score = EXCLUDED.base_score,
                        base_severity = EXCLUDED.base_severity,
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
                """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                      cvss.get("exploitabilityScore"), cvss.get("impactScore"), cwe_id))

            # Check CVSS v2.0
            elif "cvssV2_0" in metric:
                cvss = metric["cvssV2_0"]
                cur.execute("""
                    INSERT INTO cve_metrics (
                        cve_id, source, cvss_version, vector_string, base_score, 
                        base_severity, exploitability_score, impact_score, cwe_id
                    ) VALUES (%s, 'cvelist', '2.0', %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                        vector_string = EXCLUDED.vector_string,
                        base_score = EXCLUDED.base_score,
                        base_severity = EXCLUDED.base_severity,
                        cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
                """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                      cvss.get("exploitabilityScore"), cvss.get("impactScore"), cwe_id))

        # 5. Affected Products
        affected_list = cna.get("affected", [])
        for aff in affected_list:
            vendor = aff.get("vendor")
            product = aff.get("product")
            platforms = aff.get("platforms", [])
            platform = platforms[0] if platforms else None

            # Mitre lists versions in range
            versions = aff.get("versions", [])
            for ver in versions:
                v_start_inc = ver.get("version")
                fixed_ver = ver.get("lessThan") if ver.get("status") == "unaffected" else None

                cur.execute("""
                    INSERT INTO cve_affected_products (
                        cve_id, source, vendor, product, platform, version_start_including, fixed_version
                    ) VALUES (%s, 'cvelist', %s, %s, %s, %s, %s)
                """, (cve_id, vendor, product, platform, str(v_start_inc) if v_start_inc else None, str(fixed_ver) if fixed_ver else None))


# ==========================================
# SOURCE 2: NVD API
# ==========================================

def sync_nvd(conn, full_sync=False):
    """Performs incremental or full synchronization from NIST NVD API v2.0."""
    logger.info("[*] Starting NVD API Ingestion...")
    api_key = os.environ.get("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        sleep_time = 0.7
        logger.info("[*] Authenticated session using NVD_API_KEY.")
    else:
        sleep_time = 6.1
        logger.info("[!] No API key found. Using rate-limited sleep of 6.1s.")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0
    }

    # Fetch last successful sync state
    last_sync = None
    if not full_sync:
        with conn.cursor() as cur:
            cur.execute("SELECT last_successful_sync FROM sync_state WHERE source = 'nvd'")
            row = cur.fetchone()
            if row:
                last_sync = row["last_successful_sync"]

    if last_sync:
        # NVD expects date in UTC YYYY-MM-DDTHH:MM:SS format
        formatted_date = last_sync.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModStartDate"] = formatted_date
        params["lastModEndDate"] = current_date
        logger.info(f"[*] Incremental mode: querying modified CVEs between {formatted_date} and {current_date}")
    else:
        logger.info("[*] Full mode active (no last modification date filter).")

    has_more = True
    cve_count = 0

    while has_more:
        logger.info(f"[*] Fetching page starting at index {params['startIndex']}...")
        response = execute_request_with_retry(base_url, headers=headers, params=params)
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        logger.info(f"[*] Received {len(vulnerabilities)} vulnerabilities (Total matching: {total_results})")

        for vuln in vulnerabilities:
            upsert_nvd_record(conn, vuln.get("cve", {}))
            cve_count += 1

        conn.commit()

        # Update startIndex and pagination criteria
        params["startIndex"] += len(vulnerabilities)
        if params["startIndex"] >= total_results or len(vulnerabilities) == 0:
            has_more = False
        else:
            time.sleep(sleep_time)

    # Save sync state
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO sync_state (source, last_successful_sync)
            VALUES ('nvd', now())
            ON CONFLICT (source) DO UPDATE SET last_successful_sync = EXCLUDED.last_successful_sync
        """, ())
    conn.commit()
    logger.info(f"[+] Completed NVD API Ingestion. Processed {cve_count} records.")


def upsert_nvd_record(conn, cve_data):
    """Upserts a single NVD record structure into Plane A tables."""
    cve_id = cve_data.get("id")
    if not cve_id:
        return

    published = cve_data.get("published")
    last_modified = cve_data.get("lastModified")
    vuln_status = cve_data.get("vulnStatus")
    cna_org = cve_data.get("sourceIdentifier")

    # Extract title (NVD does not supply titles, default to None)
    title = None

    # Description
    description = None
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    pub_dt = date_parser.parse(published) if published else None
    mod_dt = date_parser.parse(last_modified) if last_modified else None

    with conn.cursor() as cur:
        # 1. Upsert primary record
        cur.execute("""
            INSERT INTO cves (
                cve_id, source_of_truth, title, description, published_at, updated_at, 
                vuln_status, cna_org, raw_nvd_json, last_synced_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (cve_id) DO UPDATE SET
                source_of_truth = EXCLUDED.source_of_truth,
                description = COALESCE(EXCLUDED.description, cves.description),
                published_at = COALESCE(EXCLUDED.published_at, cves.published_at),
                updated_at = COALESCE(EXCLUDED.updated_at, cves.updated_at),
                vuln_status = COALESCE(EXCLUDED.vuln_status, cves.vuln_status),
                cna_org = COALESCE(EXCLUDED.cna_org, cves.cna_org),
                raw_nvd_json = EXCLUDED.raw_nvd_json,
                last_synced_at = now()
        """, (cve_id, "nvd", title, description, pub_dt, mod_dt, vuln_status, cna_org, json.dumps(cve_data)))

        # 2. Archive source document
        cur.execute("""
            INSERT INTO cve_source_documents (cve_id, source, source_record_id, raw_json)
            VALUES (%s, 'nvd', %s, %s)
        """, (cve_id, cve_id, json.dumps(cve_data)))

        # 3. References
        references = cve_data.get("references", [])
        for ref in references:
            ref_url = ref.get("url")
            if ref_url:
                ref_tags = ref.get("tags")
                cur.execute("""
                    INSERT INTO cve_references (cve_id, source, url, tags)
                    VALUES (%s, 'nvd', %s, %s)
                    ON CONFLICT (cve_id, url) DO UPDATE SET
                        tags = EXCLUDED.tags
                """, (cve_id, ref_url, json.dumps(ref_tags) if ref_tags else None))

        # 4. Weaknesses / CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_id = None
        for weak in weaknesses:
            desc_list = weak.get("description", [])
            for desc in desc_list:
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_id = desc.get("value")
                    break
            if cwe_id:
                break

        # 5. Metrics
        metrics = cve_data.get("metrics", {})
        
        # CVSS v4.0
        for metric_obj in metrics.get("cvssMetricV40", []):
            cvss = metric_obj.get("cvssData", {})
            cur.execute("""
                INSERT INTO cve_metrics (
                    cve_id, source, cvss_version, vector_string, base_score, 
                    base_severity, exploitability_score, impact_score, cwe_id
                ) VALUES (%s, 'nvd', '4.0', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                    vector_string = EXCLUDED.vector_string,
                    base_score = EXCLUDED.base_score,
                    base_severity = EXCLUDED.base_severity,
                    cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
            """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                  metric_obj.get("exploitabilityScore"), metric_obj.get("impactScore"), cwe_id))

        # CVSS v3.1
        for metric_obj in metrics.get("cvssMetricV31", []):
            cvss = metric_obj.get("cvssData", {})
            cur.execute("""
                INSERT INTO cve_metrics (
                    cve_id, source, cvss_version, vector_string, base_score, 
                    base_severity, exploitability_score, impact_score, cwe_id
                ) VALUES (%s, 'nvd', '3.1', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                    vector_string = EXCLUDED.vector_string,
                    base_score = EXCLUDED.base_score,
                    base_severity = EXCLUDED.base_severity,
                    cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
            """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                  metric_obj.get("exploitabilityScore"), metric_obj.get("impactScore"), cwe_id))

        # CVSS v3.0
        for metric_obj in metrics.get("cvssMetricV30", []):
            cvss = metric_obj.get("cvssData", {})
            cur.execute("""
                INSERT INTO cve_metrics (
                    cve_id, source, cvss_version, vector_string, base_score, 
                    base_severity, exploitability_score, impact_score, cwe_id
                ) VALUES (%s, 'nvd', '3.0', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                    vector_string = EXCLUDED.vector_string,
                    base_score = EXCLUDED.base_score,
                    base_severity = EXCLUDED.base_severity,
                    cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
            """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                  metric_obj.get("exploitabilityScore"), metric_obj.get("impactScore"), cwe_id))

        # CVSS v2.0
        for metric_obj in metrics.get("cvssMetricV2", []):
            cvss = metric_obj.get("cvssData", {})
            cur.execute("""
                INSERT INTO cve_metrics (
                    cve_id, source, cvss_version, vector_string, base_score, 
                    base_severity, exploitability_score, impact_score, cwe_id
                ) VALUES (%s, 'nvd', '2.0', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id, source, cvss_version) DO UPDATE SET
                    vector_string = EXCLUDED.vector_string,
                    base_score = EXCLUDED.base_score,
                    base_severity = EXCLUDED.base_severity,
                    cwe_id = COALESCE(EXCLUDED.cwe_id, cve_metrics.cwe_id)
            """, (cve_id, cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity"),
                  metric_obj.get("exploitabilityScore"), metric_obj.get("impactScore"), cwe_id))

        # 6. Affected Products / CPE configurations
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    cpe_uri = match.get("criteria")
                    vulnerable = match.get("vulnerable", False)
                    v_start_inc = match.get("versionStartIncluding")
                    v_start_exc = match.get("versionStartExcluding")
                    v_end_inc = match.get("versionEndIncluding")
                    v_end_exc = match.get("versionEndExcluding")

                    if vulnerable and cpe_uri:
                        # Extract vendor and product from CPE URI
                        parts = cpe_uri.split(":")
                        vendor = parts[3] if len(parts) > 3 else None
                        product = parts[4] if len(parts) > 4 else None
                        
                        os_type = "any"
                        os_distro = "any"
                        # Parse OS type/distro hints from CPE if part is 'o'
                        if len(parts) > 2 and parts[2] == "o":
                            os_type = "linux" if "linux" in product.lower() or "linux" in vendor.lower() else "any"
                            if os_type == "linux":
                                for distro in ["rhel", "ubuntu", "debian", "arch", "suse", "fedora", "centos"]:
                                    if distro in product.lower() or distro in vendor.lower():
                                        os_distro = distro
                                        break
                            elif "windows" in product.lower() or "microsoft" in vendor.lower():
                                os_type = "windows"
                            elif "apple" in vendor.lower() or "macos" in product.lower():
                                os_type = "macos"

                        cur.execute("""
                            INSERT INTO cve_affected_products (
                                cve_id, source, vendor, product, cpe_uri, os_type, os_distro,
                                version_start_including, version_start_excluding, 
                                version_end_including, version_end_excluding
                            ) VALUES (%s, 'nvd', %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (cve_id, vendor, product, cpe_uri, os_type, os_distro,
                              v_start_inc, v_start_exc, v_end_inc, v_end_exc))

        # 7. Check if Known Exploited
        # NVD includes this in the root response structure under cisaExploitAdd
        cisa_exploit_add = cve_data.get("cisaExploitAdd")
        if cisa_exploit_add:
            cisa_due = cve_data.get("cisaActionDue")
            cisa_name = cve_data.get("cisaVulnerabilityName")
            cisa_action = cve_data.get("cisaRequiredAction")

            cur.execute("""
                INSERT INTO cve_kev (
                    cve_id, known_exploited, cisa_date_added, cisa_due_date, 
                    cisa_vulnerability_name, cisa_required_action, raw_kev_json
                ) VALUES (%s, TRUE, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    known_exploited = TRUE,
                    cisa_date_added = EXCLUDED.cisa_date_added,
                    cisa_due_date = EXCLUDED.cisa_due_date,
                    cisa_vulnerability_name = EXCLUDED.cisa_vulnerability_name,
                    cisa_required_action = EXCLUDED.cisa_required_action
            """, (cve_id, cisa_exploit_add, cisa_due, cisa_name, cisa_action, json.dumps(cve_data)))


# ==========================================
# SOURCE 3: CISA KEV
# ==========================================

def sync_kev(conn):
    """Fetches CISA Known Exploited Vulnerabilities catalog and updates cve_kev."""
    logger.info("[*] Fetching CISA KEV Catalog...")
    url = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
    
    response = execute_request_with_retry(url)
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    
    logger.info(f"[*] Parsing {len(vulnerabilities)} vulnerabilities from CISA KEV...")
    count = 0

    with conn.cursor() as cur:
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            date_added = vuln.get("dateAdded")
            due_date = vuln.get("dueDate")
            vuln_name = vuln.get("vulnerabilityName")
            required_action = vuln.get("requiredAction")
            notes = vuln.get("notes")
            vendor = vuln.get("vendorProject")
            product = vuln.get("product")

            # Ensure the CVE base record exists
            cur.execute("""
                INSERT INTO cves (cve_id, title, description, vuln_status, source_of_truth)
                VALUES (%s, %s, %s, 'Analyzed', 'kev')
                ON CONFLICT (cve_id) DO NOTHING
            """, (cve_id, vuln_name, required_action))

            # Ingest KEV entry
            cur.execute("""
                INSERT INTO cve_kev (
                    cve_id, known_exploited, cisa_date_added, cisa_due_date,
                    cisa_vulnerability_name, cisa_required_action, cisa_notes, raw_kev_json
                ) VALUES (%s, TRUE, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    known_exploited = TRUE,
                    cisa_date_added = EXCLUDED.cisa_date_added,
                    cisa_due_date = EXCLUDED.cisa_due_date,
                    cisa_vulnerability_name = EXCLUDED.cisa_vulnerability_name,
                    cisa_required_action = EXCLUDED.cisa_required_action,
                    cisa_notes = EXCLUDED.cisa_notes,
                    raw_kev_json = EXCLUDED.raw_kev_json
            """, (cve_id, date_added, due_date, vuln_name, required_action, notes, json.dumps(vuln)))

            # Seed affected products table with KEV info
            cur.execute("""
                INSERT INTO cve_affected_products (cve_id, source, vendor, product)
                VALUES (%s, 'kev', %s, %s)
            """, (cve_id, vendor, product))

            count += 1

    conn.commit()
    logger.info(f"[+] Completed CISA KEV Ingestion. Total: {count} vulnerabilities.")


# ==========================================
# SOURCE 4: OSV (GHSA Advisories Lookup)
# ==========================================

def sync_osv(conn):
    """Scrapes reference URLs for GitHub Security Advisories and queries OSV API."""
    logger.info("[*] Starting OSV Ingestion based on advisory URLs...")
    
    # Query all referenced GHSA advisory URLs
    with conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT cve_id, url 
            FROM cve_references 
            WHERE url ~* 'github.com/.*/security/advisories/GHSA-'
        """)
        rows = cur.fetchall()

    if not rows:
        logger.info("[*] No GHSA advisories discovered in references. Skipping OSV sync.")
        return

    logger.info(f"[*] Found {len(rows)} potential GHSA mappings. Fetching advisories from OSV API...")
    processed = 0

    for row in rows:
        cve_id = row["cve_id"]
        url = row["url"]

        # Parse GHSA ID from url
        # e.g., https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
        import re
        match = re.search(r'(GHSA-[a-zA-Z0-9_-]+)', url, re.IGNORECASE)
        if not match:
            continue
        
        ghsa_id = match.group(1).upper()
        
        try:
            logger.info(f"[*] Querying OSV for {ghsa_id} (linked to {cve_id})...")
            osv_url = f"https://api.osv.dev/v1/vulns/{ghsa_id}"
            response = execute_request_with_retry(osv_url)
            osv_record = response.json()

            upsert_osv_record(conn, cve_id, ghsa_id, osv_record)
            processed += 1

            # Sleep 0.3s between requests to respect API rate limits
            time.sleep(0.3)
        except Exception as e:
            logger.error(f"[-] Error querying OSV for {ghsa_id}: {e}")

    conn.commit()
    logger.info(f"[+] Completed OSV Ingestion. Synced {processed} GHSA advisories.")


def upsert_osv_record(conn, cve_id, ghsa_id, record):
    """Upserts OSV advisory metadata and ecosystem version ranges."""
    summary = record.get("summary")
    details = record.get("details")
    published = record.get("published")
    modified = record.get("modified")

    pub_dt = date_parser.parse(published) if published else None
    mod_dt = date_parser.parse(modified) if modified else None

    with conn.cursor() as cur:
        # 1. Update title/description if currently missing in CVE record
        cur.execute("""
            UPDATE cves 
            SET title = COALESCE(title, %s),
                description = COALESCE(description, %s),
                published_at = COALESCE(published_at, %s),
                updated_at = COALESCE(updated_at, %s)
            WHERE cve_id = %s
        """, (summary, details, pub_dt, mod_dt, cve_id))

        # 2. Upsert alias mapping
        cur.execute("""
            INSERT INTO cve_aliases (cve_id, alias_type, alias_value)
            VALUES (%s, 'GHSA', %s)
            ON CONFLICT DO NOTHING
        """, (cve_id, ghsa_id))

        # 3. Archive source doc
        cur.execute("""
            INSERT INTO cve_source_documents (cve_id, source, source_record_id, raw_json)
            VALUES (%s, 'osv', %s, %s)
        """, (cve_id, ghsa_id, json.dumps(record)))

        # 4. Save metrics (if severity is parsed by OSV)
        severities = record.get("severity", [])
        for sev in severities:
            vector = sev.get("score")
            sev_type = sev.get("type") # CVSS_V3, CVSS_V2
            cvss_ver = "3.1"
            if sev_type == "CVSS_V2":
                cvss_ver = "2.0"
            elif sev_type == "CVSS_V4":
                cvss_ver = "4.0"

            if vector and vector.startswith("CVSS:"):
                # Basic CVSS parse (we can map vector fields if needed)
                # For simplicity, extract vector
                cur.execute("""
                    INSERT INTO cve_metrics (cve_id, source, cvss_version, vector_string)
                    VALUES (%s, 'osv', %s, %s)
                    ON CONFLICT (cve_id, source, cvss_version) DO NOTHING
                """, (cve_id, cvss_ver, vector))

        # 5. Affected Packages
        affected = record.get("affected", [])
        for aff in affected:
            package = aff.get("package", {})
            ecosystem = package.get("ecosystem")
            pkg_name = package.get("name")

            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                introduced = None
                fixed = None
                for ev in events:
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]

                cur.execute("""
                    INSERT INTO cve_affected_products (
                        cve_id, source, ecosystem, package_name, 
                        version_start_including, fixed_version, raw_range
                    ) VALUES (%s, 'osv', %s, %s, %s, %s, %s)
                """, (cve_id, ecosystem, pkg_name, introduced, fixed, json.dumps(r)))


# ==========================================
# POST-SYNC: LABEL GENERATOR RUNNER
# ==========================================

def update_cve_labels(conn, cve_id=None, force_regen=False):
    """
    Computes and writes custom labels for newly ingested or modified CVEs.
    If cve_id is specified, only that CVE is updated.
    If force_regen is True, updates all labels.
    """
    logger.info("[*] Launching Internal Label Generator...")
    
    with conn.cursor() as cur:
        if cve_id:
            cur.execute("SELECT cve_id, last_synced_at, label_generated_at FROM cves WHERE cve_id = %s", (cve_id,))
            records = cur.fetchall()
        elif force_regen:
            cur.execute("SELECT cve_id, last_synced_at, label_generated_at FROM cves")
            records = cur.fetchall()
        else:
            # Update where label is missing OR was generated BEFORE the last sync
            cur.execute("""
                SELECT cve_id, last_synced_at, label_generated_at 
                FROM cves 
                WHERE internal_label IS NULL OR label_generated_at < last_synced_at
            """)
            records = cur.fetchall()

    if not records:
        logger.info("[*] All CVE internal labels are currently up to date.")
        return

    logger.info(f"[*] Processing labels for {len(records)} CVE records...")
    updated_count = 0

    with conn.cursor() as cur:
        for rec in records:
            cve_id = rec["cve_id"]
            
            # Fetch products
            cur.execute("""
                SELECT cpe_uri, vendor, product, ecosystem, os_type 
                FROM cve_affected_products 
                WHERE cve_id = %s 
                ORDER BY CASE WHEN source = 'nvd' THEN 1 WHEN source = 'osv' THEN 2 ELSE 3 END ASC
            """, (cve_id,))
            products = cur.fetchall()

            # Fetch metrics
            cur.execute("""
                SELECT base_score, cvss_version 
                FROM cve_metrics 
                WHERE cve_id = %s
            """, (cve_id,))
            metrics = cur.fetchall()

            # Generate label
            label = label_engine.generate_label(cve_id, products, metrics)

            # Write label
            cur.execute("""
                UPDATE cves 
                SET internal_label = %s,
                    label_generated_at = now()
                WHERE cve_id = %s
            """, (label, cve_id))

            updated_count += 1
            if updated_count % 1000 == 0:
                conn.commit()
                logger.info(f"[+] Written {updated_count} labels...")

    conn.commit()
    logger.info(f"[+] Completed label generation. Generated: {updated_count} labels.")


def main():
    parser = argparse.ArgumentParser(description="CYBER_MultiTool CVE Database Synchronization Pipeline")
    parser.add_argument("--full", action="store_true", help="Perform full synchronization (disables incremental date filtering)")
    parser.add_argument("--skip-cvelist", action="store_true", help="Skip MITRE cvelistV5 clone ingestion")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NIST NVD API v2.0 ingestion")
    parser.add_argument("--skip-kev", action="store_true", help="Skip CISA Known Exploited Vulnerabilities catalog sync")
    parser.add_argument("--skip-osv", action="store_true", help="Skip OSV/GHSA advisories scraping")
    parser.add_argument("--cvelist-dir", default="./cvelistV5", help="Path to cvelistV5 local repository (default: ./cvelistV5)")
    parser.add_argument("--regen-labels", action="store_true", help="Force recalculation of internal labels for all CVE records")
    args = parser.parse_args()

    start_time = time.time()
    logger.info("==============================================")
    logger.info("CYBER_MultiTool Ingestion Sync Pipeline Started")
    logger.info("==============================================")

    try:
        conn = get_db_connection()
    except Exception as e:
        logger.error(f"[!] Database connection failed: {e}")
        sys.exit(1)

    try:
        # Source 1: CVE List MITRE
        if not args.skip_cvelist:
            sync_cvelist(conn, args.cvelist_dir)

        # Source 2: NVD API
        if not args.skip_nvd:
            sync_nvd(conn, full_sync=args.full)

        # Source 3: CISA KEV
        if not args.skip_kev:
            sync_kev(conn)

        # Source 4: OSV API
        if not args.skip_osv:
            sync_osv(conn)

        # Post-Sync Label Generation
        update_cve_labels(conn, force_regen=args.regen_labels)

    except Exception as e:
        logger.exception(f"[!] Error executing synchronization pipeline: {e}")
    finally:
        conn.close()
        duration = time.time() - start_time
        logger.info(f"[*] Ingestion pipeline completed in {duration:.2f} seconds.")


if __name__ == "__main__":
    main()
