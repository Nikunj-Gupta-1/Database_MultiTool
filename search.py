#!/usr/bin/env python3
"""
search.py
Query API module for the CYBER_MultiTool CVE database.
Exposes functions to retrieve, search, and filter vulnerabilities.
No code is executed at the module level except imports.
"""

import logging
import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger("search_api")


def lookup_by_cve_id(conn, cve_id: str) -> dict:
    """
    Returns a single enriched CVE record containing core fields, metrics,
    references, affected products, KEV status, aliases, and the internal label.
    Returns None if the CVE ID does not exist.
    """
    query = """
        SELECT c.*, 
               COALESCE(k.known_exploited, FALSE) AS known_exploited,
               k.cisa_date_added,
               k.cisa_due_date,
               k.cisa_vulnerability_name,
               k.cisa_required_action,
               k.cisa_notes
        FROM cves c
        LEFT JOIN cve_kev k ON c.cve_id = k.cve_id
        WHERE c.cve_id = %s
    """
    
    with conn.cursor() as cur:
        cur.execute(query, (cve_id,))
        cve = cur.fetchone()
        
        if not cve:
            return None

        # Fetch aliases
        cur.execute("SELECT alias_type, alias_value FROM cve_aliases WHERE cve_id = %s", (cve_id,))
        cve["aliases"] = cur.fetchall()

        # Fetch metrics
        cur.execute("""
            SELECT source, cvss_version, vector_string, base_score, 
                   base_severity, exploitability_score, impact_score, cwe_id
            FROM cve_metrics 
            WHERE cve_id = %s
            ORDER BY base_score DESC NULLS LAST
        """, (cve_id,))
        cve["metrics"] = cur.fetchall()

        # Fetch references
        cur.execute("SELECT url, source, ref_type, tags FROM cve_references WHERE cve_id = %s", (cve_id,))
        cve["references"] = cur.fetchall()

        # Fetch affected products
        cur.execute("""
            SELECT source, vendor, product, ecosystem, package_name, platform, cpe_uri, 
                   os_type, os_distro, version_start_including, version_start_excluding, 
                   version_end_including, version_end_excluding, fixed_version
            FROM cve_affected_products 
            WHERE cve_id = %s
        """, (cve_id,))
        cve["affected_products"] = cur.fetchall()

    return cve


def lookup_by_label(conn, label: str) -> list[dict]:
    """
    Finds CVEs matching an internal label pattern.
    Supports prefix matching (e.g., 'LIN-RHEL' matches 'LIN-RHEL-DB-MYSQL-H-2024-1234').
    """
    search_pattern = label if "%" in label else f"{label}%"
    query = """
        SELECT c.*, 
               COALESCE(k.known_exploited, FALSE) AS known_exploited,
               (SELECT MAX(base_score) FROM cve_metrics m WHERE m.cve_id = c.cve_id) AS cvss_score
        FROM cves c
        LEFT JOIN cve_kev k ON c.cve_id = k.cve_id
        WHERE c.internal_label ILIKE %s
        ORDER BY c.cve_id DESC
    """
    with conn.cursor() as cur:
        cur.execute(query, (search_pattern,))
        return cur.fetchall()


def search(conn, query_str: str, filters: dict = None) -> list[dict]:
    """
    Performs a full-text search across description, title, internal label, and CVE ID.
    Supports filtering by severity, CVSS scores, KEV status, operating system, layers,
    products, ecosystems, packages, CPEs, and publication dates.
    """
    if filters is None:
        filters = {}

    sql_parts = [
        """
        SELECT c.*, 
               COALESCE(k.known_exploited, FALSE) AS known_exploited,
               (SELECT MAX(base_score) FROM cve_metrics m WHERE m.cve_id = c.cve_id) AS cvss_score
        FROM cves c
        LEFT JOIN cve_kev k ON c.cve_id = k.cve_id
        WHERE 1=1
        """
    ]
    params = []

    # 1. Full-text search
    if query_str and query_str.strip():
        # Match CVE ID or internal label exactly, or perform web search on title + description
        sql_parts.append("""
            AND (
                c.cve_id ILIKE %s OR
                c.internal_label ILIKE %s OR
                to_tsvector('english', COALESCE(c.title,'') || ' ' || COALESCE(c.description,'')) @@ websearch_to_tsquery('english', %s)
            )
        """)
        fts_query = query_str.strip()
        params.extend([f"%{fts_query}%", f"%{fts_query}%", fts_query])

    # 2. Severity filter (critical, high, medium, low)
    if "severity" in filters:
        sev_map = {
            "critical": "C",
            "high": "H",
            "medium": "M",
            "low": "L",
            "info": "I"
        }
        sev_char = sev_map.get(filters["severity"].lower())
        if sev_char:
            sql_parts.append("AND split_part(c.internal_label, '-', 5) = %s")
            params.append(sev_char)

    # 3. CVSS score range
    if "cvss_min" in filters or "cvss_max" in filters:
        cvss_min = float(filters.get("cvss_min", 0.0))
        cvss_max = float(filters.get("cvss_max", 10.0))
        sql_parts.append("""
            AND EXISTS (
                SELECT 1 FROM v_highest_cvss_score ms 
                WHERE ms.cve_id = c.cve_id AND ms.max_base_score BETWEEN %s AND %s
            )
        """)
        params.extend([cvss_min, cvss_max])

    # 4. Known Exploited filter
    if "known_exploited" in filters:
        known_exploited = bool(filters["known_exploited"])
        if known_exploited:
            sql_parts.append("AND k.known_exploited = TRUE")
        else:
            sql_parts.append("AND (k.known_exploited IS NULL OR k.known_exploited = FALSE)")

    # 5. OS Family filter
    if "os_family" in filters:
        sql_parts.append("AND split_part(c.internal_label, '-', 1) = %s")
        params.append(filters["os_family"].upper())

    # 6. Layer filter
    if "layer" in filters:
        sql_parts.append("AND split_part(c.internal_label, '-', 3) = %s")
        params.append(filters["layer"].upper())

    # 7. Product filter
    if "product" in filters:
        sql_parts.append("""
            AND (
                split_part(c.internal_label, '-', 4) ILIKE %s OR
                EXISTS (SELECT 1 FROM cve_affected_products p WHERE p.cve_id = c.cve_id AND p.product ILIKE %s)
            )
        """)
        prod = filters["product"]
        params.extend([f"%{prod}%", f"%{prod}%"])

    # 8. Vendor filter
    if "vendor" in filters:
        sql_parts.append("AND EXISTS (SELECT 1 FROM cve_affected_products p WHERE p.cve_id = c.cve_id AND p.vendor ILIKE %s)")
        params.append(f"%{filters['vendor']}%")

    # 9. Ecosystem filter
    if "ecosystem" in filters:
        sql_parts.append("AND EXISTS (SELECT 1 FROM cve_affected_products p WHERE p.cve_id = c.cve_id AND p.ecosystem ILIKE %s)")
        params.append(f"%{filters['ecosystem']}%")

    # 10. Package filter
    if "package" in filters:
        sql_parts.append("AND EXISTS (SELECT 1 FROM cve_affected_products p WHERE p.cve_id = c.cve_id AND p.package_name ILIKE %s)")
        params.append(f"%{filters['package']}%")

    # 11. CPE filter
    if "cpe" in filters:
        sql_parts.append("AND EXISTS (SELECT 1 FROM cve_affected_products p WHERE p.cve_id = c.cve_id AND p.cpe_uri ILIKE %s)")
        params.append(f"%{filters['cpe']}%")

    # 12. Date constraints
    if "published_after" in filters:
        sql_parts.append("AND c.published_at >= %s")
        params.append(filters["published_after"])

    if "published_before" in filters:
        sql_parts.append("AND c.published_at <= %s")
        params.append(filters["published_before"])

    if "updated_after" in filters:
        sql_parts.append("AND c.updated_at >= %s")
        params.append(filters["updated_after"])

    # Order query results
    if query_str and query_str.strip():
        # Rank sorting for search term query
        sql_parts.append("""
            ORDER BY 
                ts_rank(to_tsvector('english', COALESCE(c.title,'') || ' ' || COALESCE(c.description,'')), websearch_to_tsquery('english', %s)) DESC, 
                cvss_score DESC NULLS LAST, 
                c.cve_id DESC
        """)
        params.append(query_str.strip())
    else:
        sql_parts.append("ORDER BY cvss_score DESC NULLS LAST, c.cve_id DESC")

    full_sql = "\n".join(sql_parts)

    with conn.cursor() as cur:
        cur.execute(full_sql, params)
        return cur.fetchall()


def lookup_by_cpe(conn, cpe_fragment: str) -> list[dict]:
    """Finds all CVEs linked to a CPE URI matching the fragment pattern."""
    query = """
        SELECT DISTINCT c.*,
               (SELECT MAX(base_score) FROM cve_metrics m WHERE m.cve_id = c.cve_id) AS cvss_score
        FROM cves c
        JOIN cve_affected_products p ON c.cve_id = p.cve_id
        WHERE p.cpe_uri ILIKE %s
        ORDER BY cvss_score DESC NULLS LAST, c.cve_id DESC
    """
    with conn.cursor() as cur:
        cur.execute(query, (f"%{cpe_fragment}%",))
        return cur.fetchall()


def lookup_by_package(conn, ecosystem: str, package_name: str, version: str = None) -> list[dict]:
    """
    Finds CVEs affecting a package ecosystem and name.
    If version is provided, applies version range checks.
    """
    if version:
        query = """
            SELECT DISTINCT c.*,
                   (SELECT MAX(base_score) FROM cve_metrics m WHERE m.cve_id = c.cve_id) AS cvss_score
            FROM cves c
            JOIN cve_affected_products p ON c.cve_id = p.cve_id
            WHERE p.ecosystem ILIKE %s 
              AND p.package_name ILIKE %s
              AND (
                  p.version_start_including = %s OR
                  (
                      (p.version_start_including IS NULL OR %s >= p.version_start_including) AND
                      (p.version_start_excluding IS NULL OR %s > p.version_start_excluding) AND
                      (p.version_end_including IS NULL OR %s <= p.version_end_including) AND
                      (p.version_end_excluding IS NULL OR %s < p.version_end_excluding)
                  )
              )
            ORDER BY cvss_score DESC NULLS LAST, c.cve_id DESC
        """
        params = (ecosystem, package_name, version, version, version, version, version)
    else:
        query = """
            SELECT DISTINCT c.*,
                   (SELECT MAX(base_score) FROM cve_metrics m WHERE m.cve_id = c.cve_id) AS cvss_score
            FROM cves c
            JOIN cve_affected_products p ON c.cve_id = p.cve_id
            WHERE p.ecosystem ILIKE %s AND p.package_name ILIKE %s
            ORDER BY cvss_score DESC NULLS LAST, c.cve_id DESC
        """
        params = (ecosystem, package_name)

    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def get_actionable(conn, limit: int = 50) -> list[dict]:
    """Returns KEV-active or High/Critical severity CVE records."""
    query = "SELECT * FROM v_actionable_cves LIMIT %s"
    with conn.cursor() as cur:
        cur.execute(query, (limit,))
        return cur.fetchall()


def get_by_label_prefix(conn, prefix: str) -> list[dict]:
    """Retrieves all CVE records matching an internal label prefix (e.g. 'LIN-RHEL-DB')."""
    return lookup_by_label(conn, prefix)
