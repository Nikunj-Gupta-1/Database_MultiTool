#!/usr/bin/env python3
"""
cli_search.py
CLI wrapper for querying the CYBER_MultiTool CVE intelligence database.
"""

import sys
import json
from datetime import datetime, date
from decimal import Decimal
import argparse
from tabulate import tabulate

import search
import sync_cves


class SecurityJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle decimals, datetimes, and dates."""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def format_results(results, as_json=False):
    """Formats and prints list of results to stdout."""
    if not results:
        if as_json:
            print("[]")
        else:
            print("[-] No results found.")
        return

    if as_json:
        print(json.dumps(results, cls=SecurityJSONEncoder, indent=2))
        return

    # Table view
    headers = ["CVE ID", "Internal Label", "CVSS", "KEV?", "Title"]
    table_data = []
    
    for r in results:
        cve_id = r.get("cve_id", "")
        label = r.get("internal_label", "")
        
        # Determine CVSS score
        score = r.get("cvss_score")
        if score is None:
            score = "N/A"
        else:
            score = f"{float(score):.1f}"
            
        kev = "Yes" if r.get("known_exploited") else "No"
        
        title = r.get("title", "")
        if title:
            # Truncate title for readability
            title = title[:45] + "..." if len(title) > 45 else title
        else:
            title = "No Title"

        table_data.append([cve_id, label, score, kev, title])

    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def format_single_record(record, as_json=False):
    """Formats and prints a single enriched CVE record."""
    if not record:
        if as_json:
            print("{}")
        else:
            print("[-] No matching CVE record found.")
        return

    if as_json:
        print(json.dumps(record, cls=SecurityJSONEncoder, indent=2))
        return

    # Console text view
    print("=" * 70)
    print(f" CVE Record: {record.get('cve_id')}  |  Label: {record.get('internal_label')}")
    print("=" * 70)
    print(f" Title:       {record.get('title') or 'N/A'}")
    print(f" Source:      {record.get('source_of_truth')}  |  Status: {record.get('vuln_status')}")
    
    published = record.get("published_at")
    updated = record.get("updated_at")
    print(f" Published:   {published.strftime('%Y-%m-%d %H:%M:%S') if published else 'N/A'}")
    print(f" Updated:     {updated.strftime('%Y-%m-%d %H:%M:%S') if updated else 'N/A'}")
    
    kev = "YES (Known Exploited Vulnerability)" if record.get("known_exploited") else "No"
    print(f" KEV Status:  {kev}")
    print("-" * 70)
    print(" Description:")
    print(record.get("description") or "No description provided.")
    print("-" * 70)

    # Aliases
    aliases = record.get("aliases", [])
    if aliases:
        print(" Aliases:")
        for alias in aliases:
            print(f"  - {alias['alias_type']}: {alias['alias_value']}")
        print("-" * 70)

    # Metrics
    metrics = record.get("metrics", [])
    if metrics:
        print(" CVSS Metrics (highest first):")
        for m in metrics:
            score = f"{float(m['base_score']):.1f}" if m['base_score'] else "N/A"
            print(f"  - [{m['source'].upper()}] v{m['cvss_version']}: Score {score} ({m['base_severity'] or 'N/A'}) - Vector: {m['vector_string']}")
        print("-" * 70)

    # References (limit to 5)
    refs = record.get("references", [])
    if refs:
        print(f" References (showing top {min(len(refs), 5)}):")
        for ref in refs[:5]:
            print(f"  - {ref['url']}")
        print("-" * 70)

    # Affected Products (limit to 5)
    affected = record.get("affected_products", [])
    if affected:
        print(f" Affected Products (showing top {min(len(affected), 5)}):")
        for p in affected[:5]:
            if p["cpe_uri"]:
                print(f"  - CPE: {p['cpe_uri']}")
            else:
                print(f"  - Package: {p['ecosystem']} - {p['package_name']} (Range: {p['version_start_including'] or '*'} -> {p['fixed_version'] or '*'})")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="CYBER_MultiTool CVE Search CLI")
    
    # Selection targets
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve", help="Look up a single enriched CVE by ID (e.g. CVE-2024-1234)")
    group.add_argument("--label", help="Lookup CVEs by exact label or label prefix (e.g. LIN-RHEL)")
    group.add_argument("--label-prefix", help="Lookup CVEs by label prefix (e.g. LIN-RHEL-DB)")
    group.add_argument("--search", help="Perform full-text search across Title and Description")
    group.add_argument("--package", nargs=2, metavar=("ECOSYSTEM", "NAME"), help="Find CVEs affecting a package ecosystem and name")
    group.add_argument("--cpe", help="Find CVEs affecting a CPE URI fragment")
    group.add_argument("--actionable", action="store_true", help="Retrieve KEV or high-severity CVEs")
    
    # Filtering options
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Filter by severity")
    parser.add_argument("--cvss-min", type=float, help="Filter by minimum CVSS score")
    parser.add_argument("--cvss-max", type=float, help="Filter by maximum CVSS score")
    parser.add_argument("--known-exploited", type=lambda x: (str(x).lower() in ['true', '1', 'yes']), help="Filter by KEV status (true/false)")
    parser.add_argument("--os-family", help="Filter by OS Family (e.g. LIN, WIN, CONT)")
    parser.add_argument("--layer", help="Filter by architectural layer (e.g. DB, WEB, KERN)")
    parser.add_argument("--product", help="Filter by product name")
    parser.add_argument("--vendor", help="Filter by vendor name")
    parser.add_argument("--package-version", help="Filter package matches by specific version (only with --package)")
    parser.add_argument("--limit", type=int, default=50, help="Limit number of output results (default: 50)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    # Load environment variables and connect
    try:
        conn = sync_cves.get_db_connection()
    except Exception as e:
        print(f"[!] Database connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        # Build filter dict
        filters = {}
        if args.severity:
            filters["severity"] = args.severity
        if args.cvss_min is not None:
            filters["cvss_min"] = args.cvss_min
        if args.cvss_max is not None:
            filters["cvss_max"] = args.cvss_max
        if args.known_exploited is not None:
            filters["known_exploited"] = args.known_exploited
        if args.os_family:
            filters["os_family"] = args.os_family
        if args.layer:
            filters["layer"] = args.layer
        if args.product:
            filters["product"] = args.product
        if args.vendor:
            filters["vendor"] = args.vendor

        # Dispatch queries
        if args.cve:
            record = search.lookup_by_cve_id(conn, args.cve)
            format_single_record(record, as_json=args.json)
        elif args.label:
            results = search.lookup_by_label(conn, args.label)
            # Apply client side filters to label lookup if any specified
            if filters:
                results = [r for r in results if all(
                    (k == "severity" and r.get("internal_label", "").split("-")[4] == {"critical":"C", "high":"H", "medium":"M", "low":"L", "info":"I"}.get(v.lower())) or
                    (k == "known_exploited" and r.get("known_exploited") == v) or
                    (k == "os_family" and r.get("internal_label", "").split("-")[0] == v.upper()) or
                    (k == "layer" and r.get("internal_label", "").split("-")[2] == v.upper())
                    for k, v in filters.items()
                )]
            format_results(results[:args.limit], as_json=args.json)
        elif args.label_prefix:
            results = search.get_by_label_prefix(conn, args.label_prefix)
            format_results(results[:args.limit], as_json=args.json)
        elif args.search:
            results = search.search(conn, args.search, filters)
            format_results(results[:args.limit], as_json=args.json)
        elif args.package:
            eco, name = args.package
            results = search.lookup_by_package(conn, eco, name, args.package_version)
            format_results(results[:args.limit], as_json=args.json)
        elif args.cpe:
            results = search.lookup_by_cpe(conn, args.cpe)
            format_results(results[:args.limit], as_json=args.json)
        elif args.actionable:
            results = search.get_actionable(conn, args.limit)
            format_results(results, as_json=args.json)

    except Exception as e:
        print(f"[!] Query failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
