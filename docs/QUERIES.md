# Example SQL Queries — CYBER_MultiTool CVE Database

This reference document compiles 22 SQL queries for common security workflows, analytics, audit reviews, and administration tasks.

---

## 1. Vulnerability Intelligence (Plane A)

### Query 1: Retrieve all active Known Exploited Vulnerabilities (KEV)
```sql
SELECT cve_id, cisa_vulnerability_name, cisa_date_added, cisa_due_date
FROM cve_kev
WHERE known_exploited = TRUE
ORDER BY cisa_date_added DESC;
```

### Query 2: Retrieve the highest CVSS metrics for a specific CVE
```sql
SELECT source, cvss_version, base_score, base_severity, vector_string
FROM cve_metrics
WHERE cve_id = 'CVE-2024-1086'
ORDER BY base_score DESC;
```

### Query 3: Find critical-severity vulnerabilities affecting the Linux kernel
```sql
SELECT cve_id, title, internal_label, published_at
FROM cves
WHERE internal_label LIKE 'LIN-%-KERN-%-C-%'
ORDER BY published_at DESC;
```

### Query 4: Search for CVEs mentioning "remote code execution" or "privilege escalation"
```sql
SELECT cve_id, title, internal_label
FROM cves
WHERE to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')) @@ websearch_to_tsquery('english', 'remote code execution | privilege escalation')
LIMIT 10;
```

### Query 5: Find all CVEs that affect the "openssh" product
```sql
SELECT DISTINCT c.cve_id, c.internal_label, c.title
FROM cves c
JOIN cve_affected_products p ON c.cve_id = p.cve_id
WHERE p.product ILIKE 'openssh'
ORDER BY c.cve_id DESC;
```

### Query 6: Retrieve all external links tagged as a "PoC"
```sql
SELECT cve_id, url, tags
FROM cve_references
WHERE tags @> '"proof-of-concept"'::jsonb OR tags @> '"poc"'::jsonb;
```

### Query 7: List all GHSA or OSV aliases mapped to a specific CVE
```sql
SELECT alias_type, alias_value
FROM cve_aliases
WHERE cve_id = 'CVE-2021-41773';
```

### Query 8: Find vulnerabilities with CVSS scores between 8.0 and 9.5
```sql
SELECT cve_id, max_base_score
FROM v_highest_cvss_score
WHERE max_base_score BETWEEN 8.0 AND 9.5
ORDER BY max_base_score DESC;
```

### Query 9: Count vulnerabilities in the database grouped by severity (based on internal labels)
```sql
SELECT 
    split_part(internal_label, '-', 5) AS severity_code,
    COUNT(*) AS cve_count
FROM cves
WHERE internal_label IS NOT NULL
GROUP BY severity_code
ORDER BY cve_count DESC;
```

### Query 10: Find the most common CWE weaknesses in the system
```sql
SELECT cwe_id, COUNT(*) AS occurrences
FROM cve_metrics
WHERE cwe_id IS NOT NULL
GROUP BY cwe_id
ORDER BY occurrences DESC
LIMIT 10;
```

### Query 11: Get CVEs ingested or modified in the last 24 hours
```sql
SELECT cve_id, internal_label, last_synced_at
FROM cves
WHERE last_synced_at >= now() - INTERVAL '24 hours';
```

---

## 2. Findings and Assets Analytics (Plane B)

### Query 12: List all open findings for a specific scan session
```sql
SELECT finding_id, asset_type, asset_value, cve_id, severity, tool, template_id
FROM v_open_findings
WHERE session_id = '20260623_120010_pentest-ground_com';
```

### Query 13: Get count of open findings grouped by severity (using the view)
```sql
SELECT * FROM v_findings_by_severity;
```

### Query 14: Get all assets that have active Critical or High findings
```sql
SELECT DISTINCT asset_type, asset_value, severity
FROM v_open_findings
WHERE severity IN ('critical', 'high')
ORDER BY severity ASC;
```

### Query 15: Find all vulnerable packages nested inside a specific container asset
```sql
SELECT a_pkg.value AS package, f.cve_id, f.internal_label, f.severity
FROM findings f
JOIN assets a_pkg ON f.asset_id = a_pkg.id
JOIN assets a_cont ON a_pkg.parent_id = a_cont.id
WHERE a_cont.asset_type = 'container'
  AND a_cont.value = 'my-app-image:latest'
  AND f.status = 'open';
```

### Query 16: List findings marked as false positive along with operator notes
```sql
SELECT f.id, a.value AS asset, f.cve_id, f.template_id, f.false_positive_note, f.last_confirmed_at
FROM findings f
JOIN assets a ON f.asset_id = a.id
WHERE f.false_positive = TRUE;
```

### Query 17: Find the most vulnerable asset (highest count of high/critical findings)
```sql
SELECT asset_value, asset_type, COUNT(*) AS critical_high_count
FROM v_open_findings
WHERE severity IN ('critical', 'high')
GROUP BY asset_value, asset_type
ORDER BY critical_high_count DESC
LIMIT 5;
```

### Query 18: Find the oldest open finding that has not been mitigated
```sql
SELECT finding_id, asset_value, cve_id, first_found_at
FROM v_open_findings
ORDER BY first_found_at ASC
LIMIT 1;
```

### Query 19: List all assets discovered by the 'asm' tool
```sql
SELECT id, asset_type, value, first_seen_at
FROM assets
WHERE source_tool = 'asm'
ORDER BY first_seen_at DESC;
```

### Query 20: Count of unique assets grouped by type
```sql
SELECT asset_type, COUNT(*) AS asset_count
FROM assets
GROUP BY asset_type
ORDER BY asset_count DESC;
```

---

## 3. Database Administration

### Query 21: Check last successful synchronization time per source
```sql
SELECT source, last_successful_sync
FROM sync_state;
```

### Query 22: Get history of status changes on findings for audit trail
```sql
SELECT h.finding_id, f.cve_id, h.old_status, h.new_status, h.changed_by, h.changed_at, h.note
FROM finding_history h
JOIN findings f ON h.finding_id = f.id
ORDER BY h.changed_at DESC;
```
