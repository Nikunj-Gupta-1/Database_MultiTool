# Integration Guide — CYBER_MultiTool CVE Database

All tools within the CYBER_MultiTool suite query and write to this central CVE Database. 

- **Plane A (CVE Knowledge)**: Read-only for scanners. Houses CVE metadata and global vulnerability state.
- **Plane B (Findings)**: Read/Write for scanners. Stores discovered assets, active scan sessions, and findings.

---

## 1. Importing database settings and Search API

Any Python tool can import `search.py` and `sync_cves.py` directly:
```python
import psycopg
import search
import sync_cves

# Connect to database using configuration loaded from .env
conn = sync_cves.get_db_connection()
```

---

## 2. Plane A: Querying CVE Intel

### Look up a CVE by ID
```python
cve_info = search.lookup_by_cve_id(conn, "CVE-2024-1086")
if cve_info:
    print(f"Severity: {cve_info['internal_label']}")
    print(f"Max CVSS: {cve_info['metrics'][0]['base_score']}")
```

### Check if a Package/Dependency is vulnerable (SBOM Scanners)
```python
vulns = search.lookup_by_package(conn, ecosystem="PyPI", package_name="requests", version="2.25.0")
for v in vulns:
    print(f"Affects requests 2.25.0: {v['cve_id']} (Label: {v['internal_label']})")
```

---

## 3. Plane B: Writing Scan Findings

To submit findings from a new security scanner (e.g., SBOM, container scanner), follow these three steps within a transaction block:

### Step 1: Create a Scan Session
```python
session_id = "sbom-run-2026-06-25"
with conn.cursor() as cur:
    cur.execute("""
        INSERT INTO scan_sessions (session_id, tool, target, started_at, status)
        VALUES (%s, 'sbom', 'my-app-image:latest', now(), 'running')
        ON CONFLICT (session_id) DO NOTHING
    """, (session_id,))
conn.commit()
```

### Step 2: Register Discovered Assets
Assets must be created and linked hierarchically (e.g. package belongs to container, subdomain belongs to domain).
```python
# Register container image asset
container_id = asm_bridge.upsert_asset(conn, "my-app-image:latest", "container")

# Register package inside container
pkg_id = asm_bridge.upsert_asset(
    conn, 
    value="pip:requests:2.25.0", 
    asset_type="package", 
    parent_id=container_id,
    metadata={"ecosystem": "PyPI", "name": "requests", "version": "2.25.0"}
)
conn.commit()
```

### Step 3: Write the Finding
For each finding, lookup the corresponding `internal_label` from Plane A. If the CVE isn't in Plane A yet, write a stub CVE to retrieve a label.
```python
cve_id = "CVE-2020-26137"

# Get or create stub to resolve label
internal_label = asm_bridge.ensure_cve_stub_exists(conn, cve_id)

with conn.cursor() as cur:
    cur.execute("""
        INSERT INTO findings (
            session_id, asset_id, cve_id, internal_label, finding_type, 
            severity, tool, status, raw_output, last_confirmed_at
        ) VALUES (%s, %s, %s, %s, 'cve', 'high', 'sbom-grype', 'open', '{}'::jsonb, now())
        ON CONFLICT (session_id, asset_id, template_id, COALESCE(cve_id, ''))
        DO UPDATE SET last_confirmed_at = now()
    """, (session_id, pkg_id, cve_id, internal_label))
conn.commit()
```

### Step 4: Close Session
```python
with conn.cursor() as cur:
    cur.execute("""
        UPDATE scan_sessions 
        SET finished_at = now(), status = 'completed' 
        WHERE session_id = %s
    """, (session_id,))
conn.commit()
```

---

## 4. Audit Trail: Finding History

Whenever a finding status changes (e.g., marked as false positive, mitigated, or risk accepted), an entry must be created in the `finding_history` table:
```python
finding_id = 45 # Database ID of the finding
old_status = "open"
new_status = "mitigated"

with conn.cursor() as cur:
    # 1. Update finding status
    cur.execute("UPDATE findings SET status = %s WHERE id = %s", (new_status, finding_id))
    
    # 2. Append history audit entry
    cur.execute("""
        INSERT INTO finding_history (finding_id, old_status, new_status, changed_by, note)
        VALUES (%s, %s, %s, 'security_operator', 'Mitigated by patching Dockerfile base image.')
    """, (finding_id, old_status, new_status))
conn.commit()
```
