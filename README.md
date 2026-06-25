# Database_MultiTool — CVE Intelligence Database

`Database_MultiTool` is the central CVE Intelligence Database and ingestion pipeline that serves as the backbone of the `CYBER_MultiTool` security platform. It provides a single source of truth for vulnerability metadata (Plane A) and scan findings (Plane B) queried and updated by security scanning tools (ASM scanners, SBOM tools, container scanners, and baseline/hardening agents).

---

## 🚀 Key Features

- **Double-Plane Architecture**:
  - **Plane A (Knowledge)**: Universally synced, read-only plane storing what is globally known about CVEs (Mitre, NVD, CISA KEV, and OSV/GHSA).
  - **Plane B (Findings)**: Read/Write plane storing scan sessions, discovered assets (domains, subdomains, URLs, IPs, packages, containers), and scanner findings (linked directly to Plane A's vulnerability records).
- **Custom Internal Labeling System**: Automatically classifies CVEs into platform-specific, layer-categorized, and severity-graded identifiers (e.g., `LIN-ANY-KERN-LINUXKERNE-C-2024-1086`) for streamlined querying.
- **Multisource Ingestion Ingestors**:
  - **MITRE CVE List**: Local recursive JSON importer.
  - **NIST NVD API v2.0**: Incremental and full importer with built-in rate-limiting and backoff retries.
  - **CISA KEV**: Known exploited vulnerability mapping.
  - **OSV API**: Resolves GHSA security advisory package ecosystem ranges.
- **Search API & CLI Client**: Simple, fully database-indexed query module and table-formatting CLI search utility.
- **Scanner Integration Bridge**: Integrates nuclei/Friday ASM scanner assets and vulnerability findings directly into Plane B.
- **Self-Contained Local Database**: PATH-aware bash scripts to run a local PostgreSQL instance within the project directory.

---

## 📁 Repository Directory Structure

```
Database_MultiTool/
├── requirements.txt      # Python dependencies (psycopg, requests, tabulate, etc.)
├── .env.example          # Sample database configuration and API credentials
├── .gitignore            # Git exclusions (ignores local database cluster & secrets)
├── sync_cves.py          # Multistream CVE synchronization ingestor
├── label_engine.py       # Custom CPE to internal label generator
├── search.py             # Query API module (used by other tools)
├── cli_search.py         # Command-line query wrapper around search.py
├── asm_bridge.py         # Friday ASM scanner results to Plane B bridge
├── sql/
│   └── schema.sql        # Database tables, indexes, views, and subviews
├── scripts/
│   ├── pg_init.sh        # Initializes local PostgreSQL cluster in ./pgdata
│   ├── pg_start.sh       # Starts the local PostgreSQL instance
│   ├── pg_stop.sh        # Stops the local PostgreSQL instance
│   └── pg_setup_db.sh    # Configures role, creates DB, and applies schema
└── docs/
    ├── SETUP.md          # Setup guides for macOS (Homebrew) and Arch/CachyOS
    ├── LABEL_SCHEME.md   # Structure of the internal label conventions
    ├── INTEGRATION.md    # Integration instructions for future scanners
    └── QUERIES.md        # Reference list of 22 useful SQL queries
```

---

## ⚙️ Quick Start

### 1. Initialize and Start Database
```bash
# Initialize local database cluster
./scripts/pg_init.sh

# Start the cluster
./scripts/pg_start.sh

# Setup roles, databases, and schemas
./scripts/pg_setup_db.sh
```

### 2. Set Up Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Ingestion Sync
```bash
# Incremental or full CVE sync
python sync_cves.py --skip-cvelist
```

### 4. Query the Database
```bash
# Query actionable vulnerabilities
python cli_search.py --actionable --limit 10

# Lookup single CVE
python cli_search.py --cve CVE-2024-1086
```

For detailed guides, please refer to the files under the `docs/` directory.
