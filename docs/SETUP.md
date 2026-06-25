# Setup Guide — CYBER_MultiTool CVE Database

This document details the configuration and installation steps for macOS (Apple Silicon + Homebrew) and CachyOS/Arch Linux.

## Prerequisites
- **Python**: 3.11+
- **PostgreSQL**: 16

---

## 1. System Dependency Installation

### macOS (via Homebrew)
Install Python, PostgreSQL 16, and LibPQ (needed by psycopg3):
```bash
# Install packages
brew install python@3.11 postgresql@16 libpq

# Verify installation
python3 --version
postgres --version
```

### CachyOS / Arch Linux (via Pacman)
Install dependencies using pacman:
```bash
# Install packages
sudo pacman -S python postgresql postgresql-libs

# Verify installation
python3 --version
postgres --version
```

---

## 2. Python Environment Setup

Navigate to the project root directory and create a virtual environment:
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

Create your active `.env` configuration file from the provided template:
```bash
cp .env.example .env
```
*(Optional)* Add your `NVD_API_KEY` to the `.env` file to increase NVD rate limits (reducing page-request sleep times from 6.1s to 0.7s).

---

## 3. Database Cluster Configuration

This project runs PostgreSQL in a self-contained local cluster inside the project directory (`./pgdata`).

Initialize, start, and set up the schema:
```bash
# 1. Initialize the local database cluster
./scripts/pg_init.sh

# 2. Start the local database instance
./scripts/pg_start.sh

# 3. Create the roles, databases, and Plane A/B schemas
./scripts/pg_setup_db.sh
```

To stop the database cluster at any time, run:
```bash
./scripts/pg_stop.sh
```

---

## 4. Running the Synchronization Pipeline

The sync script (`sync_cves.py`) fetches, parses, and merges data from all four core upstream sources.

### Run a standard sync
```bash
python sync_cves.py
```

### Run a full historic sync (NVD page-by-page history without date filtering)
```bash
python sync_cves.py --full
```

### Skip specific ingestors (e.g. if you do not have a local MITRE clone)
```bash
python sync_cves.py --skip-cvelist
```

### Regenerate all internal labels
```bash
python sync_cves.py --regen-labels
```

---

## 5. Querying the Database via CLI

Use `cli_search.py` to search database records:
```bash
# Search for critical vulnerabilities affecting redhat
python cli_search.py --search "redhat" --severity critical

# Look up an enriched CVE by ID
python cli_search.py --cve CVE-2024-1086

# Output results in JSON format
python cli_search.py --search "apache" --json
```
