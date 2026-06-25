#!/bin/bash
# pg_setup_db.sh - Configure roles, create database, and apply schema.sql
set -e

# Detect PostgreSQL binary paths
for pg_dir in \
    "/opt/homebrew/opt/postgresql@16/bin" \
    "/usr/local/opt/postgresql@16/bin" \
    "/opt/homebrew/bin" \
    "/usr/local/bin" \
    "/usr/bin"; do
    if [ -d "$pg_dir" ]; then
        export PATH="$pg_dir:$PATH"
    fi
done

# Get the script directory and project root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( dirname "$SCRIPT_DIR" )"

cd "$PROJECT_ROOT"

# Ensure PostgreSQL is running
if ! pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
    echo "[!] PostgreSQL cluster is not running. Starting it now..."
    ./scripts/pg_start.sh
fi

echo "[*] Connecting to local PostgreSQL cluster to setup role and database..."

# Create database user role if it doesn't exist
psql -h 127.0.0.1 -p 5432 -U postgres -d template1 -c "
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cyber_admin') THEN
        CREATE ROLE cyber_admin WITH LOGIN PASSWORD 'cyber_secure_pass' CREATEDB SUPERUSER;
    END IF;
END
\$\$;
"

# Create database if it doesn't exist
if ! psql -h 127.0.0.1 -p 5432 -U postgres -d template1 -tc "SELECT 1 FROM pg_database WHERE datname = 'cyber_multitool'" | grep -q 1; then
    echo "[*] Creating database 'cyber_multitool'..."
    psql -h 127.0.0.1 -p 5432 -U postgres -d template1 -c "CREATE DATABASE cyber_multitool OWNER cyber_admin;"
else
    echo "[*] Database 'cyber_multitool' already exists."
fi

echo "[*] Applying schema.sql to 'cyber_multitool'..."
PGPASSWORD=cyber_secure_pass psql -h 127.0.0.1 -p 5432 -U cyber_admin -d cyber_multitool -f ./sql/schema.sql

echo "[+] Database setup completed successfully!"
