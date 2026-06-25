#!/bin/bash
# pg_start.sh - Start local PostgreSQL cluster
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

if [ ! -d "./pgdata" ]; then
    echo "[!] ./pgdata directory does not exist. Run pg_init.sh first."
    exit 1
fi

# Check if port 5432 is already in use
if lsof -Pi :5432 -sTCP:LISTEN -t >/dev/null ; then
    echo "[!] Port 5432 is already in use. PostgreSQL might be running already."
    exit 0
fi

echo "[*] Starting PostgreSQL cluster..."
pg_ctl -D ./pgdata -l ./pgdata/logfile start

# Wait for database server to start accepting connections
sleep 2

pg_isready -h 127.0.0.1 -p 5432
echo "[+] PostgreSQL cluster started successfully."
