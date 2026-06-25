#!/bin/bash
# pg_stop.sh - Stop local PostgreSQL cluster
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
    echo "[!] ./pgdata directory does not exist."
    exit 1
fi

echo "[*] Stopping PostgreSQL cluster..."
pg_ctl -D ./pgdata stop
echo "[+] PostgreSQL cluster stopped."
