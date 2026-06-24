#!/bin/bash
#
# init-repo.sh - Inizializza un repository backup-shield
#
# Usage:
#   ./init-repo.sh /Volumes/Backup/repo [--encrypt]
#

set -e

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <repo_path> [--encrypt]"
    exit 1
fi

REPO_PATH="$1"
ENCRYPT=false

if [[ "$2" == "--encrypt" ]]; then
    ENCRYPT=true
fi

BINARY="./target/release/backup-shield"

echo "Initializing backup-shield repository at: $REPO_PATH"
echo "Encrypt: $ENCRYPT"

# Create parent directory if needed
PARENT=$(dirname "$REPO_PATH")
mkdir -p "$PARENT"

if [[ "$ENCRYPT" == "true" ]]; then
    $BINARY init "$REPO_PATH" --encrypt
else
    $BINARY init "$REPO_PATH"
fi

echo ""
echo "Repository initialized at: $REPO_PATH"
echo ""
echo "Per fare un backup:"
echo "  $BINARY backup /path/to/source --repo $REPO_PATH -t 'my backup'"
echo ""
echo "Per listare gli snapshot:"
echo "  $BINARY snapshots --repo $REPO_PATH"