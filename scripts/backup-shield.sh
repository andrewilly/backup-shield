#!/bin/bash
#
# backup-shield.sh - Script di backup per macOS
#
# ATTENZIONE: Questo è un backup manuale base. NON è un sostituto di Time Machine.
# Non include: backup automatici, versioning, bootable recovery.
#
# Requisiti:
#   - Rust compilato: cargo build --release
#   - Repository inizializzato: ./target/release/backup-shield init /Volumes/Backup/repo
#
# Usage:
#   ./backup-shield.sh /Users/utente/Documents /Volumes/Backup/repo
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configurazione
REPO_PATH=""
SOURCE_PATH=""
TAG=""
BACKUP_NAME=""
KEEP_DAILY=7
KEEP_WEEKLY=4

# Usage
usage() {
    echo "Usage: $0 <source_path> <repo_path> [options]"
    echo ""
    echo "Arguments:"
    echo "  source_path    Path da backuppare (es. /Users/utente/Documents)"
    echo "  repo_path      Path del repository backup-shield"
    echo ""
    echo "Options:"
    echo "  -t, --tag TAG          Tag per questo backup"
    echo "  -n, --name NAME       Nome del backup (default: auto)"
    echo "  --keep-daily N        Backup giornalieri da mantenere (default: 7)"
    echo "  --keep-weekly N       Backup settimanali da mantenere (default: 4)"
    echo "  -h, --help            Questo help"
    echo ""
    echo "Esempio:"
    echo "  $0 /Users/utente/Documents /Volumes/Backup/repo -t \"backup giornaliero\""
    exit 1
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -n|--name)
            BACKUP_NAME="$2"
            shift 2
            ;;
        --keep-daily)
            KEEP_DAILY="$2"
            shift 2
            ;;
        --keep-weekly)
            KEEP_WEEKLY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
        *)
            if [[ -z "$SOURCE_PATH" ]]; then
                SOURCE_PATH="$1"
            elif [[ -z "$REPO_PATH" ]]; then
                REPO_PATH="$1"
            else
                echo -e "${RED}Too many arguments${NC}"
                usage
            fi
            shift
            ;;
    esac
done

# Validate
if [[ -z "$SOURCE_PATH" ]] || [[ -z "$REPO_PATH" ]]; then
    echo -e "${RED}Source and repo paths are required${NC}"
    usage
fi

if [[ ! -d "$SOURCE_PATH" ]]; then
    echo -e "${RED}Source path does not exist: $SOURCE_PATH${NC}"
    exit 1
fi

if [[ ! -d "$REPO_PATH" ]]; then
    echo -e "${RED}Repository does not exist: $REPO_PATH${NC}"
    echo "Inizializza con: ./backup-shield init $REPO_PATH"
    exit 1
fi

# Binary path
BINARY="./target/release/backup-shield"

if [[ ! -f "$BINARY" ]]; then
    echo -e "${YELLOW}Compilazione del binary...${NC}"
    cargo build --release
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  BackupShield - macOS Backup Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Source:      $SOURCE_PATH"
echo "Repository:  $REPO_PATH"
echo "Tag:         ${TAG:-none}"
echo "Keep:        $KEEP_DAILY daily, $KEEP_WEEKLY weekly"
echo ""

# Check disk space
SOURCE_SIZE=$(du -sh "$SOURCE_PATH" 2>/dev/null | cut -f1)
echo -e "Source size: ${YELLOW}$SOURCE_SIZE${NC}"

if [[ ! -d "$REPO_PATH" ]]; then
    echo -e "${RED}Repository not found at $REPO_PATH${NC}"
    echo "Run: ./backup-shield init $REPO_PATH"
    exit 1
fi

# Run backup
echo -e "${GREEN}Starting backup...${NC}"
START_TIME=$(date +%s)

TAG_ARGS=""
if [[ -n "$TAG" ]]; then
    TAG_ARGS="-t \"$TAG\""
fi

$BINARY backup "$SOURCE_PATH" --repo "$REPO_PATH" $TAG_ARGS

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${GREEN}Backup completed in ${DURATION}s${NC}"

# Prune old backups
echo -e "${GREEN}Pruning old backups...${NC}"
$BINARY prune "$REPO_PATH" --keep-daily "$KEEP_DAILY" --keep-weekly "$KEEP_WEEKLY"

# Verify
echo -e "${GREEN}Verifying repository...${NC}"
$BINARY verify "$REPO_PATH" --quick

# Show stats
echo ""
echo -e "${GREEN}Repository stats:${NC}"
$BINARY stats "$REPO_PATH"

echo ""
echo -e "${GREEN}Backup completato con successo!${NC}"