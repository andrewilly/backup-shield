#!/bin/bash
# BackupShield macOS System Recovery Script
# Run this script from Terminal in macOS Recovery Mode
# Copyright (c) 2026 André Willy Rizzo. All rights reserved.
#
# Usage:  ./recovery-macos.sh
#         ./recovery-macos.sh /Volumes/MyBackupDrive

set -e

# ── Safety guard: prevent runaway recursion ──────────────────────────
MAX_RECURSION=10
if [ -z "$RECOVERY_SCRIPT_DEPTH" ]; then
    RECOVERY_SCRIPT_DEPTH=0
fi
if [ "$RECOVERY_SCRIPT_DEPTH" -ge "$MAX_RECURSION" ]; then
    echo "FATAL: Recursion limit reached ($MAX_RECURSION). Aborting."
    exit 1
fi

# ── Determine script directory (works when invoked via symlink too) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOVERY_BIN="$SCRIPT_DIR/backup-shield-recovery"

# ── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            BackupShield macOS System Recovery                ║${NC}"
echo -e "${BLUE}║          Copyright (c) 2026 André Willy Rizzo                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Check we're in Recovery Mode ─────────────────────────────────────
if [ ! -f "/.fseventsd" ] && [ ! -d "/System/Library/CoreServices" ]; then
    echo -e "${YELLOW}Warning: This script is designed to run from macOS Recovery Mode.${NC}"
    echo -e "${YELLOW}Some features may not work outside of Recovery.${NC}"
fi

# ── Find repository ───────────────────────────────────────────────────
# Allow the user to pass the repo path as the first argument
REPO_PATH=""
if [ -n "$1" ]; then
    if [ -f "$1/config.toml" ]; then
        REPO_PATH="$1"
    else
        echo -e "${RED}Error: '$1' does not contain a valid backup-shield repository.${NC}"
        exit 1
    fi
fi

if [ -z "$REPO_PATH" ]; then
    DEFAULT_VOLUME="/Volumes/BACKUPSHIELD"
    if [ -f "$DEFAULT_VOLUME/config.toml" ]; then
        REPO_PATH="$DEFAULT_VOLUME"
    elif [ -f "$DEFAULT_VOLUME/system-manifest.json" ]; then
        REPO_PATH="$DEFAULT_VOLUME"
    else
        echo "Scanning for backup repositories..."
        for vol in /Volumes/*; do
            if [ -f "$vol/config.toml" ]; then
                echo -e "  ${GREEN}Found repository at: $vol${NC}"
                if [ -z "$REPO_PATH" ]; then
                    REPO_PATH="$vol"
                fi
            fi
        done
    fi
fi

if [ -z "$REPO_PATH" ]; then
    echo -e "${RED}Error: No backup-shield repository found.${NC}"
    echo ""
    echo "Connect your backup drive and try again."
    echo ""
    echo "To manually specify a repository:"
    echo "  $RECOVERY_BIN restore-system --repo /Volumes/YourDrive --target /Volumes/MacintoshHD"
    exit 1
fi

echo ""
echo -e "${GREEN}Repository found at: $REPO_PATH${NC}"

# ── Check that the recovery binary exists ────────────────────────────
if [ ! -x "$RECOVERY_BIN" ]; then
    echo -e "${RED}Error: recovery binary not found at $RECOVERY_BIN${NC}"
    echo ""
    echo "Expected to find 'backup-shield-recovery' next to this script."
    exit 1
fi

# ── Check for system manifest ────────────────────────────────────────
MANIFEST="$REPO_PATH/system-manifest.json"
if [ -f "$MANIFEST" ]; then
    echo ""
    echo -e "${BLUE}System backup information:${NC}"
    "$RECOVERY_BIN" restore-system --repo "$REPO_PATH" --info || echo "  (could not read manifest)"
    echo ""
else
    echo -e "${YELLOW}No system manifest found. This may be a file-only backup.${NC}"
fi

echo ""
echo -e "${BLUE}Available commands:${NC}"
echo ""
echo "  1) Restore entire system (reinstall macOS + restore data)"
echo "  2) Restore files only (skip macOS reinstall)"
echo "  3) List snapshots"
echo "  4) Verify backup integrity"
echo "  5) Show system info"
echo "  6) Open shell"
echo "  7) Exit"
echo ""

read -p "Select option [1-7]: " OPTION
echo ""

case $OPTION in
    1)
        echo -e "${BLUE}Full System Restore${NC}"
        echo ""
        echo "This will:"
        echo "  1. Show available target volumes"
        echo "  2. Guide you through macOS reinstallation"
        echo "  3. Restore all your data"
        echo ""

        # List available volumes
        echo -e "${YELLOW}Available volumes:${NC}"
        diskutil list internal | grep -E "^\s+[0-9]+:" || diskutil list
        echo ""

        read -p "Enter target volume path (e.g., /Volumes/MacintoshHD): " TARGET

        if [ ! -d "$TARGET" ]; then
            echo -e "${RED}Error: Volume '$TARGET' does not exist.${NC}"
            echo "Use Disk Utility to prepare the volume first."
            exit 1
        fi

        echo ""
        echo "You need to reinstall macOS first:"
        echo "  1. Quit this script (option 7)"
        echo "  2. Use 'Reinstall macOS' from the Recovery menu"
        echo "  3. Select '$TARGET' as destination"
        echo "  4. After installation, open Terminal and run:"
        echo ""
        echo "     cd \"$SCRIPT_DIR\""
        echo "     ./backup-shield-recovery restore-system --repo \"$REPO_PATH\" --target \"$TARGET\" --skip-os-install"
        echo ""
        read -p "Press Enter to continue..."
        ;;
    2)
        echo -e "${BLUE}File-Only Restore${NC}"
        echo ""
        read -p "Enter target volume path (e.g., /Volumes/MacintoshHD): " TARGET

        if [ ! -d "$TARGET" ]; then
            echo -e "${RED}Error: Volume '$TARGET' does not exist.${NC}"
            exit 1
        fi

        echo ""
        echo "Restoring data to $TARGET..."
        "$RECOVERY_BIN" restore-system --repo "$REPO_PATH" --target "$TARGET" --skip-os-install
        ;;
    3)
        echo -e "${BLUE}Snapshots:${NC}"
        "$RECOVERY_BIN" snapshots --repo "$REPO_PATH" || echo -e "${RED}Failed to list snapshots.${NC}"
        echo ""
        read -p "Press Enter to continue..."
        ;;
    4)
        echo -e "${BLUE}Verifying backup integrity...${NC}"
        "$RECOVERY_BIN" verify --repo "$REPO_PATH" || echo -e "${RED}Verification reported errors.${NC}"
        echo ""
        read -p "Press Enter to continue..."
        ;;
    5)
        echo -e "${BLUE}System Information:${NC}"
        echo ""
        echo "macOS version:"
        sw_vers 2>/dev/null || echo "  (not available)"
        echo ""
        echo "Hardware:"
        sysctl -n hw.model 2>/dev/null || echo "  (not available)"
        echo ""
        echo "Memory:"
        sysctl -n hw.memsize 2>/dev/null | awk '{print $0/1073741824 " GB"}' || echo "  (not available)"
        echo ""
        echo "Disks:"
        diskutil list 2>/dev/null || echo "  (not available)"
        echo ""
        read -p "Press Enter to continue..."
        ;;
    6)
        echo -e "${YELLOW}Starting shell. Type 'exit' to return to the menu.${NC}"
        echo ""
        LOCAL_SHELL=/bin/bash
        if [ -f /bin/zsh ]; then
            LOCAL_SHELL=/bin/zsh
        fi
        $LOCAL_SHELL
        ;;
    7)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option.${NC}"
        ;;
esac

echo ""
echo -e "${YELLOW}Returning to menu...${NC}"
RECOVERY_SCRIPT_DEPTH=$(( RECOVERY_SCRIPT_DEPTH + 1 ))
export RECOVERY_SCRIPT_DEPTH
exec "$0"
