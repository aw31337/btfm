#!/usr/bin/env bash
# Script: baseline-capture.sh
# Purpose: Capture a network and process baseline for change detection
# Usage: sudo ./baseline-capture.sh [output-dir]
# Requirements: bash, ss, ps, sha256sum, ip
# BTFM Reference: Section 2 — Network Baseline

set -euo pipefail

OUTDIR="${1:-./baseline-$(hostname)-$(date +%Y%m%d)}"
mkdir -p "$OUTDIR"

echo "[*] Capturing baseline for $(hostname) at $(date)"

# Open connections
ss -tulpan > "$OUTDIR/connections.txt"
echo "[+] Connections captured"

# Listening services only
ss -tulpn > "$OUTDIR/listening.txt"
echo "[+] Listening services captured"

# Routing table
ip route > "$OUTDIR/routes.txt"
ip neigh > "$OUTDIR/arp.txt"
echo "[+] Routing/ARP captured"

# Running processes
ps aux > "$OUTDIR/processes.txt"
echo "[+] Processes captured"

# Loaded kernel modules
lsmod > "$OUTDIR/modules.txt" 2>/dev/null || true

# Hashes of key system binaries (detect tampering)
find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} \; 2>/dev/null \
  > "$OUTDIR/binary-hashes.txt"
echo "[+] Binary hashes captured"

# Scheduled tasks
crontab -l > "$OUTDIR/user-crontab.txt" 2>/dev/null || true
ls /etc/cron* /var/spool/cron/ >> "$OUTDIR/system-cron.txt" 2>/dev/null || true

echo ""
echo "[+] Baseline saved to: $OUTDIR"
echo ""
echo "To compare against a future state:"
echo "  diff $OUTDIR/connections.txt <new-baseline>/connections.txt"
echo "  diff $OUTDIR/binary-hashes.txt <new-baseline>/binary-hashes.txt"
