#!/usr/bin/env bash
# Script: rapid-triage.sh
# Purpose: Linux rapid triage — collect volatile system state for blue team review
# Usage: sudo ./rapid-triage.sh [output-dir]
# Requirements: bash, standard Linux tools (ps, ss, who, last, find)
# BTFM Reference: Section 3 — Linux Triage

set -euo pipefail

OUTDIR="${1:-./triage-$(hostname)-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/triage.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }
run() { log "CMD: $*"; "$@" 2>&1 | tee -a "$OUTDIR/$1.txt" || true; }

log "=== BTFM Rapid Triage: $(hostname) ==="
log "Started by: $(whoami)"
log "Output: $OUTDIR"

# Volatile — collect first
log "--- Volatile State ---"
run date
run who
run w
run last -n 20
run ps aux
run ss -tulpan
run netstat -rn 2>/dev/null || ip route
run arp -n

# Logged-in users and auth
log "--- Auth & Accounts ---"
run cat /etc/passwd
run cat /etc/group
run cat /etc/sudoers
run lastlog
grep -v '^#' /etc/crontab > "$OUTDIR/crontab.txt" 2>/dev/null || true
ls /etc/cron.* /var/spool/cron/crontabs/ >> "$OUTDIR/crontab.txt" 2>/dev/null || true

# Persistence locations
log "--- Persistence ---"
find /etc/init.d /etc/rc*.d /etc/systemd/system /lib/systemd/system \
     -maxdepth 2 -type f 2>/dev/null > "$OUTDIR/services.txt" || true
find /tmp /var/tmp /dev/shm -type f -newer /etc/passwd 2>/dev/null > "$OUTDIR/tmp-new-files.txt" || true

# Recent file activity (last 24h)
log "--- Recent File Activity ---"
find / -xdev -type f -newer /proc/1 -not -path '/proc/*' -not -path '/sys/*' \
    2>/dev/null | head -200 > "$OUTDIR/recently-modified.txt" || true

# Hashes of running binaries
log "--- Running Binary Hashes ---"
ps aux --no-headers | awk '{print $11}' | sort -u | \
    while read -r bin; do
        [[ -f "$bin" ]] && sha256sum "$bin" 2>/dev/null || true
    done > "$OUTDIR/running-binary-hashes.txt"

# Logs snapshot
log "--- Logs ---"
cp /var/log/auth.log "$OUTDIR/" 2>/dev/null || cp /var/log/secure "$OUTDIR/" 2>/dev/null || true
cp /var/log/syslog   "$OUTDIR/" 2>/dev/null || cp /var/log/messages "$OUTDIR/" 2>/dev/null || true
journalctl --since "24 hours ago" > "$OUTDIR/journal-24h.txt" 2>/dev/null || true

log "=== Triage complete. Review $OUTDIR ==="
echo ""
echo "Key files to review first:"
echo "  $OUTDIR/ss.txt              — open connections"
echo "  $OUTDIR/ps.txt              — running processes"
echo "  $OUTDIR/recently-modified.txt — files changed since boot"
echo "  $OUTDIR/auth.log            — authentication events"
