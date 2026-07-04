#!/usr/bin/env bash
# linux-triage.sh — Full Linux incident response triage collection
# BTFM Section 4 — Respond | https://www.amazon.com/dp/B077WF4WYV
#
# Usage: sudo ./linux-triage.sh [case_id] [output_dir]
# Collects volatile state first (network, processes), then disk artifacts.
# All output is timestamped and hashed.

set -uo pipefail

CASE_ID="${1:-IR-$(hostname)-$(date +%Y%m%d_%H%M%S)}"
OUTPUT_DIR="${2:-/tmp/${CASE_ID}}"
mkdir -p "$OUTPUT_DIR"

TS=$(date +%Y-%m-%dT%H:%M:%S)
LOG="$OUTPUT_DIR/triage.log"

log() { echo "[$TS] $*" | tee -a "$LOG"; }

log "Linux IR Triage Started"
log "Case ID:  $CASE_ID"
log "Host:     $(hostname -f 2>/dev/null || hostname)"
log "Output:   $OUTPUT_DIR"
log "Analyst:  $(who am i 2>/dev/null | awk '{print $1}' || echo $USER)"
log "Running as: $(id)"

# ── VOLATILE: Network State ───────────────────────────────────────────────────
log "1/9 Network state (VOLATILE — capturing first)"
{
    echo "=== ACTIVE CONNECTIONS (ss) ===" && ss -antp
    echo ""
    echo "=== LISTENING PORTS ===" && ss -tlnp
    echo ""
    echo "=== ROUTING TABLE ===" && ip route 2>/dev/null || route -n
    echo ""
    echo "=== ARP CACHE ===" && arp -an 2>/dev/null || ip neigh
    echo ""
    echo "=== INTERFACES ===" && ip addr 2>/dev/null || ifconfig
    echo ""
    echo "=== DNS ===" && cat /etc/resolv.conf
    echo ""
    echo "=== HOSTS FILE ===" && cat /etc/hosts
    echo ""
    echo "=== OPEN NETWORK FILES ===" && lsof -i -n 2>/dev/null | head -100
} > "$OUTPUT_DIR/network_state.txt" 2>&1

# ── VOLATILE: Process State ───────────────────────────────────────────────────
log "2/9 Process state (VOLATILE)"
{
    echo "=== PROCESS TREE ===" && ps auxf 2>/dev/null || ps aux
    echo ""
    echo "=== PROCESS BINARY PATHS ===" && ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied"
    echo ""
    echo "=== DELETED BINARIES STILL RUNNING ===" && \
        ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" | awk '{print $NF, $9}'
    echo ""
    echo "=== ALL OPEN FILES (lsof) ===" && lsof -n 2>/dev/null | head -500
} > "$OUTPUT_DIR/process_state.txt" 2>&1

# ── VOLATILE: User Sessions ───────────────────────────────────────────────────
log "3/9 User sessions (VOLATILE)"
{
    echo "=== LOGGED IN USERS ===" && who && w
    echo ""
    echo "=== LAST LOGINS ===" && last -F 2>/dev/null | head -50
    echo ""
    echo "=== FAILED LOGINS ===" && lastb -F 2>/dev/null | head -30 || echo "(lastb needs root)"
} > "$OUTPUT_DIR/user_sessions.txt" 2>&1

# ── System Identity ────────────────────────────────────────────────────────────
log "4/9 System identity"
{
    echo "=== SYSTEM ===" && uname -a && uptime
    echo ""
    cat /etc/os-release 2>/dev/null
    echo ""
    echo "=== CPU ===" && lscpu 2>/dev/null | grep -E "Architecture|CPU|Model|Core"
    echo ""
    echo "=== MEMORY ===" && free -h 2>/dev/null
    echo ""
    echo "=== DISK ===" && lsblk 2>/dev/null && df -h
} > "$OUTPUT_DIR/system_identity.txt" 2>&1

# ── User Accounts ─────────────────────────────────────────────────────────────
log "5/9 User accounts"
{
    echo "=== /ETC/PASSWD ===" && cat /etc/passwd
    echo ""
    echo "=== ROOT-EQUIVALENT (UID=0) ===" && awk -F: '$3==0{print "[!] UID=0:", $1}' /etc/passwd
    echo ""
    echo "=== SUDO RIGHTS ===" && cat /etc/sudoers 2>/dev/null && ls /etc/sudoers.d/ 2>/dev/null
    echo ""
    echo "=== NO-PASSWORD ACCOUNTS ===" && \
        awk -F: '($2 == "" || $2 == "!") {print "[!] No password:", $1}' /etc/shadow 2>/dev/null
    echo ""
    echo "=== SSH AUTHORIZED KEYS ===" && \
        for user in $(cut -d: -f1 /etc/passwd); do
            home=$(eval echo "~$user" 2>/dev/null)
            keyfile="$home/.ssh/authorized_keys"
            [[ -f "$keyfile" ]] && { echo "--- $user ---"; cat "$keyfile"; }
        done
} > "$OUTPUT_DIR/user_accounts.txt" 2>&1

# ── Scheduled Tasks & Persistence ─────────────────────────────────────────────
log "6/9 Scheduled tasks and persistence"
{
    echo "=== SYSTEM CRONTAB ===" && cat /etc/crontab 2>/dev/null
    echo ""
    echo "=== CRON.D ===" && cat /etc/cron.d/* 2>/dev/null
    echo ""
    echo "=== USER CRONTABS ===" && \
        for user in $(cut -d: -f1 /etc/passwd); do
            out=$(crontab -u "$user" -l 2>/dev/null)
            [[ -n "$out" ]] && { echo "--- $user ---"; echo "$out"; }
        done
    echo ""
    echo "=== LD.SO.PRELOAD (rootkit indicator) ===" && \
        cat /etc/ld.so.preload 2>/dev/null && echo "[!] exists" || echo "(empty — normal)"
    echo ""
    echo "=== SUID BINARIES ===" && find / -perm -4000 -type f 2>/dev/null | sort
    echo ""
    echo "=== SYSTEMD SERVICES (enabled) ===" && \
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null
} > "$OUTPUT_DIR/persistence.txt" 2>&1

# ── Auth Logs ─────────────────────────────────────────────────────────────────
log "7/9 Auth logs"
{
    for logfile in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure.1; do
        [[ -f "$logfile" ]] && { echo "=== $logfile ==="; cat "$logfile"; }
    done
} > "$OUTPUT_DIR/auth_logs.txt" 2>&1

# Summary of suspicious auth events
{
    grep -h "Accepted password\|Accepted publickey\|Failed password\|Invalid user\|sudo:" \
        /var/log/auth.log /var/log/secure 2>/dev/null | sort | tail -100
} > "$OUTPUT_DIR/auth_summary.txt" 2>&1

# ── Recently Modified Files ────────────────────────────────────────────────────
log "8/9 Recently modified files (last 24h)"
find / \
    -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" -o \
            -path "/run/*" -o -path "$OUTPUT_DIR/*" \) \
    -mtime -1 -type f \
    2>/dev/null | sort > "$OUTPUT_DIR/recently_modified.txt"

# ── Hash Output Files ─────────────────────────────────────────────────────────
log "9/9 Hashing output"
find "$OUTPUT_DIR" -type f -not -name "hashes.sha256" -not -name "triage.log" \
    -exec sha256sum {} \; > "$OUTPUT_DIR/hashes.sha256"

log "Triage complete"
echo ""
echo "Case ID:  $CASE_ID"
echo "Output:   $OUTPUT_DIR"
echo "Files:"
ls -lh "$OUTPUT_DIR/"
