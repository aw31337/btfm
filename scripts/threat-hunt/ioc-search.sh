#!/usr/bin/env bash
# Script: ioc-search.sh
# Purpose: Search system logs and filesystem for IOCs (IPs, domains, hashes, strings)
# Usage: ./ioc-search.sh -f iocs.txt [-l /var/log] [-o results.txt]
# Requirements: bash, grep, find, sha256sum
# BTFM Reference: Section 5 — Threat Hunting

set -euo pipefail

IOC_FILE=""
LOG_DIR="/var/log"
OUTFILE="./ioc-results-$(date +%Y%m%d-%H%M%S).txt"

usage() {
  echo "Usage: $0 -f <ioc-file> [-l <log-dir>] [-o <output-file>]"
  echo "IOC file format: one IOC per line (IP, domain, hash, or string)"
  exit 1
}

while getopts "f:l:o:h" opt; do
  case $opt in
    f) IOC_FILE="$OPTARG" ;;
    l) LOG_DIR="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    *) usage ;;
  esac
done

[[ -z "$IOC_FILE" ]] && usage
[[ ! -f "$IOC_FILE" ]] && { echo "IOC file not found: $IOC_FILE"; exit 1; }

HITS=0

log_hit() {
  echo "[HIT] $*" | tee -a "$OUTFILE"
  ((HITS++)) || true
}

echo "=== IOC Hunt: $(date) ===" | tee "$OUTFILE"
echo "IOC file: $IOC_FILE" | tee -a "$OUTFILE"
echo "Log dir:  $LOG_DIR" | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

while IFS= read -r ioc || [[ -n "$ioc" ]]; do
  # Skip blanks and comments
  [[ -z "$ioc" || "$ioc" =~ ^# ]] && continue
  ioc=$(echo "$ioc" | tr -d '[:space:]')

  echo "[*] Searching: $ioc" | tee -a "$OUTFILE"

  # Search logs
  grep -rl "$ioc" "$LOG_DIR" 2>/dev/null | while read -r f; do
    log_hit "Log match in $f"
    grep -n "$ioc" "$f" 2>/dev/null | head -5 >> "$OUTFILE"
  done

  # Search /tmp and /var/tmp (common staging areas)
  find /tmp /var/tmp /dev/shm -type f 2>/dev/null | xargs grep -l "$ioc" 2>/dev/null | while read -r f; do
    log_hit "Staging area match: $f"
  done

  # If it looks like a SHA256 hash, check running binaries
  if [[ ${#ioc} -eq 64 && "$ioc" =~ ^[0-9a-fA-F]+$ ]]; then
    find /usr /bin /sbin /tmp /var/tmp -type f -exec sha256sum {} \; 2>/dev/null | \
      grep -i "$ioc" | while read -r match; do
        log_hit "Hash match: $match"
      done
  fi

  # Check /etc/hosts and DNS cache for domain IOCs
  if [[ "$ioc" =~ \. && ! "$ioc" =~ ^[0-9.]+$ ]]; then
    grep -i "$ioc" /etc/hosts 2>/dev/null && log_hit "hosts file match: $ioc" || true
  fi

done < "$IOC_FILE"

echo "" | tee -a "$OUTFILE"
echo "=== Hunt complete. Total hits: $HITS ===" | tee -a "$OUTFILE"
echo "Full results: $OUTFILE"
