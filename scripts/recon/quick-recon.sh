#!/usr/bin/env bash
# Script: quick-recon.sh
# Purpose: Common nmap scan profiles for blue team baseline and verification
# Usage: ./quick-recon.sh <target> [profile]
# Requirements: nmap
# BTFM Reference: Section 1 — Recon

set -euo pipefail

TARGET="${1:-}"
PROFILE="${2:-default}"
OUTDIR="./recon-output"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target-ip-or-range> [profile]"
  echo "Profiles: default | fast | full | udp | vuln"
  exit 1
fi

mkdir -p "$OUTDIR"
OUTFILE="$OUTDIR/${TARGET//\//_}-${PROFILE}-${TIMESTAMP}"

echo "[*] Target:  $TARGET"
echo "[*] Profile: $PROFILE"
echo "[*] Output:  $OUTFILE"
echo ""

case "$PROFILE" in
  fast)
    # Top 100 ports, version detection — quick situational awareness
    nmap -sV --top-ports 100 -T4 -oA "$OUTFILE" "$TARGET"
    ;;
  full)
    # All TCP ports, version + OS detection, default scripts
    nmap -sV -sC -O -p- -T4 -oA "$OUTFILE" "$TARGET"
    ;;
  udp)
    # Top 20 UDP ports — often overlooked in baseline checks
    nmap -sU --top-ports 20 -T4 -oA "$OUTFILE" "$TARGET"
    ;;
  vuln)
    # NSE vuln scripts — use only on systems you own or have written auth for
    nmap -sV --script vuln -T4 -oA "$OUTFILE" "$TARGET"
    ;;
  default|*)
    # Top 1000 ports, version detection, default scripts — standard first pass
    nmap -sV -sC -T4 -oA "$OUTFILE" "$TARGET"
    ;;
esac

echo ""
echo "[+] Complete. Results saved to $OUTFILE.{nmap,gnmap,xml}"
