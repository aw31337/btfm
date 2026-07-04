#!/usr/bin/env bash
# network-monitor.sh — Continuous network baseline and anomaly detection
# BTFM Section 3 — Detect | https://www.amazon.com/dp/B077WF4WYV
#
# Modes:
#   baseline  — capture network baseline (connections, listeners, routes)
#   watch     — monitor for changes vs. baseline and alert on anomalies
#   capture   — rolling tcpdump capture with rotation
#
# Usage:
#   ./network-monitor.sh baseline [output_dir]
#   ./network-monitor.sh watch [baseline_dir] [interval_seconds]
#   ./network-monitor.sh capture [output_dir] [iface] [duration_sec]

set -uo pipefail

MODE="${1:-baseline}"
IFACE="${IFACE:-any}"

log() { echo "[$(date +%T)] $*" >&2; }
warn() { echo "[$(date +%T)] [ALERT] $*" | tee -a "${ALERT_LOG:-/tmp/net_alerts.log}"; }

# ══════════════════════════════════════════════════════════════════════════════
# BASELINE MODE
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "baseline" ]]; then
    OUTPUT_DIR="${2:-/tmp/net_baseline_$(date +%Y%m%d_%H%M%S)}"
    mkdir -p "$OUTPUT_DIR"
    log "Capturing network baseline → $OUTPUT_DIR"

    # Active connections
    ss -antp > "$OUTPUT_DIR/connections.txt"
    netstat -antp 2>/dev/null >> "$OUTPUT_DIR/connections.txt" || true

    # Listening ports
    ss -tlnp > "$OUTPUT_DIR/listeners.txt"

    # Routing table
    ip route > "$OUTPUT_DIR/routes.txt"

    # ARP cache
    arp -an 2>/dev/null > "$OUTPUT_DIR/arp.txt" || ip neigh > "$OUTPUT_DIR/arp.txt"

    # Interfaces
    ip addr > "$OUTPUT_DIR/interfaces.txt"

    # DNS config
    cat /etc/resolv.conf > "$OUTPUT_DIR/dns.txt"

    # Firewall rules
    iptables -L -n -v 2>/dev/null > "$OUTPUT_DIR/firewall.txt" || true
    nft list ruleset 2>/dev/null >> "$OUTPUT_DIR/firewall.txt" || true

    # Top talkers (60s capture)
    if command -v tcpdump &>/dev/null; then
        log "Capturing 60s of traffic for top talkers"
        timeout 60 tcpdump -nn -q 2>/dev/null \
            | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -20 \
            > "$OUTPUT_DIR/top_talkers.txt" || true
    fi

    # Hash baseline
    sha256sum "$OUTPUT_DIR/"* > "$OUTPUT_DIR/baseline.sha256"

    log "Baseline saved to $OUTPUT_DIR"
    echo "$OUTPUT_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# WATCH MODE — diff against baseline
# ══════════════════════════════════════════════════════════════════════════════
elif [[ "$MODE" == "watch" ]]; then
    BASELINE_DIR="${2:-}"
    INTERVAL="${3:-60}"
    ALERT_LOG="/tmp/net_alerts_$(date +%Y%m%d).log"

    if [[ -z "$BASELINE_DIR" || ! -d "$BASELINE_DIR" ]]; then
        echo "Usage: $0 watch <baseline_dir> [interval_seconds]" >&2
        exit 1
    fi

    log "Watching network changes vs. baseline: $BASELINE_DIR"
    log "Alert interval: ${INTERVAL}s | Alerts: $ALERT_LOG"

    while true; do
        CURRENT_DIR=$(mktemp -d)
        ss -antp > "$CURRENT_DIR/connections.txt"
        ss -tlnp > "$CURRENT_DIR/listeners.txt"
        ip route > "$CURRENT_DIR/routes.txt"

        # New listeners
        NEW_LISTENERS=$(comm -13 \
            <(sort "$BASELINE_DIR/listeners.txt") \
            <(sort "$CURRENT_DIR/listeners.txt") \
        )
        if [[ -n "$NEW_LISTENERS" ]]; then
            warn "NEW LISTENING PORT DETECTED:"
            warn "$NEW_LISTENERS"
        fi

        # Removed listeners (service down)
        REMOVED_LISTENERS=$(comm -23 \
            <(sort "$BASELINE_DIR/listeners.txt") \
            <(sort "$CURRENT_DIR/listeners.txt") \
        )
        if [[ -n "$REMOVED_LISTENERS" ]]; then
            warn "LISTENER REMOVED (service stopped):"
            warn "$REMOVED_LISTENERS"
        fi

        # Route changes
        ROUTE_DIFF=$(diff "$BASELINE_DIR/routes.txt" "$CURRENT_DIR/routes.txt" 2>/dev/null)
        if [[ -n "$ROUTE_DIFF" ]]; then
            warn "ROUTING TABLE CHANGED:"
            warn "$ROUTE_DIFF"
        fi

        # New established connections to external IPs
        EXTERNAL=$(ss -antp state established 2>/dev/null \
            | awk '{print $5}' \
            | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|\*)" \
            | sort | uniq)
        if [[ -n "$EXTERNAL" ]]; then
            log "External connections active: $EXTERNAL"
        fi

        rm -rf "$CURRENT_DIR"
        sleep "$INTERVAL"
    done

# ══════════════════════════════════════════════════════════════════════════════
# CAPTURE MODE — rolling tcpdump
# ══════════════════════════════════════════════════════════════════════════════
elif [[ "$MODE" == "capture" ]]; then
    OUTPUT_DIR="${2:-/tmp/captures}"
    IFACE="${3:-any}"
    DURATION="${4:-3600}"  # default: rotate hourly

    mkdir -p "$OUTPUT_DIR"

    if ! command -v tcpdump &>/dev/null; then
        echo "Error: tcpdump not found" >&2; exit 1
    fi

    log "Starting rolling packet capture on $IFACE, rotating every ${DURATION}s"
    log "Output: $OUTPUT_DIR"

    exec tcpdump -pni "$IFACE" -s65535 -G "$DURATION" \
        -w "$OUTPUT_DIR/capture_%Y-%m-%d_%H:%M:%S.pcap" \
        2>>"$OUTPUT_DIR/tcpdump.log"

else
    echo "Usage: $0 {baseline|watch|capture} [options]" >&2
    echo "  baseline [output_dir]                     Snapshot current network state" >&2
    echo "  watch <baseline_dir> [interval_sec]       Alert on changes vs. baseline" >&2
    echo "  capture [output_dir] [iface] [rotate_sec] Rolling pcap capture" >&2
    exit 1
fi
