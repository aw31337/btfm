#!/usr/bin/env bash
# ssl-cert-check.sh — Bulk SSL/TLS certificate inspection
# BTFM Section 3 — Detect | https://www.amazon.com/dp/B077WF4WYV
#
# Usage:
#   ./ssl-cert-check.sh <host> [port]            # Single host
#   ./ssl-cert-check.sh -f hosts.txt             # File with host:port per line
#   ./ssl-cert-check.sh -r 192.168.1.0/24 443    # CIDR range (requires nmap)
#
# Output: Tab-separated: HOST | PORT | SUBJECT | ISSUER | EXPIRY | SELF-SIGNED | DAYS_LEFT

set -uo pipefail

TIMEOUT=5
OUTPUT_FILE="/tmp/ssl_check_$(date +%Y%m%d_%H%M%S).tsv"

check_cert() {
    local host="$1"
    local port="${2:-443}"

    local cert_info
    cert_info=$(openssl s_client -connect "${host}:${port}" \
        -servername "$host" \
        -timeout "$TIMEOUT" \
        </dev/null 2>/dev/null \
        | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256 2>/dev/null)

    if [[ -z "$cert_info" ]]; then
        printf "%s\t%s\tERROR: no cert retrieved\t-\t-\t-\t-\n" "$host" "$port"
        return
    fi

    local subject issuer enddate fingerprint
    subject=$(echo "$cert_info" | grep "^subject" | sed 's/subject=//')
    issuer=$(echo "$cert_info" | grep "^issuer" | sed 's/issuer=//')
    enddate=$(echo "$cert_info" | grep "^notAfter" | sed 's/notAfter=//')
    fingerprint=$(echo "$cert_info" | grep "SHA256 Fingerprint" | sed 's/SHA256 Fingerprint=//')

    # Days until expiry
    local expiry_epoch now_epoch days_left
    expiry_epoch=$(date -d "$enddate" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$enddate" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    # Self-signed check
    local self_signed="No"
    local subject_cn issuer_cn
    subject_cn=$(echo "$subject" | grep -o 'CN=[^,/]*' | head -1)
    issuer_cn=$(echo "$issuer" | grep -o 'CN=[^,/]*' | head -1)
    [[ "$subject_cn" == "$issuer_cn" ]] && self_signed="YES - SELF-SIGNED"

    # Flag expiring within 30 days
    local expiry_flag=""
    if (( days_left < 0 )); then
        expiry_flag=" [EXPIRED]"
    elif (( days_left < 30 )); then
        expiry_flag=" [EXPIRING SOON]"
    fi

    printf "%s\t%s\t%s\t%s\t%s%s\t%s\t%d days\n" \
        "$host" "$port" "$subject_cn" "$issuer_cn" "$enddate" "$expiry_flag" \
        "$self_signed" "$days_left"
}

print_header() {
    printf "HOST\tPORT\tSUBJECT CN\tISSUER CN\tEXPIRY\tSELF-SIGNED\tDAYS LEFT\n"
    printf "%s\n" "$(printf '=%.0s' {1..100})"
}

if [[ "${1:-}" == "-f" ]]; then
    # File mode: host:port or host per line
    file="${2:-hosts.txt}"
    print_header | tee "$OUTPUT_FILE"
    while IFS=: read -r host port; do
        port="${port:-443}"
        check_cert "$host" "$port" | tee -a "$OUTPUT_FILE"
    done < "$file"

elif [[ "${1:-}" == "-r" ]]; then
    # CIDR range mode
    cidr="${2:-}"
    port="${3:-443}"
    if ! command -v nmap &>/dev/null; then
        echo "Error: nmap required for range scan" >&2; exit 1
    fi
    print_header | tee "$OUTPUT_FILE"
    nmap -p "$port" --open -n -oG - "$cidr" 2>/dev/null \
    | awk '/open/{print $2}' \
    | while read -r host; do
        check_cert "$host" "$port" | tee -a "$OUTPUT_FILE"
    done

else
    # Single host mode
    host="${1:?Usage: $0 <host> [port]}"
    port="${2:-443}"
    print_header
    check_cert "$host" "$port"
fi

echo "" >&2
echo "Full output: $OUTPUT_FILE" >&2
