# OpenSSL & TLS Certificate Forensics

> BTFM Cheatsheet | Section 3 — Detect  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

---

## Get a Certificate from a Live Host

```bash
# Connect and dump cert info
openssl s_client -connect <HOST>:443

# Quick — suppress session output, cert to stdout
openssl s_client -connect <HOST>:443 </dev/null 2>/dev/null

# Save cert to PEM file
openssl s_client -connect <HOST>:443 </dev/null 2>/dev/null \
    | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > cert.pem

# Specific SNI (for shared-IP hosts)
openssl s_client -connect <HOST>:443 -servername <HOSTNAME>
```

---

## Examine a Certificate

```bash
# Full cert text
openssl x509 -text -in cert.pem

# Key fields only
openssl x509 -in cert.pem -noout -issuer -subject -startdate -enddate -fingerprint

# Subject only
openssl x509 -in cert.pem -noout -subject

# Issuer only
openssl x509 -in cert.pem -noout -issuer

# Expiry date
openssl x509 -in cert.pem -noout -enddate

# SHA256 fingerprint
openssl x509 -in cert.pem -noout -fingerprint -sha256

# Verify the certificate chain
openssl verify cert.pem

# Check if cert is self-signed (issuer == subject)
openssl x509 -in cert.pem -noout -issuer -subject | sort | uniq -d
# If output is non-empty → self-signed
```

---

## Check for Self-Signed Certs (Red Flag)

```bash
# Via tcpdump — capture SSL handshakes
tcpdump -s 1500 -A \
    '(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'

# Via tshark — extract server names from pcap
tshark -nr capture.pcap -Y "ssl.handshake.ciphersuites" -Vx \
    | grep "Server Name:" | sort | uniq -c | sort -r

# Extract cert info from pcap (ssldump)
ssldump -Nr capture.pcap | awk '
BEGIN {c=0;}
{ if ($0 ~ /^[ ]+Certificate$/) {c=1; print "==========";}
  if ($0 !~ /^ +/ ) {c=0;}
  if (c==1) print; }'
```

---

## Decode Certificate from PCAP (Wireshark/tshark)

```bash
# Export cert from pcap
tshark -nr capture.pcap -Y "ssl.handshake.certificate" \
    -T fields -e "x509sat.uTF8String" -e "x509ce.dNSName" 2>/dev/null

# Follow SSL stream (decrypt if keys available)
tshark -nr capture.pcap -o "ssl.keylog_file:/path/to/sslkeys.log" -d tcp.port==443,ssl
```

---

## Cipher Suite Analysis

```bash
# Check supported cipher suites on a host
nmap --script ssl-enum-ciphers -p 443 <HOST>

# Quick strength check
openssl s_client -connect <HOST>:443 2>&1 | grep -E "Cipher|Protocol"

# Check for weak cipher (SSLv3 / TLS 1.0)
openssl s_client -ssl3 -connect <HOST>:443 2>&1 | grep -E "CONNECTED|alert"
openssl s_client -tls1 -connect <HOST>:443 2>&1 | grep -E "CONNECTED|alert"
```

---

## Certificate Transparency & OSINT

```bash
# Search CT logs for certs issued to a domain
# (no local tool needed — use crt.sh or certspotter)
curl -s "https://crt.sh/?q=%25.<DOMAIN>&output=json" | \
    python3 -c "import sys,json; [print(c['name_value']) for c in json.load(sys.stdin)]" | sort -u

# Enumerate subdomains via cert transparency
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | \
    python3 -m json.tool | grep name_value | sort -u
```

---

## Generate Test Cert (Lab/Self-Signed)

```bash
# Self-signed cert for 365 days
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/CN=example.com/O=Test/C=US"

# Verify
openssl x509 -text -in cert.pem | grep -E "Subject:|Issuer:|Not After"
```

---

## Key Indicators of Compromise — TLS

| Indicator | Description |
|---|---|
| Self-signed cert | Issuer = Subject — common in C2 and malware |
| Short validity period | < 30 days — Let's Encrypt can be misused by attackers |
| Generic CN | `localhost`, `example.com`, or random string in CN |
| Unusual SAN | Wildcard `*.*.com` or mismatched hostname |
| Expired cert | Server accepting expired certs may indicate misconfiguration or interception |
| Certificate pinning bypass | Cert doesn't match what client expects — MITM indicator |
| Weak key | RSA < 2048 bits; EC < 256 bits |

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
