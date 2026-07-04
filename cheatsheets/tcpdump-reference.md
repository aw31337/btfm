# tcpdump Quick Reference

> BTFM Cheatsheet | Section 3 — Detect  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

---

## Basic Capture

```bash
# View ASCII traffic
tcpdump -A

# View HEX + ASCII
tcpdump -X

# With timestamps, no name resolution, verbose
tcpdump -tttt -n -vv

# Capture on specific interface
tcpdump -i eth0

# Capture on ANY interface
tcpdump -i any

# Save to file
tcpdump -w capture.pcap

# Read from file
tcpdump -r capture.pcap
```

---

## Filtering

```bash
# Specific host
tcpdump host 192.168.1.100

# Traffic between two hosts
tcpdump host 10.0.0.1 && host 10.0.0.2

# Specific port
tcpdump port 443

# Protocol
tcpdump tcp
tcpdump udp
tcpdump icmp

# Source or destination
tcpdump src host 10.0.0.5
tcpdump dst port 80

# Exclude a network or host
tcpdump not net 10.10 && not host 192.168.1.2

# Multiple conditions
tcpdump host 10.10.10.10 && \( 10.10.10.20 or 10.10.10.30 \)

# Filter by IP
tcpdump ip dst 8.8.8.8

# Exclude IPv6
tcpdump not ip6

# Only IPv6
tcpdump ip6
```

---

## Incident Response Captures

```bash
# Find top talkers after 1000 packets (DDoS indicator)
tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort -n | uniq -c | sort -nr

# Capture from target host on port 80 to file
tcpdump -w capture.pcap -i any dst <TARGET_IP> and port 80

# Grab cleartext credentials (HTTP/FTP/SMTP/IMAP/POP3)
tcpdump -n -A -s0 port http or port ftp or port smtp or port imap or port pop3 | \
    egrep -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user ' \
    --color=auto --line-buffered -B20

# Search traffic for keyword "pass"
tcpdump -n -A -s0 | grep -i pass

# Capture with rotating files (1000MB per file)
tcpdump -n -s65535 -C 1000 -w 'capture_%Y-%m-%d_%H:%M:%S.pcap'

# Capture on rotating hourly schedule
tcpdump -pni any -s65535 -G 3600 -w 'any_%Y-%m-%d_%H:%M:%S.pcap'

# Get throughput
tcpdump -w - | pv -bert > /dev/null

# Stream capture to remote host
tcpdump -w - | ssh <REMOTE_HOST> -p 22 "cat - > /tmp/capture.pcap"
```

---

## SSL/TLS Analysis

```bash
# Detect suspicious or self-signed SSL certificates
tcpdump -s 1500 -A \
    '(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'

# Extract cert server names
tshark -nr capture.pcap -Y "ssl.handshake.ciphersuites" -Vx | \
    grep "Server Name:" | sort | uniq -c | sort -r
```

---

## BPF Filters (Advanced)

| Filter | Description |
|---|---|
| `tcp[tcpflags] & tcp-syn != 0` | SYN packets only |
| `tcp[tcpflags] & (tcp-syn\|tcp-fin) != 0` | SYN and FIN packets |
| `tcp[tcpflags] == tcp-rst` | RST-only packets |
| `icmp[icmptype] = icmp-echo` | ICMP echo requests (ping) |
| `port 53` | DNS traffic |
| `not port 22` | Everything except SSH |
| `greater 1000` | Packets larger than 1000 bytes |
| `less 64` | Packets smaller than 64 bytes |

---

## Output Options

| Flag | Description |
|---|---|
| `-n` | No DNS resolution |
| `-nn` | No DNS, no service name resolution |
| `-v` / `-vv` / `-vvv` | Verbosity |
| `-A` | Print as ASCII |
| `-X` | Print as HEX + ASCII |
| `-s0` | Capture full packet (no snaplen limit) |
| `-c <N>` | Stop after N packets |
| `-C <MB>` | Rotate pcap file every N MB |
| `-G <sec>` | Rotate pcap file every N seconds |
| `-w <file>` | Write to pcap file |
| `-r <file>` | Read from pcap file |
| `-i <iface>` | Specify interface |
| `-D` | List available interfaces |
| `-e` | Print link-level headers (MAC addresses) |
| `-q` | Quiet (less output) |
| `-tttt` | Absolute timestamps |
| `-ttt` | Delta timestamps |

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
