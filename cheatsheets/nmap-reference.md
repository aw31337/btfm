# Nmap Quick Reference

> BTFM Cheatsheet | See book for full context

## Scan Types

```bash
nmap -sS <target>        # SYN scan (stealth, requires root)
nmap -sT <target>        # TCP connect scan (no root needed)
nmap -sU <target>        # UDP scan
nmap -sn <target>        # Ping sweep (no port scan)
nmap -sV <target>        # Version detection
nmap -sC <target>        # Default scripts
nmap -O  <target>        # OS detection (requires root)
nmap -A  <target>        # Aggressive: -sV -sC -O --traceroute
```

## Port Selection

```bash
nmap -p 22,80,443 <target>        # Specific ports
nmap -p 1-1024 <target>           # Range
nmap -p- <target>                  # All 65535 ports
nmap --top-ports 100 <target>     # Top 100 most common
nmap --top-ports 1000 <target>    # Top 1000 (default)
```

## Speed (T0=paranoid → T5=insane)

```bash
nmap -T1 <target>    # Slow — evades basic IDS
nmap -T4 <target>    # Fast — standard for most use
nmap -T5 <target>    # Very fast — noisy, may drop packets
```

## Output Formats

```bash
nmap -oN output.txt    # Normal (human readable)
nmap -oX output.xml    # XML (tool-parseable)
nmap -oG output.gnmap  # Greppable
nmap -oA output        # All three at once (recommended)
```

## Useful Combinations

```bash
# Quick first pass — top 1000 ports, version, scripts
nmap -sV -sC -T4 -oA quick-scan <target>

# Full TCP sweep — all ports
nmap -p- -T4 -oA full-tcp <target>

# Version + OS on specific ports
nmap -sV -O -p 22,80,443,3389 <target>

# Vulnerability scan (use only on authorized targets)
nmap --script vuln <target>

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users -p 445 <target>

# HTTP title and server headers
nmap --script http-title,http-server-header -p 80,443,8080 <target>
```

## Target Specification

```bash
nmap 192.168.1.1            # Single IP
nmap 192.168.1.1-254        # Range
nmap 192.168.1.0/24         # CIDR
nmap -iL hosts.txt          # From file
nmap --exclude 192.168.1.1  # Exclude host
```
