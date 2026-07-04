# Linux Live Triage — Command Reference

> BTFM Cheatsheet | Section 4 — Respond  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

Run as root. Capture volatile state in order — network connections before processes, processes before files.

---

## System Information

```bash
date && uname -a
hostname -f 2>/dev/null || hostname
cat /etc/os-release
cat /etc/issue
uptime
last reboot | head
```

---

## Network State (Capture First)

```bash
# Active connections
ss -antp
netstat -antp 2>/dev/null

# Listening ports
ss -tlnp
netstat -tlnp 2>/dev/null

# Routing table
ip route
netstat -rn

# ARP cache
arp -an
ip neigh

# DNS cache / config
cat /etc/resolv.conf
cat /etc/hosts

# All open sockets by process
lsof -i -n
```

---

## Process State

```bash
# Full process tree
ps auxf

# By CPU usage (descending)
ps aux --sort=-%cpu | head -20

# Process binary paths (check for deleted binaries still running)
ls -la /proc/*/exe 2>/dev/null

# Command line for specific PID
cat /proc/<PID>/cmdline | tr '\0' ' '

# All open files for a process
lsof -n -p <PID>

# Map memory regions of a process
cat /proc/<PID>/maps

# Find processes with no parent (potential injection)
ps -eo pid,ppid,comm | awk '$2==1{print}'
```

---

## User & Auth Activity

```bash
# Logged-in users
who
w

# Login history
last -F | head -30

# Failed logins
lastb -F | head -20

# Auth log events
grep "Accepted\|Failed\|Invalid\|Failure" /var/log/auth.log 2>/dev/null | tail -50
grep "Accepted\|Failed\|Invalid\|Failure" /var/log/secure 2>/dev/null | tail -50

# Sudo activity
grep "sudo" /var/log/auth.log 2>/dev/null | tail -20

# All local accounts
cat /etc/passwd

# Root-equivalent users (UID=0)
awk -F: '$3==0{print "[!] UID=0 user:", $1}' /etc/passwd

# Accounts with no password
awk -F: '($2 == "" || $2 == "!") {print "[!] No password:", $1}' /etc/shadow 2>/dev/null

# SSH authorized keys for all users
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(eval echo "~$user")
    keyfile="$home/.ssh/authorized_keys"
    if [[ -f "$keyfile" ]]; then
        echo "=== $user ($keyfile) ==="; cat "$keyfile"
    fi
done
```

---

## Scheduled Tasks

```bash
# System crontabs
crontab -l 2>/dev/null
cat /etc/crontab
cat /etc/cron.d/* 2>/dev/null

# All user crontabs
for user in $(cut -d: -f1 /etc/passwd); do
    output=$(crontab -u "$user" -l 2>/dev/null)
    [[ -n "$output" ]] && echo "=== $user ===" && echo "$output"
done

# At jobs
atq 2>/dev/null

# Systemd timers
systemctl list-timers --all 2>/dev/null
```

---

## Persistence & Backdoors

```bash
# ld.so.preload (rootkit indicator — should be empty)
cat /etc/ld.so.preload

# SUID binaries (compare against baseline)
find / -perm -4000 -type f 2>/dev/null | sort

# SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort

# World-writable files in system dirs
find /etc /bin /sbin /usr/bin /usr/sbin -perm -0002 -type f 2>/dev/null

# Services that are enabled (non-standard)
systemctl list-unit-files --type=service --state=enabled 2>/dev/null

# Check /etc/init.d/
ls -la /etc/init.d/ 2>/dev/null

# Hidden files in home directories
find /home /root -name ".*" -type f 2>/dev/null | grep -v ".bash\|.profile\|.vim\|.git"

# Recently installed packages
rpm -qa --queryformat '%{INSTALLTIME:date} %{NAME}\n' 2>/dev/null | sort -r | head -20
dpkg -l 2>/dev/null | awk '{print $1,$2,$3}' | grep "^ii" | tail -30
```

---

## File System Activity

```bash
# Files modified in the last 24 hours (excluding noisy paths)
find / \
    -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" -o -path "/run/*" \) \
    -mtime -1 -type f \
    2>/dev/null | sort

# Files modified in last hour
find /etc /home /root /tmp /var/tmp /usr/bin /usr/sbin \
    -mmin -60 -type f 2>/dev/null | sort

# Check /tmp and /var/tmp for executables
find /tmp /var/tmp -type f -executable 2>/dev/null

# Files with no owner (orphaned — attacker artifacts)
find / -nouser -not -path "/proc/*" 2>/dev/null | sort
```

---

## Quick Hash of Suspicious File

```bash
sha256sum /path/to/suspicious
md5sum /path/to/suspicious

# Check against VirusTotal (requires vt-cli)
# vt file <hash>

# Check file type
file /path/to/suspicious
strings /path/to/suspicious | head -50
```

---

## Network Traffic (Live Capture)

```bash
# Capture all traffic for 60 seconds
tcpdump -nn -c 10000 -w /tmp/capture.pcap &
sleep 60 && kill %1

# Watch top talkers in real time
tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head

# Grab cleartext credentials
tcpdump -n -A -s0 port http or port ftp or port smtp or port pop3 | \
    grep -i 'pass=\|pwd=\|login=\|password='
```

---

## Triage Collection (One-Shot)

```bash
#!/bin/bash
OUT="/tmp/triage_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

date > "$OUT/timestamp.txt"
uname -a >> "$OUT/timestamp.txt"

ss -antp > "$OUT/network.txt"
ps auxf > "$OUT/processes.txt"
ls -la /proc/*/exe > "$OUT/proc_exe.txt" 2>&1
who > "$OUT/users.txt"
last -F >> "$OUT/users.txt"
crontab -l > "$OUT/cron.txt" 2>&1
find /tmp /var/tmp -type f > "$OUT/temp_files.txt" 2>&1
cat /etc/ld.so.preload > "$OUT/ldpreload.txt" 2>&1
find / -perm -4000 -type f > "$OUT/suid.txt" 2>&1

sha256sum "$OUT/"* > "$OUT/hashes.sha256"
echo "Triage complete: $OUT"
```

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
