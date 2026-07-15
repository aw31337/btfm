# DNS Forensics
*Section 3 — DETECT | BTFM v2*

Commands for investigating DNS activity on Windows and Linux systems.

---

## Windows — DNS Server Log Path

Analytical ETL log (requires DNS debug logging enabled):
```
%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl
```

Standard DNS Server event log:
```
%SystemRoot%\System32\Winevt\Logs\DNS Server.evtx
```

---

## Read DNS Analytical Log (PowerShell)

Parse the ETL analytical log (oldest events first):
```powershell
Get-WinEvent -Path '%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl' -Oldest | Sort-Object -Property TimeCreated -Descending | Select-Object -First 100
```

Read a generic ETL trace log:
```powershell
Get-WinEvent -Path 'C:\Tracing\TraceLog.etl' -MaxEvents 100 -Oldest
```

---

## Windows — Hash All Executables (Integrity Check)

MD5 hash of every .exe from C:\ root (useful for baseline comparison):
```powershell
Get-ChildItem C:\ -File -Recurse -Filter *.exe | Get-FileHash -Algorithm MD5
```

---

## Windows — Enumerate Drivers

List all installed drivers in table format:
```
driverquery /FO table
```

---

## Windows — USB Device History

List USB devices from registry:
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses /s /f FriendlyName
```

---

## Windows — Open Files / Handles (Sysinternals)

List all open file handles:
```
handle.exe
```

List handles for a specific process name:
```
handle.exe -p <PROCESS_NAME>
```
Ref. https://docs.microsoft.com/en-us/sysinternals/downloads/handle

---

## Linux — Scan UDP Port 53 (DNS)

Scan single host for open UDP DNS port:
```bash
nmap -sU -p 53 <TARGET_IP>
```

Scan and skip ping (useful when ICMP is blocked):
```bash
nmap -sU -sT -v -Pn <TARGET_IP>
```

---

## Linux — tcpdump DNS Traffic

Capture DNS queries on interface:
```bash
tcpdump -i eth0 -n port 53
```

Capture DNS traffic to/from a specific host:
```bash
tcpdump -c 1000 -n -i eth0 -p host <TARGET_IP>
```

---

## Linux — Grep Successful SSH Logins

```bash
grep Accepted /var/log/secure
grep Accepted /var/log/auth.log
```

Check audit log for privileged activity:
```bash
cat /var/log/audit/audit.log | grep -i "execve\|USER_AUTH\|USER_LOGIN"
```
