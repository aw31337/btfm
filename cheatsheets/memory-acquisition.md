# Memory Acquisition
*Section 2 — PROTECT / Section 4 — RESPOND | BTFM v2*

Commands for acquiring memory from live Windows and Linux systems.
Tools require elevated privileges (Administrator / root).

---

## Windows — WinPmem (Open Source)

Acquire full physical memory:
```
winpmem_mini_x64_rc2.exe memdump.raw
```
Ref. https://github.com/Velocidex/WinPmem

---

## Windows — Volatility Plugins (Post-Acquisition)

Scan for hidden/injected processes (malfind):
```
volatility3 -f <MEMORY_IMAGE> windows.malfind
```

Scan process list including hidden processes:
```
volatility3 -f <MEMORY_IMAGE> windows.psscan
```

Get WMI process details from live system (PowerShell):
```powershell
Get-WmiObject Win32_Process -Filter "name = 'firefox.exe'" | Select-Object CommandLine
```

---

## Windows — SRUM Dump (System Resource Usage Monitor)

Export SRUM database for analysis:
```
srum_dump2.exe -SRUM_INFILE C:\Windows\System32\sru\SRUDB.dat -OUT <OUTPUT>.xlsx
```
Ref. https://github.com/MarkBaggett/srum-dump

---

## Linux — LiME (Loadable Kernel Module)

Load LiME and dump RAM to USB drive:
```bash
sudo insmod lime-<KERNEL_VERSION>.ko "path=/media/<USB>/memdump.lime format=raw"
```

Build LiME for current kernel:
```bash
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make
```
Ref. https://github.com/504ensicsLabs/LiME

---

## Linux — AVML (Azure VM Memory)

Acquire memory (no kernel module required):
```bash
sudo avml output.lime
```
Ref. https://github.com/microsoft/avml

---

## Linux — Mirror a Website for Offline Comparison

```bash
wget -m <TARGET_URL>
```

---

## Live Artifact Collection (Windows — CLI)

Snapshot of running state to files:
```
netstat -abfo > netstat.txt
net user > users.txt
net share > shares.txt
tasklist /v > processes.txt
dir %systemroot%\Prefetch > prefetch.txt
type C:\Windows\System32\driverstc\hosts >> hosts.log
```
