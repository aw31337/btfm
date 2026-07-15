# KAPE — Kroll Artifact Parser/Extractor
> Section 4 — RESPOND | Live Artifact Collection
> Ref: https://www.sans.org/tools/kape/

## Basic Usage

```powershell
# Run a KAPE target and module
PS C:\> kape.exe -t <target_file> -m <module_name> -o <output_directory>

# Example — collect Recent Files
PS C:\> kape.exe -t "C:\Users\user\AppData\Local\Microsoft\Windows\Recent" -m "RecentFiles" -o "C:\Analysis\RecentFiles"
```

## Common Targets

| Target | Description |
|--------|-------------|
| `!SANS_Triage` | Full triage collection |
| `WindowsTimeline` | Activity Cache (ActivitiesCache.db) |
| `WebBrowsers` | Chrome, Firefox, IE/Edge artifacts |
| `Prefetch` | Prefetch files (execution evidence) |
| `SRUM` | System Resource Usage Monitor |
| `EventLogs` | Windows Event Logs (EVTX) |
| `RegistryHives` | SAM, SYSTEM, SOFTWARE, NTUSER.DAT |
| `MFT` | Master File Table |
| `USBDevicesLogs` | USB connection logs |
| `RecentDocs` | LNK files and recent items |

## Collect and Process in One Pass

```powershell
# Target + module in single run, VHDX output
PS C:\> kape.exe --tsource C:\ --target !SANS_Triage --tdest C:\Output\Triage --mdest C:\Output\Modules --module !EZParser --vhdx TargetName

# Remote collection via UNC
PS C:\> kape.exe --tsource \\RemoteHost\C$ --target !SANS_Triage --tdest C:\Output
```

## Driver Verification (collect alongside KAPE)

```powershell
# Verify standard driver integrity
PS C:\> verifier /standard /driver myDriver.sys

# List all loaded drivers
C:\> driverquery /FO table
```

## SRUM Dump (companion tool)
> Ref: https://github.com/MarkBaggett/srum-dump

```powershell
# Export SRUM database to spreadsheet
C:\> srum_dump.exe -i C:\Windows\System32\sru\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o output.xlsx
```
