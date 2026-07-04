# Windows Event IDs — Quick Reference

> BTFM Cheatsheet | See book for full analysis context

## Authentication & Logon

| Event ID | Description | Notes |
|---|---|---|
| 4624 | Successful logon | Check logon type (2=interactive, 3=network, 10=remote) |
| 4625 | Failed logon | >5 in short window = brute force indicator |
| 4634 | Logoff | |
| 4647 | User-initiated logoff | |
| 4648 | Logon with explicit credentials | Pass-the-hash, runas |
| 4672 | Special privileges assigned | Admin-level logon |
| 4768 | Kerberos TGT requested | |
| 4769 | Kerberos service ticket requested | Kerberoasting: encryption type 0x17 |
| 4771 | Kerberos pre-auth failed | Bad password or locked account |
| 4776 | NTLM auth attempt | Local SAM auth |

## Account Management

| Event ID | Description |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | Password change attempt |
| 4724 | Password reset by admin |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4728 | User added to global security group |
| 4732 | User added to local security group |
| 4740 | Account locked out |
| 4756 | User added to universal security group |

## Process & Execution

| Event ID | Description | Notes |
|---|---|---|
| 4688 | Process created | Enable "Include command line" via GPO |
| 4689 | Process terminated | |
| 4697 | Service installed | |
| 7045 | New service installed | System event log |
| 4698 | Scheduled task created | |
| 4702 | Scheduled task updated | |

## Lateral Movement

| Event ID | Description |
|---|---|
| 4778 | RDP session reconnected |
| 4779 | RDP session disconnected |
| 5140 | Network share accessed |
| 5145 | Shared object access check |
| 4648 | Explicit credential use (PtH indicator) |

## Object Access & Audit

| Event ID | Description |
|---|---|
| 4656 | Handle to object requested |
| 4663 | Object access attempted |
| 4670 | Object permissions changed |
| 4907 | Audit policy changed |

## System & Policy

| Event ID | Description |
|---|---|
| 1102 | Security audit log cleared |
| 4616 | System time changed |
| 4719 | Audit policy changed |
| 6005 | Event log service started (system boot) |
| 6006 | Event log service stopped |

## Logon Type Reference

| Type | Description |
|---|---|
| 2 | Interactive (keyboard at console) |
| 3 | Network (SMB, mapped drives) |
| 4 | Batch (scheduled task) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext (Basic auth) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (cached domain creds) |
