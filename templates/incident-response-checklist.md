# Incident Response Checklist

> BTFM Template | Section 4 — Respond  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

---

## Case Header

| Field | Value |
|---|---|
| Incident ID | |
| Date Opened | |
| Severity | Critical / High / Medium / Low |
| Incident Type | (Malware / Ransomware / Intrusion / Data Breach / DDoS / Insider) |
| Incident Manager | |
| Lead Analyst | |
| Legal Notified | Yes / No / Date: |
| Exec Notified | Yes / No / Date: |

---

## IDENTIFICATION

**Priority (H/M/L) | Effort (H/M/L) | Status (Open/Closed)**

### Malware / Threat Analysis
- [ ] Acquire copy of malicious file(s) for analysis | P:__ E:__ Status:__
- [ ] Which AV/malware tools can detect and remove the threat? | P:__ E:__ Status:__
- [ ] Malicious effects list — all changes (files, settings, registry, services) | P:__ E:__ Status:__
- [ ] Where does malware/attacker exit the network? | P:__ E:__ Status:__
- [ ] Malicious internal/external connections still active? | P:__ E:__ Status:__
- [ ] Malware listening on any ports? | P:__ E:__ Status:__
- [ ] Malware original infection method / weakness? | P:__ E:__ Status:__

### Packet Capture
- [ ] Capture of malware spreading to other systems | P:__ E:__ Status:__
- [ ] Capture of C2 communication (ports, IPs, DNS, protocols) | P:__ E:__ Status:__

### Data / Scope
- [ ] Sensitive data at risk? (Credentials, PII, IP, financial) | P:__ E:__ Status:__
- [ ] DNS entries on infected systems checked? | P:__ E:__ Status:__
- [ ] Patient-zero (first infected system) identified? | P:__ E:__ Status:__
- [ ] Patient-zero hard drive preserved? | P:__ E:__ Status:__
- [ ] Vulnerability scan — missing patches identified? | P:__ E:__ Status:__
- [ ] List of all infected systems compiled? | P:__ E:__ Status:__
- [ ] Systems stopped reporting to AV/update servers? | P:__ E:__ Status:__
- [ ] Desktop management tool inventory run? | P:__ E:__ Status:__
- [ ] Any scripts needed on live infected systems? | P:__ E:__ Status:__

---

## CONTAINMENT

- [ ] Systems status mapped: Unknown / Clear / Suspicious / Infected count: | P:__ E:__ Status:__
- [ ] Network device changes (Switches / Routers / Firewalls / IPS / NAC / Wi-Fi) | P:__ E:__ Status:__
- [ ] Active Directory OU isolation of suspected systems | P:__ E:__ Status:__
- [ ] Active Directory user account restrictions and resets | P:__ E:__ Status:__
- [ ] Active Directory policies to prohibit threat execution | P:__ E:__ Status:__
- [ ] Email quarantine / blocking of malicious domains | P:__ E:__ Status:__
- [ ] DNS sinkhole / block of C2 domains | P:__ E:__ Status:__
- [ ] Internet access restricted for affected segment | P:__ E:__ Status:__
- [ ] Credentials rotated (admin, service accounts) | P:__ E:__ Status:__

---

## ERADICATION

- [ ] All infected systems identified and documented | P:__ E:__ Status:__
- [ ] Malware removed from all systems | P:__ E:__ Status:__
- [ ] Malicious files, registry keys, scheduled tasks removed | P:__ E:__ Status:__
- [ ] Malicious accounts or backdoors removed | P:__ E:__ Status:__
- [ ] Vulnerability that enabled infection patched | P:__ E:__ Status:__
- [ ] AV / EDR signatures updated and scans run | P:__ E:__ Status:__
- [ ] Threat intelligence IOCs shared with detection tools | P:__ E:__ Status:__

---

## RECOVERY

- [ ] Clean systems re-imaged from known-good baseline | P:__ E:__ Status:__
- [ ] Restored from backup (verify backup integrity first) | P:__ E:__ Status:__
- [ ] Multi-factor authentication enforced on affected accounts | P:__ E:__ Status:__
- [ ] Monitoring enhanced for recurrence detection | P:__ E:__ Status:__
- [ ] Systems returned to production | P:__ E:__ Status:__

---

## LESSONS LEARNED

- [ ] Post-incident review scheduled (within 72 hours) | Date:__
- [ ] Root cause documented | P:__ E:__ Status:__
- [ ] Gap in detection identified | P:__ E:__ Status:__
- [ ] Playbook / runbook updated | P:__ E:__ Status:__
- [ ] Training need identified | P:__ E:__ Status:__
- [ ] Metrics captured (MTTD, MTTR, scope, cost) | P:__ E:__ Status:__

---

## Evidence & Documentation

| Evidence ID | Description | Hash | Location |
|---|---|---|---|
| | | | |
| | | | |

---

## Timeline of Key Events

| Date/Time | Event | Source |
|---|---|---|
| | Incident detected | |
| | IR team engaged | |
| | Containment initiated | |
| | Eradication complete | |
| | Recovery complete | |

---

*Template from the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
