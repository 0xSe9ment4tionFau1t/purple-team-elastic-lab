# KQL Investigation Queries — Purple Team Elastic Lab

Queries used during the investigation phase of each attack stage. All queries target the Elastic SIEM / Discover interface (logs-* data view).

---

## Stage 1 — Reconnaissance: Port Scan

Confirm scan activity and scope it to a single host.

```kql
source.address: "192.168.x.x"
```

Narrow to specific ports identified during the scan:
```kql
source.address: "192.168.x.x" AND
destination.port: (135 OR 139 OR 445)
```

---

## Stage 2 — Initial Access: SMB Brute Force

Identify failed and successful logon attempts against the target account.

```kql
host.name: "winpro1" AND
winlog.event_data.TargetUserName: "user" AND
(event.action: "logged-in" OR event.action: "logon-failed")
```

Post-compromise activity check — assess actions taken after successful authentication:
```kql
host.name: "winpro1" AND
user.name: "user" AND
@timestamp >= "2026-04-27T13:10:58"
```

---

## Stage 3 — Execution: WMI Remote Command Execution

Detect cmd.exe spawned by WmiPrvSE.exe (WMI abuse indicator).

```kql
host.name: "winpro1" AND
user.name: "user" AND
process.parent.name: "WmiPrvSE.exe" AND
process.name: "cmd.exe"
```

Inspect commands executed through the WMI session (filter by parent process in Discover):
```kql
host.name: "winpro1" AND
user.name: "user" AND
process.parent.name: "WmiPrvSE.exe"
```

---

## Stage 4 — Persistence: PowerShell + Registry Autorun

Detect PowerShell execution parented to cmd.exe with suspicious flags.

```kql
host.name: "winpro1" AND
user.name: "user" AND
process.parent.name: "cmd.exe" AND
process.name: "powershell.exe"
```

Detect registry autorun key modification:
```kql
host.name: "winpro1" AND
registry.path: "*\\CurrentVersion\\Policies\\Explorer\\Run*"
```

---

## Stage 5 — Exfiltration: HTTP via curl

Detect outbound data transfer via curl from the compromised account.

```kql
host.name: "winpro1" AND
user.name: "user" AND
process.name: "curl.exe"
```

Full process chain reconstruction — trace from WMI root to exfiltration:
```kql
host.name: "winpro1" AND
user.name: "user" AND
process.parent.name: ("WmiPrvSE.exe" OR "cmd.exe" OR "powershell.exe")
```

---

## General — Timeline Reconstruction

Reconstruct the full attack timeline on a host from a known start time:
```kql
host.name: "winpro1" AND
user.name: "user" AND
@timestamp >= "2026-04-27T12:20:00"
```
