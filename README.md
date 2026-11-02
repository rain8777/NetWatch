# NetWatch 1.0 - Windows internet activity monitor, diagnostic and repair tool

Single file: `NetWatch.bat` (batch launcher with the PowerShell program embedded after a marker line; nothing else to install).

## IMPORTANT: testing status
This was written and **syntax-checked only** (PowerShell parser: 0 errors; all called commands resolve to defined functions or real Windows cmdlets/tools). It was **not executed on Windows** because no Windows environment was available. Treat every feature below as "implemented, untested" until you run the test procedures in section 8. Report any failure and it can be fixed quickly.

## 1. Setup and usage
1. Save `NetWatch.bat` anywhere (keep Windows line endings; do not open and re-save in an editor that converts them).
2. Double-click it. Pick a menu number. Most read-only features work without admin.
3. For per-process bandwidth, SFC/DISM, restore points, DNS flush, Defender scan and failed-logon checks, use **Settings > 6 Relaunch as Administrator** (UAC prompt) or right-click > Run as administrator.
4. Data is stored in `%LOCALAPPDATA%\NetWatch` (`logs`, `reports`, `quarantine`, `backups`, `data`). Nothing is sent anywhere; no network access except the connectivity/DNS tests you run.
5. If SmartScreen or policy blocks it, that is Windows protecting you; the script is plain text you can read.

## 2. Supported systems
Windows 10 (build 10240+) and Windows 11, Windows PowerShell 5.1 (built in). Not for Windows Server Core or non-Windows systems. Wi-Fi details parse English `netsh` labels only (best effort on other languages).

## 3. Administrator requirements
| Needs admin | Works without admin |
|---|---|
| Per-process bandwidth (ETW), SFC, DISM, restore point, DNS flush, Defender scan, HKLM startup changes, Security-log failed logons, audit-policy display | Live monitor, connections/process listing (some paths hidden), startup review, diagnostics, file activity list, security indicators, health check, HKCU startup disable, temp quarantine, reports |

## 4. Traffic measurement and attribution method
* **Adapter speed/totals: directly measured** from `Get-NetAdapterStatistics` deltas over real elapsed time, for physical adapters that are Up. VPN traffic is counted once, on the physical adapter.
* **Per-process bytes: directly measured, admin only, on demand.** Menu 4 starts a temporary ETW session on `Microsoft-Windows-Kernel-Network` (via `logman`), records TCP/UDP payload sizes by PID for 10-120 s, parses the trace with `Get-WinEvent`, then deletes the trace. Process identity uses before/after process snapshots; PID reuse, exited processes, `System` (PID 4) and shared `svchost` hosts are flagged, and the **unattributed** difference to adapter totals is shown.
* **Connection counts per process** are shown only as labelled indicators, never as bandwidth.
* Not measurable here: traffic of other devices, router-level usage, encrypted payload contents, per-file transfers over HTTPS, exact attribution inside shared service hosts.
* Loopback filtering of ETW events is best effort.

## 5. Implementation status
| Feature | Status |
|---|---|
| Launcher, 12-item menu, settings, logging, retention, config | Implemented (untested) |
| A. Connection/adapter change detection, layered connectivity test (adapter, gateway, external IP, DNS, web TCP), new process/connection/listener/repeated-failure events, config change events | Implemented (untested) |
| B. Process and connection inspection, detail view, signatures, parent, owner, services in svchost, first/last seen (while monitor ran) | Implemented. Privileges limited to owner; no token elevation level |
| C. Startup review: Run/RunOnce (incl. Task Manager disabled state), Startup folders, non-Microsoft scheduled tasks, auto-start services outside the Windows folder | Implemented. Microsoft tasks and Windows-folder services are summarized only |
| D. Live dashboard, peaks, history, utilization, burst detection | Implemented (untested) |
| D. Per-process bandwidth | Implemented via ETW (admin). Untested, see risk note |
| E. File activity | Partial: recent file listing, flags, Zone.Identifier origin domain, optional local SHA-256, timing correlation with logged bursts. **Not implemented:** process-attributed file events (needs Object Access auditing or Sysmon; NetWatch does not change audit policy) |
| F. Diagnostics | Implemented (untested) |
| G. Health check | Implemented, including read-only `sfc /verifyonly` (admin) |
| H. Security scan | Implemented; indicators only; no reputation lookups |
| I. Three-outcome classification with evidence, checks, limitations, history and reclassification | Implemented |
| J. Repair center: restore point, DNS flush, temp quarantine, startup disable/restore, runaway-process stop, file quarantine/restore, Defender scan, SFC/DISM, traffic advice | Implemented (untested) |
| Network resets (Winsock, TCP/IP reset, DHCP renew), permanent deletion, service disabling, task removal, registry deletion beyond Run values | **Deliberately not implemented** |
| L. Reports: TXT (optional redaction), CSV exports | Implemented |

## 6. Known limitations and risks
* ETW event layout (property order for PID and size) and the loopback test are written from knowledge of the Kernel-Network provider and were not verified on a live system. If menu 4 shows nothing or odd values, that is the first place to look.
* Classification is evidence-based but conservative: only broken Run-key entries and old unlocked temp files can reach SAFE CANDIDATE; Microsoft-signed Windows-folder components and registered security products are PROTECTED; everything else is NEEDS REVIEW. A signature is not a guarantee.
* "Category" labels (browser, cloud sync, update...) are name/path hints, not proof.
* Command lines can contain secrets; they are shown on screen only for the selected process, and stored startup commands have `token=`-style values redacted. Reports still contain paths.
* The live monitor blocks for a few seconds during periodic connectivity tests when the network is down.
* Closing the window during a trace may leave the session running; the exit handler stops it, or run `logman stop NetWatchKN -ets`.

## 7. Safety design
Monitoring/investigation never modify the system. Every repair shows issue, evidence, action, exact target, effect, classification, admin need and recovery plan, requires typing `YES`, checks the recovery step actually succeeded before acting, verifies the result and logs it. PROTECTED items are refused. No hidden service, scheduled task or persistence is created.

## 8. Test procedures
1. **Launch:** run the .bat; main menu appears, no red errors. Settings > 7 lists commands as available.
2. **A/D monitor:** menu 1 > 1. Rates appear after the second sample. Start a large download: download rate rises, a BURST event appears. Press P, A, R, Q. Toggle Wi-Fi/Ethernet or airplane mode: ADAPTER_STATE and CONNECTIVITY events appear; check `logs\events.csv`.
3. **B:** menu 2 > 1, then enter a PID; compare with Task Manager and `netstat -ano`.
4. **C:** menu 3; compare with Task Manager > Startup and `taskschd.msc`; open an entry detail; export CSV.
5. **D per-process (admin):** menu 4, 20 s, open a video or download during capture; the browser should dominate; check the unattributed line.
6. **E:** download a file, then menu 5 with 15 minutes; it should appear with its web origin.
7. **F:** menu 6 on a working connection (expect ONLINE interpretation); then disable the adapter's DNS (use an invalid DNS server temporarily) and re-run (expect DNS findings). Restore your DNS afterwards.
8. **G/H:** menus 8 and 7 produce findings with evidence/severity; verify a few by hand.
9. **J:** (a) restore point (admin) and check `rstrui.exe`; (b) create a dummy file in a temp folder, quarantine it via option 6, restore via option 7 and compare the hash; (c) add `HKCU\...\Run` test value `NWTest` pointing to a missing file, disable via option 4, restore via option 7; (d) decline a prompt: nothing changes.
10. **Reports:** menu 10 > 1; open the TXT and CSV; check redaction.

## 9. Repair verification and recovery
* Quarantined files: `%LOCALAPPDATA%\NetWatch\quarantine\<id>.qfile` plus `<id>.qfile.json` (original path, SHA-256, time, reason). Restore with menu 9 > 7, or manually rename/move back.
* Disabled startup entries: registry export in `backups\run_*.reg` (double-click to re-import) and the saved value in `data\disabled_startup.json`; restore with menu 9 > 7.
* Restore point: only reported as existing if `Get-ComputerRestorePoint` finds it after creation.
* All repairs are logged as `REPAIR`, `REPAIR_DECLINED`, `REPAIR_REFUSED` or `REPAIR_ABORTED` events in `events.csv`.
* NetWatch never permanently deletes quarantined items; delete the folder yourself when you are sure.

## 10. Report format (structure only; real reports are generated by menu 10)
```
NETWATCH REPORT v1.0.0   generated <time>
System / elevation / session id
CONNECTIVITY SNAPSHOT (measured now)
PER-PROCESS BANDWIDTH (only if a capture was run)
FINDINGS: [severity] module / title (status, confidence) @ time, evidence, cause, next step, repair options, classification
CLASSIFICATIONS RECORDED THIS SESSION: outcome, reason, limitations
SESSION EVENTS
```
No example with numbers is included because none could be genuinely measured here.
