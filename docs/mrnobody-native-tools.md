# P13 Windows Native Tools / LOLBins Simulation and dual P10

P13 is a Windows-only phase with predefined telemetry actions. It accepts a
behavior selector, RFC1918 target, WinRM transport/port, username and timeout.
It never accepts arbitrary commands, URLs, DLLs or downloaded executables.

| Behavior | Controlled action | ATT&CK |
| --- | --- | --- |
| `encoded-powershell` (default) | Native PowerShell `-EncodedCommand` prints a fixed MrNobody marker | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| `certutil-decode` | `certutil -decode` decodes fixed local Base64 text, verifies its contents and removes both files | [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/) |
| `bits-job` | BITSAdmin creates an empty uniquely named job and cancels it in `finally`; no URL, transfer or execution callback | [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197/) |

Mappings were checked against the MITRE pages on 2026-11-01. Certutil decode is
not mapped to tool transfer or generic System Binary Proxy Execution. BITS job
telemetry does not prove that a transfer or persistent execution occurred.
Rundll32 and regsvr32 are reserved for future controlled behaviors; they are not
offered as placeholder actions that merely launch a tool or report false success.

Full Incident order is P01 → P02 → P03 → optional P08 → P09 → optional P10 → P11
→ P13 → P04 → P05 → P06 → P07. P13 defaults to encoded PowerShell in Full
Incident. Use the builder or standalone selector for another behavior.
Auto Discovery automatically adds and locks P01/P03 prerequisites in the builder.
P13 filters P03 inventory to Windows access for the same incident and skips
nonfatally when Windows access is absent. A target override filters established
access. Fixed Targets supplies Windows access directly, without discovery.

CLI example (runtime password follows the existing secret-input policy):

```sh
mrnobody phase 13 --target 192.168.1.15 --protocol winrm-http --user Administrator --behavior certutil-decode
```

Normal, Slow and Custom Timing use the shared execution planner. Schedules save
only structured phase parameters and timing. Runtime credentials stay in memory.
Native actions use existing WinRM result semantics, candidate fallback and worker
timeouts. Nonzero native exits are controlled action errors (79); transport,
authentication, invalid configuration and worker failures remain hard failures.
No compatible campaign target returns the existing skip code 78.

Every action records behavior, native executable, target, transport/method,
interpreter, ATT&CK ID, timestamps, exit code, outcome, bounded redacted output,
temporary directory and cleanup result. Certutil files live only in a newly
created GUID directory under the target account's temporary path. BITS uses a
unique job name also recorded in output evidence. Cleanup is attempted even
after an action error; interruption/timeout can leave artifacts and is reported
as requiring independent verification. Repeated successful runs leave no files
or jobs behind. Raw native stdout is suppressed except the fixed marker and
controlled artifact/cleanup records.

Reports, Ground Truth, Investigation, live overview and HTML/PDF exports use the
shared phase pipeline. Guidance covers Security 4688, PowerShell 4103/4104,
WinRM, Sysmon process/file/image events, BITS Operational logs and Wazuh
correlation. Students compare actual exit/outcome/cleanup evidence with host
logs; the report does not claim that a sensor detected the simulation. Restrict
WinRM, apply least privilege and tested application control, and detect unusual
native-tool command lines and parent processes.

## P10 independent runtime commands

Full Campaign has two optional inputs: **PowerShell command (Windows)** and
**Bash command (Linux)**. With P10 included, whitespace is trimmed and each
nonblank input runs against one compatible target using platform-specific
candidate fallback. Both configured commands are attempted independently.
Blank input skips only that platform. Both blank returns 78 with
`PHASE_SKIPPED reason=NOT_CONFIGURED`; subsequent campaign phases continue.

Both successes complete P10. A success plus a controlled command error or absent
compatible target completes with a partial warning and separate action evidence.
All controlled errors produce the existing nonfatal action-error skip. Exhausted
transport/authentication failures and infrastructure failures fail the phase,
including when the other platform succeeded. Report status remains the existing
complete/skipped/failed model; the action evidence explains partial outcomes.

The GUI Review displays configured/not configured for each platform, never raw
commands. Builder and scheduler runtime forms accept the same independent inputs.
API runtime keys are `powershell_windows` and `bash`; environment keys are
`MRN_POWERSHELL_WINDOWS_SECRET` and `MRN_BASH_SECRET`. Commands never enter saved
definitions, execution summaries or schedule storage. The legacy `powershell` /
`MRN_POWERSHELL_SECRET` standalone/custom input remains supported with its
original single-candidate Auto behavior.

## Release scope and verification

This release updates GitHub runtime files and the updater manifest only.
`MRNOBODY/mrnobody_userdata.yaml` and fresh-install cloud-init are deliberately
frozen. Fresh installs need the existing Update flow to obtain the deferred
P10/P11/P13 runtime additions; installer parity is tested with an explicit
deferred-file list. No running VM is changed or contacted by these tests.

`tests/mrnobody/native_dual.py` covers registry, parameters, dependencies/order,
timing, native script parsing, mocked transport exits, cleanup evidence,
per-behavior ATT&CK, redaction, export/live data, candidate fallback, dual-command
outcomes, endpoints, schedule serialization and command secrecy. Builder DOM
tests and `dual_review.cjs` verify selectors, prerequisites and safe Review text.
Existing Linux fixtures execute only inert/fake transports, never lab targets.
