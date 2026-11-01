# P10 Custom Remote Command and P11 Persistence

P10 preserves WinRM/NTLM + PowerShell and adds Linux Bash through the same
OpenSSH/sshpass programs and host-key policy used by the earlier phases. There
is no new SSH library. Windows supports winrm-http/https; Linux supports ssh.
Choose `platform=windows|linux|auto`, transport, target, username, optional port
and timeout (5–300 seconds). Fixed targets execute directly. Auto Discovery adds
P01 → P03 and consumes only this incident's compromised access inventory. A
per-phase target override filters that inventory; it does not bypass P03.

Auto tries compatible candidates in inventory order, stopping after the first
completed action. Transport/authentication failures permit candidate fallback;
all candidates failing transport is a hard phase failure. Syntax/nonzero command
exit is a controlled P10 action failure (79), continuing the campaign with a
clearly reported skipped phase/command_error. Standalone retains nonzero exit.
Exit zero with warnings/stderr succeeds. Timeouts/configuration/internal failures
remain hard failures; remote actions may still be running after a WinRM timeout.

For compatibility, the runtime API field remains `powershell` and the environment
input remains `MRN_POWERSHELL_SECRET`, including for Bash. Neither is stored in a
scenario, schedule definition, CLI argument, or report. The builder requests the
command when running/arming; schedule credentials/commands expire on restart or
edit. Select an explicit platform for platform-specific commands; an Auto command
must suit whichever compatible host is chosen. No command-language guessing occurs.

## P11 controlled persistence

P11 accepts `platform`, `method`, `action=create|cleanup`, `artifact` (default
`telemetry`, 1–32 lowercase letters/digits/hyphens), and the same access fields.
The deterministic name is `mrnobody-p11-<artifact>`. Auto chooses Scheduled Task
on Windows or user cron on Linux. It uses a fixed harmless payload and never
accepts arbitrary persistence commands, elevates privileges, changes audit policy,
or hides artifacts. Artifacts remain until explicit cleanup. Choose a different
suffix for concurrent exercises; repeat the same suffix to reuse/update an artifact.

| Method | Artifact / behavior | Requirements / cleanup |
| --- | --- | --- |
| scheduled-task | Task Scheduler task named `mrnobody-p11-<artifact>`; daily fixed echo process | ScheduledTasks module and task registration rights. Ownership description checked before overwrite/removal. Cleanup unregisters and verifies absence. |
| service | Automatic Windows Service; fixed .NET ServiceBase executable under `%ProgramData%/MrNobody/P11/<name>/<name>.exe` | Administrative service rights, Windows PowerShell/.NET compiler and ServiceProcess assembly. Description, binary path and owner marker checked. Cleanup stops/deletes the service, verifies absence and removes only its owned directory. No service credentials are persisted. |
| cron | User crontab entry every five minutes, `logger -t mrnobody-p11`; exact namespaced comment | crontab, logger and flock. Lock protects read/modify/write, preserves unrelated entries, replaces its own entry without duplication. Cleanup removes the exact marker. |
| systemd | `~/.config/systemd/user/<name>.service`; visible oneshot `/usr/bin/true`, enabled on user-manager start | Existing user systemd manager and `/usr/bin/true`. No sudo, linger or system-wide changes. Cleanup disables/stops, removes owned unit and reloads manager. Persistence lasts within the existing user-manager lifecycle. |

Unsupported Linux cron/systemd environments return a clearly recorded prerequisite
skip (78), handled nonfatally by the campaign and standalone wrapper. A missing
compatible host in an Auto campaign skips P11. Direct target failure and all-target
transport/authentication failures remain hard failures. Artifact creation/cleanup
failure stays hard; partial artifacts may remain. Cleanup is repeatable. Reports
include target, platform, method, action, artifact/path, timestamps, outcome, exit
code and cleanup parameters. Re-run cleanup against the same target **and user**
using the recorded method and suffix, even after a partial failure or timeout.

Example (passwords supplied via runtime environment/secret input):

```bash
scripts/run-phase.sh 10 --target 192.168.1.20 --protocol ssh --platform linux --user ubuntu
scripts/run-phase.sh 11 --target 192.168.1.20 --protocol ssh --method cron --artifact lesson
scripts/run-phase.sh 11 --target 192.168.1.20 --protocol ssh --method cron --artifact lesson --action cleanup
```

## Integration and evidence

Full Incident order: P01 → P02 → P03 → P08 (optional) → P09 (DC prerequisite)
→ P10 (existing opt-in, Auto) → **P11 (required integration, Auto)** → P04 → P05
→ P06 → P07. Custom fixed-target runs need no discovery prerequisites. Custom
Auto runs add/lock dependencies before Review. Normal, Slow and Custom Timing,
CLI/GUI standalone, scheduler, imports/exports and live status use the existing
phase registry and structured execution model (schema version remains 1).

Ground Truth/Investigation and HTML/PDF exports share action evidence. P10 keeps
the existing scrub-before-truncate 512-character preview per stream, suppresses
sensitive commands, uses quoted single-line evidence, and never retains raw
output. Linux streams are drained with bounded memory; oversize previews are
withheld. Unlabelled unknown secrets cannot always be recognized: target-side
PowerShell/audit logs may also capture commands. Use synthetic lab data.

The supported technique metadata is narrowed to the recorded action method when
action evidence exists. Mappings were verified against MITRE ATT&CK on 2026-11-01:

- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/)
- [T1543.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002/)

Detection guidance covers Security 4698/4702/4699/4697, TaskScheduler Operational,
System 7045/7036, cron/syslog, user-systemd journal, process/audit and FIM/Wazuh
sources. This is investigation guidance, not a claim that sensors observed them.

## Fresh installation

`MRNOBODY/mrnobody_userdata.yaml` downloads the remote-action, SSH and
persistence helpers and the P11/P13 phase scripts before service startup. The
existing manifest already distributes these files for later updates; it is
unchanged. Fresh installation no longer needs an initial Update for these files.

The existing WinRM venv (pywinrm/requests-ntlm), system Flask/ReportLab, OpenSSH
and sshpass already cover the completed stack; no packages are added. Planning
creates `data/planning` (0700) and its SQLite database (0600) automatically.
Runtime uploads and incident-specific directories are created on demand under
the existing root-owned runtime, state, logs and reports directories. Remote
cron/systemd/Windows facilities remain target prerequisites.

The install test parses cloud-config, requires each manifest runtime file to
be downloaded exactly once, stages only those downloads, and checks application
imports, health, phase discovery, planning storage, report/live endpoints and
static assets. It never runs the installer, starts campaigns or contacts targets.

Tests use fake transports, isolated home directories and inert campaign phases;
they never contact the running VM or any lab host. Real Windows artifact creation
requires a later authorized lab smoke test; compile-only Windows service verification, mock responses and static checks do
not prove target-specific privilege or service availability.
