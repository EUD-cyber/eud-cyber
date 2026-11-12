# P10 Custom Remote Command and P11 Persistence

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

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

## P11 paired persistence and bounded DNS activity

Previously P11 selected one harmless artifact: a daily Windows task running echo,
an idle native Windows service, a five-minute user cron logger, or a user-systemd
oneshot running true. Explicit legacy methods retain their original behavior and
cleanup identities. They cannot generate DNS activity.

Auto now chooses **task-service** on Windows or **cron-systemd** on Linux.
All artifacts use mrnobody-p11-<artifact> (default suffix: telemetry). Use separate
suffixes for separate exercises. Repeating the same parameters reuses the pair
and **does not extend its UTC deadline**. Configuration changes or recreation
after expiry require Cleanup first. Recurring create schedules need an explicit Cleanup between exercises; they do not silently renew expired activity. Clean legacy artifacts with their original
method before selecting a pair. P11 finishes after verification; remote activity
is independent of Normal/Slow/Custom campaign timing and campaign completion.

| Method | Mechanisms and scope | Prerequisites |
| --- | --- | --- |
| task-service | Real Windows Service Control Manager service plus a visible SYSTEM Scheduled Task every minute. The task checks the deadline and starts the service. Native .NET ServiceBase executable under %ProgramData%\MrNobody\P11\<name>, with config.txt, owner.txt and status.txt. The same native executable supports a fixed --maintain mode, avoiding any task dependency on PowerShell script execution policy. Manual service startup; task maintains it. | WinRM, administrative task/service rights, Windows PowerShell and .NET Framework 4.6+ compiler with System.ServiceProcess.dll. Source is packaged in persistence_actions.py; no downloaded wrapper/package. Executable/config directory ACL is Administrators/SYSTEM only. Service runs as LocalSystem with explicit administrative lab access. |
| cron-systemd | One marked user-crontab entry every minute checks/starts ~/.config/systemd/user/<name>.service. Long-running Type=simple Python worker; files under ~/.config/mrnobody/<name>. | SSH, Python 3, crontab, /usr/bin/systemctl and an existing reachable user systemd manager. No sudo or linger changes. Cron sets XDG_RUNTIME_DIR to the existing /run/user/<uid>. Persistence is limited to that manager's lifecycle. |

Configuration is available through standalone GUI/API/CLI, Scenario Builder and
scheduler. Full Incident exposes P11 fields and a persistence object in its
campaign/schedule API specification. Dependencies and order are unchanged: Auto
consumes P03 access; fixed targets execute directly. Auto retains first-success
candidate behavior with compatible transport fallback.

- platform: auto/windows/linux; method: auto/task-service/cron-systemd.
  Legacy methods: scheduled-task/service/cron/systemd.
- action: create/cleanup; artifact: 1–32 lowercase letters/digits/hyphens.
- persistence_dns: disabled/enabled (default disabled). DNS requires a pair and
  an explicit persistence_resolver: unicast RFC1918 IPv4 on your internal lab
  networks. No gateway inference, public resolver or target default resolver.
- persistence_domain: evilcorp.test by default; reserved lowercase **.test** names
  only. No operator command, URL, arbitrary payload or answer execution.
- persistence_interval: 60 seconds by default, integer 10–3600.
  persistence_duration: 3600 seconds by default, integer 60–14400; interval must
  fit. This is a finite activity ceiling, **not automatic artifact cleanup**.
  Workers also enforce a monotonic runtime ceiling and a query-count bound.

The service sends a fixed DNS A question directly to the chosen resolver over
UDP 53, bypassing client DNS caches. Recursion-desired is clear (RD=0).
Configure a dedicated **non-forwarding authoritative .test zone**, returning a
fixed lab A address or NXDOMAIN. Restrict target egress to that resolver.
No host data, credentials, external C2, remote instructions or exfiltration is
included. Replies are checked for transaction/question/header and NOERROR or
NXDOMAIN; answer records are discarded. A matching reply confirms an exchange,
not A-record resolution or sensor detection. Socket waits are bounded at two
seconds; an in-flight attempt can finish just after expiry. The interval is a
pause between attempts.

Choose a resolver whose target-to-resolver path crosses the monitored OVS ports;
confirm the OVS mirror includes this path. Docker embedded DNS (127.0.0.11) and
container bridge traffic are not automatically visible to OVS/Suricata. Use an
explicit resolver on a monitored lab subnet. Correlate resolver logs or packet
capture/Suricata eve.json before claiming visibility. P11 deploys no resolver,
routes, mirrors or containers.

Creation verifies service active and task actions/triggers, or Linux unit
enablement plus exactly one cron entry. Fixed counters record attempts, matching
replies, last query timestamp, accepted RCODE and deadline. DNS failure is a
warning on an installed pair, not fabricated success. Evidence is a creation-time
snapshot; no remote polling occurs after phase completion. Missing verification
is a hard error. Unsupported Linux prerequisites return 78; transport/action
failures remain hard errors. Timeout or failure can leave partial artifacts.

Cleanup removes the restart trigger first, stops/deletes the service, removes
owned files/unit, verifies absence and is repeatable. Unrelated cron entries
remain intact; ownership conflicts fail closed. Reuse the exact target, username,
method and suffix even after timeout. Deadline expiry stops service/DNS activity;
inert task/cron, service registration and configuration remain until manual P11
Cleanup. Campaign cancellation does not clean remote artifacts. Cleanup needs
no original DNS options. Runtime credentials are never persisted in artifacts.

Example (supply credentials via execution-time secret input):

    scripts/run-phase.sh 11 --target 192.168.1.20 --protocol ssh --user ubuntu \
      --method cron-systemd --artifact lesson --persistence-dns enabled \
      --persistence-domain evilcorp.test --persistence-resolver 192.168.1.53 \
      --persistence-interval 60 --persistence-duration 3600
    scripts/run-phase.sh 11 --target 192.168.1.20 --protocol ssh --user ubuntu \
      --method cron-systemd --artifact lesson --action cleanup

Windows uses winrm-http or winrm-https and task-service with lab admin access.

## Integration and evidence

Full Incident order: P01 → P02 → P03 → optional P08 → P09 → optional P10 → **P11** → P04 → P05 → P06 → P07. Unsupported prerequisites retain their existing skip behavior. Custom fixed-target runs need no discovery prerequisites. Custom
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
action evidence exists. P11 mappings were verified against current MITRE ATT&CK on 2026-11-06:

- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/)
- [T1543.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002/)

P11 does not map T1071.004 (Application Layer Protocol: DNS): fixed benign questions
are DNS-beacon-like activity without an application-layer C2 protocol. Pair evidence
maps both platform-specific persistence techniques; legacy evidence keeps its single
mapping. No network detection is inferred from service installation.

Detection guidance covers Sysmon process/DNS where configured, DNS/firewall logs,
Suricata when visible, and Security 4698/4702/4699/4697, TaskScheduler Operational,
System 7045/7036, cron/syslog, user-systemd journal, process/audit and FIM/Wazuh
sources. This is investigation guidance, not a claim that sensors observed them.

## Fresh installation

`MRNOBODY/mrnobody_userdata.yaml` downloads the remote-action, SSH and
persistence helpers and the P11 phase script before service startup. The
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
