# MrNobody P09 and P10

Both phases are included in Full Incident as well as standalone/custom scenarios.
The default flow is P01 → P02 → P03 → optional P08 → P09 → P10 → P04 → P05 → P06 → P07.
P09 executes only when P03/P08 found Windows/RDP access; otherwise its action
is skipped with an explicit ground-truth reason. P10 is optional and disabled by
default, like P08. Enable its checkbox and enter a runtime PowerShell command.
Schedules save the enable flag, with command content held only in the runtime
lease. CLI Full Incident uses MRN_POWERSHELL_ENABLED=1 plus
MRN_POWERSHELL_SECRET. Missing input is rejected before launch when enabled. AD or WinRM failures follow the existing
stop-on-phase-failure policy. Historical reports retain their existing layout.

## Access and dependencies

Auto Discovery adds and locks P01 → P03 before P09 or P10 in phase selection.
Both require a compromised Windows entry from this incident's P03 inventory;
Linux-only access is insufficient. An RDP success in P03 establishes an access
candidate, not proof that WinRM is reachable or that the account has AD rights.
Both new phases execute using existing pywinrm/NTLM, never through RDP.

Fixed Targets allows either new phase alone, using the private IPv4 target,
Windows username and WinRM protocol. Common Target fills the target, with local
overrides. Discovery is not forced when access is supplied directly. Only
RFC1918 IPv4 endpoints are accepted, including inventory-consuming runs. The
existing Windows transport certificate policy is retained (lab certificates are
not verified); select winrm-https where available. Default ports are 5985/5986.

## P09: AD account and privileged group membership

Select the lab domain controller itself and provide a Windows account already
authorized to create domain users and change Domain Admins membership. The
ActiveDirectory PowerShell module must exist on that DC. P09 deliberately does
not open a second hop to a different DC: a member server/workstation records its
domain when available and fails with target_must_be_domain_controller. In Auto
mode each Windows candidate is tried; unsuitable candidates are recorded as
failures, not silently counted as successful privilege escalation.

The action discovers the domain and DC, resolves Domain Admins by domain SID
plus RID 512 (supports localized group names), looks up mrnobody, creates it
**disabled** if absent, and adds direct membership only when needed. It verifies
membership afterwards. Existing account passwords, enablement and other state
are preserved. No new password is created, returned or stored. This demonstrates
account creation/group privilege changes without creating a new usable login;
it does not bypass AD permissions. Repeated runs accurately record
already_exists_unchanged/already_member. Partial failures retain completed
account/group steps. Failed AD exception text is omitted.

Cleanup is deliberate and manual: compare account/group actions with evidence,
remove membership added by this exercise when appropriate, and delete only an
account proven to have been created for the lab. Never blindly delete a
pre-existing mrnobody account. Cleanup itself is not automatically scheduled.

## P09 prerequisite status

P09 uses the existing `skipped` terminal phase state when an authenticated
Windows target reports that it is not a domain controller and no usable DC was
found. A transport failure on another candidate does not turn that missing
prerequisite into a hard failure. Both built-in campaigns and custom scenarios
record `PHASE_SKIPPED` and continue to the next selected phase. They do not emit
`PHASE_COMPLETE` for the skipped action. P03 dependencies and builder validation
remain unchanged.

The P09 worker/script uses exit 78 for this prerequisite outcome. The standalone
CLI/report wrapper records phase `skipped`, retains exit 78 in the report, and
returns 0 for the handled nonfatal outcome. Thus existing GUI and scheduler exit
conventions remain compatible; an overall completed run does not mean P09 ran.
Other phases' exit 78 is still an error. Direct users of `09-ad-privilege.sh`
must handle its exit 78 explicitly.

Investigation and Ground Truth views (including HTML/PDF exports) explain
`No Active Directory Domain Controller discovered` and retain candidate target,
domain (for example WORKGROUP), dc=unknown and account/group=not_attempted.
Live Campaign cards and Execution Overview show SKIPPED; subsequent phases
advance normally and skipped phases are excluded from executable-phase progress.

All candidates failing transport/authentication is still a hard failure.
Configuration, invalid worker responses, timeouts and account/group/command
errors on a DC remain failures, even when another candidate is WORKGROUP.
Valid DC account/group actions and MITRE mappings are unchanged.

## P10: custom PowerShell

The builder configuration describes its target/protocol/username/port and optional
5–300 second action timeout. On Review or in Schedules, the clearly labeled P10
PowerShell command field supplies **runtime-only** content (up to 16384
characters, including multiline scripts). Arbitrary commands can contain secrets;
the model's existing allowlist of non-secret scenario parameters does not permit
persisting them. Save-only, duplicate and scenario/schedule serialization never
contain this command. Each scenario has at most one P10, so its single runtime
command is unambiguous.

The standalone phase detail form provides the same runtime input. CLI operators
supply MRN_POWERSHELL_SECRET in the process environment and use `mrnobody run 10`
with normal target/protocol/user arguments; command content is never a CLI flag.
Do not put secrets in command-line arguments or in tracked configuration files.
An existing session-only service environment may supply the same variable for
unattended execution. The scheduler can instead retain it in its existing
in-memory credential lease, which expires on service restart or schedule
edit/delete. Re-arm after restart. A missing command/credential prevents dispatch
or produces a failed run; it never falls back to a default action.

WinRM runs the operator's supplied PowerShell. Endpoint scope validation limits
the connection target; it is not a PowerShell language sandbox. Operators remain
responsible for limiting the command's effects to the controlled lab.

## Timing, locking and evidence

Normal/Slow/Custom profiles use the existing execution plan and absolute phase
offsets. There is no second pacing system. The action timeout bounds the local
WinRM worker per target (default 60 seconds). A timed-out or interrupted remote
command may still be running on Windows: investigate target-side state before
retrying. Exit codes describe transport/script completion, not proof of every
intended side effect. Existing execution.lock and process-group cancellation
remain shared by standalone, custom and scheduled runs.

New scripts carry declarative phase and MITRE metadata, so `/api/phases`, phase
detail/run, CLI listing, builder capabilities and live current/next/timeline use
the same registries. The manifest includes the scripts and Windows adapter;
installer/updater generic paths already install scripts and web modules. No
special install step, remote agent or new Python dependency is introduced.

Permanent MRN reports include per-target timestamped action start/result events,
protocol, method, safe command summary, exit/transport status and warnings. P09
also records domain/DC, account action and group action. P10 records stdout/stderr
byte counts; **all** raw output, command content and transport exception text are
omitted, including from raw MrNobody logs. This prevents arbitrary embedded
tokens from leaking through heuristic redaction. Supplied credentials are
environment-only and existing environment redaction remains applied. Inventory
passwords are never consumed by these phases.

Investigation and Ground Truth views, MITRE summary/direct links, timeline,
evidence references, detection/investigation/mitigation guidance and HTML/PDF
exports use the existing Reports V2 pipeline. Guidance is advice, not a claim
that Wazuh collected an event. Target-side PowerShell logs may contain command
content; handle those logs according to the lab's access policy.

## Student analysis and verified references

For P09, compare Security 4720 (creation), 4728 (global security-group membership),
4738 (account changes), and 4624/4672 around the action times. Check subject,
member SID, domain and group RID 512. Idempotent runs may generate neither a new
creation nor membership-add event. In Wazuh, filter win.system.eventID and the
corresponding subject/target fields after enabling the relevant audit collection.

For P10, correlate WinRM Operational, PowerShell Operational 4103/4104 and Security
4688/4624 where enabled. Identify who executed the command, on which endpoint,
and whether independent target artifacts corroborate the reported exit status.
Apply least privilege, restrict management paths, monitor privileged group
changes and enable protected PowerShell logging.

MITRE mappings verified against technique pages on 2026-11-01:

- P09: [T1136.002 Domain Account](https://attack.mitre.org/techniques/T1136/002/),
  [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/),
  [T1078.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002/).
  Valid Accounts describes supplied domain access; metadata is not proof of a
  new mrnobody login or an observed successful use of every mapped technique.
- P10: [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/).
- Microsoft: [4720 account creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720),
  [4728 global group membership](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728),
  [PowerShell logging and protected events](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows).

## Verification scope

Offline fixtures mock WinRM and process launches; they cover metadata, dependency
order, Auto/Fixed targeting, runtime inputs, scheduler serialization/lease expiry,
profiles, redaction, timeout outcomes, reports/exports, live status and frontend
builder behavior. Linux CI additionally runs inert runner fixtures and shared
lock tests. No real Windows/domain action or VM deployment is part of validation.
