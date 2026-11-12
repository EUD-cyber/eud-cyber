# MrNobody P09 and P10

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

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
domain when available and is skipped with target_must_be_domain_controller. In
Auto mode each Windows candidate is tried; a skipped candidate is not evidence
of successful privilege escalation.

The action discovers the domain and DC, resolves Domain Admins by domain SID
plus RID 512 (supports localized group names), looks up mrnobody, creates it
**enabled** if absent, and adds direct membership only when needed. New accounts
report `account=created_enabled`. An existing disabled account receives the
runtime password and is enabled (`enabled_existing`); this also repairs accounts
created without a password by earlier P09 versions. An already enabled account
is not recreated and its password is preserved (`already_enabled`). Membership
reports `group=added` or `already_member`. Both enabled state and direct group
membership are read back and verified before reporting success. This makes a
newly created/enabled account usable for later lab testing; it does not bypass
AD permissions, password policy, logon restrictions or account expiry. Partial
failures retain completed account/group steps. Failed AD exception text is omitted.

### Runtime password (standalone, custom, campaign and scheduler)

P09 reuses the existing execution-time Windows password: `MRNOBODY_PASSWORD`,
falling back to `NORDIC_RDP_PASSWORD`. This password authenticates WinRM and sets
the password for **new or disabled** mrnobody accounts. It must satisfy the lab
domain password policy; rejection is a hard AD-action failure. Enabling an
existing disabled account deliberately resets its password to this value. For
an already enabled account, use its existing password in later tests.

The standalone GUI/API uses its existing runtime `password` input. Standalone
CLI (`mrnobody run 09 --target <private-DC-IP> --protocol winrm-http`) uses the
existing runtime password environment; supply it securely and avoid password command-line
arguments or shell history. Built-in campaigns and custom executions use their
existing runtime `rdp_password` input (`NORDIC_RDP_PASSWORD` in CLI campaigns).
Fixed custom phases receive it through `phase_environment`; Auto mode uses the
same runtime credential for discovered candidates. Scheduler arming uses the
existing process-local Windows credential lease; re-arm after service restart.
Normal/Slow/Custom timing does not alter this credential path.

No new secret field is added to saved scenarios or schedules. The password and
substituted PowerShell exist only in process memory/WinRM transport; neither is
written to MrNobody reports, logs or runtime state. Base64 is quoting, not
encryption. Target-side PowerShell/script-block auditing may capture the script;
protect that evidence as credential-bearing. No password is hardcoded or returned.

### P09 final result

P09 emits `PHASE_COMPLETE`/exit 0 when at least one eligible DC returns exit 0
with a verified enabled account and verified Domain Admins membership, and no
candidate reports a hard action/configuration/internal failure. Earlier or later
transport/authentication failures do not poison that success. Nonempty stderr
(including PowerShell module-progress CLIXML) is counted, not treated as failure;
raw output is omitted. All transport/authentication failures remain fatal, as do
account creation/password/enablement/group failures, invalid responses, worker
timeouts and malformed configuration, even alongside another DC success.

Ground Truth retains candidate timestamps, target, protocol, method, exit code,
domain/DC, account/group states and stdout/stderr byte counts. Investigation and
Ground Truth views and their HTML/PDF exports show the same final P09 success
and candidate evidence, including any earlier failed attempt. Live Campaign and
Execution Overview/timeline use the successful phase exit/state and advance to
the next selected phase. Historical report evidence is not rewritten.

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

## P10 result and exit semantics

P10 uses the remote execution exit/error result, never stderr byte count alone.
The runtime parses the supplied text inside a protected ScriptBlock invocation;
syntax errors, unknown commands, terminating errors and default nonterminating
PowerShell errors become a controlled command error. Warnings/information do not
fail the action. A nonzero native executable exit is also a command error.
PowerShell error records use ErrorActionPreference=Stop by default; an operator
can still explicitly handle errors inside their own script. See
[PowerShell preference semantics](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1)
and [exit-code semantics](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-5.1).

- Exit 0: PHASE_COMPLETE, including success with nonfatal stderr/warnings.
- Exit 79: WINDOWS_ACTION_ERROR and PHASE_SKIPPED with
  `Custom PowerShell command failed`. Full Incident and custom campaign runners
  handle this exit, store phase skipped, and continue to the next selected phase.
  Standalone CLI retains exit 79 and a failed incident with phase skipped, making
  the command error visible to its caller. Direct script callers must handle 79.
- Exit 1: hard infrastructure/configuration/runtime failure. All candidate
  transports/authentication failing, no Windows targets, missing required runtime
  input, timeouts and internal worker errors remain hard failures.

A failed transport candidate does not invalidate another candidate's successful
execution. A command error on any reachable target remains explicit even if
another target succeeded; it is a controlled action error rather than a silent
success. Infrastructure/internal errors cannot be masked by another success.

Both report views and HTML/PDF exports retain operational P10 action results,
target, protocol/method, timestamp, redacted command label, exit code where known
and output byte counts. Raw command/output/error content remains completely
omitted. The live timeline shows skipped plus the command-error explanation,
or complete plus nonfatal warning metadata; campaign progression uses the
existing skipped state. Dependencies, timing profiles, scheduling, MITRE metadata,
and runtime-only command/credential handling are unchanged.

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
byte counts; raw output, command content and transport exception text are
omitted. P10 additionally retains safe previews as described below. Supplied credentials are
environment-only and existing environment redaction remains applied. Inventory
passwords are never consumed by these phases.

### P10 safe output previews

P10 captures stdout and stderr separately. Each safe preview is at most **512
characters**, including a trailing ellipsis when truncated. Redaction runs on
the complete accepted input before truncation: existing environment/credential
redaction and export scrubbing remove supplied secrets, credential assignments,
authorization values, URL passwords, private keys and common token forms.
Commands mentioning credentials, secrets, tokens or wordlists, and direct file
reads (`Get-Content`, `gc`, `cat`, `type`) have previews withheld. Streams over
64 KiB are withheld rather than partially decoded or partially redacted.

PowerShell CLIXML progress objects (including “Preparing modules for first use”)
are discarded. Only top-level string output/error/warning records are used;
PowerShell newline escapes are decoded. Malformed/unsupported XML is omitted.
These display rules never influence the recorded exit code or failure semantics.

The ground-truth log stores only these scrubbed previews, JSON-quoted on one
physical line with spaces/equals escaped to prevent forged event fields. Both
Investigation and Ground Truth show timestamped, per-target **Safe stdout/stderr
output preview** labels through existing P10 action evidence. HTML and PDF use
the same report model and reapply export redaction. No unrestricted output is
saved in the raw evidence appendix; existing dashboard behavior is unchanged.

A preview confirms returned text such as `MRNOBODY_P10_TEST_OK`, hostname or
whoami; it does not prove a side effect. Redaction cannot reliably recognize an
arbitrary unlabelled secret or every indirect file-reading command. Use benign
verification output, never credential/token dumps or wordlist-printing actions.

Investigation and Ground Truth views, MITRE summary/direct links, timeline,
evidence references, detection/investigation/mitigation guidance and HTML/PDF
exports use the existing Reports V2 pipeline. Guidance is advice, not a claim
that Wazuh collected an event. Target-side PowerShell logs may contain command
content; handle those logs according to the lab's access policy.

## Student analysis and verified references

For P09, compare Security 4720 (creation), 4722 (enablement), 4724 (password reset), 4728 (global security-group membership),
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
