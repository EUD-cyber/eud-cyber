# P11 Full Campaign — instructor-owned isolated CyberLab

P11 is an explicit, visible teaching exercise. Starting Full Campaign consents to
these fixed lab actions on the allowlist formed by completed, same-incident P03
authentication evidence. No target scan, credential guessing, arbitrary payload,
hidden artifact, privilege escalation, C2 or exfiltration is added here.

## Selection and actions

Only P03 schema-v2 hosts with `authenticated=true`, `compromised=true` and a
verified `access_methods` record qualify. Linux requires `ssh_session_marker`
over SSH; Windows requires `read_only_windows_identity` over WinRM HTTP/HTTPS.
P11 preserves the verified protocol, port and username. RDP alone, port-open
results, failed/unconfirmed authentication, legacy/incomplete inventories,
other incidents, non-private addresses and a changed runtime username are
excluded. Passwords remain runtime-only; keep the original campaign credentials
unchanged between P03 and P11. Persisted credentials are never consumed.

Every eligible Linux host gets cron, systemd user-service, bounded background
process, and `cron-systemd-process`. Every Windows host gets Scheduled Task,
service, and task-service. No success, skip or individual error stops this loop.
The previous `cron-systemd` standalone method remains available and unchanged.
Existing standalone names/actions keep their behavior.

Campaign activity is fixed to **300 seconds**, DNS disabled, and low (2% of one
CPU core) for process demonstrations. The combined Linux scenario uses a real
visible Python systemd MainPID with at most 20ms CPU per second. Cron can start
that user service only before its original UTC deadline. It needs an already
working user manager; P11 does not enable linger, sudo or install packages.
The Windows service uses the existing fixed native worker with manual startup
and automatic activity stop at expiry; task-service adds its bounded trigger.
The single Scheduled Task runs a fixed echo once, with an EndBoundary and a
10-second execution limit. Single cron logs a fixed training marker only before
its absolute deadline. No method accepts remote commands.

Names are `mrnobody-p11-fc-<8 hex incident hash>-<method>`. They are stable on
rerun and distinct across methods. Any existing directory, task, service, unit,
cron reference or orphan process in the requested namespace is checked before
creation. Existing artifacts, even apparently owned ones, are never adopted,
renamed or overwritten: `SKIPPED – Artifact already exists` is recorded. An
unexpected query/write error remains a failure, not a collision skip.

## Evidence and status

Ground truth records one terminal result per target/method, its requested action,
artifact name and path, cleanup suffix, target verification, expiry when verified,
and PID for processes. Failed/time-limited calls may have left partial artifacts;
their cleanup remains required. Missing expiry/state is explicitly unverified.
`method_results` in the JSON report retains these terminal records. Raw transport
output and credentials are not included. These receipts establish target state,
**not SIEM/Wazuh detection**; sensor corroboration is separate.

All success -> SUCCESS/exit 0. All controlled skips or no eligible targets ->
SKIPPED/exit 78. Any success mixed with skips/errors, or partial target evidence ->
PARTIAL/exit 80. Errors without any success/partial result -> FAILED/exit 1.
Full Campaign handles exit 80 as partial and continues, retaining partial overall
status. A wholly failed P11 keeps the existing campaign failure behavior.

## Stop, cleanup and validation after update

1. Merge the P11 source PR, then run `mrnobody update` on the instructor VM.
   Update follows the configured branch; an unmerged PR is not in main.
2. In the isolated lab, run P03 with the intended credentials and inspect its
   same-incident `compromised-hosts.json` records. Include two Linux SSH hosts,
   Windows WinRM HTTP/HTTPS where available, an RDP-only host and a failed login.
3. Start Full Campaign. Expect four terminal P11 records per eligible Linux host
   and three per Windows host; none for the RDP-only or failed-login hosts.
   Confirm the recorded state and process PID locally. Service-manager failure
   on one Linux host must not prevent other methods/hosts from being attempted.
4. Repeating P11 with the same incident produces collision skips without writes.
   Existing artifacts from any MrNobody instance are preserved. Different
   incidents use different names; never delete an artifact to bypass a skip.
5. Activity stops after five minutes. The visible cron/task/unit/service/files
   remain as investigation evidence and require explicit cleanup. Expired cron
   entries are inert; an expired service worker does not resume activity.
6. To stop early or remove evidence, use standalone **P11 Cleanup** with the exact
   target, verified transport/port, original username, method and **full artifact
   suffix from ground truth** (`fc-…-method`, excluding `mrnobody-p11-`). Reserved
   campaign suffixes select the bounded cleanup implementation. For the combined
   scenario choose `cron-systemd-process`. Cleanup stops the owned process/service
   before removing its owned files/trigger; repeat cleanup to verify idempotence.
   Do this separately for each successful or possibly partial action. Never run
   cleanup for a skipped foreign artifact. Stopping the campaign runner alone
   does not clean remote artifacts; expiry still bounds activity.

## Future reporting roadmap — intentionally not implemented

Add per-technique practical local Windows/Linux detection instructions
(PowerShell, `systemctl --user`, `crontab -l`, `ps`/`top`) and SIEM/Wazuh search
examples. Separate expected telemetry, target ground truth and corroborated
sensor detections. This change adds no such detection-query generator.
