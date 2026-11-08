# P09 standalone submission and output

## Root cause
At main 6dabd2d3297815c945d7d657b0f4d5971c4eb0d2, standalone Attack Techniques rendered protocol and port as empty editable inputs with generic ssh/22 placeholders. P09 automatically enters scenario validation, which requires a protocol. Leaving protocol empty (or entering ssh) returns HTTP 400 before opening campaign.log. The shared message box is outside the local phase feedback flow; P09 had neither local submission state nor P06-style job tracking. This reproduces a no-log failure path; the original user's exact browser/runtime failure cannot be proven without their runtime logs.

## Changed behavior
- app.js renders P09 protocol as read-only WinRM HTTP and port as read-only 5985, defaults timeout to 60, validates required fields, submits canonical winrm-http/5985 regardless of DOM edits, disables duplicate submission and follows execution-status. Submission, rejection, transport and status feedback is visible beside the form and in Logs/Output. Invalid JSON/proxy responses include HTTP status. A bounded submission timeout reports uncertainty and asks the operator to inspect status before retrying.
- app.py canonicalizes only the standalone P09 endpoint and validates target/username/runtime password/timeout before launch. Launch errors are actionable and do not echo exception text. Submission and launch failures append to the shared execution log.
- 09-ad-privilege.sh announces dispatch and reports missing configuration/runtime failures. Standalone P09 uses HTTP/5985.
- windows_actions.py emits a TCP reachability-check event, probes the selected private target's TCP 5985 in the bounded worker, then attempts existing NTLM/WinRM execution. A failed probe returns an actionable error; a listening port is not treated as proof of WinRM/authentication or AD success. Missing pywinrm/NTLM dependency imports have a distinct safe diagnostic.
- Existing structured start/result/skip/completion events and verified AD result parsing remain. PowerShell and raw transport errors are never logged. Credentials remain environment-only; no AD action or password semantics changed.
- Custom/full execution, scheduler contracts and other phase transport choices remain intact. Historical reports are not rewritten. Existing install paths distribute these files; update-manifest.txt hashes are refreshed, with no new runtime dependency.
- Offline API/worker regression tests, existing fake-WinRM integration tests and Playwright UI tests cover fixed settings, submissions, validation/errors, status transitions and log rendering. Existing custom/full, report and other-phase tests remain in the CI suite.

## Verification and limitations
GitHub Actions runs Python/JavaScript/Bash syntax, updater manifest consistency, offline regression suites and browser tests. No deployment or lab command is executed by this change. Live target reachability and NTLM/AD permissions are checked only when an operator runs P09; no access to a user's target is assumed.
# P09 verification and repeat runs

P09 uses authenticated NTLM WinRM and verifies that the remote system is a
writable domain controller before any AD write. TCP reachability or an HTTP 405
from `/wsman` confirms the listener only; neither proves the host is a DC.
For this CyberLab installation, select the Windows Server 2025 DC at
`192.168.2.200` with WinRM HTTP port `5985`. Do not select an ordinary RDP/SSH
endpoint such as `192.168.1.120`.

For Full Campaign, set `NORDIC_AD_DC_TARGET=192.168.2.200` in the runtime
environment to pin P09 to that DC, or use a fixed-target scenario with P09's DC
target. This address is a lab-specific example, never a global default. The
standalone/fixed scenario target takes precedence over a campaign DC pin.
With no pin, inventory candidates must explicitly identify a DC using boolean
`domain_controller=true` or integer `domain_role=4/5`; ordinary RDP/Windows
classification is insufficient. Each candidate must then pass the authenticated
DC precheck. No candidates produces SKIPPED with
`no_dc_candidates_configure_dc_target`. Credentials remain runtime-only.

The precheck reads the exact `mrnobody` account and Domain Admins resolved by the
current domain SID plus RID 512. Existing accounts must have the exact name and
description `MrNobody controlled lab account`, including accounts created by old
P09 releases. Name or privileged membership alone is insufficient ownership.
An ownership conflict blocks changes; P09 never automatically adopts an account.
Only a missing account, a disabled owned account, or missing direct group
membership is changed. Enabled accounts retain their password. Writes use the
resolved account identity, and DC/domain/account identities are checked again.

An independent session then reads Enabled and direct Domain Admins membership.
Only confirmed postconditions produce SUCCESS. Evidence distinguishes
`created_enabled`, `enabled_existing`, `already_enabled`, `added` and
`already_member`, with SID/DC identity and `verified` fields. An uncertain write
followed by a successful postcheck reports the observed existing state rather
than claiming which write completed. The generated PowerShell refreshes all
account flags after writes, and the Python coordinator performs another read in
a separate authenticated session. An incomplete read returns internal `ready`,
never `success`; it is only a prerequisite for the guarded write.
Exceptions and raw remote output are omitted.

`invalid_ad_response` means response validation failed, not that TCP 5985 is
unreachable. Diagnostics now include only fixed `schema_field`, `schema_reason`
and `schema_type` codes, covering nonzero PowerShell status, malformed JSON,
SID/domain identity, enum and boolean type errors. String booleans and serialized
SID objects/arrays are rejected; PowerShell emits explicit string identities and
boolean flags. Neither values, unknown keys, exception text nor remote stream
previews are logged. The 2026-11-08 log confirms precheck validation failure but
does not identify the rejected field; that exact live cause cannot be recovered
from the old log. Valid typed responses pass the actual PowerShell fixture tests.

The configured 5–300 second value bounds each read wait. WinRM operation timeout
is at most 60 seconds, read timeout is the configured value plus 10 seconds, and
the three-stage worker budget is `3 * (timeout + 10) + 20` seconds (230 seconds
at the default 60). A worker timeout starts a separate read-only verification
worker with budget `2 * (timeout + 10) + 20`; it never replays the write.
Unconfirmed or unknown state after an attempted write reports PARTIAL (exit 80),
not SUCCESS. Precheck connection/configuration errors report FAILED; a confirmed
non-DC reports SKIPPED. Full Campaign retains partial phase evidence and continues;
its final report remains partial. No automatic rollback is performed.

The update manifest and fresh-install cloud-init include `web/p09_actions.py`.
This repository change does not deploy or run P09 against the lab VM.

After this fix is merged into `main`, run `sudo mrnobody update`. For this lab,
set `NORDIC_AD_DC_TARGET="192.168.2.200"` in
`/opt/nordic-attack/config/defaults.conf` for Full Campaign, or select that target
in standalone P09. Do not configure Kali `192.168.1.120` as the DC.
Run standalone P09 twice using the GUI with runtime administrator credentials.
The second run must show `WINDOWS_ACTION_SUCCESS`, `verified=True`,
`account=already_enabled`, `group=already_member`,
`verification=independent_read_only` and `PHASE_COMPLETE`.
If ownership conflicts, inspect the account manually: only the exact historical
P09 description plus matching name and domain SID permits reuse. An unmarked
legacy-looking account is never adopted automatically.
