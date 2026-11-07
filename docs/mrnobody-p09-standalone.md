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
