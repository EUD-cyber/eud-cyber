# P06 standalone execution

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

## Independent simulated default

In Attack Techniques, enter the private lab target, SSH/WinRM transport and current
runtime credentials, then select RUN P06. Leave the remote file and staging incident
fields empty. No P05 run or `staged-data.json` is needed.

P06 creates exactly one `corporate-secret-data.txt` in a new incident-specific temporary
directory on the target. The contents explicitly say **SIMULATED COMPANY DATA** and
contain only invented training values and the incident ID. The generated payload is
under 1 KiB. Existing files and directories are never collected; arbitrary source paths
are unsupported. Existing directories/files are not overwritten. Failed creation or
remote size/hash verification stops execution.

Linux uses SSH. Windows uses WinRM HTTP/HTTPS and the existing installed pywinrm venv.
The optional port defaults to SSH 22, WinRM HTTP 5985 or HTTPS 5986. Credentials are
execution-time inputs and are excluded from reports; SSH passwords use the child
environment rather than process arguments.

CLI: `MRNOBODY_PASSWORD` supplies the password. Run:

```sh
run-phase.sh 06 --target <private-ip> --protocol ssh --user <user>
```

API: POST `/api/phase/06/run` with `target`, `protocol`, `username`, and runtime `password`.
Omit both `file` and `staging_incident` for the independent default. Dry run validates
and previews dispatch without creating a remote file or starting a receiver.

The form preserves visible validation/submission/running/final job feedback and the
incident correlation introduced by the P06 RUN fix. An acknowledgement is insufficient:
received bytes must match the expected size and SHA256 before success is recorded.

## Reuse registered P05 synthetic evidence

For backward-compatible standalone reuse, supply **both** the exact remote synthetic
`file` and its original `staging_incident`. The selected artifact must exist in the
current staging inventory with matching incident, target, platform, path, positive
size, SHA256 and `synthetic-training-data` type. Missing/replaced inventories, incomplete
evidence and mismatched incidents fail visibly; no latest incident is selected.

```sh
run-phase.sh 06 --target <private-ip> --protocol ssh --user <user> \
  --file <registered-remote-synthetic-path> --staging-incident <P05-id>
```

The new execution has its own incident ID; the source incident is retained separately.
The selection is revalidated at execution time. Specifying only one reuse field fails
instead of silently selecting the synthetic default.

## Campaigns and custom scenarios

Full Campaign and Auto Discovery retain their P03/P05 dependency workflow. P06 consumes
actual staged artifacts belonging to the current incident and never substitutes its
independent default. Missing/foreign inventories, absent staged hosts or unverified
transfers fail clearly. Legacy records without a SHA256 cannot establish verified success.

A Fixed Targets custom scenario with P06 alone can omit `file` and works independently.
If P05 is included, it must precede P06; P06 resolves the target's current-incident
synthetic staging output even when the optional file field is empty. Missing P05 output
fails rather than creating replacement evidence. `@staged` remains supported and strictly
checks the current incident. Auto Discovery keeps its prerequisite phases.

## Evidence and cleanup

Incident JSON and both Ground Truth and Investigation views, including Affected Assets
and HTML/PDF exports, expose the recorded source host/path/name, synthetic source kind,
source and execution incident IDs, local receiver path, sizes, SHA256, timestamps and
verification result. Preparation is not transfer success. Failed preparation/transfer
attempts remain separate from verified transfers and do not inflate the transfer count.
Standalone P06 reports exclude unrelated state snapshots.

Generated source files and received artifacts are retained for investigation. After the
exercise, remove only the exact recorded generated file and its incident directory.
There is no blanket directory cleanup or collection.

Regression tests use temporary installs, a loopback receiver and SSH/WinRM transport
doubles. They exercise actual dispatch, receiver verification, reporting and HTML/PDF
exports without contacting target hosts or deploying VMs. Windows PowerShell scripts
are parsed without execution. Live SSH/WinRM end-to-end validation remains a lab check.
