# P06 standalone execution

The Attack Techniques P06 form takes a **remote synthetic file path**, not a local file upload.
Run P05 first, then copy its incident ID and exact file path from its report. Enter the
same target, its SSH/WinRM transport and current runtime credentials. The port is optional
(SSH 22, WinRM HTTP 5985, HTTPS 5986). Select the staging incident explicitly.

The selected artifact must exist in the current staged-data.json, with the same original
incident, target, platform, file path, positive size and SHA256 and synthetic-training-data
type. P17 synthetic archives recorded in this schema also work. A missing file, replaced
inventory, wrong incident or incomplete evidence is rejected visibly. P06 does not generate
a new staging file, choose the latest incident implicitly or reuse stored credentials.
If another run replaced staged-data.json, run P05 again and use that new evidence.

The new P06 execution has its own incident ID. The original staging ID is logged as
EXFIL_STAGING_SELECTED; the source inventory is never relabelled. The execution validates
the selection again before starting its receiver. It verifies received bytes and SHA256
against the selected evidence. An acknowledgement alone does not count as success.
A failed, skipped or mismatched standalone transfer exits nonzero and produces a failed
standalone report. The phase form shows validation, submission, running and final status,
correlated by the new job incident ID, with details in live output and Reports.

CLI reuse: run-phase.sh 06 --target <private-ip> --protocol ssh --user <user>
--file <remote-path> --staging-incident <P05-id>. Pass MRNOBODY_PASSWORD in the environment.
Campaign mode retains its existing state workflow. Fixed-target custom scenarios use the
current incident's staging artifact and can continue to use @staged; they do not need a
foreign incident selector.

Regression tests use an isolated temporary install, a loopback HTTP receiver and a remote
transport double. They never contact a target or deploy a VM. Windows transport selection
and validation are tested offline; these are not a live WinRM end-to-end test.
