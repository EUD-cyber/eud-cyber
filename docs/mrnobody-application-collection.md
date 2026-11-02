# P15–P17 application, reversible evasion and collection simulations

These phases extend the existing CLI/API, metadata-driven GUI, version 1 custom
scenarios, scheduler, Normal/Slow/Custom start offsets, execution timeline and
Investigation/Ground Truth reports (including HTML/PDF). No running lab host is
provisioned or modified by this source change. Runtime credentials remain in the
existing execution environment/credential lease, never in scenario/state files.

## P15 profiles

`sqli` sends one fixed boolean SQL expression to the optional **MrNobody Web Lab
v1** endpoint. Its ephemeral SQLite database contains one synthetic marker.
`traversal` requests `../synthetic-marker.txt`; the endpoint implements a virtual
path lookup and never reads an OS file. It is a traversal *analogue*, not a
filesystem escape. Neither profile establishes shell/session access. Neither
updates compromised-hosts.json, even after successful validation.

The registry in `web/web_profiles.py` specifies profile ID/name, expected app,
method, endpoint/query, verification marker, ATT&CK mapping, access semantics and
cleanup. `web_path` selects a simple absolute base path (default `/mrn-lab`);
target/port/protocol select a private numeric IPv4 service. Only these two fixed
profiles are initially supported; Juice Shop is not silently treated as this app.
Additional providers must define their own fingerprint and safe verification.

P15 fingerprints before validation: exact app/version/synthetic JSON is required.
Unreachable/mismatched apps skip; a matching app with failed validation fails.
Candidate mismatch followed by a matching successful candidate succeeds. Only
fixed evidence markers and HTTP status are retained; arbitrary response bodies,
cookies, authorization and server exception text are omitted. Requests are bounded
to three seconds and 4 KiB, never follow redirects or use proxies/DNS. HTTPS uses
certificate verification. At most 64 discovered candidates are examined.

On a deliberately isolated lab web host, an instructor can manually run:

```sh
python3 web_lab.py --bind 192.168.1.20 --port 8088
```

Use Fixed Targets with HTTP/8088, or include 8088 in P02 web discovery ports for
Auto/Full Incident. The optional server is not automatically started or installed
as a service. Stop the foreground process after teaching. It has no persistent
database or cleanup artifacts. Do not expose this teaching endpoint publicly.

```sh
mrnobody run 15 --target 192.168.1.20 --protocol http --port 8088 --web-profile sqli --web-path /mrn-lab
```

## P16 reversible behaviors

Both platforms support `config-toggle` and `log-rename`. They operate exclusively
on namespaced synthetic copies of `monitor.conf` or `exercise.log`, never real
security services, audit policies, antivirus exclusions or system logs.
`config-toggle` changes the fixed enabled marker to disabled, verifies it and
restores the original in finally/trap-equivalent logic. `log-rename` moves the
synthetic log to `.mrn-restore`, verifies it, then moves it back. A rerun first
recovers an interrupted `.mrn-restore` after validating its exact original marker.

The stable instructor templates are under:

| Platform | Template directory | Per-incident working directory |
| --- | --- | --- |
| Linux | `/var/tmp/MrNobody-exercises/templates` | `/var/tmp/MrNobody-exercises/<MRN-ID>` |
| Windows | `C:\ProgramData\MrNobody\Exercises\templates` | `C:\ProgramData\MrNobody\Exercises\<MRN-ID>` |

`monitor.conf` must contain exactly `MrNobody synthetic monitor enabled` plus LF.
`exercise.log` must contain exactly `MrNobody synthetic exercise log` plus LF.
The phase makes the namespaced copy only after template verification. Missing
templates/artifacts skip; marker mismatch, action or restore errors fail.
No free-form service/config/path inputs exist, so the builder shows only fields
used by the selected platform/behavior. Restore paths and before/action/after
states are reported. Re-run `--action cleanup` with the original incident and
target to recover interrupted work. Normal successful runs already restore the
original synthetic contents; the restored exercise copy may remain for inspection.

```sh
NORDIC_INCIDENT_ID=MRN-lesson mrnobody run 16 --target 192.168.1.20 --protocol ssh --behavior config-toggle
NORDIC_INCIDENT_ID=MRN-lesson mrnobody run 16 --target 192.168.1.20 --protocol ssh --behavior config-toggle --action cleanup
```

## P17 datasets, archives and downstream state

The stable synthetic datasets live under the same platform root in
`datasets/finance` (`customers.txt`, `invoices.txt`) or `datasets/engineering`
(`design.txt`, `inventory.txt`). Each file must contain exactly
`MrNobody synthetic <dataset> <filename>` plus LF. There is no recursive search.
Only these names, regular small files and exact synthetic contents qualify.
Symlink/reparse traversal is rejected. Linux additionally rejects hard links.
Missing files yield partial collection with the actual file names/count and a
warning; no files skips. Unexpected contents fail closed rather than archiving
unrelated data. Instructors prepare these fixtures explicitly; the phases never
seed user data or search homes/secret stores.

P17 creates `<MRN-ID>/<archive_name>.tar.gz` on Linux using Python tarfile and
`<MRN-ID>\<archive_name>.zip` on Windows using .NET ZipFile. Default suffix:
`collection`. Reruns verify an existing archive's names and synthetic contents
before replacing it. Cleanup verifies the same scope before removal. Archive
creation/verification failure is a failure, never successful empty collection.
Linux targets require Python 3; Windows requires PowerShell/.NET archive support.
Transport/dependency failures are reported through the existing SSH/WinRM runner.

Successful archives update **the existing `staged-data.json`** with its ordinary
`ip/platform/access/staged/file/size/sha256/data_type` fields, plus additive
`producer_phase=17`, dataset, count and collection incident. P17 invalidates a
matching previous archive entry before rerunning, preventing stale P06 transfers
after a failed archive rebuild. P05 retains current-incident P17 entries and skips
duplicate synthetic staging on those hosts; other hosts retain P05's behavior.
P06 consumes the same inventory. Fixed/custom P06 can use `file=@staged`.
`--action cleanup` with the same incident/dataset/archive suffix removes the
verified archive and its matching state entry. No password is written to state.

```sh
NORDIC_INCIDENT_ID=MRN-lesson mrnobody run 17 --target 192.168.1.20 --protocol ssh --dataset finance --archive-name collection
NORDIC_INCIDENT_ID=MRN-lesson mrnobody run 17 --target 192.168.1.20 --protocol ssh --dataset finance --archive-name collection --action cleanup
```

## Ordering, dependencies and compatibility

Full Incident order:
`01 → 02 → 15 → 03 → 08(optional) → 09 → 10(optional) → 11 → 12 → 13 → 14 → 16 → 04 → 17 → 05 → 06 → 07`.

P15 Auto requires P02 → P01 only. P16/P17 Auto require compatible established P03
access → P01, without adding unrelated post-compromise phases. Fixed Targets
accept direct private targets and runtime transport credentials. The builder
recursively inserts prerequisites and orders selected phases with semantic edges:
P15 before access, P16 after selected persistence/native tools and before P17,
P17 before staging/exfiltration. It never inserts optional phases merely to impose
those order constraints. The API validates the same edges for saved/imported
definitions. Normal and Slow share existing pacing; Custom supports start offsets.
Schedules and imports/exports keep version 1 and persist no credentials.

Missing optional endpoints/datasets are nonfatal skips. Actual validation,
archive, action and restoration failures remain failures. P01–P14 fields,
historical report loading and state schemas remain compatible. New report fields
are additive; old reports do not gain phantom P15–P17 actions.

Investigation guidance covers web/proxy/WAF/Wazuh/Suricata, Windows process and
file auditing/Sysmon/PowerShell, Linux audit/journal/FIM, remediation and the
limits of each sensor. Ground Truth records target, selected profile/behavior,
fixed request/fingerprint evidence, state/restore or archive metadata, outcomes,
warnings and timestamps. Live status uses the existing lifecycle events.

## ATT&CK mapping verification

Reviewed against the current MITRE pages on 2026-11-02:

| Behavior | Mapping | Interpretation |
| --- | --- | --- |
| SQLi validation | [T1190](https://attack.mitre.org/techniques/T1190/) | App exploitation analogue; no host compromise claim |
| Virtual traversal marker | T1190 + [T1005](https://attack.mitre.org/techniques/T1005/) | Additional synthetic local-data retrieval analogue |
| Synthetic monitor toggle | [T1685](https://attack.mitre.org/techniques/T1685/) | Current Disable or Modify Tools; Defense Impairment; replaces legacy T1562.001 |
| Reversible synthetic log rename | [T1070](https://attack.mitre.org/techniques/T1070/) | Parent Indicator Removal analogue, not file deletion or real log clearing |
| Synthetic collection/library archiving | T1005 + [T1560.002](https://attack.mitre.org/techniques/T1560/002/) | Both implementations call libraries; do not claim utility-based T1560.001 |

Action-specific technique sets feed reports/MITRE summary; metadata is a
behavioral mapping, not evidence of a real adversary or actual defensive impairment.

## Distribution and validation

The updater manifest includes the three phase wrappers and four support modules.
Cloud-init uses an explicit download list rather than consuming this manifest at
first boot, so only these seven new files were added to its downloads. No new
packages, duplicated existing downloads or automatic target provisioning were added.

`tests/mrnobody/application_collection.py` exercises profiles/fingerprints,
candidate fallback, data scope, restore/recovery/idempotency, Linux archives,
isolated PowerShell fixture actions, both transport parsers, state linkage,
API/custom/scheduler contracts, timing, reports/exports and live overview.
The full existing validation workflow remains enabled; no test deploys a VM.
