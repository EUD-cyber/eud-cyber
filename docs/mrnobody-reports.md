# V2 incident reports / ground truth

Full Incident publishes `/opt/nordic-attack/reports/<incident-id>.json` after a
campaign completes, fails, or receives a catchable INT/TERM stop. Reports use the
existing incident ID, phase order (01,02,03,08,04,05,06,07), metadata comments,
campaign state, inventory, and shared `incident-ground-truth.log`. Runtime state,
logs, history, technical paths and services keep their existing behavior.

Reports are atomic, immutable snapshots: a repeated incident ID retains its first
report. Use a fresh incident ID for each campaign. A reporting error logs a warning
and preserves the original campaign exit code. SIGKILL, power loss and failures
before campaign state creation cannot invoke the finalizer. Historical reports
are not fabricated from today's shared runtime state.

## Schema version 1

| Field | Content |
| --- | --- |
| `schema_version`, `generated_at` | Schema number and UTC snapshot time |
| `incident` | `id`, `scenario`, `started`, `ended`, `status`, `exit_code` |
| `summary` | Counts of inventory hosts, compromised hosts, successful transfers, impacted hosts |
| `campaign` | Existing campaign metadata, configuration and phase state, with credential values removed |
| `inventory`, `compromised_hosts` | Incident-matched inventory documents, retaining original host/access fields |
| `phases` | Ordered IDs/names, runtime and normalized status, start/end times, MITRE tactic and technique ID/name pairs, outcome counts and events |
| `events` | Timestamp, phase, action, source/target, protocol/method when recorded, outcome, parsed fields, original message, evidence path/line, phase MITRE IDs |
| `evidence` | Incident-matched networks, inventory, web targets, compromised hosts, staging, exfiltration, impact and wordlist state, including original paths, hashes, bytes and timestamps |
| `sources`, `warnings` | State source paths and missing, corrupt or foreign-incident evidence warnings |

Incident status is `complete`, `failed` or `interrupted`. Phase status is `success`,
`failure`, `skipped`, `not_run` or `interrupted`; `runtime_status` retains the
original value. A phase completing does **not** mean every host action succeeded.
Action outcomes separately distinguish `success`, `failure`, `skipped` and
`observed` (discovery/start/informational events without a conclusive result).

Unknown source/target, protocol, start/end and unavailable evidence remain null.
The generator never invents a source address or infers authentication success
from a port being open. Evidence times retain the original timezone and precision;
snapshot times use UTC. Log matching uses exact incident IDs and excludes entries
before the campaign start (at the log's one-second precision).

MITRE IDs come from `MITRE_TECHNIQUES`. The parallel, pipe-separated
`MITRE_TECHNIQUE_NAMES` metadata supplies human-readable names without a second
mapping in the reporter. Names follow [MITRE ATT&CK](https://attack.mitre.org/techniques/).
`mitre_mapping: "phase_metadata"` explicitly identifies action mappings as inherited
phase metadata, rather than a claim that every listed technique occurred in every
event. Custom metadata without names remains valid and yields null names.

Credentials are removed recursively from state snapshots, including passwords in
wordlist-generated compromised hosts. Original state/log files are never rewritten.
Ground-truth messages are reconstructed from redacted parsed fields; phase implementations must
continue to avoid logging credentials. No wordlist contents or credential cache
files are read. Missing optional phase 08 evidence is permitted.

## API and GUI

- `GET /api/reports` returns `{count, reports}` with newest-first incident metadata
  and summary counts. Missing report directory returns an empty list. Invalid,
  corrupt and symbolic-link report files are ignored.
- `GET /api/reports/<incident-id>` returns the complete JSON document; missing,
  invalid or unreadable reports return JSON error status 404. IDs cannot contain
  path separators. Existing historical H3 IDs are accepted for compatibility.
- Reports navigation loads the list. Refresh reports reloads it. Open report
  displays incident metadata, inventory, compromised hosts, expandable phase
  timelines/MITRE mappings and staging/exfiltration/impact/wordlist evidence,
  with a link to the JSON. Evidence is rendered as text, including host-supplied
  names and messages. Empty, missing and failed requests have visible messages.

The existing manifest builder automatically includes `web/reports.py`, metadata,
backend and GUI updates. Its existing exclusions keep generated `reports/*`,
state and logs out of update payloads. The updater already validates Python files
and restarts the web service when web files change; no new dependency is required.

## Validation

Run `python tests/mrnobody/reports.py --bash`,
`python tests/mrnobody/backend.py`, `python tests/mrnobody/runtime.py --bash`,
`node tests/mrnobody/reports.cjs`, and the existing scenarios/logs JavaScript tests.
The report suite runs the actual scenario with **only harmless mock phases** in a
temporary installation. It covers optional wordlist enable/disable, success,
failure, TERM interruption and reporting failure, as well as snapshot isolation,
redaction, immutable publication, malformed evidence, timestamps and outcomes.
The PR validation workflow runs these checks automatically.

## Reports V2: additive student analysis

The ground-truth schema remains `schema_version: 1`; existing fields and atomic
first-writer-wins publication remain compatible. New documents additionally carry:

| Field | Meaning |
| --- | --- |
| `report_type` | `campaign` or `standalone_phase` |
| `phase_id` | Selected phase for standalone reports only |
| `analysis_version` | `2`, the educational extension version |
| `phases[].analysis` | Recorded status, event-derived findings, evidence path/line references, detection, investigation tasks and prevention guidance |
| `phases[].mitre.techniques[].url` | Validated direct technique/sub-technique URL, or null for invalid metadata |
| `mitre_summary` | Deduplicated phase metadata mappings, mapped phases and phases with action-level events |

`observed_phases` in the MITRE summary means action-level events exist for that
phase. It does **not** establish that every mapped technique ran or succeeded.
The GUI labels this distinction. Recommendations are static per phase, separately
labelled as educational guidance; they do not claim the CyberLab detected the
activity. Wazuh, Suricata, auth/journal, Windows audit, web, firewall, FIM/EDR and
egress evidence are suggested only where relevant and available. Findings come
only from recorded events. Missing/foreign state is excluded with warnings.

Historical JSON files are never rewritten. The default detail API adds the same
student view in memory to historical schema-1 reports, with `campaign` as the
default type. `GET /api/reports/<id>?raw=1` returns the stored technical document
without read-time educational enrichment (credential redaction still applies).
New stored documents already include their educational extension. The list API
adds `report_type` and `phase_id`; routes, IDs and existing list fields are retained.
GUI details retain the event table, state evidence and JSON link while adding
expandable student sections and a MITRE summary with safe direct links.

## Standalone phases

Existing individual-run flows (GUI Run phase, `mrnobody run 03`, or
`run-phase.sh 03 --target <host>`) are wrapped by `web/reports.py`. Every actual
individual invocation gets a fresh `MRN-YYYYMMDD-HHMMSS-<random-suffix>` ID,
exported to the unchanged phase implementation. Both explicit standalone
parameters and state-consuming individual runs are covered; their execution mode
and inputs remain as before. `--dry-run`, listing and full campaign routing are
unchanged and do not create an individual report.

After success, failure or catchable INT/TERM, a permanent
`/opt/nordic-attack/reports/<id>.json` contains exactly the selected phase.
Wrapper start/end timestamps record the invocation; action events still come from
the ground-truth log. Return codes are preserved and report-generation errors
produce a warning. No campaign.json is created, cleared or overwritten by the
wrapper. Phase scripts retain their existing state-file behavior. State-consuming
phases may read earlier state, but only snapshots carrying the fresh report ID
are attributed to the new report. Missing evidence remains unavailable, never
relabelled. SIGKILL/power loss cannot guarantee a final report.

Full Incident continues using its existing finalizer and incident ID and produces
one combined report in campaign phase order, including skipped/not-run sections.
It does not produce one standalone report per campaign phase.

No dependencies or install payload paths were added: `MRNOBODY/mrnobody_userdata.yaml`
already installs `web/reports.py`. The normal manifest includes every modified
runtime file and continues excluding generated reports, logs and state. No VM
deployment or changes to a running installation are part of this repository update.

## Reports incident analysis dashboard

The Reports page now opens each campaign or standalone snapshot as an incident
overview, with type, ID, status, start/end and five metric cards. Existing summary
counts are preserved: exfiltration counts **recorded transfer entries**, not an
inferred number of compromised or exfiltrated hosts. Missing snapshot data is
shown as unavailable; a recorded empty collection is zero. Technique count is
the number of unique valid ATT&CK IDs mapped in the report.

The selectable timeline follows `01,02,03,08,04,05,06,07` and shows phase names,
timestamps and success/failure/skipped/interrupted/not_run styles with text labels.
Missing phase records (including other phases in a standalone report) are labelled
as absent and cannot be selected. The first recorded phase is selected initially.
Each phase shows What happened, Findings, Detection, Investigation,
Prevention/Mitigation and Evidence references, with technical events collapsed.
An additional collapsed section preserves snapshot state, events, campaign state,
source paths and the existing raw JSON link. Historical reports without analysis
fields remain readable with explicit unavailable messages.

MITRE cards merge the existing summary and phase metadata, deduplicate by valid
technique/sub-technique ID, and combine mapped phase IDs. Links are constructed
from validated IDs on `attack.mitre.org`; stored URLs are never trusted. Mappings
remain distinct from proof of execution or success.

Affected assets combine inventory, web targets, compromised, staging, successful
exfiltration-source and impact evidence, plus explicit action events. Snapshot
membership establishes compromise/staging/impact unless explicitly false, matching
the current success-only state writers. Exfiltration requires `successful: true`
or `EXFIL_SUCCESS`, and attributes the state to the source rather than receiver.
Failed transfer sources are targeted only. Explicit failed access events establish
targeting, never compromise. Every row lists its evidence sources; an unmarked
state means no supporting evidence, not proof of absence. No later attack state is
inferred from an earlier state or from phase completion.

History controls filter by type, report status, recorded phase and ID/IP/hostname.
All filters are client-side and use the unchanged list/detail APIs. Phase matching
includes recorded skipped/not_run phases. Host search includes recorded asset
evidence, including assets absent from discovery. Detail snapshots are fetched on
demand with at most four concurrent requests per filtering pass and cached in
memory, since published reports are immutable. Failed detail reads can be retried
and are reported in the filter notice; stale filter/selection responses cannot
replace newer results. History totals cover all reports, independent of filters.

The dashboard preserves the existing JSON schema and CLI. Frontend regression checks in
`tests/mrnobody/reports.cjs` cover metrics, timeline/navigation, MITRE deduplication
and safe links, asset evidence, filters/search, collapsed raw evidence, historical,
empty/error states, asynchronous selection and text-safe host-supplied content.

## Investigation View and Ground Truth View

Every report opens in **Investigation View**. The always-visible switch lets
everyone choose **Ground Truth View** freely, without roles or access control.
Both use the same cached report; switching preserves the selected phase and does
not fetch again. These are educational presentation choices, not security boundaries.

Investigation View shows incident status, start/end, aggregate summary metrics,
phase timeline/status, MITRE mappings, discovered inventory and educational
detection, investigation and mitigation guidance. Detailed findings are replaced
with an investigation prompt. Compromise/staging/exfiltration/impact membership,
action-level outcomes, exact source/target and raw technical evidence are shown
in Ground Truth View. The history totals/search remain unchanged. Ground Truth
View retains the complete existing dashboard, evidence tables and raw JSON.

## HTML and PDF exports

The detail toolbar always offers **Download HTML**, **Download PDF**, and
**Open raw JSON** for campaign and standalone phase reports. Exports follow the
selected view and contain every recorded phase, independently of the selected
timeline phase. Existing JSON APIs and `?raw=1` behavior are unchanged.

- `GET /api/reports/<incident-id>/export/html?view=investigation`
- `GET /api/reports/<incident-id>/export/pdf?view=ground-truth`

Omitting `view` defaults to `investigation`; accepted values are `investigation`
and `ground-truth`. Unsupported formats/views return 400, absent/invalid reports
404. PDF dependency unavailable returns a JSON 503 with an installation hint;
HTML and JSON continue working. Responses are attachments with view-specific
filenames, no-store caching, nosniff and a restrictive content security policy.

Both formats share a read-only content model: overview, type, status, start/end,
metrics, timeline, inventory, direct MITRE technique/sub-technique links,
phase guidance and recommendations. Ground Truth View exports add actual
compromised hosts, detailed findings and a separately labelled technical appendix
with phase times, exact outcomes/events, evidence references and stored snapshots.
Investigation exports explain how to obtain that appendix without embedding it.
HTML is self-contained with print CSS; PDF is generated on the server with A4
layout, flowing paragraphs, an appendix page break, footers/page numbers and
clickable MITRE links. No browser print dialog or external asset fetch is used.

Exports reapply credential redaction and additionally omit credential/wordlist
containers, API keys, authorization headers and labelled free-form secrets.
Host text is escaped for both renderers; MITRE URLs are constructed from validated
IDs, never trusted stored URLs. As with capture-time redaction, arbitrary unlabelled
secrets cannot be identified reliably; never record secrets in free-form evidence.
Stored/historical JSON is never rewritten, and exports do not create report files.

### Dependencies and installation

PDF uses the maintained ReportLab Python library (tested with 4.x). Fresh Ubuntu
userdata installs `python3-reportlab` and downloads `web/report_exports.py`.
The system service continues to use `/usr/bin/python3`, not the WinRM venv.
The updated updater installs the distro package when absent, including a no-change
update. Package installation is not undone by file rollback.

For an existing installation whose updater predates this dependency, install
`python3-reportlab` with apt before updating, or run `mrnobody update` again after
the first update to let the new updater install it. A missing dependency does
not prevent the web service, HTML or JSON from working. No deployment is performed
by this repository change.

CI installs Flask, ReportLab and pypdf for real export-route/PDF parsing tests.
P10 action evidence in both views and exports includes labeled safe stdout/stderr
previews (512 characters per stream, redacted before truncation, no raw output).
See [P10 safe output previews](mrnobody-windows-actions.md#p10-safe-output-previews)
for CLIXML cleanup, sensitive-output withholding and redaction limitations.
`python tests/mrnobody/report_exports.py` covers both views, both report types,
historical raw compatibility/immutability, links, text safety, redaction, PDF
pagination/content, long evidence, invalid requests and missing dependency.


## P04 internal discovery evidence

P04 keeps the existing Linux SSH and Windows WinRM probes and configured port set. It now captures exact DISCOVERY, PING and TCP stdout records through web/p04_evidence.py. Only allowlisted IP targets and ports, exact line grammar and results following a DISCOVERY marker are accepted; duplicate results use the first observation. Arbitrary remote text cannot inject Ground Truth events. These remain source-reported observations, not independent sensor detections. Capture is bounded at 8 MiB / 65,536 accepted records per source; a truncation event identifies incomplete evidence.

Incident JSON phase 04 contains discovery.sources, discovery.targets (source-target pairs), discovery.probes with timestamps and Ground Truth path/line references, counts and a truncation flag. Planned ports without responses are unknown. No-reply does not establish host absence; closed preserves the existing probe's result and can include timeout/filtering. Execution completion is separate from probe status. Remote execution failure returns failure while retaining partial observed evidence. Historical generic INTERNAL_DISCOVERY events remain readable and never acquire inferred ping or port results.

For the verified 192.168.1.20 → 192.168.1.1 test, Ground Truth shows Linux/SSH, ping reachable, 22/80/443 open and 445/3389/5985/5986 closed. Both hosts are involved: remote execution source and scanned target. Neither role establishes new compromise. Hosts discovered remains inventory count; compromised remains incident-scoped compromise state; involved hosts is the P04 source/target plus inventory union. Standalone P04 consumes no unrelated state snapshots as report evidence; availability reads not applicable / not produced, without importing foreign incident IDs.

Investigation retains prompts and aggregate overview; exact probe answers and references appear in Ground Truth GUI/HTML/PDF. Details show at most 100 sources and pairs; raw event previews are bounded and full recorded JSON remains available. T1082/T1016/T1018 are phase metadata: this TCP/ICMP evidence supports remote system discovery, not successful lateral compromise or proof that system-information/configuration queries ran.

Offline regressions: python tests/mrnobody/p04_evidence.py (Linux runs mocked SSH/WinRM execution, Auto/P03/P01 and standalone wrapper, failures and absent responses, immutable JSON and HTML/PDF); node tests/mrnobody/reports.cjs covers safe text rendering and host roles. No live targets are contacted.


## Artifact evidence standard and P05 workflow

File-producing phases should project observations through `artifact_evidence` in
`web/reports.py`. The versioned record includes kind (file, archive, service,
scheduled task, cron entry, systemd unit, DNS simulation artifact, etc.), host,
name/path, action, timestamp, verification, content/purpose when known,
read-only inspection guidance, cleanup instructions/status and source references.
Missing values remain unrecorded. A phase completing is never sufficient evidence
of an artifact or its successful cleanup. Adapters must explicitly select actual
action evidence. `display` holds text-only label/value pairs shared by the GUI and
HTML/PDF exporters; `inspection` contains separately displayed example commands.
Never put host text into HTML or execute inspection commands in the report server.

P05 now parses historical STAGING_START / STAGING_SUCCESS fields (including Windows
paths) into structured artifacts and supplements missing fields only from a
strictly matching staged-data.json incident snapshot. The identity is host plus
full path. Repeated observations merge references; the latest event supplies the
recorded result, timestamp, size and hash. State generation time is not claimed as
file creation time. Immutable historical JSON files are enriched on read, not
rewritten. Old unquoted free-form fields can be ambiguous (for example a filename
containing ` key=`); only recoverable fields are projected. Invalid hashes/sizes
remain unavailable. Full raw events and Ground Truth line references remain intact.

Both report views and both export formats show Data Staging Findings with each
host, SSH/WinRM method, safely recorded user, created directory, exact file path,
filename, byte size, full SHA256, timestamp and synthetic-data classification.
Long values wrap; the GUI offers SHA256 copy when browser clipboard access exists.
Metrics distinguish successfully staged hosts, unique artifacts created/recorded,
known total bytes, unknown sizes, failed/skipped outcomes and overall phase status.
For historical reports only (P12–P18 are unavailable in the active product), retained P17 archives count as staged, never newly created P05 files. P17 adopts
the shared component only for already-recorded successful archive creation;
other phases keep their current reports until explicit adapters are implemented.
The generic model supports those artifact types without inventing observations.

On the recorded host, use the provided exact-path `ls -lah`, `cat`, `sha256sum`
(Linux) or `Get-Item`, `Get-Content`, `Get-FileHash -LiteralPath` (Windows) examples
with an authorized account. Commands quote paths for the respective shell and are
read-only, although reads may update access/audit metadata. Compare current size
and hash with the capture; the file may have changed. Correlate SSH/WinRM execution,
account, creation time and synthetic markers with Wazuh FIM/audit, auditd/journal,
PowerShell and Sysmon where configured. These are investigation suggestions, not
claims of detected SIEM events or independently verified file contents.

The P05 generator writes five synthetic customer/order rows using example.invalid
addresses plus fictitious NordicERP/NordicMES/NordicShop system information. The
CONFIDENTIAL label is part of the simulation; this is no real confidential dataset.
Retained P17 archives use their own collection evidence instead of this template
description. T1074 Data Staged describes preparation for P06, not exfiltration.
Affected Assets identifies the authenticated staging source separately from a
receiver observed in P06 evidence; neither role establishes a new compromise.
Standalone P05 can correctly show zero P03-compromised hosts while showing involved
and staged hosts. Unrelated phase snapshots are not applicable/not produced;
foreign staging snapshots remain excluded with a visible mismatch warning and real
P05 failures remain visible. P05 retains artifacts for P06 and offers no automatic
cleanup; remove only independently confirmed incident artifacts after the exercise.

Offline regressions: `python tests/mrnobody/staging_artifacts.py`,
`node tests/mrnobody/reports.cjs`, existing report/export tests and validation CI.
No VM access or deployment is required for this reporting change.
