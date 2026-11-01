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
