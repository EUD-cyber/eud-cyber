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
The existing ground-truth event messages are retained; phase implementations must
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
