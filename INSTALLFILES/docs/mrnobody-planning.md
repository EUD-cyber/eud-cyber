# Custom scenarios, execution profiles and schedules

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

This bundle extends the existing MrNobody V2 Flask service, Bash campaign,
standalone runner and Reports V2. It does not install or configure detection
products, change coverage/comparison features, or deploy to a running VM.

## Workflow

Open **Scenarios → Custom Scenario Builder**. The workflow is basics → target
mode → phase selection/order → phase configuration → profile/timing → schedule
→ review/save/run. Completed, current and upcoming steps are marked separately.
Each Next validates the current step and keeps actionable errors beside the
controls. Review is reachable only after valid basics, targets, phase order,
phase configuration, timing and schedule; save is revalidated by the server.
The library supports edit, duplicate, schedule and delete for custom definitions;
built-in scripts are protected. Saved custom scenarios also appear alongside
built-ins. RUN opens the builder's readable review, including runtime credentials
and P08 wordlist upload. Library cards summarize target mode, enabled phase flow,
profile, planned duration and schedule count. Edit/duplicate/schedule/delete and
built-in protection remain unchanged.

**Auto Discovery** inserts and enables P01 first, including when switching an
existing draft from fixed targets. Adding a phase recursively inserts missing
prerequisites without duplicates: P02/P03 need P01; P04/P05/P07 need P03; P06
needs P03 and P05; P08 needs P01 and P03. Capability metadata and backend
validation use the same dependency table. Required phases cannot be disabled or
removed, and reorder controls cannot break dependencies or move P01 from first.
Cards mark Required/Auto-added prerequisite and explain which discovery,
compromised-host or staged-data output they consume. Fixed-only parameters are
cleared when entering Auto and their controls are hidden.

**Custom / Fixed Targets** adds no phases automatically. Switching from Auto
removes prerequisites inserted during the current editing session, retaining
explicit selections; reopening a saved definition treats its saved phases as
explicit. The optional Common Target fills only ordinary `target` fields,
including phases added later. It never fills P01 subnet or P04 source. Editing
a phase target makes it a local override; later Common Target changes preserve
overrides. Use Common Target restores inheritance. Clearing Common Target clears
inherited targets only. This convenience state is local to the draft: saved
definitions contain the resolved per-phase targets with the existing schema.
Required fields, private lab addresses, protocols, ports and synthetic-file
paths are checked before leaving Phase Configuration.

Review shows name/description, target mode, ordered phase flow, prerequisite
marks, fixed/common targets, required runtime credentials, profile/planned span
and local schedule. Raw definition JSON is available under **Advanced / Show
JSON**, collapsed by default. Save, Save + Run Now and Save scenario + schedule
retain their existing execution/persistence paths.

Fields come from installed `ATTACK_PARAMETERS` metadata, constrained by adapters
for the current scripts. Fixed mode exposes supported source/target, subnet,
protocol, port, username and synthetic-file inputs. Auto mode uses fresh phase
inventories and the existing campaign configuration/credentials. Unsupported
keys, protocols, order dependencies and timing controls fail server validation.
Fixed targets must be RFC1918 IPv4; discovery networks must be /24 or smaller.
P04 needs both source and target. P06 accepts only synthetic staging paths, or
`@staged` to resolve the target's current synthetic P05 output at execution time.
Existing synthetic staging and impact restrictions remain in the phase scripts.

## Storage and API

`/opt/nordic-attack/data/planning/execution.sqlite3` holds two tables, `scenarios`
and `schedules`. The database and definition schema both start at version 1.
Scenario definitions are JSON documents with `version`, generated `custom-…` ID,
`name`, `description`, `target_mode`, ordered `phases` (ID, enabled, parameters,
timing) and `profile`. Runtime inventory, state, logs and reports stay in their
existing directories. The updater manifest excludes `data/`; updates do not
replace user definitions or schedule state. Back up the planning database when
the service is stopped, or use SQLite's backup API for a live backup.

Planning endpoints:

- `GET /api/planning/capabilities`
- `GET/POST /api/custom-scenarios`, `PUT/DELETE /api/custom-scenarios/<id>`
- `POST /api/executions/run` with `execution` and optional execution-time `credentials`
- `GET/POST /api/schedules`, `PUT/DELETE /api/schedules/<id>`
- `POST /api/schedules/<id>/{run,enable,disable,arm}`

An execution reference selects `phase`, `campaign` or `custom` and its ID.
Standalone references can carry validated parameters, target mode and timing.
Custom references use the saved definition; Full Incident can use Normal or
Slow. For phase-specific campaign timing, create a custom definition in the
builder. Other existing campaign scripts retain their Normal runner behavior.

## Scheduler and overlap

The existing `nordic-incident-web.service` starts one persisted scheduler thread;
no browser session, cron entry, extra service or external queue is needed.
SQLite transactions claim due work every five seconds and advance the next run
before launching. Run Once disables itself at claim. Recurring schedules use a
fixed interval of at least 60 seconds anchored to the original UTC start; missed
intervals coalesce into one run after restart. GUI date/time input uses the
browser timezone and sends an explicit UTC instant. Recurrence is elapsed time,
so a daily interval can shift local wall time across daylight-saving changes.

Dispatch is at most once, not an automatic retry policy. A crash after claim can
leave a missed run; it is marked interrupted at service restart. A busy run is
skipped, logged, and not queued for later. Schedule Run Now leaves the normal
next run unchanged. Disable/delete affects future dispatches, not a run already
started. Run one web-service instance; the shipped systemd unit already does.

All launches call the existing phase/scenario endpoints. The shared POSIX
`runtime/execution.lock` is inherited by runners and held until they exit; CLI,
GUI and scheduled launches cannot clear each other's inventory. Process-group
cancellation and the existing report-on-exit behavior remain in effect.
Scheduler start, skip, completion, interruption and failure are appended to
`logs/campaign.log` using internal IDs and fixed messages, without secret values.

## Credentials

Scenario and schedule JSON never contain passwords, wordlist contents or upload
paths. Phase passwords travel in the subprocess environment rather than command
arguments. Builder Review offers execution-only P08 usernames and a wordlist
upload for Save + Run Now, reusing the existing multipart campaign endpoint;
uploaded files are restricted to mode 0600.
Saving a definition alone never submits the upload. Scheduled P08 uses the
existing service-side wordlist source; the Schedule step explains this explicitly.
The builder can arm a newly saved schedule with temporary runtime passwords,
using the same in-memory credential lease as the Schedules editor.

Schedules can be armed with temporary passwords through Schedules. Those values
exist only in service memory; editing/deleting the schedule or restarting the
service clears them. **Schedule persistence does not imply credential persistence.**
After restart, a run needing unavailable credentials is recorded as needing
input. Supply credentials again using **Edit / supply credentials → Supply
credentials without changing schedule**. A skipped one-time run can then be
started with Run Now or explicitly re-enabled.

For unattended operation across service restarts, an administrator may supply
`NORDIC_SSH_PASSWORD` / `NORDIC_RDP_PASSWORD` through the service's protected
environment or systemd credential management. Optional wordlist phases require
`NORDIC_WORDLIST_FILE` and optionally `NORDIC_WORDLIST_USERS` in that environment,
or an upload through the existing Run form. No path or secret is copied into
the definition database. A root-readable systemd drop-in/EnvironmentFile is one
deployment option; it is not created by this feature. Secure credential source
configuration and deployment remain the VM administrator's responsibility.

## Timing and reports

Normal with no timing config retains existing activity and phase delays.
Structured Normal custom runs use the selected order without adding delays.
Slow defaults to four hours. The GUI uses Hours/Minutes/Seconds controls for
campaign target duration and custom per-phase offsets/activity durations.
Delay min/max also use Hours/Minutes/Seconds; jitter is displayed as 0–100%
and converted to the existing 0–1 fraction. Recurrence uses Repeat every plus
minute/hour/day/week units, converted to whole seconds (1 minute–365 days).
Existing fractional durations and second-based recurrence values load without
rounding or schema migration. Date/time input and Review show browser timezone
and the computed local start. Normal, Slow and Custom plans retain seconds in
the backend schema. Review states that target duration/planned span is best-effort
and actual runtime may extend beyond it.

Discovery gets 40% of weighted
time, web discovery 25%, and later phases get absolute start offsets in the
remaining slots; weights are normalized over the enabled phases. Discovery
enumerates the same filtered network list and spaces bounded `nmap -sn` host
probes over its slot. Web discovery spaces host/port checks, with its existing
HTTP/HTTPS requests performed inside each check. This is pacing for lab
exercises, not a guarantee of avoiding detection.

Custom Timing exposes offset on each phase, plus duration/minimum delay/maximum
delay/jitter only on P01/P02. Timing is best effort: it never cancels an action
to force a deadline, and slow tools can extend the overall run. A phase with
one action cannot distribute that action across an entire duration. Other
phases do not advertise internal pacing controls they cannot implement.

Custom runs execute through the existing Full Incident setup, phase function,
state updates and EXIT reporter. Standalone runs retain their existing reporter.
Reports keep schema version 1 and add optional `execution`, `scenario_name` and
profile/timing metadata. Selected custom phases retain their order; other phases
appear skipped. Investigation/Ground Truth views and HTML/PDF exports use the
same report paths. Historical MRN/H3 report reading remains supported; new GUI
campaign IDs are collision-resistant MRN IDs. There is no new H3 branding.

## Validation

`tests/mrnobody/planning.py` covers schema validation, CRUD/duplicate, phase
order/dependencies, private targets, timing, runtime credentials, shared runner
dispatch, one-time/recurring claims, restart persistence, overlap and redaction.
With `--bash`, Linux CI runs the actual campaign and scheduler against inert
phase fixtures, verifies the POSIX lock and checks reports plus HTML/PDF export.
No real numbered phase payload executes in these tests.

`tests/mrnobody/planning.cjs` exercises automatic P01, recursive prerequisites,
protected reorder/disable/remove, mode switches, Common Target inheritance and
overrides, per-step validation, readable review/Advanced JSON, friendly timing
and recurrence conversions, library summaries and runtime-only P08 multipart.
Backend tests verify advertised dependencies/required fields against validation
and exercise the reused multipart upload with no secrets in planning storage.
Existing frontend, backend, Full Incident, standalone, historical report and
export tests remain in the validation workflow. Fresh-install userdata fetches
the new modules and GUI asset; the updater manifest includes their checksums.

## P08 wordlist source in the GUI

Full Incident hides P08 configuration until its checkbox is enabled. Choose an
upload or an existing absolute wordlist path on the MrNobody server. Existing
files must be regular, readable and non-empty; they are not changed or deleted.
The chosen source alone is submitted. Supplying both an upload and a path is
rejected. Paths are validated by the server before a campaign starts.

Custom Scenario Review / Run Now also accepts an execution-only server path.
Paths, usernames and uploads supplied there do not enter the saved definition.
Schedules retain their existing service-side NORDIC_WORDLIST_FILE behavior.
Existing CLI wordlist handling is unchanged.
