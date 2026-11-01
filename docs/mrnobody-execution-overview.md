# Dashboard execution overview

The existing Incident Status panel now displays the active MRN incident ID,
campaign/custom scenario/standalone phase name and ID, Normal/Slow/Custom profile,
start and elapsed time, planned duration, current phase, next pending phase and
an ordered timeline. The existing dark dashboard and status cards remain.
Navigation order is Dashboard, Campaigns, Scenarios, Phases, Schedules,
Inventory / State, Reports, System; all use the existing active-page handler.

Progress counts completed executable phases in the selected plan. Installed
but unselected phases are excluded; skipped phases do not inflate progress.
Failed/interrupted phases retain their outcome and do not count as completed.
This is phase-state progress, never an estimate of remaining wall-clock time.
Slow/Custom plans display available start offsets and activity windows in
hours/minutes. A planned window is a pacing target, not a timeout or promise.
Waiting for an offset can still appear as a running phase because that is the
existing runner's state. Preparing runs explicitly say phase state is pending.

Completed, failed and interrupted runs remain visible until the next execution.
Reports V2 supplies the terminal outcome and incident-report shortcut. With no
execution, the panel says **No active execution**; existing historical reports
can provide a last-incident shortcut. No report is fabricated if reporting fails.
In that case the process exit or last recorded state supplies a best-effort final
summary; elapsed time is limited to the last observed timestamp. Standalone CLI
runs without GUI launch metadata become visible when their report is published.

## Read-only API

`GET /api/execution-status` returns version 1 with `active`, `status`, incident
ID, `execution` display metadata, timestamps/durations, `timeline`, current/next
phase, `progress` (`complete`, `total`, `percent`, `basis`), report ID and up to
six lifecycle log entries. POST is unsupported. The endpoint never changes
execution, scheduler, database, reports or runner locks. It reads the existing
campaign state and Reports V2. Refresh uses the dashboard's existing status
poll with a single in-flight request; no websocket, timer or execution engine
is added. Matching final reports are immutable and reused for the summary.

`runtime/execution-overview.json` is an atomic, mode-0600 launch display record
written only after the existing locked Popen succeeds. It contains incident ID,
execution type/name/ID, selected phase IDs, profile, offset/window numbers,
manual/scheduler trigger, schedule reference and process identity. It excludes
parameters, credentials, environment dumps, command arguments, uploaded paths
and wordlist data. Linux PID start ticks recognize surviving children after a
web-service restart without mistaking a reused PID for the same process.
Scheduler context is scoped to one dispatch and cannot leak into manual runs.

The standalone Reports V2 wrapper reuses the GUI-generated incident ID for a
tracked launch. Independent CLI launches still generate unique IDs. Campaign
and standalone reports, Investigation/Ground Truth, HTML/PDF export, cancellation,
shared execution locks and persisted schedules retain their existing paths.

The API projects an explicit allowlist rather than returning raw execution JSON.
Existing redaction is applied as a final filter. Live log entries come from the
bounded tail of the incident ground-truth log and match the exact incident ID.
Only known lifecycle event names and numeric phase IDs are exposed; raw commands,
tool stdout, wordlist candidates and event fields are never copied. The frontend
uses text nodes, validates report IDs and allowlists CSS status classes.

## Builder and installation compatibility

Auto Discovery still inserts/locks P01 first and recursively orders prerequisites.
Fixed Targets still adds no prerequisites, exposes phase-specific fields and
retains Common Target overrides without filling P01 subnets or P04 source.
Each Next and final Save validate; readable Review precedes collapsed JSON.
Action delay minimum/maximum now use the same Hours/Minutes/Seconds controls
as offsets and activity windows, preserving fractional seconds in storage.
Scheduler recurrence remains natural minute/hour/day/week units. P08 runtime
uploads and credentials remain execution-only.

The projection lives in the existing `web/execution.py` and `web/static/app.js`
assets already downloaded by cloud-init. The rebuilt update manifest includes
their checksums and
continues to exclude runtime/state/logs/reports/data, including the planning DB.
No cloud-init modification, service, database schema migration, dependency or
VM deployment is added.

## Verification

`tests/mrnobody/overview.py` covers endpoint read-only behavior, selected phase
progress, timing, scheduler context, stale state, terminal outcomes, restart
identity and exclusion of secrets/raw log fields. `overview.cjs` exercises idle,
campaign/custom/standalone rendering, friendly timing, scheduler metadata,
timeline statuses, failure/interruption, report actions, hostile text and exact
navigation order/active behavior. Planning API tests verify actual launch
metadata; Linux inert-runner tests verify scheduled execution through report
publication and the overview. Existing platform and export tests remain in CI.
