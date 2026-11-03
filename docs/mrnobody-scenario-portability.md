# Scenario JSON portability

Custom scenario cards on **Scenarios** offer **Export**. Select a JSON file and
choose **Import Scenario** on the same page. The builder Review step also offers
**Export saved scenario** (exports the last saved definition, not unsaved edits).
Downloads use `mrnobody-scenario-<safe-name>-v1.json`.

The existing scenario model is the document format. `scenario_model.VERSION = 1`
is the canonical schema version, stored in the existing integer `version` field.
No parallel wrapper or package format is introduced. Documents retain name,
description, teaching objective, source custom ID, preset origin where present,
ordered techniques including disabled entries, target mode, non-secret technique
parameters and Normal/Slow/Custom profile and timing. The model has no created or
updated timestamps, so none are invented. Advanced / Show JSON shows the version.

Every import allocates a new custom ID. A source ID is validated but never used to
replace an existing scenario. Built-in presets remain read-only. Existing preset
and custom Duplicate actions still open the builder; saving creates a custom ID,
and custom duplicates use the `(copy)` name suffix. Preset origin is retained.

## Compatibility and review

Version 1 documents are validated against installed capabilities. Legacy documents
with no version or integer version 0 are supported **only when they use this same
model shape**. The centralized deterministic migration fills the model's existing
description/profile defaults and sets `needs_review: true`. It never maps IDs,
reorders, enables, removes or invents techniques. Future/other versions are rejected.
The library displays Compatible / Ready, Needs configuration or Needs review.

Edit a migrated definition, inspect targets, Attack Technique order and timing,
then use **Save and acknowledge migration review** in the builder Review step.
Until acknowledgement, the backend blocks direct execution and scheduling, even
if an ordinary edit tries to remove the review flag. Acknowledgement validates
complete runnable configuration. Missing fixed-target inputs can be imported for
editing but remain non-executable. Unknown/deferred techniques, including P19,
are explicitly rejected even if disabled. No entries are silently removed.

## Security and scheduling

Import is a non-executing POST to `/api/custom-scenarios/import`. Export is GET
`/api/custom-scenarios/<id>/export`; review acknowledgement is POST
`/api/custom-scenarios/<id>/review` with `{"acknowledged": true}`. Parsing is bounded
to 128 KiB and rejects malformed/duplicate-key JSON, excessive nesting, non-finite
numbers, unknown fields, secret fields and recognizable embedded credential/key
material. Errors never echo rejected values. Validation uses the existing
RFC1918-only rules, supported configuration choices, dependency/order checks and
timing limits. Documents remain declarative; runtime shell/cron commands cannot
be introduced by import. Export validates the saved definition again and fails
closed on secret content rather than silently stripping fields.

Passwords, wordlists, tokens, keys and P10 PowerShell/Bash command text are not
portable scenario configuration. P10 platform, protocol, target and timeout
settings are retained; independent Windows PowerShell and Linux Bash commands
continue to be supplied only for execution or held temporarily in scheduler
memory. Free-text teaching content must not contain secrets.

Schedules are installation-specific and kept separate: JSON contains no schedule
linkage. Import never runs, arms or creates schedules. Imported executions later
use their new ID, retained name and schema version in existing report metadata.
Historical reports and definitions already at version 1 retain their format.

No runtime module or dependency was added. Cloud-init already downloads all three
modified runtime files; the update manifest hashes are refreshed. No VM deployment
or changes to backup tags/branches are part of this feature.

Offline tests: `python tests/mrnobody/scenario_portability.py` and
`node tests/mrnobody/planning.cjs`, alongside the existing validation workflow.
