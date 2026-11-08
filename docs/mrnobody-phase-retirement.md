# P12–P18 removal and update instructions

Active product: **P01–P11 only**. P08 and P10 remain optional in Full Incident.
P09 is retained; its reported failure is deferred to the next task. No VM deploy.

Full Incident order: P01 → P02 → P03 → optional P08 → P09 → optional P10 →
P11 → P04 → P05 → P06 → P07. CLI IDs/aliases, GUI catalogue, builder, scheduler,
API routes and adapters reject retired phases even when old scripts remain on disk.
Presets using them are removed entirely, rather than silently shortened. The two
nginx beacon endpoints are also removed.

Seven scripts and seven exclusive Python modules are deleted from source,
userdata and the generated update manifest. Shared SSH/WinRM, P11 and report/export
modules remain. No pip/apt package was exclusive to the removed modules: they used
standard-library modules and shared dependencies. The existing service unit has
no phase-specific file list to change. Historical report adapters remain read-only.

## Existing VM: after this GitHub change is merged

Finish or stop running campaigns, keep your normal user-data backup, then run
these commands on the VM yourself:

```sh
sudo mrnobody update
sudo mrnobody update
```

Two passes support the old updater. Pass one installs the closed registries,
reduced campaign/UI, new updater and cleanup helper, then restarts services.
An old updater cannot delete obsolete files. Pass two invokes the new cleanup
even when no files changed. With the new updater already installed, one successful
pass suffices.

The new updater takes the campaign lock and rejects updates while execution runs.
Downloads/hashes are validated first. Cleanup occurs after activation and health
checks succeed, so a failed update can roll back with previous code. Cleanup is
idempotent, limited to exact obsolete script/module paths and their Python
bytecode. It does not touch `state/`, `reports/`, `data/`, `logs/`, runtime records
or local configuration. Symlinked code directories are rejected. If cleanup fails,
correct the reported local permissions and rerun update; user data is retained.

Check `mrnobody list` and `/api/planning/capabilities`: both must expose P01–P11
only. Paths in `web/retired_files.py` must be absent after pass two. Old custom
scenarios retain their complete definitions, including disabled retired phases,
and show **Unavailable** in the library and schedule views. Execution, scheduling,
import and validated export reject them explicitly. To change scope deliberately,
duplicate/edit a copy, explicitly remove unavailable entries, and review remaining
targets/dependencies/timing. Historical report data is never rewritten.

## Fresh installation

Use updated `MRNOBODY/mrnobody_userdata.yaml` after merge. Its downloads match
`update-manifest.txt`; retired entry points/modules are not fetched. No installation
or service start on a VM was performed while preparing this change.

## Verification

Run `.github/workflows/mrnobody-validation.yml`. New `phase_retirement.py` covers
leftover-file registries, CLI IDs/aliases, direct routes/adapters, Full Incident,
all remaining configurations, saved scenarios/schedules and user-data preservation.
`install.py` imports an application built only from userdata downloads.
`release_validation.py` checks hashes and updater success/rollback/hash failure.
Existing P08/P10/P11, planning, historical report and browser suites remain.
All remote actions are mocked or inert local fixtures; no real target validation
or P09 fix is claimed.

See the [optional future roadmap](roadmap/mrnobody-optional-phases.md).
