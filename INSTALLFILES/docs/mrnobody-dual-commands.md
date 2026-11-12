# P10 independent runtime commands

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

Full Campaign has two optional inputs: **PowerShell command (Windows)** and
**Bash command (Linux)**. With P10 included, whitespace is trimmed and each
nonblank input runs against one compatible target using platform-specific
candidate fallback. Both configured commands are attempted independently.
Blank input skips only that platform. Both blank returns 78 with
`PHASE_SKIPPED reason=NOT_CONFIGURED`; subsequent campaign phases continue.

Both successes complete P10. A success plus a controlled command error or absent
compatible target completes with a partial warning and separate action evidence.
All controlled errors produce the existing nonfatal action-error skip. Exhausted
transport/authentication failures and infrastructure failures fail the phase,
including when the other platform succeeded. Report status remains the existing
complete/skipped/failed model; the action evidence explains partial outcomes.

The GUI Review displays configured/not configured for each platform, never raw
commands. Builder and scheduler runtime forms accept the same independent inputs.
API runtime keys are `powershell_windows` and `bash`; environment keys are
`MRN_POWERSHELL_WINDOWS_SECRET` and `MRN_BASH_SECRET`. Commands never enter saved
definitions, execution summaries or schedule storage. The legacy `powershell` /
`MRN_POWERSHELL_SECRET` standalone/custom input remains supported with its
original single-candidate Auto behavior.
