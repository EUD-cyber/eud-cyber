# Generic Full Incident scenario

The V2 default scenario is now `full-incident`, named **Full Incident**, distributed as `scenarios/full-incident.sh`. The default `/api/start` and dynamic `/api/scenario/<scenario_id>/start` routes continue to share validation, credentials, logging and process handling. No campaign was launched. Both V2 and legacy IncidentVM health endpoints report exactly **MrNobody Incident Platform**.

## Deployment and updater

The manifest contains the new scenario path and SHA256 hashes of the exact distributed bytes. The cloud-init installer downloads the new filename. The updater has no managed obsolete-file deletion mechanism: its removal logic only rolls back files newly installed during a failed update. It is unchanged.

Consequently an existing installation may retain `/opt/nordic-attack/scenarios/full-incident-h3.sh` after updating. Dynamic discovery may still display that old script as an additional H3 scenario, and its old dynamic route can still run it. The default web route and phase runner exclusively use the new canonical file. After a successful update, an administrator should review and retire the obsolete scenario script if desired; this PR does not automate deletion or migrate runtime data. Fresh installs and the repository contain only the new V2 scenario.

Historical logs, state, uploads, reports and runtime files are untouched.

## Exact changed files

- Renamed `TESTFILES/ATTACKER-V2/scenarios/full-incident-h3.sh` to `TESTFILES/ATTACKER-V2/scenarios/full-incident.sh`; generic metadata, description and CLI confirmation.
- `TESTFILES/ATTACKER-V2/scripts/run-phase.sh`: canonical campaign path.
- `TESTFILES/ATTACKER-V2/web/app.py`: default scenario ID and health service identity.
- `TESTFILES/ATTACKER-V2/web/static/app.js`: generic button, reset, selection and confirmation text.
- `TESTFILES/ATTACKER-V2/web/templates/index.html`: generic start button.
- `TESTFILES/ATTACKER-V2/update-manifest.txt`: canonical scenario path and regenerated hashes.
- `MRNOBODY/mrnobody_userdata.yaml`: new source and destination filename.
- `INCIDENTVM/web/app.py`: generic health service identity.
- `tests/mrnobody/backend.py`: new default ID and exact health identity assertion.
- `tests/mrnobody/scenarios.cjs`: generic default button expectation.
- `tests/mrnobody/runtime.py`: canonical scenario path.
- `docs/mrnobody-live-output-cleanup.md`: mark the earlier retained-reference audit as historical.
- `docs/mrnobody-h3-decoupling.md`: this change/deployment audit.

## Intentionally retained references

- `TESTFILES/ATTACKER/scenarios/full-incident-h3.sh` and `TESTFILES/ATTACKER/attackctl`: separate legacy H3 exercise and its launcher.
- `TESTFILES/ATTACKER/scripts/01-recon.sh`: documentation/output identifying that legacy exercise.
- `INCIDENTVM/IncidentVM_userdata.yaml`: downloads and checks that legacy exercise.
- `INCIDENTVM/web/app.py` and `INCIDENTVM/web/templates/index.html`: legacy H3 script, API route, function and exercise-specific labels; two ID validators retain historical H3 compatibility.
- `tests/mrnobody/backend.py` and `tests/mrnobody/runtime.py`: historical H3 ID fixtures and compatibility checks.
- This audit and the previous audit: old filenames and compatibility/deployment documentation. HTML `h3` tags and CSS selectors are structural headings.

No H3 or Nordic Incident Control/Campaign branding remains in active V2 code/config/systemd/nginx or the MrNobody installer. Existing Nordic paths, service filenames and environment variables remain compatible.

## Validation

Python AST and JavaScript syntax checks; isolated backend/frontend routing, credential handling, exact health branding, live-log polling, scroll preservation, error recovery, historical ID compatibility and manifest byte hashes. The existing PR workflow additionally runs Bash syntax checks and safely evaluates extracted ID assignments; it never sources or executes a campaign.
