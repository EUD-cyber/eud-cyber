# Live output and MrNobody naming cleanup

The Campaigns, Scenarios, Phases and System pages each show the existing shared `/api/log` output. One two-second poll updates visible panels; opening another page refreshes its output immediately. Hidden panels retain their content and scroll position. Manual refresh is available on each page. Output is rendered as text. A reader scrolling through older output keeps their position, and failed polls preserve the last output and display a retry message. Phase starts, campaign actions, updates and navigation refresh the panels immediately. The log is explicitly labelled as shared because the existing backend already combines these operations in `campaign.log`.

The generic platform name is exactly **MrNobody Incident Platform**. Newly generated campaign/phase fallback IDs use `MRN-YYYYMMDD-HHMMSS`. The campaign still exports the ID to phases; phase logs, campaign logs, campaign state, `/tmp/nordic-impact-${INCIDENT_ID}` and `C:\NordicIncident\<ID>\impact` continue to derive their values from that ID. Supplied IDs, including historical `H3-` IDs, are retained. No historical files are renamed, deleted or migrated. Existing `/opt/nordic-attack` locations, environment variable names and service filenames remain compatible.

The older `INCIDENTVM` generator and older CLI campaign also generate MRN IDs. The older status and log validators accept both MRN and H3 IDs. Dynamic scenario routing and the default scenario's existing identifier are preserved.

## Intentionally retained H3 references

- `TESTFILES/ATTACKER-V2/scenarios/full-incident-h3.sh`: scenario ID `full-incident-h3`, name `Full H3 Incident`, H3-specific description and confirmation prompt identify this particular scenario.
- `TESTFILES/ATTACKER-V2/web/app.py`, `scripts/run-phase.sh`, `web/static/app.js`, `web/templates/index.html`, `update-manifest.txt`, and `MRNOBODY/mrnobody_userdata.yaml`: route defaults, default-scenario labels and file references continue to identify/load that H3 scenario.
- Older `INCIDENTVM/web/app.py`: the `/api/campaign/h3` route and `start_h3_campaign` function identify its H3 scenario. The two `(?:MRN|H3)` validation patterns intentionally read historical IDs.
- Older `INCIDENTVM/web/templates/index.html`: H3 start/running labels and `/api/campaign/h3` refer to that scenario, rather than the platform name.
- Unchanged older `INCIDENTVM/IncidentVM_userdata.yaml`, `TESTFILES/ATTACKER/attackctl`, `TESTFILES/ATTACKER/scripts/01-recon.sh`, and the confirmation in `TESTFILES/ATTACKER/scenarios/full-incident-h3.sh`: installation paths, menu text and scenario-specific references continue to identify the H3 exercise.
- `tests/mrnobody/*`: H3 fixtures verify routing and historical compatibility.
- HTML `<h3>` elements elsewhere in the repository are heading markup.

The legacy `TESTFILES/ATTACKER/attackctl` had CRLF line endings that made `bash -n` fail at its `case` statement. They are normalized to LF; its menu/routing behavior and H3 scenario label remain unchanged.

## Validation

`python tests/mrnobody/backend.py`, `python tests/mrnobody/runtime.py`, `node tests/mrnobody/scenarios.cjs` and `node tests/mrnobody/logs.cjs` run isolated checks. Process launches and frontend submissions are replaced with test doubles. Tests cover default/custom scenario routing, credential handling, historical log reads, ID generation and validation, output placement, refresh behavior, scroll preservation, failed polls, recovery, text rendering, and distributed manifest hashes.

The PR validation workflow also checks Python/JS syntax and runs `bash -n` on scripts. `runtime.py --bash` evaluates only extracted single-line ID assignments against empty, MRN and H3 fixtures. It never sources scripts or launches a campaign. No end-to-end campaign is run as part of this change.

## Exact changed files

- `TESTFILES/ATTACKER/attackctl`

- `.github/workflows/mrnobody-validation.yml`
- `INCIDENTVM/web/app.py`
- `INCIDENTVM/web/static/style.css`
- `INCIDENTVM/web/templates/index.html`
- `MRNOBODY/mrnobody_userdata.yaml`
- `TESTFILES/ATTACKER-V2/config/defaults.conf`
- `TESTFILES/ATTACKER-V2/nginx/nordic-incident.conf`
- `TESTFILES/ATTACKER-V2/scenarios/full-incident-h3.sh`
- `TESTFILES/ATTACKER-V2/scripts/01-discovery.sh`
- `TESTFILES/ATTACKER-V2/scripts/02-web.sh`
- `TESTFILES/ATTACKER-V2/scripts/03-access.sh`
- `TESTFILES/ATTACKER-V2/scripts/04-lateral.sh`
- `TESTFILES/ATTACKER-V2/scripts/05-staging.sh`
- `TESTFILES/ATTACKER-V2/scripts/06-exfil.sh`
- `TESTFILES/ATTACKER-V2/scripts/07-impact.sh`
- `TESTFILES/ATTACKER-V2/scripts/08-wordlist.sh`
- `TESTFILES/ATTACKER-V2/systemd/nordic-incident-web.service`
- `TESTFILES/ATTACKER-V2/update-manifest.txt`
- `TESTFILES/ATTACKER-V2/web/static/app.js`
- `TESTFILES/ATTACKER-V2/web/static/style.css`
- `TESTFILES/ATTACKER-V2/web/templates/index.html`
- `TESTFILES/ATTACKER/scenarios/full-incident-h3.sh`
- `TESTFILES/ATTACKER/scripts/05-staging.sh`
- `tests/mrnobody/backend.py`
- `tests/mrnobody/logs.cjs`
- `tests/mrnobody/runtime.py`
- `tests/mrnobody/scenarios.cjs`
- `docs/mrnobody-live-output-cleanup.md` (this audit)
