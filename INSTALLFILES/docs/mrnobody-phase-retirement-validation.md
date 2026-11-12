# Removal validation and exact changed files

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

Scope: retire P12–P18; no P09 troubleshooting, no target/VM deployment and no
new or modified offensive payloads. P08/P09/P10 phase scripts and the shared P11
payload module are byte-for-byte unchanged. P05 changes remove only P17 reuse
routing/metadata; its target payloads are unchanged. Historical report adapters
remain available for previously saved evidence.

## Local results

- All 25 Python regression suites passed in an isolated Linux filesystem,
  including real CLI wrappers and inert Full Incident fixtures, install materialization,
  update rollback/no-change cleanup, P09 configuration, P10/P11 and report/export tests.
- All eight JavaScript suites passed, including unavailable legacy scenario UI.
- Playwright GUI checks passed at 1440/1024/768/390px. Read-only localhost server;
  no campaigns or scheduler started. Documentation screenshots refreshed.
- Manifest hashes, embedded installer Bash syntax and runtime Bash/JavaScript checks passed.
- Windows P11 parsing and service compilation passed. Its existing lifecycle fixture
  could not assign Administrators ownership under this local account
  (`SetAccessControl`: SID may not be the owner). P11 payload/test unchanged;
  the existing Windows GitHub Actions job is the independent check for this environment limit.

Passing mocked P09 tests does not establish that the reported real P09 failure is
fixed. P09 investigation is explicitly the next separate milestone.

## Exact file list

Status: A added, M modified, D deleted. Paths are repository-relative.

```text
M	.github/workflows/mrnobody-validation.yml
M	MRNOBODY/mrnobody_userdata.yaml
M	TESTFILES/ATTACKER-V2/nginx/nordic-incident.conf
M	TESTFILES/ATTACKER-V2/scenarios/full-incident.sh
M	TESTFILES/ATTACKER-V2/scripts/05-staging.sh
D	TESTFILES/ATTACKER-V2/scripts/12-credential-access.sh
D	TESTFILES/ATTACKER-V2/scripts/13-native-tools.sh
D	TESTFILES/ATTACKER-V2/scripts/14-c2.sh
D	TESTFILES/ATTACKER-V2/scripts/15-web-app.sh
D	TESTFILES/ATTACKER-V2/scripts/16-defense-evasion.sh
D	TESTFILES/ATTACKER-V2/scripts/17-collection.sh
D	TESTFILES/ATTACKER-V2/scripts/18-dns.sh
M	TESTFILES/ATTACKER-V2/scripts/run-phase.sh
M	TESTFILES/ATTACKER-V2/scripts/update.sh
M	TESTFILES/ATTACKER-V2/update-manifest.txt
M	TESTFILES/ATTACKER-V2/web/app.py
D	TESTFILES/ATTACKER-V2/web/collection_state.py
D	TESTFILES/ATTACKER-V2/web/dns_actions.py
M	TESTFILES/ATTACKER-V2/web/execution.py
D	TESTFILES/ATTACKER-V2/web/exercise_actions.py
M	TESTFILES/ATTACKER-V2/web/exfil_validation.py
D	TESTFILES/ATTACKER-V2/web/lab_actions.py
D	TESTFILES/ATTACKER-V2/web/native_actions.py
M	TESTFILES/ATTACKER-V2/web/planning_api.py
M	TESTFILES/ATTACKER-V2/web/remote_actions.py
A	TESTFILES/ATTACKER-V2/web/retired_files.py
M	TESTFILES/ATTACKER-V2/web/scenario_model.py
M	TESTFILES/ATTACKER-V2/web/scheduler.py
M	TESTFILES/ATTACKER-V2/web/static/app.js
M	TESTFILES/ATTACKER-V2/web/static/planning.js
M	TESTFILES/ATTACKER-V2/web/static/style.css
A	TESTFILES/ATTACKER-V2/web/unavailable.py
D	TESTFILES/ATTACKER-V2/web/web_lab.py
D	TESTFILES/ATTACKER-V2/web/web_profiles.py
M	TESTFILES/ATTACKER-V2/web/windows_actions.py
M	docs/images/mrnobody-ui/attack-techniques.png
M	docs/images/mrnobody-ui/builder.png
M	docs/images/mrnobody-ui/dashboard.png
D	docs/mrnobody-application-collection.md
D	docs/mrnobody-credential-beacon-simulation.md
D	docs/mrnobody-dns-activity.md
A	docs/mrnobody-dual-commands.md
D	docs/mrnobody-native-tools.md
M	docs/mrnobody-p06-standalone.md
A	docs/mrnobody-phase-retirement-validation.md
A	docs/mrnobody-phase-retirement.md
M	docs/mrnobody-remote-persistence.md
M	docs/mrnobody-reports.md
M	docs/mrnobody-scenario-presets.md
M	docs/mrnobody-ui-redesign.md
A	docs/roadmap/mrnobody-optional-phases.md
D	tests/mrnobody/application_collection.py
D	tests/mrnobody/dns_activity.py
M	tests/mrnobody/full_incident.py
M	tests/mrnobody/install.py
D	tests/mrnobody/lab_phases.py
M	tests/mrnobody/native_dual.py
M	tests/mrnobody/persistence_dns.py
A	tests/mrnobody/phase_retirement.py
M	tests/mrnobody/planning.cjs
M	tests/mrnobody/release_validation.py
M	tests/mrnobody/remote_actions.py
M	tests/mrnobody/runtime.py
M	tests/mrnobody/scenario_portability.py
M	tests/mrnobody/scenario_presets.py
M	tests/mrnobody/scenarios.cjs
M	tests/mrnobody/ui.py
M	tests/mrnobody/ui_browser.cjs
```

See [update instructions](mrnobody-phase-retirement.md) and the
[optional roadmap](roadmap/mrnobody-optional-phases.md).
