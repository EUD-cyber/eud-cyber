# MrNobody Scenario Presets

Built against main `3f51fc1c6ddb9af75f69a12a466309f68f6e00aa`.
The installed script catalogue and `scenario_model.validate` remain authoritative.
Templates fail closed if their installed techniques or adapters are unavailable.
They use the existing structured campaign runner; no new attack implementations
or execution services are introduced. The legacy Full Incident script, APIs,
CLI and opt-in command/wordlist behavior are unchanged.

| Stable ID (prefix `preset-`) | Ordered Attack Techniques | Targets / profile |
| --- | --- | --- |
| recon-only | P01 → P02 | Auto Discovery / Normal |
| credential-attack | P01 → P03 → P12 | Auto Discovery / Normal |
| windows-domain-compromise | P01 → P03 → P09 → P11 → P12 → P13 | Fixed Targets / Normal |
| c2-detection | P01 → P03 → P14 → P18 | Auto Discovery / Normal |
| web-attack | P01 → P02 → P15 | Auto Discovery / Normal |
| collection-exfiltration | P01 → P03 → P17 → P05 → P06 | Auto Discovery / Normal |
| ransomware-style | P01 → P03 → P11 → P12 → P14 → P16 → P17 → P05 → P06 → P07 | Auto Discovery / Normal |
| slow-intrusion | P01 → P02 → P03 → P11 → P12 → P14 → P16 → P04 → P17 → P05 → P06 → P07 | Auto Discovery / Slow, 14,400 seconds |
| full-attack-incident | P01 → P02 → P15 → P03 → P11 → P12 → P14 → P18 → P16 → P04 → P17 → P05 → P06 → P07 | Auto Discovery / Normal |

## Configuration and teaching decisions

- Credential Attack validates supplied credentials (P03), then inspects a
  temporary synthetic credential file (P12 metadata). Wordlist guessing is not a
  default. Existing wordlist support remains available in the builder.
- Windows Domain Compromise requires explicit private target addresses and a
  discovery subnet. Common Target can populate the target fields; individual
  overrides still work. P03 validates RDP; subsequent actions use WinRM. P09 must
  point at a lab DC with AD tools and account/group management rights. It makes
  persistent domain changes and needs separate lab rollback; authentication
  alone does not supply the necessary privileges. The existing prerequisite
  check may skip an incompatible DC. P11 defaults to a marked Scheduled Task;
  P13 uses fixed encoded PowerShell telemetry. Credentials remain runtime-only.
- P10 is intentionally omitted: arbitrary commands are execution-time inputs,
  not secret-free scenario parameters. Users can add it in the builder with the
  existing independent PowerShell and Bash inputs; blank commands retain their
  existing NOT_CONFIGURED behavior.
- Web scenarios require an explicit fingerprinted MrNobody Web Lab target.
  Review its port, path and SQL injection/traversal profile in the builder.
  Auto mode filters services found by P02; the endpoint must be reachable in
  those discovery results. P15 emits synthetic application telemetry and never
  creates host-compromise state. Its position before P03 is a parallel web
  exercise branch, not an invented host-access dependency.
- C2 and broad ATT&CK scenarios require a private, non-forwarding lab DNS
  endpoint. Defaults are five HTTP and five DNS marker check-ins, five-second
  intervals and 10% jitter. DNS has a 60-second ceiling; both actions retain
  existing bounded budgets. Approximately a minute of check-in activity is
  expected, in addition to discovery, authentication and transport time.
- P17 archives only marker-verified synthetic datasets. P05 preserves the
  collection archive and P06 consumes shared synthetic staged-data state.
  Impact remains the existing synthetic exercise behavior.
- Slow Intrusion uses the existing four-hour Slow profile and generated
  absolute offsets, including paced discovery/web probes. It adds no sleeps or
  independent timing implementation. Duration is a target, not a timeout.
- The broad ATT&CK preset uses cross-platform actions where possible. AD
  management and Windows-only native tools belong to the Windows preset;
  adding them mechanically would imply incompatible platform/privilege paths.

## Library and API

Definitions live in the already distributed `web/scenario_model.py` alongside
schema version 1. `GET /api/scenario-presets/<id>` returns a template suitable
for the builder. `/api/scenarios` includes teaching objectives, ordered flow,
profile, target mode, readiness, required non-secret inputs and duration where
known. Missing installed capabilities hide incompatible presets.

Built-ins are read-only. Edit and Duplicate both open a fresh custom draft.
Run opens Review (or the first incomplete builder step) and requires an explicit
Save + Run action and any execution-time credentials. Incomplete presets show
Needs configuration and disable Run while Edit/Duplicate stay available. The
server also rejects incomplete saves, direct runs and scheduling. Saving a
configured clone produces a new `custom-*` ID. Schedule a configured clone
through the existing builder or custom library.

Preset provenance (`id`, canonical name, version), scenario version, teaching
objective, ordered phases, profile and planned timing travel in the same
`MRN_EXECUTION` object as custom scenarios. Provenance survives duplication and
editing. Reports retain the existing Investigation/Ground Truth JSON, HTML and
PDF paths; exports show provenance, version and ordered flow. MITRE summaries
exclude skipped/not-run actions and retain observed-versus-metadata distinctions;
phase completion is not evidence that every mapped technique succeeded.

No new runtime files are introduced, so cloud-init already fetches all required
assets. Update-manifest hashes must change for the modified distributed files.
Nothing in this change deploys to or contacts a running lab VM.

## Validation

`python tests/mrnobody/scenario_presets.py` checks every template against the
real catalogue, dependencies, readiness, secret exclusion, clone/edit/run and
schedule paths with mocked launchers, timing, shared collection ordering and
report/export provenance. `planning.cjs` loads all nine real templates through
the builder and checks order, required inputs and Review; `scenarios.cjs` checks
cards, objective text and action eligibility. These are part of the existing
GitHub validation workflow. Existing regression and inert-runner tests remain.
