# P19 offline validation foundation (incomplete)

Based on main `3f51fc1c6ddb9af75f69a12a466309f68f6e00aa`.

This review artifact implements only an offline, in-memory provider contract and
synthetic evidence evaluator. It is not an installed Attack Technique and does
not validate a real service vulnerability. No network traffic, remote commands,
credentials, persistence, files on targets, or real access are produced.

## Included profile

`offline-marker-v1` represents an explicitly synthetic CyberLab HTTP service
(port 8080). The pre-check compares a supplied fixture fingerprint, port and
protocol; validation compares a benign in-memory proof marker. RFC1918 literal
IPv4 addresses are required, even though no connection occurs. There are no
runtime or internet dependencies beyond Python's standard library. Cleanup is
unnecessary. The registry rejects duplicate identifiers and is read-only.

Auto evaluates caller-supplied discovery observations. Fixed requires a private
target and filters observations to that target. Neither mode performs discovery.
Unknown profiles, unsupported config fields and invalid targets fail closed.

Outcomes are SUCCESS for a synthetic proof, FAILURE for a matching fixture with
bad proof, and NOT_APPLICABLE for no matching fixture. A later successful
candidate overrides earlier mismatches or failures. These are exercise outcomes,
not claims of host compromise. Access metadata always explicitly states that
real access was not verified and compromise state was not changed.

Evidence is allowlisted: profile, safe target/service metadata, match/proof
booleans, fixed action descriptions, outcomes, timestamps and warnings. Raw
observations, response bodies, credentials and arbitrary supplied strings never
enter the returned evidence. JSON output remains explicitly marked simulation.
No ATT&CK technique is assigned because no actual adversary behavior occurs.

## Teaching notes

Students can compare the synthetic mismatch, failed proof and accepted proof
cases. Ask: Does a banner prove a vulnerability? Does a marker prove shell access?
Which independent evidence would establish the actual scope of access?

This offline exercise creates no service, Wazuh, Suricata, proxy/WAF or OS
telemetry. Do not present its results as observed detections. A teacher can use
separately prepared, labeled sample logs to discuss request correlation,
timestamps, application authorization decisions and alert interpretation.
Discuss removing unnecessary exposure, authentication/authorization enforcement,
patching and validating the effectiveness of those mitigations.

## Explicitly incomplete

No actual vulnerability-validation provider or automatic handoff to the existing
compromised-host state is included. Connecting newly gained service access to
the existing persistence, credential-access, defense-evasion, exfiltration and
impact chain is outside this contribution.

No P19 CLI registration, builder UI, campaign ordering, scheduler, timing, live
overview, Investigation/Ground Truth renderer, HTML/PDF export or MITRE UI
integration is implemented. The redesigned Attack Techniques pages and all
P01–P18 files are untouched. Full Incident placement remains unchanged.

The module lives under docs/examples rather than distributed runtime paths, so
userdata, cloud-init and update-manifest changes are unnecessary. Existing
backup tags/branches, updater and clean-install behavior are untouched. No VM
deployment or connection is part of this change.

## Verification

Run `python -m unittest discover -s tests/mrnobody -p p19_offline.py`.
The tests cover profile registration, invalid config, private-address boundaries,
Auto/Fixed selection, candidate fallback, all outcomes, evidence redaction,
timestamps, bounded input and explicit absence of real access claims.
Existing runtime/UI regression tests are not substitutes for this offline suite.
