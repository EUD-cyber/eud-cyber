# MrNobody incremental roadmap

This is a descriptive backlog. Nothing here registers phases, installs scripts,
adds presets or enables execution.

## Milestones

1. Remove P12–P18 from the active product. Keep P01–P11, including P08, P09 and
   P10. Preserve user scenarios, schedules and reports. Verify install and migration.
2. **Separate next task: investigate P09.** It is currently reported as failing.
   Its worker/payload is unchanged here. Mocked tests do not establish a real fix.
3. Stabilize target evidence for the remaining product before expanding scope.
4. Consider one optional capability at a time. There is no commitment to all seven
   and no executable placeholder registration.

## Optional future candidates

| Former ID | Descriptive scope | Required execution/evidence value |
|---|---|---|
| P12 | Credential access teaching exercise | Agreed synthetic test material, actual target-side action, host events, outcome and cleanup evidence. Never infer access from attacker intent. |
| P13 | Windows native tools / LOLBins | An agreed bounded native-tool action actually executed on target, process telemetry and verified cleanup. Distinct value beyond P10. |
| P14 | HTTP(S) C2 detection exercise | Verified target-originated check-ins, correlated server/network evidence, truthful failures and bounded timing. |
| P15 | Application security exercise | Genuine agreed lab application response, fingerprint and request/response evidence. Explicitly establish whether any host access occurs. |
| P16 | Defense evasion exercise | Reversible target-side change, evidence of change and restoration, explicit interrupted-cleanup handling. |
| P17 | Collection/archive exercise | Agreed synthetic files, verified target archive size/hash and traceable downstream staging/transfer linkage. |
| P18 | DNS activity detection exercise | Target-originated questions, resolver/network evidence and truthful partial/failure outcomes. Assess value beyond P11 DNS activity. |

Each candidate requires a separately requested milestone with reviewed scope,
prerequisites, offline tests, authorized lab validation, installation/migration plan
and evidence acceptance criteria. This removal introduces or modifies no offensive
payloads. Plans here cannot be selected or executed by CLI, GUI or a campaign.
