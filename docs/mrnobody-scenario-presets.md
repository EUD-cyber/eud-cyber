# MrNobody scenario presets

The active preset is **Recon Only** (`preset-recon-only`): P01 → P02,
Auto Discovery, Normal timing. It uses the shared planner and can be duplicated.

Presets containing retired phases are removed entirely: Credential Attack,
Windows Domain Compromise, C2 Detection Exercise, Web Attack, Collection +
Exfiltration, Ransomware-style Incident, Slow Intrusion and Full ATT&CK-style
Incident. No existing preset silently becomes a smaller scenario. Full Incident
remains a separate built-in campaign using P01–P11.

Saved custom scenarios retain their original phase list. A retired phase reference,
even when disabled, makes the definition unavailable for execution and scheduling.
The library and schedules explain this state. Original database/JSON data remains.
Duplicate/edit a copy and explicitly remove unavailable entries to change scope.

See [update instructions](mrnobody-phase-retirement.md) and the
[optional future roadmap](roadmap/mrnobody-optional-phases.md).
