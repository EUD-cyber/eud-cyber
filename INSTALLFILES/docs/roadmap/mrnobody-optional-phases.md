# MrNobody incremental roadmap

## P06 Live Lab Sprint 1

Implemented as an explicit standalone opt-in: one verified generated P06 fixture
is forwarded outbound from Slave to configured Master using the existing Agent
transport. Master stores actual bytes, SHA-256 and P06/Agent/Campaign receipt
evidence atomically; Receiver shows verification. See [operation and tests](../mrnobody-p06-live-lab.md).
Default P06, P05 reuse, Full Campaign, ZTD and heartbeat retain their existing flow.
Periodic transfers, P11 beaconing and campaign integration remain future work.

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

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

## Master receiver og redigerbare phase-standarder

Receiver Dashboard V1 er read-only. Master-destinationsforslag er nu tilføjet
til det eksisterende P06 exfiltration destination IPv4-felt under Full Incident
configuration (Settings). Forslaget læses gennem `/api/config` fra den validerede
startup-konfiguration i `/etc/mrnobody/deployment.conf`.

- Kun `agent` med gyldig Master URL får et forslag. `standalone`, `master`,
  manglende/ugyldig konfiguration eller manglende URL giver blankt felt.
- IPv4-feltet bruger kun en bogstavelig IPv4-adresse; DNS-navne bliver ikke slået
  op eller indsat som IP. API'ets `receiver_suggestions` adskiller `ipv4`, `host`
  og fuld `url`, som bevarer scheme, port og sti til fremtidige URL-felter.
- Forslaget er redigerbart. Genindlæsning af config i samme side overskriver ikke
  en eksisterende værdi eller et felt, brugeren bevidst har tømt. En fuld
  browser-reload indlæser et nyt forslag; formulardata gemmes ikke permanent.
- Gennemgang: standalone P06 har ingen separat destination; P11 har kun
  `persistence_resolver` (intern DNS-resolver), ingen HTTP C2-/beacon-destination.
  Resolver, `.test`-domæne, targets, scope og execution er uændrede. Derfor
  tilføjes ingen falske eller ikke-funktionelle P06/P11-felter.
- Den eksisterende P06 kører stadig en lokal IncidentVM upload-receiver.
  Master Receiver kan endnu ikke erstatte denne. Forslaget dokumenterer en
  destination, ikke at forbindelsen eller P06-overførslen virker. Bekræft en
  kompatibel lokal modtager før eksekvering; ingen automatisk start sker her.

## Efterfølgende sprints

- P06: periodiske syntetiske overførsler til Master Receiver med korrekt
  protokol, autentifikation og evidens. Implementeres ikke i destinationssprintet.
- P11: separat kontrolleret C2/beacon-integration, når et reelt destinationsfelt
  og en kompatibel modtager findes. Brug aldrig Master som DNS-resolver implicit.

Krav der fortsat gælder for kommende destinationsfelter:

- Ved Slave/Agent med konfigureret Master: foreslå/prefill Master-adressen som
  REDIGERBAR standard i relevante C2-/exfil-felter. Hent MRNOBODY_MASTER_URL
  fra /etc/mrnobody/deployment.conf gennem eksisterende valideret public config/API;
  eksponér aldrig tokens eller andre hemmeligheder. Udvid public API valideret, hvis
  adressen ikke allerede er tilgængelig. Konfigureret betyder ikke forbundet.
- Standalone eller ingen Master URL: blankt felt, ingen fallback til andre IP'er.
  Bevar brugerens indtastning; overskriv ikke et bevidst valgt mål ved refresh.
- Gennemgå både P06 og P11 samt øvrige phases for faktiske C2-/exfil-felter.
  Ingen generel prefill af vilkårlige target-IP'er. Bevar http:// eller https://
  og korrekt port i URL-felter. Udtræk kun host til et IP/host-felt; kopiér aldrig
  URL til IP-felt. Hvis IP kræves, må et DNS-navn ikke indsættes som IP.
- Forslaget må aldrig tvinge en forbindelse, ændre attack-scope eller bruge Master
  som attack-target uden brugerens bevidste valg. Vis adressernes rolle tydeligt,
  og kræv bevidst valg før eksekvering mod Master.
- Fjernstart/stop fra Master af både individuelle attacks og hele scenarier
  på én eller flere Slaves/Agents
  forbliver et roadmapkrav via Agent-initieret polling. Ingen fjernstart/stop
  eller ændring af eksisterende Campaign Control i Receiver Dashboard V1.
