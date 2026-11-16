# Full Incident – P06/P11 Live Lab

## Verificeret omfang

Udgangspunkt: main `6e6eb7fca37c323f3f74aa3834c42bf6a1c2829a` (PR #110).
P11 campaign-API og standalone P06/P11 var allerede implementeret. Dette trin
føjer synlige, eksplicitte Live Lab-valg til den lokale Full Incident-form på en
konfigureret Slave Agent og integrerer P06 med den eksisterende faste fixture.
Det tilføjer ingen generisk Master-fjernstart, nye mål eller multi-agent jobs.
Masters faste P11-jobside beholder sin eksisterende 3-beacon-operation uændret.

Begge campaign-valg er som standard slået fra. P11 har særskilte HTTP-felter:
interval 10–300 sekunder (default 30), duration 60–1800 (default 180), højst
1–60 forsøg (default 6). De er uafhængige af målenes eksisterende P11 DNS-
indstillinger og aktivitetens deadline. Valgene nulstilles ved scenarieskift og
manglende deployment-status og kan kun vælges i Full Incident på en Agent.
De bliver aldrig gemt i scenarier, eksport eller schedules.

## P06: én genereret fil og én Master-kvittering

Ved eksplicit opt-in bruger P06 ikke P05's filvalg. Den vælger deterministisk den
første sorteret efter mål-IP/platform blandt P03's fuldførte, verificerede,
samme-incident-adgange. Kun én kilde vælges; et mislykket forsøg vælger ikke
automatisk et nyt mål. P03 skal stå før P06 i planen. Ingen adgang, forkert
incident, ufuldstændig evidens eller ændret konto giver ingen P06 Live Lab-trafik.

Den eksisterende P03-evidensverifier genbruges: privat IPv4, autentificeret
SSH-session eller read-only Windows-identitet, nøjagtig protokol/port/konto og
samme runtime-konto med password til den aktuelle kørsel. Passwords fra gemt
inventar bruges ikke. Der foretages ingen ny discovery eller credential guessing.

På det valgte mål genererer den eksisterende P06-pipeline præcis én fast fil:
`corporate-secret-data.txt` med tydeligt fiktive øvelsesdata og campaign-ID.
Den læser ingen eksisterende virksomhedsdata, mapper, brugerfiler eller vilkårlig
sti. P06 genbruger standalone-adapteren internt, men rapporteres under samme
Full Incident/campaign-ID. P05 og øvrige faser beholder deres normale adfærd.

Filen uploades først tilbage til Slavens lokale P06-receiver. Denne tilstand
bruger den lokale interfaceadresse fra ruten til det verificerede mål; det
generelle destination-IP-felt/Master-adresseforslaget bruges ikke til dette hop.
Målet skal kunne nå Slavens exfil-port (typisk 9090). Ingen ny port tilføjes.
Først efter verificeret lokal størrelse/SHA256 og præcist fixtureindhold sendes
filen én gang udgående fra Slave til den eksisterende Master Receiver.

Master kontrollerer indhold, størrelse og SHA256 og committer kvitteringen før
ACK. Campaign/P06/Agent kan korreleres i Receiver og Slave Ground Truth. Local
transfer og Master receipt er særskilte resultater: uden Master-ACK fejler P06,
selv om filen blev verificeret lokalt. En kvittering beviser levering, ikke SIEM-
detektion. Kilde-/modtagerartefakter beholdes som tidligere; ingen automatisk
sletning eller restore på målmaskinen tilføjes.

P06's Master-forsøg køres nu i en engangsproces med 10 sekunders samlet grænse
for DNS, TLS og responslæsning samt Stop-håndtering. Barnet dræbes og reapes ved
Stop/deadline. Ingen automatisk retry: et mistet ACK kan have en committed
Receiver-event. Kontrollér Master før et nyt forsøg. Denne afgrænsning gælder
også standalone Live Lab; eksisterende måltransporter er ellers uændrede.

## P11: eksisterende foreground-loop, nu med UI

P11's Slave-origin HTTP(S)-loop starter fortsat først efter alle eksisterende
P11-målhandlinger er lykkedes. Ingen P03-adgange, skip/kollision, partial,
fejl eller Cleanup starter beacons. ACK-fejl kan fejle fasen efter vellykkede
målhandlinger; remote artefakter kræver stadig Cleanup.

Hvert HTTP-forsøg er fortsat begrænset af 10 sekunder eller resterende levetid,
inklusive DNS/respons. Retry bruger et planlagt forsøg, uden catch-up burst.
Token-, TLS- og ACK-schemafejl stopper løkken. Ingen kommando/tasking modtages.
Stop af campaign standser foreground-loop/requests; målenes persistence/DNS
følger deres egen deadline og kræver separat Cleanup. Se `p11-full-campaign.md`.

## API og grænser

Den eksisterende lokale `POST /api/scenario/full-incident/start` (og `/api/start`)
accepterer `p06_live_lab`, `p11_live_lab`, `beacon_interval`, `beacon_duration`,
`beacon_count`. JSON-valg skal være rigtige booleans. GUI multipart sender kun
strenge `true`/`false`; dublerede/andre toggle-værdier afvises. Inherited Live Lab-
flags ryddes ved hver start; kun P06/P11 modtager deres egen runtime-konfiguration.
P06 er afgrænset til Full Incident. P11's eksisterende runtime-API for gyldige
custom-scenarier med P03 før P11 Create er bevaret; scheduler/persistens udvides ikke.

Master-URL, Agent-ID, token og CA kommer fra eksisterende privat Agent-config;
ingen nye destination-/credentialfelter. Brug verificeret HTTPS/SAN/CA. Eksisterende
udtrykkelig lab-HTTP-politik er bevaret for disse lokale Live Lab-flows; Masters
separate jobpolling kræver stadig altid verificeret HTTPS. Ingen TLS-downgrade
eller deaktiveret certifikatvalidering tilføjes. Receiver beholder sin labnetgrænse.
Masters dynamiske webflade kræver fortsat administratorlogin/Origin/CSRF.

## Opdatering: Master først, Slave derefter

Efter merge til main (updateren henter ikke en featurebranch):

1. Stop en aktiv campaign på Slaven og afvent afslutning. Gem backup, men bevar
   Agent-ID/token, registry og workerjournaler.
2. På **Master**: `sudo mrnobody update`, derefter
   `sudo systemctl restart nordic-incident-web`. Log ind som administrator.
3. På **Slave**: `sudo mrnobody update`, derefter
   `sudo systemctl restart nordic-incident-web mrnobody-agent`.
4. På Slave: `sudo python3 /opt/nordic-attack/web/agent_client.py --check` og
   `systemctl is-active mrnobody-agent.service`. Kontrollér samme Agent-ID online
   på Master. Verificér SAN/CA og den eksisterende `ca_file`/tillid normalt.
5. Dette er den lokale campaign-runner. Den separate `mrnobody-agent-jobs.service`
   er ikke en forudsætning og aktiveres ikke af denne ændring. Hvis den allerede
   bruges, følg dens eksisterende unit-opdateringsguide; slet ikke journalen.

## Praktisk labacceptance

* Kør først en almindelig campaign med begge Live Lab-valg fra. Forvent ingen
  nye P06/P11 Master-receipts; normal P03/P05-staging, DNS og rapporter skal virke.
* På den parrede Slave: vælg Full Incident, slå P06 til. Kontrollér bekræftelsen,
  start og find `P06_CAMPAIGN_LIVE_SOURCE` samt faktisk mål/fil i Ground Truth.
  Forvent én genereret fil, verificeret lokal transfer og ét committed Master-
  event med samme Agent/campaign, P06, størrelse og SHA256. Andre P03-hosts må
  ikke få ekstra P06 Live Lab-filer. P05 kan stadig have egne normale artefakter.
* Gentag med P11 til, fx interval 30, duration 90, count 3. Efter vellykkede
  målhandlinger forventes tre ACK'er cirka 30 sekunder fra hinanden. DNS-felter
  og HTTP-felter er separate; HTTP stammer fra Slaven.
* Brug Master Receiver med Agent/campaign-filter. Sammenhold event-ID med
  `P11_BEACON_ACK`/P06-state og packet capture. Normal campaign-rapport er fra den
  lokale runner; et Receiver-ACK beviser ikke detektionsreglernes resultat.
* Blokér midlertidigt Slave→Master: P06 skal afslutte forsøget inden grænsen;
  P11 følger sine begrænsede forsøg. Forvent ingen falske ACK'er. Test Stop under
  request/ventetid og kontrollér ingen nye forsøg efter Stop. Et allerede committed
  Master-event kan stadig findes; Stop kan ikke tilbagekalde modtaget trafik.
* Test manglende/forældet P03, forkert konto, ingen Agent-config, forkert CA/SAN,
  scenarieskift, checkbox-defaults, nye sessions og scheduler uden live flags.
* Stop før eksisterende P11 Cleanup med nøjagtigt dokumenteret artifact-suffix,
  original konto/transport. Bekræft remote oprydning separat; lokal Stop gør det
  ikke. Fjern kun P06's nøjagtigt dokumenterede genererede fil, hvis labopgaven
  kræver det; ingen brede eller automatiske oprydningskommandoer.

Lokale fixture-/HTTPS-/browsertests er ikke bevis på virkelig VM/NAT/systemd,
Windows-service, firewall eller SIEM-test. Disse acceptpunkter kræver lab-evidens.
