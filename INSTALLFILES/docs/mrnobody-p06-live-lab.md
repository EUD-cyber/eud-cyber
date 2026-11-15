# P06 Live Lab – Sprint 1

Live Lab er et eksplicit valg i **Attack Techniques → P06**. Feltet er slået fra
som standard og nulstilles, når formularen åbnes igen. Normal standalone P06,
ZTD, heartbeat, P11 og Full Campaign beholder deres eksisterende funktion.
Der er ingen nye periodiske overførsler, automatisk retry eller C2-kommandoer.

## Forløb og afgrænsning

1. P06 opretter sin faste `corporate-secret-data.txt` på det valgte lab-target
   via den eksisterende SSH/WinRM-adgang. Filen indeholder kun opfundne data.
2. Det eksisterende P06-forløb sender filen fra target til Slaves lokale receiver
   og verificerer størrelse og SHA-256. Denne del kræver fortsat, at target kan
   nå Slaves P06-receiver; Live Lab ændrer ikke dette eksisterende netværkskrav.
3. Kun hvis Live Lab er valgt, læser Slave netop denne modtagne fil fra den
   aktuelle P06-evidens. Indholdet skal være identisk med den faste generator.
   Brugerfiler, mapper, symlinks, ændrede filer og P05-genbrug afvises.
4. Slave sender én autentificeret JSON/base64-overførsel til
   `/api/master/agents/p06-file` via eksisterende `AgentTransport` og den
   konfigurerede `MRNOBODY_MASTER_URL`. IP og DNS virker gennem samme transport.
   Slave→Master er udgående og NAT-venlig; ingen ny lytteport på Slave.
5. Master kræver registreret, ikke-spærret Agent-ID/token, Master-rolle og
   privat lab-kildeadresse. HTTPS validerer certifikatet; HTTP kræver det
   eksisterende eksplicitte lab-flag. Redirects og miljø-proxyer anvendes ikke.
6. Master begrænser request til 8192 bytes og afkodet fil til 4096 bytes,
   kontrollerer deklareret størrelse, SHA-256 og det præcise P06-generatorindhold.
   Filbytes gemmes som SQLite BLOB i `p06_receipts`, atomisk med et `exfil`-event
   i `receiver_events`, knyttet via event-ID til Agent-ID og Campaign-ID/P06.
   Databasen er `/var/lib/mrnobody/master/registry.sqlite3`.
7. Først efter commit kvitterer Master med modtagelsestid, event-ID, størrelse,
   hash og `verified=true`. Slave kontrollerer kvitteringen og gemmer `live_lab`
   i `state/exfiltration.json`. Manglende/fejlbehæftet kvittering fejler jobbet;
   en vellykket lokal target→Slave-overførsel kan stadig være bevaret som evidens.

Receiver-dashboardet på Master viser P06, verificeret SHA-256 og faktisk modtaget
filstørrelse. Ældre metadata-events vises med “Not verified”. Filindhold og tokens
udleveres ikke gennem dashboardet. Et mistet svar kan betyde, at Master har gemt
filen, selvom Slave viser fejl. Der sendes ikke automatisk igen; sammenhold
Agent-ID og Campaign-ID før en ny manuel kørsel. Gentagelser giver separate events.

## Opdatering af Master og Slave

`sudo mrnobody update` henter fra `main`. En feature-branch bliver derfor først
installeret med denne kommando, når ændringen er flettet ind i `main`.

Kør først på Master og derefter på Slave:

```sh
sudo mrnobody update
```

Updateren bevarer deployment-konfiguration, Agent-identitet og Master-database,
installerer den nye receiverkode og aktiverer nginx-konfigurationen. Kør update
igen, hvis første kørsel kun opdaterede en ældre updater. Der kræves ingen
geninstallation eller ny identitet. Se [Master/Slave-konfiguration](mrnobody-agent-client.md).
Slave skal have rollen `agent`, en gyldig Master-URL og en eksisterende registreret
identitet. Master skal allerede vise Slave som online. Automatisk ZTD-enrollment
kan fortsat bruges; der kræves ikke ny manuel parring.

Kontrollér på Slave:

```sh
sudo python3 /opt/nordic-attack/web/agent_client.py --check
systemctl is-active mrnobody-agent.service
```

Ved HTTPS skal Slaves eksisterende CA-konfiguration stole på Masters certifikat;
brug et DNS-navn/IP, der matcher certifikatet. Deaktiver ikke certifikatkontrollen.
Det generelle “IncidentVM IP”-felt ændrer ikke Live Labs Master-destination.

## Manuel lab-test

1. Åbn Slaves P06. Indtast et godkendt privat lab-target, transport og aktuelle
   SSH/WinRM-credentials. Lad fil og staging incident være tomme.
2. Kør først med Live Lab **fra**. Normal P06 skal fungere som før, uden nyt
   P06-file-event på Master.
3. Vælg Live Lab og kør én gang. Notér job/Campaign-ID. Jobbet skal ende complete,
   og output skal vise “Master verified receipt”.
4. Åbn **Master → Receiver** over HTTPS, og filtrér på Agent-ID og Campaign-ID.
   Bekræft P06, status received, faktisk størrelse og SHA-256. Sammenhold med
   Slaves `/opt/nordic-attack/state/exfiltration.json` → `live_lab`.
5. Blokér Slaves udgående forbindelse til Master i lab-firewallen og gentag
   med Live Lab valgt. Jobbet skal fejle på manglende kvittering. Genåbn trafikken.
   Eksisterende heartbeat kan naturligvis også påvirkes af netværksblokeringen.
6. Prøv Live Lab sammen med et filnavn/staging incident: formular/API skal afvise
   før eksekvering. Vælg normal P06 igen for den eksisterende P05-genbrugsfunktion.

## Automatiske checks

Fra `INSTALLFILES/` på Linux med Flask/reportlab/PyYAML/pypdf installeret:

```sh
python3 tests/mrnobody/p06_live_lab.py -v
python3 tests/mrnobody/p06_default.py -v
python3 tests/mrnobody/p06_standalone.py -v
node tests/mrnobody/p06_live_lab.cjs
node tests/mrnobody/receiver_dashboard.cjs
```

Browserchecks kræver Playwright/Chromium. Testene bruger isolerede fixtures,
Flask-testklient og SQLite; de kontakter ingen eksterne lab-targets. Den eksisterende
P06-dispatchtest bruger kun en lokal loopback-receiver og transportdobler.
Fysisk Master/Slave- og firewalltest skal stadig udføres i labbet.
