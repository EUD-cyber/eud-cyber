# Master fixed P11 web control

## Implementeret omfang

Dette trin bygger på PR #108 (fast P11-jobkø) og PR #109 (administratorlogin).
`/master/admin` kan nu vælge én registreret online Agent, eksplicit starte ét
fast syntetisk `p11-live-lab`-job, vise de seneste 50 jobs og per-job-status,
opdatere automatisk hvert 5. sekund mens siden er synlig og anmode om Stop med
bekræftelse. Hver jobvisning linker til filtrerede Receiver-events. Der produceres
fortsat ingen normal campaign-rapport for denne faste jobfunktion.

Operationen er uændret: 3 syntetiske beacons med 30 sekunders interval til den
konfigurerede Master Receiver, højst 90 sekunders aktivitet og 180 sekunders
jobdeadline. Agent-initieret polling, individuelle Agent-tokens, durable journal,
idempotens, én aktiv global kø og Stop-/offline-/deadline-semantik er bevaret.
Der er ingen generisk P01–P11/scenario-fjernstart eller multi-agent campaigns.
Heartbeat online beviser ikke, at den separate jobworker er startet.

## Administratorgrænse og migration fra PR #109

**Hele Masters dynamiske webinterface kræver nu administratorlogin**, inklusive
konfiguration, rapporter og eksisterende lokale run/update/scheduling-API'er.
Det lukker de tidligere ubeskyttede lokale administrationsruter, som ellers kunne
omgå beskyttelsen af den nye jobfunktion. Adgangen er ikke begrænset til P11:
root uddelegerer med administratornøglen også platformens eksisterende lokale
webadministration. Udsted den kun til en betroet Master-administrator.

Undtagelser er statiske installerede filer, GET health, loginsiden/session-API'et
og den præcise allowlist af POST Agent-protokolruter. Disse POST-ruter beholder
deres egne token-, schema-, rolle-, TLS- og Receiver-labnetkontroller. Der er
ingen bred undtagelse for `/api/master/*`. Agent/standalone beholder den eksisterende
lokale webadgang; deres job- og Master-administratorruter er ikke tilgængelige.

* Root opretter en separat tilfældig 256-bit adminnøgle. Kun SHA256 gemmes i
  `/etc/mrnobody/web-admin/credential.json`: root-ejet 0600-fil i 0700-mappe;
  symlinks/hardlinks/usikre modes afvises. Ingen standardnøgle, automatisk
  provisioning eller genbrug af Agent/enrollment-token. Manglende nøgle giver 503.
* Opaque serverbaserede sessioner har 15 minutters absolut levetid. Cookien er
  `__Host-mrn-admin`, Secure, HttpOnly, SameSite=Strict, Path=/, uden Domain.
  Gamle PR #109-cookies accepteres ikke. Genstart, fjernelse/rotation af nøglefilen
  kræver nyt login. Root-filen genlæses ved hvert beskyttet request.
* Verificeret browser-HTTPS, præcist root-konfigureret Host/Origin og ingen CORS.
  Alle mutationer kræver Origin og sessionsbundet CSRF-header, også gamle lokale
  administrationsruter. Sessionlogin kræver Origin og bounded JSON; logout kræver
  yderligere CSRF. Credentials/CSRF gemmes aldrig i browserlager, URL eller logs.
* Den eksisterende loopback-nginx må sætte TLS-headeren; fjernklienter må ikke.
  Port 8082 skal fortsat være bundet til loopback og utilgængelig fra andre VM'er.
  Lokal root-/nginx-kompromittering ligger uden for denne webgrænse.
* Globale procesgrænser: 5 loginforsøg/minut, 120 sessionrequests/minut,
  600 øvrige Master-requests/minut, 30 autentificerede mutationer/minut og
  6 jobmutationer/minut. Maks. 16 sessioner. 429 har Retry-After: 60.
  En enkelt administrator bør højst have få dashboardfaner åbne.
* Jobmutationer kræver strict JSON på højst 1024 bytes, ingen queryparametre,
  dublerede/ekstra felter eller operation/target-parametre. Legacy-mutationer har
  et ekstra loft på 8 MiB og beholder deres eksisterende indholdsvalidering.
* Master-svar er no-store og har CSP/nosniff/referrer-beskyttelse. Eksisterende
  rapporteksporter beholder deres strengere scriptfrie sandbox.

Der understøttes fortsat én webproces. Session-/ratelageret er trådsikkert, men
ikke delt mellem processer; kør ikke flere workers uden et separat design.
En delt root-udstedt nøgle giver ikke MFA eller personligt revisionsspor.
De globale grænser kan give kortvarig DoS. Omgå dem ikke med klient-IP-headere.

## Job-API og idempotens

Alle følgende kræver administrator-session, HTTPS og korrekt Host. Mutationer
kræver desuden Origin/CSRF:

* GET `/api/master/admin/jobs`: nyeste 50, ingen tokenhash eller request-key.
* POST samme sti: præcis `agent_id` og `request_key`. Operationen er fast.
* GET `/api/master/admin/jobs/JOB_ID`: status, deadline og fejlkategori.
* POST `/api/master/admin/jobs/JOB_ID/stop`: præcis `confirm_job_id=JOB_ID`.

Startknappen sender kun efter et eksplicit klik. Browseren gemmer kun det
igangværende forsøgs Agent-ID/request-key i sessionStorage, aldrig credentials.
Ved netværksfejl eller tvetydigt svar beholdes denne key over reload/login, og
knappen gentager samme request. Gentagen key returnerer samme job, også efter
terminal status. Et nyt forsøg får først en ny key, når det tidligere svar er
bekræftet eller definitivt afvist før enqueue. Uden browserlager gælder retry-
identiteten kun den aktuelle side; kontrollér historikken efter reload, før du
starter igen. Browseren starter aldrig automatisk et nyt job ved refresh.

Stop af et queued job er straks terminalt. Aktivt Stop er en anmodning indtil
Agentens næste polling/ACK eller deadline; UI viser `stop_requested`. En sen
succes efter Stop bliver stadig `stopped`. Terminale jobs genstartes ikke.
Deadlinefejl beviser ikke, hvor mange beacons der nåede frem; Receiver er evidens.

## Master først, Slave derefter

Kør efter merge; updateren henter main, ikke feature-branchen. Gem backup af
programfiler/aktive units. Bevar registry, Agent-ID, tokens og workerjournal.

1. På Slave: `sudo systemctl stop mrnobody-agent-jobs` hvis den er installeret.
2. På **Master**: `sudo mrnobody update`, derefter
   `sudo systemctl restart nordic-incident-web` og
   `sudo systemctl status nordic-incident-web --no-pager`.
3. På Master, hvis der ikke findes en administratornøgle: kør i privat root-
   terminal nedenstående med det faktiske betroede origin uden afsluttende slash.
   Output er hemmeligt; gem det sikkert, ikke i chat, shellargumenter eller logs:

```sh
sudo python3 /opt/nordic-attack/web/master_admin.py provision --origin https://master.lab
```

En allerede provisioneret PR #109-nøgle virker fortsat. Ingen automatisk
overskrivning. Åbn `https://master.lab/master/admin` og log ind. Manglende nøgle
låser Masters dynamiske webadgang; CLI-opdatering/registry-administration virker
fortsat. Verificer HTTPS/SAN/CA normalt, ingen `-k` eller HTTP-downgrade.

4. På **Slave**: `sudo mrnobody update`. Master-URL skal være HTTPS og matche SAN;
   CA skal være betroet via systemlager eller eksisterende `ca_file` i den private
   `/etc/mrnobody/agent.json`. Tidligere `http://10.134.71.3` er utilstrækkeligt.
5. `sudo systemctl restart mrnobody-agent`. Bekræft samme Agent-ID online på Master.
6. Installer og start den separate worker eksplicit på Slave:

```sh
sudo install -m 0644 /opt/nordic-attack/systemd/mrnobody-agent-jobs.service /etc/systemd/system/mrnobody-agent-jobs.service
sudo systemctl daemon-reload
sudo systemctl enable --now mrnobody-agent-jobs.service
sudo systemctl status mrnobody-agent-jobs.service --no-pager
```

Updateren vedligeholder endnu ikke den aktive jobunit; kopier den ved opdatering.
Frisk installation distribuerer UI/auth-filer, men opretter ikke adminnøgle eller
starter jobworkeren automatisk. Ingen indgående Slave-port/NAT-forwarding kræves.

## Labacceptance og tilbagekaldelse

* Før login: Master-konfiguration, jobstart/-stop, lokale run/update/schedules og
  rapportadgang skal afvises. Agent-token må ikke give administratoradgang.
  Heartbeat og tokenbeskyttet polling/Receiver skal stadig fungere.
* Efter login: vælg én online Agent. Klik Start. Følg queued/delivered/running og
  til sidst succeeded. Receiver-linket skal vise præcis tre verificerede beacons
  med sekvens 1,2,3 og job-ID som campaign-ID, cirka 30 sekunder mellem ACK'er.
* Gentag samme request-key (eller retry efter tabt svar): samme ID, ingen ny
  kørsel. Reload må kun læse status; ingen automatisk POST. Manglende worker
  giver queued og senere deadlinefejl, ikke en påstået succes.
* Start separat job, annuller Stop-dialogen: ingen request. Bekræft Stop efter
  første ACK. Afvent terminal `stopped`, vent mindst 35 sekunder og kontrollér
  uændret Receiver-antal. Prøv også queued Stop, offline/revoked Agent og
  worker-/netværksafbrydelse uden replay. Slet ikke journalen for at genstarte.
* Test ugyldig CSRF/Origin, HTTP/forkert SAN/ukendt CA, rategrænse, sessionudløb,
  logout og nøglefjernelse. Port 8082 skal være utilgængelig fra en anden VM.
* Tilbagekald via `sudo rm -- /etc/mrnobody/web-admin/credential.json`.
  Næste beskyttede request skal give 503. Provision igen for rotation; gammel
  cookie/nøgle skal afvises. Genstart kræver også nyt login.
* Gentag eksisterende ZTD, heartbeat, P06/P11 DNS/Live Lab, Full Campaign,
  standalone og Receiver/rapporter på de relevante Agent-/standalone-roller.
  Masters eksisterende lokale UI-handlinger kræver nu login/CSRF.

Lokal CLI er fortsat tilgængelig som beskrevet i `docs/master-remote-sprint1.md`.
Ingen af disse trin må rapporteres udført på brugerens VM'er uden gemt evidens.
Lokal HTTPS-/browser-/fixturetest er ikke virkelig NAT-, systemd- eller VM-test.
