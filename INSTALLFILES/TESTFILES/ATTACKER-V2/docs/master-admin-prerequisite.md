# Sprint 2: administratorforudsætning — webjobkontrol blokeret

## Verificeret udgangspunkt og afgrænsning

16. november 2026: GitHub main er `1bee07b02b7cd10bf9526fbf62962ac005da618e`,
merge af PR #108. Dets træ `830203f129c4f9a0a0b4d586f521b6773cb58623` er identisk
med det lokale udgangspunkt `5aa2ff7`. Seneste Work-verifikation dokumenterede
371 beståede Python-tests og 3 skips, samt lokal rigtig TLS: 3 ACK med cirka
30 sekunders interval og Stop uden nye beacons efter 35 sekunder. Den udførte
ikke brugerens Master/Slave-VM-test. En overdragelse er ikke testbevis.

Der findes kun lokal Master CLI til den faste syntetiske `p11-live-lab`-operation
(3 beacons, 30 sekunder, højst 90 sekunder). Hverken P01–P11/scenariefjernstart
eller multi-agent findes. De eksisterende webvisninger bruger TLS og labgrænser,
ikke autentificerede webadministratorer. Agent-/enrollment-tokens er ikke admin.

Denne ændring leverer derfor kun en opt-in loginforudsætning og tydelig blokering:

* `/master/admin`: separat loginvalideringsside; kun loaded Master og HTTPS.
* `/api/master/admin/session`: POST login, GET session, DELETE logout.
* Root opretter en separat tilfældig 256-bit administratornøgle. Kun SHA256-hash
  gemmes i en root-ejet 0700-mappe og en almindelig 0600-fil uden links.
  Der er ingen standardnøgle, automatisk aktivering eller genbrug af Agent-token.
* Opaque sessioncookie: Secure, HttpOnly, SameSite=Strict, begrænset sti,
  15 minutters absolut udløb. Sessioner og CSRF-token ligger kun i proceshukommelsen.
  Intet credential i URL, browserlager eller API-svar. POST udskifter gammel session.
* Eksakt root-konfigureret HTTPS-origin og Host; ingen CORS. Origin kræves ved
  login/logout; logout kræver også CSRF-token. Bounded JSON, ingen queryparametre,
  ingen dublerede JSON-felter. Alle svar er no-store; siden har restriktiv CSP.
* Globalt højst 120 sessionsrequests/minut og 5 loginforsøg/minut, uafhængigt af
  klient-IP/forwarded-IP. Højst 16 samtidige sessioner. Ingen lockout nulstilles
  ved succes. Grænserne deles mellem tråde, men ikke mellem processer.
* Manglende/utryg nøglefil giver 503. Fjernelse/rotation tilbagekalder sessioner
  ved næste request; procesgenstart tilbagekalder alle sessioner.

**Ingen web-start/stop/status/historik-ruter til jobs er installeret**, heller ikke
efter login. `web_job_control=false`. Der er ingen jobvalg, startknap eller Stop,
der giver indtryk af en funktion, som ikke er tilgængelig.

## Blokering før aktivering af jobkontrol

Loginvalidering giver i denne version ingen jobautorisation og beskytter ikke
platformens eksisterende lokale run/update-API'er. Den skal ikke markedsføres
som et fuldt sikret administrationsinterface. Ingen af de eksisterende
Agent-, Receiver-, rapport-, ZTD-, heartbeat- eller eksekveringsruter ændres.

Før jobautoritet kobles på, kræves dokumenteret deploymentkontrol af HTTPS,
proxy-tillidsgrænsen, sessiontilbagekaldelse og isolation fra det eksisterende
webinterfaces privilegerede lokale handlinger. Backend accepterer kun TLS-header
fra loopback; den eksisterende port 8082 skal fortsat bindes til loopback og må
ikke eksponeres. Lokal adgang til denne proxygrænse er ikke en ny adminidentitet.
Der skal vælges en beskyttet adminflade/procesgrænse før privilegerede jobruter
bygges. En grøn loginfixture validerer ikke denne deploymentgrænse.

Kun én webproces understøttes af forudsætningen. Ved flere workers kræves delt,
privat session-/ratelager før integration. Global begrænsning kan give kortvarig
login-DoS; den må ikke erstattes med tillid til vilkårlige IP-headere. En delt
root-udstedt nøgle giver ikke personligt revisionsspor eller MFA.

## Master først, Slave derefter

Kør først efter merge; `mrnobody update` henter main, ikke feature-branchen.
Gem backup af programfiler og den aktive jobunit. Bevar registry, Agent-ID,
credentials og workerjournal; slet dem ikke ved rollback eller frisk installation.

1. Stop en eksisterende jobworker på Slave: `sudo systemctl stop mrnobody-agent-jobs`.
2. **Master:** `sudo mrnobody update`, derefter
   `sudo systemctl restart nordic-incident-web` og
   `sudo systemctl status nordic-incident-web --no-pager`.
3. **Slave:** `sudo mrnobody update`. Kontroller, at Master-URL bruger HTTPS og
   matcher certifikatets SAN; CA skal være betroet via eksisterende `ca_file` i
   `/etc/mrnobody/agent.json` eller systemets tillidslager. Ingen `-k`, HTTP eller
   deaktiveret verifikation. Det tidligere `http://10.134.71.3` er ikke tilstrækkeligt.
4. Genstart heartbeat: `sudo systemctl restart mrnobody-agent`. Bekræft samme
   Agent-ID online på Master. Online beviser ikke aktiv jobworker.
5. Installer jobunit og start den eksplicit på Slave:

```sh
sudo install -m 0644 /opt/nordic-attack/systemd/mrnobody-agent-jobs.service /etc/systemd/system/mrnobody-agent-jobs.service
sudo systemctl daemon-reload
sudo systemctl enable --now mrnobody-agent-jobs.service
sudo systemctl status mrnobody-agent-jobs.service --no-pager
```

Updateren distribuerer unitfilen, men vedligeholder endnu ikke den aktive kopi.
Frisk installation distribuerer loginfilerne; den opretter ingen adminnøgle og
starter ikke automatisk jobworkeren. Ingen indgående Slave-port kræves.

## Kontrolleret loginvalidering på Master

Brug det faktiske betroede HTTPS-origin uden afsluttende slash, fx
`https://master.lab`. Opret kun fra en privat lokal root-terminal; output er den
hemmelige nøgle, som skal gemmes sikkert og ikke indsættes i chats, logs, shell-
argumenter eller screenshots:

```sh
sudo python3 /opt/nordic-attack/web/master_admin.py provision --origin https://master.lab
```

Åbn `/master/admin` via netop dette origin og indtast nøglen. Kontroller login,
refresh, logout og at jobkontrol stadig er blokeret. Forkert nøgle og Agent-token
skal afvises. Test HTTP, forkert Host/Origin, manglende CSRF ved logout, 15 minutters
udløb og rategrænser i isoleret lab. Kontrollér proxykonfiguration og firewall;
port 8082 må ikke kunne nås fra en anden VM. Certifikatet skal valideres normalt.

Tilbagekald nøgle og alle sessioner ved at fjerne præcis credentialfilen:

```sh
sudo rm -- /etc/mrnobody/web-admin/credential.json
```

Næste sessionsrequest skal give 503. Kør provision igen for rotation og test at
en gammel cookie afvises. En genstart skal også kræve nyt login. Updateren må
ikke overskrive `/etc/mrnobody/web-admin`. Der er ingen nøgle i repositoryet.

## P11-labtest indtil webjobkontrol er godkendt

Brug én registreret online Agent og den eksisterende lokale CLI:

```sh
sudo python3 /opt/nordic-attack/web/master_jobs.py start AGENT_ID lab-s2-001
sudo python3 /opt/nordic-attack/web/master_jobs.py status MRN-job-JOBHEX
sudo python3 /opt/nordic-attack/web/master_jobs.py stop MRN-job-JOBHEX
```

Erstat placeholders med det faktiske ID. Gentag samme request-key: samme job-ID,
ingen dobbeltkørsel. Et queued job kan stoppes før levering. Lad et separat job
fuldføre: præcis tre bekræftede Receiver-beacons med job-ID som `campaign_id`,
derefter `succeeded`. I Master > Receiver filtreres Agent-ID og campaign-ID;
GET `/api/master/receiver/events?agent_id=AGENT_ID&campaign_id=MRN-job-JOBHEX`
viser evidensen over eksisterende lab-HTTPS-adgang. Dette job producerer endnu
ikke en selvstændig almindelig campaign-rapport.

Start et nyt job, stop efter første ACK, afvent `stopped`, vent mindst 35 sekunder,
og kontrollér uændret antal events. Aktivt Stop er en anmodning indtil terminal
status; deadlinefejl beviser ikke trafikantal. Offline/uregistreret/spærret Agent
skal afvises. Test worker-/netværksafbrydelse uden replay og gentag baseline for
ZTD, heartbeat, Receiver, P06/P11 DNS/Live Lab og Full Campaign. Bevar workerens
journal ved alle genstarter. De komplette eksisterende fejlsemantikker står i
`docs/master-remote-sprint1.md`.

Disse VM-kontroller er udestående. Lokale fixtures er ikke VM-/NAT-/systemd-bevis.
