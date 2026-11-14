# MrNobody Master: registrering og heartbeat, protokol 1

Denne pakke tilføjer kun identitet og tilstedeværelsesstatus i den eksisterende
backend. Agentklienten beskrives i mrnobody-agent-client.md. Jobkørsel og filoverførsel er endnu ikke implementeret.

## Operatør på Master VM

Efter opstart med gyldig master-rolle køres som root:

    python3 /opt/nordic-attack/web/master_registry.py issue lab1-mrnobody
    python3 /opt/nordic-attack/web/master_registry.py list
    python3 /opt/nordic-attack/web/master_registry.py revoke lab1-mrnobody

Issue skriver én JSON-respons med agent-ID og en tilfældig nøgle. Overfør nøglen
til den tilhørende agent via en betroet kanal; læg den ikke i Git eller logs.
Kun hash gemmes i /var/lib/mrnobody/master/registry.sqlite3. Den private
registermappe har mode 0700 og databasen 0600 på Linux. Registret overlever
geninstallation af /opt/nordic-attack.

Et eksisterende agent-ID overskrives ikke. En spærret nøgle afvises til både
registrering og heartbeat. Ny nøgle kræver i denne version et nyt agent-ID.

## Agent-API

Begge endpoints kræver Authorization: Bearer <agentens nøgle>. HTTPS er standard.
HTTP accepteres kun ved eksplicit MRNOBODY_LAB_HTTP=1 på Master; agentklienten
kræver samme opt-in. HTTP viser nøglen i capture-trafikken og er til labøvelser.

POST /api/master/agents/register:

    {"agent_id":"lab1-mrnobody","name":"lab1-MrNobody","protocol_version":1}

POST /api/master/agents/heartbeat:

    {"agent_id":"lab1-mrnobody","protocol_version":1}

Agenten skal registreres før første heartbeat. Gentagen registrering er
idempotent og bevarer det oprindelige registreringstidspunkt. Svaret angiver
30 sekunder som heartbeat-interval; status bliver offline efter mere end
90 sekunder uden kontakt. Tidsstempler er serverens Unix-tid, ikke agentens ur.

Kun disse JSON-felter accepteres; request-body er begrænset til 4096 bytes.
API'et returnerer aldrig agentnøgler eller nøglehashes. Uden lab-mode accepteres
kun operatørudstedte nøgler. Med eksplicit lab-mode kan private labadresser
automatisk registrere et nyt ID med en individuel persistent nøgle; se
[lab ZTD-guiden](mrnobody-agent-client.md). Eksisterende eller spærrede identiteter
kan ikke overskrives gennem automatisk registrering.

En manglende database giver 503 uden lab-enrollment; gyldig lab-registrering
initialiserer databasen automatisk.
Andre roller og ugyldig deployment-konfiguration giver 404.

## HTTPS og afgrænsning

X-Forwarded-Proto=https accepteres kun fra loopback, hvor den eksisterende
nginx-proxy overskriver headeren. Eksterne afsendere kan ikke bruge headeren
til at omgå standardkravet om HTTPS. Port 80 videresender kun de to præcise
agent-endpoints med X-Forwarded-Proto=http; backendflaget bestemmer, om HTTP
accepteres. Andre HTTP-stier beholder redirect til HTTPS. Fremtidig agentklient skal verificere Masterens
certifikat; loopback-undtagelsen i installationskontrollen bruges ikke her.

Autentifikationen gælder de to nye endpoints. Den ændrer ikke de eksisterende
UI-/execution-ruters adgangskontrol. Masterens administrationsflade skal fortsat
ligge bag labbets adgangsgrænse; offentlig administration kræver særskilt
adgangskontrol. Agents-fanen viser Master agents med agent-ID, navn, status og seneste kontakt.
Oversigten er read-only og opdateres med Refresh agents. Den vises kun på
Master. Ingen nøgler eller nøglehashes sendes til browseren. Agentklienten konfigureres og aktiveres
eksplicit og forbinder ud gennem NAT.

## Administrationsoversigt

GET /api/master/agents er en HTTPS-only læserute på den eksisterende
administrationsflade. Den følger samme labnet-adgangsgrænse som den øvrige UI;
den bruger ikke agentnøgler som administratorlogin. Lab-HTTP-flaget gælder registrering, heartbeat og rapportmetadata. Andre roller returnerer 404. En endnu ikke oprettet
database giver en tom oversigt uden at oprette filer. Registerfejl giver 503.
Online er seneste kontakt inden for 90 sekunder. Oversigten og den valgte
Agent-detaljevisning opdateres hvert 30. sekund, når fanen er synlig, samt med
Refresh agents. Klik View agent for at se ID, navn, status og seneste heartbeat;
Back to agents lukker detaljen. Pending og Revoked bevares som særskilte statusser.
Detaljen bruger samme GET-svar som listen og introducerer ingen nye API-ruter.
Ved registerfejl fjernes de viste data, indtil en opdatering lykkes.

Efter opdatering af runtime kræves genstart af nordic-incident-web og en
browsergenindlæsning. Big/Mini og installationsflowet ændres ikke.

Browserregressionstesten kan køres med Playwright og Chromium installeret:

    MRN_CHROME_PATH=/sti/til/chromium node INSTALLFILES/tests/mrnobody/master_overview.cjs

Alle browserens requests håndteres af test-fixtures; der kræves ingen kørende Master.

## Opdatering og manuel kontrol

Kør på Master og derefter på Slave:

    sudo mrnobody update

Updateren genstarter webservicen ved ændrede webfiler. Genindlæs Master-browseren
helt (Ctrl+F5), åbn Agents og klik View agent. Kontroller ID, navn, status og
seneste heartbeat. Lad fanen være synlig og kontroller, at kontaktens tidspunkt
opdateres. Uden kontakt i mere end 90 sekunder skal status blive Offline ved
næste opdatering. Updateren genstarter også en allerede aktiv Agent-service og genindlæser nginx.
Identitet og konfiguration bevares; der kræves ingen geninstallation eller ny parring.
VM-testen skal udføres i det eksisterende lab; browsertesten bruger fixtures.

## Rapportmetadata gennem udgående forbindelse

Agenten sender efter hver vellykket registrering/heartbeat en separat
autentificeret POST til `/api/master/agents/reports`. Heartbeat-payloaden og
protokolversion 1 er bevaret. NAT og OPNsense kræver ingen indgående åbning til
Slaven. HTTPS og eksisterende certifikatkontrol er standard; den eksakte
metadata-rute tillader også allerede konfigureret lab HTTP med individuel nøgle.

Master gemmer én atomisk erstattet metadataoversigt pr. autentificeret Agent i
en ekstra SQLite-tabel. Gentagne anmodninger er idempotente; tom oversigt fjerner
tidligere metadata. Synkronisering ændrer ikke heartbeat-tidspunkt eller status.
Eksisterende databaser kræver ingen manuel migration. Gamle Slaves fortsætter
med register/heartbeat. En ny Slave fortsætter heartbeat, hvis en gammel Master
afviser metadata-ruten, eller metadataoverførslen fejler; der forsøges igen efter
næste vellykkede kontakt. Ved fejl beholder Master senest modtagne oversigt og
dens synkroniseringstid. Det viste tidspunkt dokumenterer modtagelse, ikke at
rapportindhold er overført eller verificeret.

Afgrænsning:

- Højst 50 poster og 32768 bytes pr. POST; register/heartbeat beholder 4096 bytes.
- Kun rapport-ID, status, campaign/standalone_phase, phase-ID og start/sluttid.
  Metadata-ruten sender ingen lokale stier, output, credentials eller rapportindhold.
- Agenten undersøger højst 1000 lokale JSON-kandidater, sorteret efter filnavn
  inden for dette udsnit. Hver fil er højst 2 MiB; samlet læsebudget er 8 MiB
  pr. synkronisering. Oversigten er derfor et afgrænset udsnit, ikke et fuldt arkiv.
- Symlinks, ikke-regulære filer, ugyldige snapshots og forkert schema/ID springes
  over. Nye rapporter, rettelser og sletninger afspejles ved næste synkronisering
  inden for udsnittet. Der oprettes ingen rapporter af synkroniseringen.

Efter `sudo mrnobody update` først på Master og derefter på Slave: genindlæs
browseren med Ctrl+F5, åbn Agents → View agent, og vent på næste kontakt samt
fanens opdatering (normalt under et minut). Kontroller metadata mod en eksisterende
rapport på Slaven, både campaign og standalone_phase hvis de findes. Kontroller,
at heartbeat fortsat flytter sig. En tom oversigt vises særskilt fra en Slave,
der endnu ikke har synkroniseret. Ingen rapport skal køres for at teste overførslen.

## Rapportvisning og download

Efter metadata spørger Agenten via autentificeret POST til
`/api/master/agents/report-transfer` efter én manglende, afsluttet JSON-rapport.
Den læser kun `<kendt rapport-ID>.json` i `/opt/nordic-attack/reports` og uploader
højst én rapport pr. kontakt (normalt hvert 30. sekund). Ingen shellkommandoer,
vilkårlige filstier eller indgående Slave-forbindelser anvendes. Running-rapporter
venter på afslutning. Genforsøg og gamle Masters stopper ikke heartbeat.

Master gemmer rapportkopier i en ekstra SQLite-tabel i samme private registry.
Der bruges højst 50 aktuelle kopier á 2 MiB pr. Agent; HTTP-body er begrænset til
2 MiB + 4096 bytes. Kopier fjernes, når inventaret fjerner rapporten eller ændrer
dens metadata. Afsluttede snapshots med uændrede metadata behandles som uforanderlige;
indholdsændringer alene udløser ikke ny overførsel. Dette er et udsnit, ikke backup.
Kopier overlever genstart og update. Ingen credentials eller konfigurationsfiler ændres.

Agents → View agent viser **View report** og **Download JSON**, når kopien findes.
View report genbruger den eksisterende HTML-rapporteksport med escaping og en
scriptfri browserpolitik. JSON-download bruger den eksisterende filtrering af
følsomme felter og tekst før overførsel og igen før lagring på Master. Umarkerede
hemmeligheder i fri tekst kan ikke garanteres genkendt; rapporter skal kun indeholde
labdata. `X-Report-SHA256` er SHA256 af de præcise downloadbytes, ikke originalfilen
på Slaven. Begge browserfunktioner kræver HTTPS fra et privat labnet og følger
UI'ens eksisterende netværksbaserede adgangsmodel. Spærrede Agents kan ikke uploades
eller læses. HTTP-overførsel kræver eksisterende lab-opt-in, privat kildeadresse og
Agentens individuelle nøgle; HTTPS-certifikater verificeres fortsat.

Manuel kontrol: opdater Master først, derefter Slave med `sudo mrnobody update`.
Genindlæs Master med Ctrl+F5, og åbn Agents → View agent. Brug en eksisterende,
afsluttet rapport; ingen phase skal startes. Vent normalt 30–60 sekunder på første
kopi og længere for flere rapporter. Kontroller læsbar visning, JSON-download,
rapport-ID, og at heartbeat fortsætter. Kontroller efter Master-genstart, at kopien
stadig kan hentes. En gammel Slave viser metadata og ventestatus, indtil den opdateres.

Offline-tests: `python INSTALLFILES/tests/mrnobody/master_reports.py -v` samt
Agent-, registry- og Master-browserregressionerne. Den nye test indgår i CI.
Faktisk NAT/OPNsense, nginx-reload og VM-genstart skal stadig verificeres i labbet.

## Efterfølgende roadmap

Næste lille trin er read-only capability-discovery og jobstatus til Master Campaign
Control via Agent-initieret polling. Eksekvering skal forblive slået fra, indtil en
fast godkendt jobtype, labafgrænsning og statusforløb er testet.

Et vigtigt senere krav er start/stop af både individuelle phases og komplette
scenarier på én eller flere Slaves fra Master. Der er ingen ny fjernstart eller
fjernstyring i rapporttrinnet. P01–P11, standalone og ZTD-flowet er bevaret.
