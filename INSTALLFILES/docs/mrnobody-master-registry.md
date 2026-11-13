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
API'et returnerer aldrig agentnøgler eller nøglehashes. Der er ingen åben
selvtilmelding: kun operatørudstedte nøgler kan bruges.

En manglende database giver 503 og oprettes ikke af en HTTP-request.
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
adgangskontrol. Settings viser nu Master agents med agent-ID, navn, status og seneste kontakt.
Oversigten er read-only og opdateres med Refresh agents. Den vises kun på
Master. Ingen nøgler eller nøglehashes sendes til browseren. Agentklienten konfigureres og aktiveres
eksplicit og forbinder ud gennem NAT.

## Administrationsoversigt

GET /api/master/agents er en HTTPS-only læserute på den eksisterende
administrationsflade. Den følger samme labnet-adgangsgrænse som den øvrige UI;
den bruger ikke agentnøgler som administratorlogin. Lab-HTTP-flaget gælder kun
registrering og heartbeat. Andre roller returnerer 404. En endnu ikke oprettet
database giver en tom oversigt uden at oprette filer. Registerfejl giver 503.
Online er seneste kontakt inden for 90 sekunder; visningen opdateres manuelt.

Efter opdatering af runtime kræves genstart af nordic-incident-web og en
browsergenindlæsning. Big/Mini og installationsflowet ændres ikke.

Browserregressionstesten kan køres med Playwright og Chromium installeret:

    MRN_CHROME_PATH=/sti/til/chromium node INSTALLFILES/tests/mrnobody/master_overview.cjs

Alle browserens requests håndteres af test-fixtures; der kræves ingen kørende Master.
