# MrNobody Master Passive C2/Exfil Receiver V1

Passivt API til syntetiske HTTP-testevents i et isoleret lab. Ingen kommandoer,
jobkø, callbacks, filer eller rigtig eksfiltration. Ingen P06/P11-integration
i receiver-transport V1. Dashboard V1 tilføjer kun læsning. De eksisterende phases, heartbeat og ZTD ændres ikke.

## API

`POST /api/master/receiver/events`, `Content-Type: application/json`,
`Authorization: Bearer <agentens eksisterende individuelle nøgle>`.

Kun en indlæst Master-konfiguration og private labkilder accepteres. HTTPS er
standard; HTTP kræver Masters eksisterende `lab_http`-opt-in. Nginx overskriver
forwarding-headere; API stoler kun på dem fra loopback. Begræns netværksadgangen
til labbet. Der åbnes ingen ny port eller service.

Eksempel på body (alle felter er obligatoriske; ekstra og duplikerede felter afvises):

```json
{
  "protocol_version": 1,
  "agent_id": "lab1-mrnobody",
  "campaign_id": "MRN-synthetic-test",
  "event_type": "http_test",
  "timestamp": "2026-11-15T12:00:00Z",
  "bytes": 128,
  "synthetic": true
}
```

Agenten skal allerede være registreret og ikke spærret. Godkendte lab-targets
bruger en separat udstedt og registreret testidentitet; del ikke Slavens nøgle.
Receiveren opretter ingen identiteter og registrerer ingen agents automatisk.

Body er højst 4096 bytes, også uden Content-Length. `agent_id` følger registryets
eksisterende format. `campaign_id` er 1–101 ASCII-bogstaver/tal/underscore/bindestreg
med bogstav/tal først. Eventtyper er `http_test`, `beacon`, `exfil`; de sidste to
er kun syntetiske labels. Timestamp er RFC3339 med sekunder, valgfrit 1–6 decimaler
og obligatorisk Z/UTC-offset; lagres normaliseret til UTC. `bytes` er et heltal
0–2147483647 (bool afvises): afsenderens **oplyste syntetiske datamængde**, ikke
målt netværksvolumen eller bevis for dataoverførsel. `synthetic` skal være `true`.
Campaign-ID er en korrelationslabel; receiveren starter eller verificerer ingen kampagne.

Efter vellykket commit returneres HTTP 200 med `protocol_version`, `accepted: true`,
unik `event_id`, `status: received` og serverens `received_at` (Unix-sekunder).
Modtagelsesstatus sættes af serveren; den kan ikke leveres af klienten.
400: ugyldigt input; 401: manglende/forkert/spærret nøgle; 403: transport/labgrænse;
404: forkert rolle/konfiguration; 405: forkert metode; 409: registrering mangler;
413: for stor body; 415: forkert medietype; 503: lagring utilgængelig.

## Persistent logning og begrænsninger

En additiv, lazy migration opretter `receiver_events` i den eksisterende private
`/var/lib/mrnobody/master/registry.sqlite3`. Tabellen gemmer `id`, `agent_id`,
`campaign_id`, `event_type`, `timestamp`, `bytes`, `received_at` og `status`.
Ingen rå payload eller nøgler lagres i eventloggen. Transaktionen skal være committed,
før der kvitteres. Registrering, heartbeat og rapporttabeller bevares; events ændrer
ikke `last_seen_at`. Loggen overlever procesgenstart og normale kodeopdateringer.

Kun accepterede events logges. Afviste requests får HTTP-fejl og bliver ikke
ground truth. Genforsøg giver en ny kvittering og en ny række: ingen deduplikering
i V1. Et tabt HTTP-svar kan derfor give dubletter. Dashboardet nedenfor viser kvitteringerne.
Ingen automatisk oprydning/retention endnu; hold testmængden begrænset og overvåg
diskplads. En storagefejl kvitteres aldrig som modtaget.

## Verifikation og roadmap

`python INSTALLFILES/tests/mrnobody/master_receiver.py -v` tester Flask og SQLite
uden at åbne en listener eller kontakte et lab. Omfatter adgangsgrænser, validering,
vedvarende logning, samtidige writes, fejlstatus og uændret heartbeat.

Der er endnu ingen fjernstart i den aktuelle Master Campaign Control. Roadmapet
bevarer **start/stop af enkelte attacks og hele scenarier fra Master** via
Agent-initieret polling. Det implementeres særskilt; receiveren udfører aldrig jobs.
P06/P11-integration og korrelation er senere trin.

Ingen deploy eller `mrnobody update` skal køres på en igangværende Big-installation
for at teste denne ændring. Faktisk nginx/NAT og genstart af Master-VM skal senere
verificeres separat i labbet.

## Receiver Dashboard V1

Receiver-fanen vises kun ved rolle=master og indlæst konfiguration. Genbruger
UI-styling og viser Agent-ID, Campaign-ID, event_type, event timestamp i UTC,
received_at i UTC, deklarerede syntetiske bytes og status. Events er kvitteringer,
ikke bevis for rigtig C2/eksfiltration eller målt trafik.

`GET /api/master/receiver/events` følger den eksisterende administrative
lab-HTTPS-grænse (nginx-adgang, ingen Agent Bearer-nøgle til UI-læsning).
HTTP afvises også med lab_http. Ikke-Master/ugyldig konfiguration: 404;
transport/labgrænse: 403; ugyldig query: 400; storagefejl: 503.
Svar har Cache-Control: no-store og kun de otte dokumenterede eventfelter.
Ingen nøgler, rå payloads eller agent credentials eksponeres.

Query: limit=1..100 (standard 50), before=positivt SQLite event-ID,
agent_id og campaign_id (eksakte, validerede ID'er). Ukendte/duplikerede
parametre afvises. Sortering er id DESC, dvs. nyeste serverkvittering først,
uafhængigt af afsenderens timestamp. Svaret er events samt next_before
(null når sidste side er nået). Næste kald bruger before=next_before. Ingen
ubegrænset liste eller OFFSET. Nye writes forskyder ikke ældre sider.

UI viser 50 pr. side med Older events og Latest events, samt Agent/Campaign-filtre.
Refresh sker hvert 30. sekund på den aktuelle side, når fanen/dokumentet er synligt.
Latest events går tilbage til nyeste side med de anvendte filtre. Ved fejl fjernes
gamle resultater, og der vises en retry-besked. Manglende database eller en ældre
database uden receiver-tabellen giver en tom liste uden initialisering/migration.
Læsningen bruger SQLite mode=ro og skriver aldrig. Ingen retention i dette trin.

Tests: `python INSTALLFILES/tests/mrnobody/receiver_dashboard.py -v` og
`node INSTALLFILES/tests/mrnobody/receiver_dashboard.cjs`. Browser-testen bruger
lokale mock-svar; ingen test kontakter VM eller udfører attacks.

Opdater kun Master med `sudo mrnobody update`, når installationen er færdig og
VM'en er klar til normal opdatering. Slave behøver ingen opdatering til dashboardet.
Ingen VM-genstart kræves af dette trin.
