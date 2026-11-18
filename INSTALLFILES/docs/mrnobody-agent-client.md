# MrNobody lab ZTD: Master og Slave

**Installationsblokering:** Nye Slaves kræver nu en Master-udstedt parring.
Installeren opretter fortsat en lokal identitet, men har endnu ingen betroet
kanal til automatisk at udstede/installere parringsoplysninger. Geninstaller
ikke med forventning om fuld ZTD eller webadgang uden login. Se
[krav før geninstallation](../TESTFILES/ATTACKER-V2/docs/lab-access-preinstall.md).

Single VM -> MrNobody -> Slave kræver kun Master-adressen ud over de almindelige
VM-valg. Nye Master/Slave-installationer bruger lab HTTP. Big/Mini/Custom beholder
deres agentrolle og bruger samme bootstrap, når en Master-URL er konfigureret.
Standalone har ingen Master-forbindelse. Master/Standalone installerer eller
aktiverer aldrig agentservicen gennem dette flow; unitens ExecCondition afviser
også en gammel agent-unit, hvis rollen senere ændres.

## Automatisk installation

Cloud-init opretter `/etc/mrnobody/agent.json` lokalt med mode 600, et tilfældigt
UUID-baseret Agent-ID og et individuelt tilfældigt 256-bit token. Der er ingen
fælles statisk nøgle eller krav om forbindelse til Master under
bootstrap. Identiteten publiceres atomisk før første netværkskontakt. Gentagen
bootstrap, genstart og update genbruger filen; en ugyldig eksisterende fil
overskrives aldrig. Klon ikke en allerede bootstrappet Slave som en ny agent.

Installationen aktiverer og starter `mrnobody-agent.service`. Agenten forbinder
udad gennem NAT og forsøger registrering via `/api/master/agents/register`.
Det kræver en forudgående Master-udstedt parring; bootstrap alene er ikke nok. Master
gemmer kun tokenets hash og bruger Agent-ID som nøgle, aldrig kilde-IP. Flere
Slaves bag samme NAT bliver derfor individuelle agenter. Et mistet svar kan
trygt gentages med samme ID/token; et eksisterende ID med et andet token eller
en spærret identitet bliver afvist.

Automatisk enrollment med selvvalgt token er afvist. Hverken lab-flag,
kildeadresse, NAT eller identitetsheaders giver tilladelse til at oprette en
agent i Master-registret. Allerede udstedte credentials bruger det eksisterende
autentificerede registreringsflow. HTTPS beholder certifikatvalidering.

Agenten sender heartbeat cirka hvert 30. sekund. Netværksfejl og midlertidige
serverfejl giver retry med jitter og eksponentiel ventetid, højst 60 sekunder.
Efter genforbindelse registrerer den sig igen. Forkerte/spærrede credentials og
certifikatfejl stopper klienten med en forklaring i journalen. Der udføres ingen
jobs eller filoverførsel, og agenten åbner ingen lytteport.

## Eksisterende installationer

Kør `sudo mrnobody update` på Master og Slave. Kør den igen på Slave, hvis første
kørsel hentede selve den nye updater. Den nye updater reparerer også en manglende
eller disabled unit, når alle kodehashes allerede matcher. Den bevarer
`deployment.conf`, `agent.json` og `/var/lib/mrnobody/master/registry.sqlite3`.
En allerede aktiv agent genstartes ved agentkodeændringer.

Master-konfiguration i `/etc/mrnobody/deployment.conf`:

```sh
MRNOBODY_ROLE="master"
MRNOBODY_MASTER_URL=""
MRNOBODY_LAB_HTTP="1"
```

Slave-konfiguration (tilpas Master-adressen):

```sh
MRNOBODY_ROLE="agent"
MRNOBODY_MASTER_URL="http://10.134.71.3"
MRNOBODY_LAB_HTTP="1"
```

Bevar øvrige indstillinger og undgå dublerede linjer. Genstart
`nordic-incident-web` på Master efter konfigurationsændringer. Ved manuel
reparation på Slave kan `sudo python3 /opt/nordic-attack/web/agent_client.py
--bootstrap` køres uden netværk, efterfulgt af
`sudo systemctl enable --now mrnobody-agent.service`.

## Kort testguide i CyberLab

1. Afklar installationsblokeringen ovenfor, og provisionér en gyldig parring
   via en betroet kanal før denne testguide. Opdater eksisterende parrede
   installationer med ovenstående roller og lab-flag.
2. På Slave: `systemctl is-enabled mrnobody-agent` og
   `systemctl is-active mrnobody-agent` skal vise `enabled` og `active`.
   `sudo python3 /opt/nordic-attack/web/agent_client.py --check` viser ID,
   Master-URL og transport uden at afsløre token.
3. På Master: `curl -sk https://127.0.0.1/api/master/agents` skal vise Slave som
   `online`. Vent mindst 30 sekunder og kontrollér, at `last_seen_at` flytter sig.
4. Stop Master-webservicen, og genstart Slave. Den skal fortsat være aktiv og
   logge retry. Start Master igen; Slave skal blive online uden manuel handling.
5. Gem lokalt på Slave: `sudo sha256sum /etc/mrnobody/agent.json`. Genstart og
   kør `sudo mrnobody update`; kontrollér samme hash og samme Agent-ID bagefter.
   Del ikke filens indhold. Installer en anden Slave bag samme NAT og kontrollér
   to forskellige ID'er i Master-listen.
6. På Master/Standalone må agentservicen ikke være aktiv.

Fejlsøg med `journalctl -u mrnobody-agent -n 50 --no-pager`. Registry-listen og
websiden bruger fortsat HTTPS; de eksakte register/heartbeat/reports-stier tillader lab HTTP. Settings viser konfiguration, mens registry-listen viser faktisk kontakt.

## Valgfri manuel HTTPS-parring

Uden lab-mode kræves fortsat Master-udstedte credentials:
`sudo python3 /opt/nordic-attack/web/master_registry.py issue AGENT_ID` på Master.
Overfør JSON privat til Slave, sæt mode 600, og brug
`sudo python3 /opt/nordic-attack/web/agent_client.py --pair PRIVATE_JSON --ca-file CA_PEM`.
Aktiver derefter agentservicen. Behold Masterens private TLS-nøgle på Master.
En eksisterende identitet erstattes aldrig. Spærring udføres på Master med
`sudo python3 /opt/nordic-attack/web/master_registry.py revoke AGENT_ID`.

## Rapportmetadata i Master V2

Opdater først Master og derefter Slave med `sudo mrnobody update`.
En aktiv Agent-service genstartes af updateren; privat identitet og indstillinger
bevares. Efter næste kontakt sender Slaven en afgrænset metadataoversigt fra
eksisterende `/opt/nordic-attack/reports/*.json`. Masterens Agents → View agent
viser posterne og tidspunktet for seneste modtagelse. Genindlæs browseren helt.

Metadata sendes særskilt fra heartbeat, via samme udgående forbindelse og nøgle.
Fejl stopper ikke heartbeat. Gamle Slaves virker fortsat uden metadata; en ny
Slave kan fortsat holde kontakt med en gammel Master. Se
[registry-guiden](mrnobody-master-registry.md#rapportmetadata-gennem-udgående-forbindelse)
for felter, grænser og manuel kontrol. Afsluttede rapporter overføres nu én ad
gangen med Agent-initieret polling og upload af navngivne JSON-snapshots.
Master viser View report og Download JSON efter modtagelse. Eksisterende filtrering
af følsomme rapportdata genbruges; højst 2 MiB pr. rapport. Visning og download
kræver lab HTTPS. Identitet, ZTD og heartbeat er bevaret. Fjernstart af phases og
scenarier er endnu ikke implementeret. Se
[rapportguiden](mrnobody-master-registry.md#rapportvisning-og-download).
