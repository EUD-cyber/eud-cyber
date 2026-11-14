# MrNobody lab ZTD: Master og Slave

Single VM -> MrNobody -> Slave kræver kun Master-adressen ud over de almindelige
VM-valg. Nye Master/Slave-installationer bruger lab HTTP. Big/Mini/Custom beholder
deres agentrolle og bruger samme bootstrap, når en Master-URL er konfigureret.
Standalone har ingen Master-forbindelse. Master/Standalone installerer eller
aktiverer aldrig agentservicen gennem dette flow; unitens ExecCondition afviser
også en gammel agent-unit, hvis rollen senere ændres.

## Automatisk installation

Cloud-init opretter `/etc/mrnobody/agent.json` lokalt med mode 600, et tilfældigt
UUID-baseret Agent-ID og et individuelt tilfældigt 256-bit token. Der er ingen
fælles statisk nøgle, manuel parring eller krav om forbindelse til Master under
bootstrap. Identiteten publiceres atomisk før første netværkskontakt. Gentagen
bootstrap, genstart og update genbruger filen; en ugyldig eksisterende fil
overskrives aldrig. Klon ikke en allerede bootstrappet Slave som en ny agent.

Installationen aktiverer og starter `mrnobody-agent.service`. Agenten forbinder
udad gennem NAT og registrerer sig via `/api/master/agents/register`. Master
gemmer kun tokenets hash og bruger Agent-ID som nøgle, aldrig kilde-IP. Flere
Slaves bag samme NAT bliver derfor individuelle agenter. Et mistet svar kan
trygt gentages med samme ID/token; et eksisterende ID med et andet token eller
en spærret identitet bliver afvist.

Automatisk enrollment kræver `MRNOBODY_LAB_HTTP="1"` på Master og en kildeadresse
inden for RFC1918, IPv6 ULA eller loopback. Kun den lokale nginx må levere
X-Real-IP, som nginx overskriver med forbindelsens faktiske kildeadresse.
Offentlige adresser kan ikke automatisk enrolles; behold labbet isoleret og
uden internet-portforwarding. Dette er lab-adgang, ikke et internet-login.
Allerede udstedte credentials kan fortsat bruge det eksisterende autentificerede
registreringsflow. HTTPS-konfiguration beholder certifikatvalidering.

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

1. Installer eller opdater Master og Slave med ovenstående roller og lab-flag.
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
websiden bruger fortsat HTTPS; kun de to eksakte register/heartbeat-stier tillader
lab HTTP. Settings viser konfiguration, mens registry-listen viser faktisk kontakt.

## Valgfri manuel HTTPS-parring

Uden lab-mode kræves fortsat Master-udstedte credentials:
`sudo python3 /opt/nordic-attack/web/master_registry.py issue AGENT_ID` på Master.
Overfør JSON privat til Slave, sæt mode 600, og brug
`sudo python3 /opt/nordic-attack/web/agent_client.py --pair PRIVATE_JSON --ca-file CA_PEM`.
Aktiver derefter agentservicen. Behold Masterens private TLS-nøgle på Master.
En eksisterende identitet erstattes aldrig. Spærring udføres på Master med
`sudo python3 /opt/nordic-attack/web/master_registry.py revoke AGENT_ID`.
