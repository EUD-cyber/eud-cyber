# MrNobody agent: udgående identitet og heartbeat

Agenten forbinder ud gennem NAT. Den åbner ingen lytteport og udfører ikke jobs
eller filoverførsel. Nye installationer bruger HTTP mellem Master og Slave på
det interne labnet. MrNobody-websiden og registry-oversigten beholder HTTPS.
HTTP sender agenttoken ukrypteret. Brug forbindelsen på et betroet, isoleret
labnet; nøglefiler overføres fortsat sikkert via SSH/SCP.

## 1. Udsted nøgle på Master

Ny installation: vælg Master og Slave i Single VM, eller behold agentrollen i
Big/Mini/Custom. Ingen nøgle indbygges i Cloud-init. En gyldig agent får nu
systemd-unit installeret, men afventer eksplicit parring og aktivering.
Master og Standalone får ikke agentservicen installeret af dette flow.

Eksisterende installation: kør `sudo mrnobody update` på Master og Slave.
Hvis den gamle updater henter den nye updater for første gang, køres kommandoen
én gang mere på Slave; den nye kode reparerer også servicen uden filændringer.
En allerede aktiv agent genstartes ved agentkodeændringer. En inaktiv agent
aktiveres aldrig automatisk. Roller, `/etc/mrnobody/agent.json`, deployment.conf
og `/var/lib/mrnobody/master/registry.sqlite3` bevares.
Den nye updater skriver placeringen af en bevaret rollback-backup under
`/var/backups/mrnobody-update.*`. En gammel updater beholder sin gamle
backupadfærd ved første kørsel. Tag derfor VM-snapshot før den første opdatering.

Kør som root på den kørende Master (ét unikt ID pr. Slave):

    (umask 077; set -o noclobber; python3 /opt/nordic-attack/web/master_registry.py issue lab1-mrnobody > /root/lab1-agent.json)

Kontrollér kommandoens succes før overførsel. Master gemmer kun tokenets hash.
Et eksisterende ID overskrives ikke. Udsted ikke samme ID igen; brug et nyt ID
og spær det gamle, hvis den oprindelige nøgle er mistet.

Overfør JSON-filen til `/root/lab1-agent.json` på den tilsvarende Slave via
SSH/SCP med verificeret SSH-værtsnøgle eller en anden betroet administratorkanal.
Del aldrig token i chat, Git, kommandolinjeargumenter eller Cloud-init-log.
Filen skal være ejet af root og have mode 600 på Slave. Fx som root på Master:

    scp /root/lab1-agent.json root@SLAVE_IP:/root/lab1-agent.json

Er root-SSH ikke tilgængeligt, benyttes den eksisterende sikre administrationskanal.
HTTP-forbindelsen kræver ingen CA-fil. Masterens private TLS-nøgle må aldrig overføres.

## 2. HTTP mellem Master og Slave

Single VM-menuen spørger Slave om Master-IP/værtsnavn og valgfri port.
Den gemmer `http://...` og aktiverer lab-HTTP uden spørgsmål om protokol eller CA.
En ny Master får også lab-HTTP aktiveret. Slave og Standalone spørger altid om
labnummer og bruger første ledige VMID i intervallet lab × 1000 til +999.
Master spørger i stedet om et VMID og kontrollerer hele clusteret for kollisioner;
kontrollen gentages umiddelbart før oprettelse.

Big/Mini/Custom beholder agentrollen. Den fælles Big/Mini-renderer tillader HTTP
og sætter lab-HTTP på nye agenter. Ingen nøgle genereres på Slave eller indbygges
i installationsloggen. Standalone får ingen Master-forbindelse.

Eksisterende installationer bevarer deres valgte transport ved update.
For at skifte en eksisterende installation til HTTP redigeres
`/etc/mrnobody/deployment.conf`. Bevar rollen og de øvrige indstillinger;
tilføj eller erstat flaget, så det kun forekommer én gang.

På Master:

    MRNOBODY_ROLE="master"
    MRNOBODY_MASTER_URL=""
    MRNOBODY_LAB_HTTP="1"

På Slave (tilpas adressen):

    MRNOBODY_ROLE="agent"
    MRNOBODY_MASTER_URL="http://10.134.71.3"
    MRNOBODY_LAB_HTTP="1"

Genstart `nordic-incident-web` på Master efter ændring af indstillingerne.
På en allerede parret Slave genstartes `mrnobody-agent` efter ændring af URL'en.
En uparret Slave følger trin 3. En eksisterende agentidentitet skal ikke udstedes
igen. Ingen CA-fil eller certifikatændring er nødvendig for HTTP-forbindelsen.

Kun `/api/master/agents/register` og `/api/master/agents/heartbeat` er åbne på HTTP.
Webside, Settings, registry-listen og alle andre HTTP-stier omdirigerer fortsat
til HTTPS. Der er ingen automatisk protokolfallback, og en tidligere eksplicit
HTTPS-konfiguration beholder fuld certifikatvalidering.

## 3. Kontrol og eksplicit aktivering

Disse kommandoer køres som root på agenten efter sikker overførsel af nøglefilen:

    chmod 600 /root/lab1-agent.json
    python3 /opt/nordic-attack/web/agent_client.py --pair /root/lab1-agent.json
    systemctl enable --now mrnobody-agent.service

    python3 /opt/nordic-attack/web/agent_client.py --check
    systemctl status mrnobody-agent.service --no-pager

`--pair` kræver gyldig agentrolle og Master-URL med lab-HTTP aktiveret. Den validerer
den private Master-udstedte fil, registrerer sig og sender heartbeat. Først efter succes
gemmes identiteten atomisk som `/etc/mrnobody/agent.json` med mode 600.
En eksisterende identitet overskrives aldrig. Forkert token, deaktiveret HTTP
på Master eller utilgængelig Master efterlader ingen ny lokal identitet;
ret årsagen og gentag parringen med den samme udstedte fil.
Aktivering er et separat eksplicit trin. `--check` validerer lokalt uden netværk;
`--once` kan fortsat bruges til én registrering og heartbeat.

Kontrollér derefter på Master:

    python3 /opt/nordic-attack/web/master_registry.py list

Master skal vise online og en fremrykkende last_seen_at efter mindst 30 sekunder.
GET `/api/master/agents` findes på den opdaterede Master over HTTPS. Hvis en ældre
installation stadig giver 404, kontrollér Master-rollen og genstart webservicen
efter update. Endpointet kan vise en tom liste før første udstedelse.
Fjern de midlertidige JSON-kopier fra begge VM'er efter bekræftet succes; behold
agentens `/etc/mrnobody/agent.json`. Stop med
`systemctl disable --now mrnobody-agent`. Spær en nøgle på Master med
`python3 /opt/nordic-attack/web/master_registry.py revoke lab1-mrnobody`.
Registry er driftsdata uden for installationsmappen og ændres ikke af updateren.

## Drift og afgrænsning

Heartbeats sendes hvert 30. sekund. Netværksfejl giver eksponentiel ventetid
med jitter, højst 60 sekunder, og ny registrering efter genforbindelse.
Spærrede/forkerte nøgler, forkert protokol og certifikatfejl stopper klienten;
systemd genstarter ikke disse permanente fejl. Loggen indeholder ikke nøglen.

Settings viser den valgte transport. Forbindelsesstatus er ikke målt af
webservicen; Masterens registry-CLI viser den seneste agentkontakt.
Default Big/Mini har fortsat ingen automatisk aktiveret agentforbindelse.
