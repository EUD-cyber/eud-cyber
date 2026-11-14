# MrNobody agent: udgående identitet og heartbeat

Agenten forbinder ud gennem NAT. Den åbner ingen lytteport og udfører ikke jobs
eller filoverførsel. HTTPS er standard; HTTP er et eksplicit undervisningsvalg.

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
Kopiér også det offentlige CA-/tillidscertifikat via den betroede kanal ved intern
CA eller selvsigneret TLS. Masterens private TLS-nøgle må aldrig overføres.

## 2. Vælg transport efter installation

Single VM-menuens slavevalg spørger nu om Master-IP/værtsnavn og HTTP/HTTPS
og gemmer valget i /etc/mrnobody/deployment.conf. Standalone spørger ikke om Master.
Big/Mini/Custom beholder agentrollen. Menuen udsteder ingen nøgle og aktiverer ikke
agentservicen; følg nøgle-, tillids- og aktiveringstrinnene her.
Eksisterende VM'er kan fortsat ændres efter installation. Bevar filens rolle
og angiv Master-URL på agenten.

HTTPS på agenten:

    MRNOBODY_ROLE="agent"
    MRNOBODY_MASTER_URL="https://master.lab.example"
    MRNOBODY_LAB_HTTP="0"

Master beholder rolle master og MRNOBODY_LAB_HTTP="0" som standard.
Ved intern CA eller selvsigneret certifikat tilføjes en absolut sti til et
offentligt CA-/tillidscertifikat i agent.json, fx:

    "ca_file": "/etc/mrnobody/master-ca.pem"

Masterens certifikat skal matche URL'ens DNS-navn eller IP. Det eksisterende
standardcertifikat med CN=incidentvm passer ikke automatisk til et nyt navn.
Der findes ingen mulighed for at ignorere certifikatfejl i HTTPS-klienten.
Brug et CA-udstedt certifikat med korrekt subjectAltName, eller klargør et
selvsigneret certifikat med korrekt DNS-/IP-SAN på Master først. Til et isoleret
lab med Master-IP 10.134.71.3 kan følgende køres som root på Master, før parring.
Tilpas IP'en, og behold backupmappen, hvis certifikatet skal rulles tilbage:

    backup=$(mktemp -d /var/backups/mrnobody-tls.XXXXXXXX)
    cp -a /etc/nordic-incident/tls/incident.crt /etc/nordic-incident/tls/incident.key "$backup/"
    openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
      -subj '/CN=10.134.71.3' -addext 'subjectAltName=IP:10.134.71.3' \
      -keyout "$backup/new.key" -out "$backup/new.crt"
    install -m 0600 "$backup/new.key" /etc/nordic-incident/tls/incident.key
    install -m 0644 "$backup/new.crt" /etc/nordic-incident/tls/incident.crt
    nginx -t && systemctl reload nginx

Hvis kontrollen fejler, gendannes incident.crt og incident.key fra backupmappen
før reload. Eksisterende agenter skal have opdateret tillid ved certifikatskift.
Overfør kun `incident.crt` til `/etc/mrnobody/master-ca.pem` på Slave via den
betroede SSH-kanal. Par aldrig mod et tilfældigt hentet, ubekræftet certifikat.
Masterens private TLS-nøgle skal ikke kopieres til agenten.

### HTTP til trafikøvelser

Sæt MRNOBODY_LAB_HTTP="1" i deployment.conf på både Master og agent.
Agentens URL vælges eksplicit som http://master.lab.example. På Master er
MRNOBODY_MASTER_URL fortsat tom; serverflaget tillader kun registrering og heartbeat
over HTTP. HTTPS fungerer stadig, og HTTPS-validering slås ikke fra af flaget.

HTTP viser Authorization-nøglen og JSON-payload i capture-trafikken. Brug
særskilte øvelsesnøgler, og spær dem bagefter med registry-CLI'ens revoke.
UI og øvrige HTTP-stier beholder HTTPS-redirect. Der følges ingen redirects
eller automatisk fallback mellem protokollerne.

Efter ændring af Masterens deployment.conf genstartes nordic-incident-web.
På agenten genstartes mrnobody-agent efter konfigurationsændringer; genstart
også webservicen, hvis Settings skal læse de nye konfigurationsværdier.

## 3. Kontrol og eksplicit aktivering

Disse kommandoer køres som root på agenten efter overførsel af nøgle og tillid:

    chmod 600 /root/lab1-agent.json
    python3 /opt/nordic-attack/web/agent_client.py --pair /root/lab1-agent.json --ca-file /etc/mrnobody/master-ca.pem
    systemctl enable --now mrnobody-agent.service

    python3 /opt/nordic-attack/web/agent_client.py --check
    systemctl status mrnobody-agent.service --no-pager

Udelad --ca-file ved et certifikat, der allerede er betroet af operativsystemet.
`--pair` kræver gyldig agentrolle, Master-URL og HTTPS, validerer den private
Master-udstedte fil, registrerer sig og sender heartbeat. Først efter succes
gemmes identiteten atomisk som `/etc/mrnobody/agent.json` med mode 600.
En eksisterende identitet overskrives aldrig. Forkert token, manglende CA,
certifikat/navnefejl eller utilgængelig Master efterlader ingen ny lokal identitet;
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
