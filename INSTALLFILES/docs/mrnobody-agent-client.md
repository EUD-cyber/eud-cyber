# MrNobody agent: udgående identitet og heartbeat

Agenten forbinder ud gennem NAT. Den åbner ingen lytteport og udfører ikke jobs
eller filoverførsel. HTTPS er standard; HTTP er et eksplicit undervisningsvalg.

## 1. Udsted nøgle på Master

Kør som root på den kørende Master:

    python3 /opt/nordic-attack/web/master_registry.py issue lab1-mrnobody

Gem JSON-responsen som /etc/mrnobody/agent.json på den tilhørende agent.
Agenten accepterer responsens agent_id, token, protocol_version og
heartbeat_interval. Valgfrie felter er name og ca_file.

Filen skal være ejet af servicebrugeren root og privat på Linux:

    chmod 600 /etc/mrnobody/agent.json

Agent-ID'et er knyttet til den ene nøgle. Læg ikke virkelige nøgler i Git.

## 2. Vælg transport efter installation

Single VM-menuens slavevalg spørger nu om Master-IP/værtsnavn og HTTP/HTTPS
og gemmer valget i /etc/mrnobody/deployment.conf. Standalone spørger ikke om Master.
Big/Mini-flowet ændres ikke. Menuen udsteder ingen nøgle og aktiverer ikke
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

Disse kommandoer køres på agenten:

    python3 /opt/nordic-attack/web/agent_client.py --check
    python3 /opt/nordic-attack/web/agent_client.py --once

Check validerer konfiguration og CA-fil uden netværk. Once registrerer agenten
og sender ét heartbeat. Masterens lokale registry-CLI viser herefter status.

Servicen leveres i /opt, men installeren aktiverer den ikke automatisk:

    systemctl enable --now /opt/nordic-attack/systemd/mrnobody-agent.service

Den bruger samme Python/backendkode som den eksisterende installation.
Efter en opdatering genstartes mrnobody-agent for at indlæse ændret Python-kode.
Stop den igen med systemctl disable --now mrnobody-agent.

## Drift og afgrænsning

Heartbeats sendes hvert 30. sekund. Netværksfejl giver eksponentiel ventetid
med jitter, højst 60 sekunder, og ny registrering efter genforbindelse.
Spærrede/forkerte nøgler, forkert protokol og certifikatfejl stopper klienten;
systemd genstarter ikke disse permanente fejl. Loggen indeholder ikke nøglen.

Settings viser den valgte transport. Forbindelsesstatus er ikke målt af
webservicen; Masterens registry-CLI viser den seneste agentkontakt.
Default Big/Mini har fortsat ingen automatisk aktiveret agentforbindelse.
