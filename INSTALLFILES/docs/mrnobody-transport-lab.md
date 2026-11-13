# Elevøvelse: sammenlign HTTP og HTTPS

Dette er en manuel accepttest, ikke en allerede udført VM-test.
Brug arbejdsgrenens runtime på to lab-VM'er. Main har ikke disse funktioner.
Master oprettes via Single VM; Big/Mini/Custom bevarer agentrollen.
Installationsmenuen vælger endnu ikke HTTP: transport vælges efter installation.

## Forberedelse

Følg [agentopsætningen](mrnobody-agent-client.md) for en separat øvelsesidentitet,
privat agent.json og et betroet Master-certifikat, der matcher URL'ens navn/IP.
Begynd med HTTPS og MRNOBODY_LAB_HTTP="0" på begge maskiner.
Master har MRNOBODY_ROLE="master" og tom MRNOBODY_MASTER_URL;
agenten har MRNOBODY_ROLE="agent" og sin https://-Master-URL.
Brug en labforbindelse, hvor eleven kan observere agentens udgående trafik.
Capture på agentens netkort viser trafikken før NAT; capture ved Master kan
vise NAT-gatewayens kildeadresse. Agenten kræver ingen indgående portåbning.

## 1. HTTPS

Kør som root på agenten:

    python3 /opt/nordic-attack/web/agent_client.py --check

Start Wireshark-capture på det relevante netkort. Brug displayfilter
`ip.addr == <MASTER_IP> && tcp.port == 443`, og erstat <MASTER_IP> med IPv4-adressen.
Kør derefter:

    python3 /opt/nordic-attack/web/agent_client.py --once

Forvent "Registration and heartbeat accepted." og exitkode 0.
Kontrollér på Master:

    python3 /opt/nordic-attack/web/master_registry.py list

Agenten skal være online med last_seen_at. Uden TLS-dekryptering kan eleven
se forbindelsen og TLS-trafikken, men ikke Authorization-header eller JSON.
Bemærk hvilke metadata der stadig er synlige, fx IP-adresser og timing.

## 2. HTTP

Stop først en eventuelt kørende agentservice, så baggrundstrafik ikke forveksles
med one-shot-testen:

    systemctl stop mrnobody-agent

Sæt MRNOBODY_LAB_HTTP="1" på begge VM'er og agentens Master-URL til http://
med samme værtsnavn. Bevar de øvrige værdier. Genstart på Master:

    systemctl restart nordic-incident-web

Start en ny capture med displayfilter
`ip.addr == <MASTER_IP> && tcp.port == 80`. Kør --check og --once igen på agenten.
Forvent to POST-requests: /api/master/agents/register og
/api/master/agents/heartbeat. Brug Follow TCP Stream til at finde agent-ID,
JSON-felter og Authorization-header. Sammenlign med HTTPS-capturen.
HTTP afslører øvelsesnøglen; captures skal behandles som nøglemateriale.

## 3. Heartbeat og afslutning

Ved behov aktiveres den leverede service eksplicit efter agentopsætningen.
Se mindst to heartbeats med cirka 30 sekunders mellemrum.
Stop agentservicen og vent mere end 90 sekunder siden sidste kontakt:
Masterens list skal vise offline. Web-Settings må ikke bruges som bevis
for kontakt; den viser konfiguration, ikke målt forbindelsesstatus.

Spær øvelsesidentiteten på Master:

    python3 /opt/nordic-attack/web/master_registry.py revoke <AGENT_ID>

Kør --once med den gamle nøgle: forvent afvisning og exitkode 2.
Sæt begge LAB_HTTP-værdier til "0", gendan agentens https://-URL og genstart
Masterens webservice. En fortsat agentforbindelse kræver en ny identitet/nøgle
og gyldigt TLS-certifikat; genstart kun servicen efter disse er på plads.
Nye identiteter er nødvendige, fordi samme ID ikke kan genudstedes i denne version.

Gem resultatet som: version/commit, capturested, HTTP/HTTPS-resultat,
online/offline-resultat og tilbagekaldelsesresultat. Undlad token i rapporten.
Øvelsen ændrer ikke Big/Mini-installationsflowet.
