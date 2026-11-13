# Fejlsøgning af Master/agent

Start med [agentopsætningen](mrnobody-agent-client.md).
[Elevøvelsen](mrnobody-transport-lab.md) beskriver en manuel trafiktest.
Disse checks udføres på allerede installerede lab-VM'er.

## Lokal konfiguration før netværk

På agenten:

    python3 /opt/nordic-attack/web/agent_client.py --check

Exitkode 0 betyder, at lokal konfiguration og trust kan indlæses; den beviser
ikke forbindelse til Master. Exitkode 2 betyder en permanent fejl.
Kontrollér agentrolle, udfyldt Master-URL og privat root-ejet agent.json
(mode 0600). JSON skal have agent_id og token; brug ikke ekstra felter
til egne noter. CA-filen skal være en eksisterende absolut sti.

HTTP kræver både http://-URL og LAB_HTTP="1" på agenten.
HTTPS bevarer altid certifikatvalidering, også når LAB_HTTP er sat.
Værtsnavn/IP i URL skal passe til certifikatet. Kopiér kun det offentlige
tillidscertifikat, aldrig Masterens private nøgle.

## Forbindelse og serverrespons

Kør --once for én registrering og ét heartbeat. Exitkode 0 betyder begge
requests blev accepteret; 1 er en midlertidig fejl; 2 kræver rettelse.
Klienten følger ikke redirects og skifter ikke automatisk protokol.

| Observation | Kontrol |
| --- | --- |
| Ingen forbindelse eller timeout | DNS, valgt port, agentens udgående adgang, NAT og Masterens nginx. |
| TLS-fejl | Certifikatets navn, gyldighed, VM'ernes ur og agentens CA-tillid. |
| 401 | Agent-ID og tilhørende nøgle; er identiteten spærret? |
| 403 over HTTP | Masterens LAB_HTTP skal være "1"; genstart webservicen efter ændring. |
| 404 | Gyldig masterrolle og korrekt URL til de præcise endpoints; ugyldig deployment-konfiguration skjuler API'et. |
| 409 heartbeat | Registrering kræves; baggrundsklienten registrerer igen. |
| 503 | Masterens register kan ikke læses; udsted første identitet via CLI, hvis databasen endnu ikke findes. Kontrollér også rettigheder og disk. |
| Redirect | Forkert URL/proxy; agenten afviser redirects. |
| Settings viser Not monitored | Dette er forventet: webservicen måler ikke agentforbindelsen. Brug Masterens registry-CLI. |

Fejl kan også komme fra nginx eller anden proxy; en HTML-fejlside er ikke
et gyldigt agentprotokolsvar. Den faktiske HTTP-status og proxylog hjælper
med at skelne routingfejl fra backendafvisning.

## Service og status

På agenten:

    systemctl status mrnobody-agent --no-pager
    journalctl -u mrnobody-agent -n 50 --no-pager

Servicen leveres inaktiv og skal aktiveres eksplicit. Hvis unit ikke findes,
følg aktiveringskommandoen i agentopsætningen. Permanent fejl/exitkode 2
genstartes ikke automatisk. Ret årsagen og kør systemctl restart mrnobody-agent.
Efter deployment-ændringer på Master kræves restart af nordic-incident-web.
Agenten indlæser ændringer ved genstart; web-Settings kræver også webrestart.

På Master:

    python3 /opt/nordic-attack/web/master_registry.py list

pending betyder udstedt men endnu ikke registreret. online betyder kontakt
inden for 90 sekunder; offline betyder længere tid uden kontakt.
revoked betyder spærret. Dette er tilstedeværelse, ikke kontrol af agentens
øvrige funktioner. En mistet/spærret nøgle erstattes med et nyt agent-ID;
slet ikke databasen for at genbruge ID'et.

Del kun redigerede logs. HTTP-captures indeholder bearer-nøglen, selv om
agentens egne statuslogs ikke udskriver den.
