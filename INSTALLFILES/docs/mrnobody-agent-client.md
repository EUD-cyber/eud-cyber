# MrNobody Lab Mode: automatisk Master og Slave

Lab Mode kræver ingen manuel nøgle, tokenoverførsel, parringskommando,
aktiveringslink eller web-login. Alle, der kan åbne en Master, kan styre dens
registrerede Slaves. Der er ingen elev-/læreropdeling på den enkelte Master.
Se [installations- og adgangsmodellen](../TESTFILES/ATTACKER-V2/docs/lab-access-preinstall.md).

Installationsflowet skriver den valgte rolle og Master-URL. Slave opretter
/etc/mrnobody/agent.json atomisk med mode 0600, et tilfældigt UUID-baseret
Agent-ID og et individuelt token. Første kontakt til en eksplicit Lab Mode
Master binder automatisk ID/token. Gentagen registrering kan ikke ændre en
eksisterende binding eller genaktivere en spærret identitet. Master gemmer
tokenets hash. Heartbeat, jobpolling, P06/P11 og Receiver kontrollerer bindingen.

Kilde-IP bruges ikke som agentidentitet. Flere Slaves bag samme NAT har hver
deres identitet. Slaven kontakter den konfigurerede Master udad. IP/DNS og
oversatte porte understøttes. Master-adressen skal være kendt af deployment-
flowet og kunne nås; der indføres ikke discovery på tværs af NAT.

Genstart, bootstrap og update genbruger den eksisterende private identitetsfil.
En ugyldig fil overskrives ikke automatisk. Nye Slaves skal have deres egen
identitet; kloning af en allerede startet Slave kopierer ellers identiteten.

mrnobody-agent.service håndterer registrering og heartbeat. Lab Mode aktiverer
også den afgrænsede P11 job-worker. Online betyder heartbeatkontakt; Receiver
viser modtaget øvelsestrafik. Master/Standalone aktiverer ikke agentservicen.
Protected mode bevarer eksplicit Master-udstedt parring og HTTPS-validering.

Valgfrie fejlsøgningskommandoer, ikke manuelle installationstrin:

    mrnobody lab-status
    systemctl status mrnobody-agent mrnobody-agent-jobs
    sudo python3 /opt/nordic-attack/web/agent_client.py --check

Opdatering bevarer deployment.conf, agent.json, registry og jobjournal.
