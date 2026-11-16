# Master Remote Execution — Sprint 1

## Implementeret omfang

Udgangspunkt kontrolleret 15. november 2026: main `cd50d4e68275e66cbfd84ee8034ac0703edbc325`.
PR #107 er merget og tilføjede kun visning af manglende campaign-funktioner.

Dette trin tilføjer én operation, `p11-live-lab`, på én registreret Slave ad gangen.
Den bruger den eksisterende P11 Live Lab-beaconfunktion direkte: tre syntetiske
`MRN-EXERCISE-ONLY`-beacons til den konfigurerede Master med 30 sekunders interval,
højst 90 sekunders beaconaktivitet. Normalt færdig efter cirka 60 sekunder.
Succes kræver tre verificerede ACK'er. Der sendes ingen kommandoer, mål-IP'er,
stier, credentials eller scenarieparametre i jobbet. Der oprettes ingen
persistensartefakter på målmaskiner.

Master har lokal administrator-CLI til start/status/stop; der er ingen ny
webbaseret operatoradgang. Slaven har en separat, eksplicit aktiveret systemd-unit
til udgående polling. Den eksisterende heartbeat-service ændrer ikke adfærd og
aktiverer aldrig jobworkeren. Ingen indgående Slave-port eller NAT-portforwarding
er nødvendig. P01–P11 generelt, komplette scenarier og multi-agent campaigns er
fortsat ikke fjernstyrbare. Dashboardet viser dette samt den snævre pollingstøtte.

## Sikkerhed og fejlsemantik

- Kun verificeret HTTPS til jobs, også når installationens lab HTTP er aktiveret.
  Den eksisterende transport afviser redirects og miljøproxyer og validerer TLS.
- Jobbet bindes til Agent-ID og hash af det individuelle token ved oprettelsen.
  Udstedte, men ikke registrerede, offline og spærrede agenter afvises.
  Et heartbeat er ikke bevis på, at jobworkeren er aktiv.
- SQLite-transaktioner serialiserer køen; højst ét aktivt job globalt. Samme
  request-key returnerer samme job, også efter afslutning. En anden agent med
  samme key afvises. Maksimalt 10.000 beholdte job; ingen automatisk sletning,
  som kunne bryde idempotens.
- `queued -> delivered -> running -> succeeded/failed/stopped`. Terminale
  tilstande er uforanderlige. Succes før modtagelse/accept afvises. Stop af et
  queued job afslutter straks; stop af et aktivt job sætter `stop_requested`.
  En sen succes efter stop bliver `stopped`.
- Slavejournalen ligger privat i `/var/lib/mrnobody/agent-jobs/journal.sqlite3`.
  Job-ID gemmes før accept/aktivitet. En usikker `running`-post efter genstart
  bliver `failed`, aldrig genkørt. En mistet terminal kvittering gentages uden
  ny aktivitet. Linux fillås afviser en samtidig workerproces.
- Netværksfejl under kørsel annullerer beaconløkken; retry genkører ikke jobbet.
  Protokol-, token-, TLS- eller lagerfejl stopper workeren. Udløbne eller
  credentialændrede/spærrede jobs bliver `failed` ved næste databaseadgang.
  Jobfristen er 180 sekunder fra oprettelse; leverede jobs genudsendes kun med
  samme ID og bliver aldrig automatisk genkøet. Workerens lokale kørsel har
  desuden en 100-sekunders grænse.
- Stop observeres normalt ved næste polling efter højst to sekunder. En
  igangværende transport kan forsinke det med op til cirka ti sekunder. Stop er
  en anmodning, indtil status er terminal; en deadlinefejl beviser ikke præcis,
  hvor mange beacons der nåede frem. Kontrollér Receiver for faktisk trafik.
- Ingen shell, C2-tasking, målmaskine-cleanup, generisk faseadapter eller ny
  DNS-adfærd. Stop af denne operation standser kun dens syntetiske beacons.

## Opdatering og eksplicit aktivering

Brug et isoleret lab med korrekt Master-certifikat og et hostname/IP, der matcher
certifikatets SAN. Slaven skal stole på udstederen, eventuelt via eksisterende
`ca_file` i den private `/etc/mrnobody/agent.json`. Bevar Agent-ID og token.
Se også `INSTALLFILES/docs/mrnobody-agent-client.md` i repositoryet.

Master Receiver beholder sin eksisterende lab-netværksgrænse: P11-trafik skal ses
fra en tilladt lab-adresse. Brug lab-routing/NAT eller en privat labforbindelse;
åbn ikke labbet mod internettet. Offentlig NAT-adgang alene opfylder ikke denne
Receiver-grænse.

Efter merge til main:

1. Stop en eventuelt allerede aktiveret `mrnobody-agent-jobs.service` på Slave
   før opdatering. Gem en lokal backup af programfiler og systemd-unit.
2. Kør `sudo mrnobody update` på både Master og Slave. Updateren distribuerer de
   nye filer via SHA256-manifestet. Den installerer/aktiverer ikke den nye unit
   i `/etc/systemd/system`. Bevar registry, agentjournal og credentials.
3. På Slave: skift kun Master-URL'en i `/etc/mrnobody/deployment.conf` til den
   korrekte `https://...`-adresse. Sørg for tillid til Master-certifikatet.
   Genstart eksisterende heartbeat: `sudo systemctl restart mrnobody-agent`.
   Bekræft, at samme Agent-ID står online på Master.
4. Genstart Master-webservicen, hvis updateren ikke allerede har gjort det:
   `sudo systemctl restart nordic-incident-web`.
5. Installér og start jobworkeren eksplicit på Slave:

```sh
sudo install -m 0644 /opt/nordic-attack/systemd/mrnobody-agent-jobs.service /etc/systemd/system/mrnobody-agent-jobs.service
sudo systemctl daemon-reload
sudo systemctl enable --now mrnobody-agent-jobs.service
sudo systemctl status mrnobody-agent-jobs.service
```

Før merge henter `mrnobody update` stadig main. Til test af feature-branchen:
checkout `feature/master-remote-sprint1` i en separat labkopi af repositoryet;
verificér dens manifest med `tools/build-manifest.sh` og sammenlign før/efter.
Stop en eksisterende jobworker. Tag backup. Kopiér kun følgende fra
`INSTALLFILES/TESTFILES/ATTACKER-V2/` til de samme relative stier under
`/opt/nordic-attack/` på begge VM'er (mode 0644):

```text
web/agent_client.py
web/master_api.py
web/master_jobs.py
web/agent_jobs.py
web/static/app.js
systemd/mrnobody-agent-jobs.service
docs/master-remote-sprint1.md
```

Følg derefter trin 3–5. Den eksisterende updater henter stadig main; kør den
ikke oven på feature-installationen, før branchen er merget. Ved senere
opdateringer skal den særskilte jobworker stoppes, unit kopieres igen og workeren
startes eksplicit; updateren håndterer endnu ikke dens aktive systemd-unit.

## Start, status og stop fra Master

Brug det faktiske Agent-ID fra Master > Agents. Kør lokalt på den konfigurerede
Master som administrator. Request-key identificerer ét forsøg; gentag samme key
ved mistet output, og brug en ny key kun når et nyt forsøg ønskes.

```sh
sudo python3 /opt/nordic-attack/web/master_jobs.py start AGENT_ID lab-sprint1-001
sudo python3 /opt/nordic-attack/web/master_jobs.py status MRN-job-JOBHEX
sudo python3 /opt/nordic-attack/web/master_jobs.py stop MRN-job-JOBHEX
```

Erstat `MRN-job-JOBHEX` med hele `job_id` fra startsvaret. Output er JSON og
indeholder aldrig token/hash. Start returnerer normalt `queued`; status giver
også deadline og en fast fejlkategori. Der er endnu ingen central jobhistorik-UI
eller almindelig campaign-rapport for dette trin. Receiver viser beacons med
job-ID'et som `campaign_id`.

## Konkret labtest — endnu ikke gennemført på rigtige VM'er

1. Kontrollér baseline: samme Slave-ID, heartbeat online, Master Receiver og de
   eksisterende lokale ZTD/P06/P11/DNS/Full Campaign/standalone-flows.
2. Stop jobworkeren, opret ét job og gentag samme request-key: samme ID, ingen
   trafik. En ny key afvises, mens jobbet er aktivt. Stop dette queued job;
   forvent `stopped` og nul beacons.
3. Start workeren, brug ny key og følg status. Forvent `running`, tre
   verificerede P11 Receiver-events med sekvens 1, 2, 3 og samme job-ID, derefter
   `succeeded`. Gentag key og genstart workeren: ingen ekstra beacons.
4. Start nyt job. Efter første beacon: send stop. Afvent `stopped`, vent mindst
   35 sekunder og kontrollér, at beaconantallet ikke vokser. Stop ændrer ikke
   andre lokale kørsler eller persistensartefakter.
5. Start nyt job og genstart workeren under kørsel. Forvent `failed`, ikke
   genkørsel. Gentag med afbrudt Master-forbindelse: beacons afbrydes, og jobbet
   bliver `failed` ved genforbindelse eller efter serverfristen ved næste
   statusadgang. Receiver kan indeholde et delvist antal hændelser.
6. Forsøg job med forkert agenttoken eller en anden Agent-ID: 401 og ingen
   aktivitet. Spær agenten under et job: afvisning, workerstop og jobfejl.
   Et forkert TLS-certifikat skal stoppe workeren, selv ved lab HTTP opt-in.
7. Stop workeren igen. Kør baseline-flows fra punkt 1. Bekræft, at der ikke er
   åbnet en lytteport på Slaven, og at standalone ikke kontakter Master.

Log: `sudo journalctl -u mrnobody-agent-jobs -n 50 --no-pager`. Fejltekst er bevidst
generisk; kontrollér certifikat, registrering og lager uden at kopiere tokens
til logs. Der sendes kun en fast status, aldrig lokal exceptiontekst til Master.

## Tilbageførsel

Stop/deaktivér jobworkeren med
`sudo systemctl disable --now mrnobody-agent-jobs.service`. Gendan de berørte
programfiler og evt. tidligere unit fra backup, kør `systemctl daemon-reload` og
genstart web/heartbeat. Behold agentjournalen og registry-databasen; sletning kan
ødelægge idempotens. Den nye `execution_jobs`-tabel er additiv; gammel kode
ignorerer den. Behold credentials og øvrige lokale konfigurationer uændret.

## Automatiske kontroller

`INSTALLFILES/tests/mrnobody/master_jobs.py` dækker allowlist, tokenbinding,
transaktioner, gentagen levering, genstart, stop, offline/udløb, lagerfejl,
netværksannullering, strengt HTTPS/protokolformat samt eksisterende beaconløkkes
tre kvitteringer gennem de faktiske Flask-ruter og AgentTransport. Tiden er
accelereret i sidstnævnte test; den erstatter ikke den praktiske NAT/TLS/VM-test.
Eksisterende registry-, agent-, reports-, Receiver-, P06/P11- og campaign-tests
skal fortsat køres. Testene aktiverer ikke angrebsoperationer på virkelige mål.

Verificeret 15. november 2026 på midlertidige Ubuntu-kopier: 190 Python-tests
bestået i 18 testfiler, heraf 21 nye jobtests. De øvrige filer var
`master_registry`, `agent_client`, `master_reports`, `master_receiver`,
`receiver_dashboard`, `p06_live_lab`, `p11_live_lab`, `p11_campaign`,
`campaign_live_lab`, `deployment_settings`, `installer_roles`, `update_agent`,
`update_nginx`, `persistence_dns`, `p06_standalone`, `full_incident` og
`standalone_ports`. Linux-Python-afhængigheder blev brugt til PDF/DNS-testene.
Agents Playwright-testen (`master_overview.cjs`) bestod også med kontrol af den
nye begrænsede kapabilitetsvisning. Manifestet indeholder 56 filer og skal
regenereres og kontrolleres ved kodeændringer. Praktisk VM/NAT/TLS-labtest og
automatisk livscyklushåndtering af den nye worker i updateren udestår.
