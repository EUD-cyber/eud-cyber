# MrNobody i Big/Mini: rolle og Master-adresse

## Ændring

Når MrNobody tilvælges, viser hovedmenuen et ekstra trin med **Standalone**
eller **Slave/Agent**. Master er fortsat kun et Single VM-valg.

`installer_menu.py` gemmer rollen i menuens JSON. Kommandoen `selection`
returnerer profil, labantal, rolle og derefter komponenterne. `install.sh`
eksporterer `MRNOBODY_ROLE` og nulstiller `MRNOBODY_MASTER_URL`, så gamle
miljøværdier ikke genbruges.

`deploy.sh` bevarer rollen. Efter OPNsense- og GUACVM-IP-valgene for alle labs,
men før repo-/pakke-/netværksopsætning og tmux, spørges Slave/Agent én gang om
Master IP/URL. Samme adresse bruges til alle 1–16 labs. Standalone og installation
uden MrNobody spørger aldrig. Standalone rydder også en eventuel gammel URL.

En IP eller et værtsnavn med valgfri port bliver til `http://...`, som i det
eksisterende Single VM Slave-flow. En eksplicit HTTP/HTTPS-URL bevares, inklusive
port og sti. Login, query, fragment og ugyldige porte afvises. HTTP sender
agenttrafik ukrypteret på labnettet; vælg en HTTPS-URL, hvis Master tilbyder det.
Q eller manglende input stopper før værtsopsætning og tmux.

De eksisterende eksplicitte tmux-miljøargumenter overfører begge variabler og
overskriver eventuelle gamle serverværdier. MrNobody-installeren bruger sin
eksisterende validering og unikke cloud-init-snippet pr. VM; dens kørselskode er
uændret. Direkte `deploy.sh`-kald bevarer agent som standardrolle og kan angive
`MRNOBODY_ROLE=standalone` eller en allerede udfyldt `MRNOBODY_MASTER_URL`.
Direkte kald til selve MrNobody-installeren bevarer den tidligere adfærd.

Big/Mini-ressourcer, øvrige VM-installere, Single VM-roller og agent/ZTD/heartbeat
er uændrede. Der findes ikke et aktivt Custom-valg i dette checkout.

## Automatiske tests

Kør fra `INSTALLFILES` på Linux med Python 3 og Bash:

```bash
python3 -m unittest discover -s tests/installer -v
sudo python3 -m unittest discover -s tests/installer -p test_lab_mrnobody.py -v
python3 -m unittest discover -s tests/mrnobody -p 'single_vm*.py' -v
python3 tests/mrnobody/installer_roles.py -v
python3 tests/mrnobody/agent_client.py -v
python3 tests/mrnobody/master_registry.py -v
python3 tests/mrnobody/deployment_settings.py -v
python3 tests/mrnobody/update_agent.py -v
python3 tests/mrnobody/update_nginx.py -v
```

De nye deploymenttests erstatter alle Proxmox-/værtskommandoer og opretter ingen
VM'er. De kører begge profiler og roller for hvert labantal 1–16, validerer
prompt-rækkefølge, miljøoverførsel og faktiske cloud-init-snippets, samt fejl ved
manglende Master-input. En ekstra test bruger en rigtig tmux-server med separat
socket og gamle rolle-/URL-værdier; MrNobody-arbejderen får lukket standardinput.
Denne test springes over, hvis tmux ikke er installeret. Root kræves kun til at
passere deploymentens eksisterende root-kontrol.

Valideret på en isoleret kopi på Linux-filsystem: **181 tests, 180 bestået,
1 sprunget over** (eksisterende Flask-adaptertest uden Flask-afhængigheden).
Heraf 27 installer-tests, 65 Single VM-tests, 6 rolletests, 33 agent-tests,
26 registry-tests, 9 konfigurationstests og 15 updater-tests.
Menu- og deploymatrix dækker hver 64 kombinationer.
**17 Bash-filer og 6 Python-filer** bestod syntakskontrol.
Alle **49 eksisterende manifest-hashes** matcher det kanoniske Git-indhold;
ingen distribuerede platformfiler eller hashes er ændret.
Windows-checkout med CRLF skal testes med Git/Linux-linjeskift og Linux-
filrettigheder; credentialtests kræver reelle Unix-rettigheder.

## Manuel test på en egnet Proxmox-testvært

1. Start hovedinstalleren fra denne branch. Vælg Big, ét lab og MrNobody.
   Bekræft, at næste trin kun viser Standalone og Slave/Agent.
2. Vælg Standalone og gennemfør OPNsense/GUACVM-IP-valgene. Bekræft, at der
   aldrig spørges efter Master. Kontroller den genererede MrNobody-snippet:
   `MRNOBODY_ROLE=standalone` og tom `MRNOBODY_MASTER_URL`.
3. Gentag med Mini og Slave/Agent på ledige labs. Bekræft, at Master-prompten
   kommer efter alle OPNsense/GUACVM-IP-valg og før værtsopsætning/tmux.
   Prøv tom adresse eller ugyldig port og derefter en gyldig IP/URL.
4. Følg `deploy.log` eller `tmux attach -t deploy-all`. Bekræft, at MrNobody
   ikke afventer rolle-/IP-input. Kontroller hver labs unikke snippet for
   `MRNOBODY_ROLE=agent`, valgt URL og `MRNOBODY_LAB_HTTP="1"`.
5. Når VM'erne er klar, kontroller `/etc/mrnobody/deployment.conf` i gæsten,
   registrering på Master og efterfølgende heartbeat. Gentag uden MrNobody
   og kontroller Single VM Master/Slave/Standalone ved behov.

Der er ikke udført en fuld Proxmox-/VM-installation i denne ændring.
