# MrNobody Single VM-installation

## Fra hovedmenuen

Vælg Single VM, derefter MrNobody, Big/Mini og til sidst Master, Slave eller Standalone.
Kun Master spørger om egen IP-adresse/subnet, gateway og DNS og genbruger
bridgen fra hovedinstallerens valg. Slave og Standalone bruger eksisterende
lab-bridges og statiske IP'er som beskrevet nedenfor.
Storage, Ubuntu-image og valgt hardware genbruges fra hovedinstallerens valg.
Master spørger om VMID; et optaget ID afvises, og kontrollen gentages før oprettelse.
Slave og Standalone spørger om labnummer og bruger første ledige VMID i
intervallet labnummer × 1000 til labnummer × 1000 + 999.
Slave spørger desuden efter Master-IP/værtsnavn med valgfri port og bruger HTTP.
Master og Slave får MRNOBODY_LAB_HTTP="1" i deres nye deployment.conf.
Websiden beholder HTTPS. Ingen CA-opsætning kræves til Master/Slave-forbindelsen.
Standalone og Master får ingen Master-adressespørgsmål.
Agentnøgle parres efter installation som beskrevet i
[mrnobody-agent-client.md](mrnobody-agent-client.md). Agentservicen aktiveres
ikke automatisk, og ingen nøgle gemmes i Proxmox-snippet.

Menuen henter image, opretter VM og starter første boot. Den venter på, at VM'en
selv slukker via cloud-init poweroff. Derefter oprettes First_snapshot, og Master
startes igen. Ingen QEMU Guest Agent- eller HTTP/HTTPS-kontrol bruges.
Slukning er afslutningssignalet, ikke en kontrol af cloud-init-fejl eller webservice.
Ved fejl, timeout eller afbrydelse bevares VM og dens identitet til fejlsøgning.
Eksisterende VM'er overtages ikke automatisk af en ny menuinstallation.

## Separate CLI-værktøjer


Denne vej opretter én slukket MrNobody Master-VM med én bridge.
Master bruger BRIDGE fra hovedinstallerens første valg uden et nyt bridgevalg.
Ved direkte start uden BRIDGE spørges om bridge. IP-adresse/CIDR, gateway
og DNS spørges altid for Master. Standalone/agent returnerer indtil videre
uden yderligere opsætningsspørgsmål.
Big/Mini bruger fortsat den eksisterende labinstaller og agentrollen.

Kør fra repositoryets INSTALLFILES-mappe på Proxmox:

    python3 -m MRNOBODY.single_vm_create

Dette viser kun planen. For faktisk oprettelse:

    python3 -m MRNOBODY.single_vm_create --image /sti/ubuntu-cloud.img --create

Værktøjet kræver root ved oprettelse og beder om VMID, rolle, netværk,
hardware og storage. Efter planen skal VMID bekræftes med OPRET <VMID>.

- Både cluster-VMID og lokal bridge/storage kontrolleres igen før oprettelse.
- Image skal allerede eksistere som en selvstændig raw/qcow2-fil.
- Diskudvidelse er +SIZE oven i image-disken, som i labinstalleren.
- Snippet-stien findes med pvesm; en eksisterende snippet overskrives ikke.
- VM'en startes ikke og har onboot=0.
- Ved fejl efter oprettelsesforsøg bevares VM/snippet til inspektion.

## Guest-kilde og arbejdsbranch

Den fælles cloud-init henter som hidtil guest-filer fra main. Arbejdsbranchens
guest-ændringer er først tilgængelige der efter merge. Til en isoleret prøve
før merge kan en gennemgået, fuld commit-SHA vælges eksplicit:

    python3 -m MRNOBODY.single_vm_create --image /sti/ubuntu-cloud.img --source-ref FULD_COMMIT_SHA --create

Det ændrer kun den nye VM's snippet; den aktive lab-template ændres ikke.

## Første opstart og baseline

Nye VM'er får et instance-ID i VM-beskrivelse og Single VM-snippet.
Cloud-init-template beholder automatisk poweroff, også for Single VM.
Big/Mini-template ændres ikke.

Separat første opstart kan køres med oprettelsens VMID og instance-ID:

    python3 -m MRNOBODY.single_vm_boot --vmid 9000 --instance-id INSTANCE_ID

Værktøjet kræver en slukket VM med korrekt identitet og uden First_snapshot.
Det starter VM'en og venter højst 1800 sekunder på status stopped.
Der vises fremdrift hvert 30. sekund. Derefter kontrolleres VM-identiteten igen,
og First_snapshot oprettes. CLI-værktøjet efterlader VM'en slukket;
hovedmenuen starter den efterfølgende igen.
Der bruges ingen Guest Agent, cloud-init-status, installationsmarkør eller health-request.
Også manuel slukning eller et nedbrud kan derfor opfylde afslutningssignalet.

Ved timeout/fejl bevares VM'en; ingen stop, shutdown, destroy eller rollback.
Timeout kan angives med --timeout (1-7200 sekunder).

Automatisk første-opstart understøtter kun VM'er fra denne version af Single
VM-oprettelsen. Tidligere VM'er uden instance-ID overtages ikke automatisk.

## Det resterende Master-arbejde

Rollen master genkendes af den eksisterende backend/UI, men Master/agent-
registrering og heartbeat findes; agenten afventer eksplicit parring og aktivering. Provisionering og opstartsforløb skal
stadig afprøves på rigtig Proxmox; de isolerede tests bruger simulerede svar.

## Single VM-menu: roller og lab-netværk

Vælg `Single VM` → `MrNobody` → `Big`/`Mini` → `Master`, `Slave` eller `Standalone`.
Master beholder den oprindeligt valgte bridge og spørgsmål om egen IP/CIDR,
gateway og DNS. Slave og Standalone læser i stedet de statiske værdier fra
`MRNOBODY/mrnobody_installer.sh`:

| Netkort | Bridge | IP/CIDR |
| --- | --- | --- |
| net0 / LAN1 | `lab${LAB}_lan1` | `192.168.1.254/24` |
| net1 / OOBM | `lab${LAB}_oobm` | `172.20.0.254/24` |
| net2 / LAN2 | `lab${LAB}_lan2` | `192.168.2.254/24` |

Gateway og DNS er `192.168.1.1`. Alle tre bridges skal eksistere; menuen
opretter dem ikke. Labnummer spørges altid med standarden `1`; Enter vælger
lab1. Der spørges aldrig om Slave/Standalone-VM'ens egne IP-adresser.
Kun Slave spørger om Master-adresse; forbindelsen bruger HTTP. Big/Mini og fremtidig
Custom beholder agent/slave-rollen; denne rettelse tilføjer ingen Custom-profil.

## Øvrige lab-VM'er under Single VM

Alle 11 VM'er fra Big/Mini-menuen kan vælges enkeltvis: OPNsense, GUACVM,
Kali01, VulnSrv01, VulnSrv02, Kali02, AppSrv01, Client01, Wazuh, T-Pot og
MrNobody. Efter VM-valget vises Big og Mini med CPU, RAM og diskudvidelse
fra de samme variabler som hovedmenuen, inklusive eventuelle egne overrides.
Single VM bruger præcis den valgte profils indstillinger uden at eksportere
dem tilbage til Big/Mini-menuen. Eksisterende Big-socketstandarder bevares.

Labnummer `[1]` vælger de eksisterende lab-bridges, IP-standarder og VM-navne.
Enter vælger lab1; 1-16 accepteres, og Q vender tilbage. VMID vælges af den
fælles installer fra labnummer × 1000. MrNobody Slave/Standalone bruger samme
labinterval og navnet `labN-MrNobody`; Master bevarer den separate netopsætning
og spørger om et ledigt VMID. Master spørger ikke om labnummer.

Kun den valgte VM installeres. OPNsense kører først sin WAN-konfiguration,
og GUACVM kører først sin IP-konfiguration. Ingen fuld labinstallation eller
OVS-/værtsopsætning startes. Manglende bridges/storage eller en eksisterende
VM af samme type i labbet stopper før installation. Andre VM'er i samme lab
forhindrer ikke, at en manglende VM tilføjes.
