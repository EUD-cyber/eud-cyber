# MrNobody Single VM-installation

## Fra hovedmenuen

Vælg Single VM og derefter MrNobody Master, slave/agent eller standalone.
For alle roller spørger menuen om
IP-adresse/subnet, gateway og DNS. Bridge, storage og Ubuntu-image genbruges
fra hovedinstallerens valg; VMID vælges fra 9000 og op, og hardware får
MrNobody-standardværdierne.
Slave spørger desuden efter Master-IP/værtsnavn (med valgfri port) og HTTP/HTTPS.
HTTPS er standard. HTTP indsætter MRNOBODY_LAB_HTTP="1" i den nye agents
deployment.conf; samme flag skal sættes på Master for HTTP.
Standalone og Master får ingen Master-adressespørgsmål.
Agentnøgle og CA-tillid sættes op efter installation som beskrevet i
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
kommunikation er fortsat deaktiveret. Provisionering og opstartsforløb skal
stadig afprøves på rigtig Proxmox; de isolerede tests bruger simulerede svar.
