# MrNobody Single VM-oprettelse

Denne vej opretter én slukket MrNobody VM med én valgt bridge.
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

Nye VM'er får et instance-ID i både VM-beskrivelse og Single VM-snippet.
Oprettelseskommandoens JSON viser dette ID. Den genererede snippet slår kun
Single VM's automatiske cloud-init-poweroff fra; Big/Mini-template bevares.

Kør næste trin med det valgte VMID og det returnerede instance-ID:

    python3 -m MRNOBODY.single_vm_boot --vmid 9000 --instance-id INSTANCE_ID

Forløbet afviser en allerede kørende VM, forkert identitet og et eksisterende
First_snapshot. Det starter VM'en, venter højst 1800 sekunder som standard
og kontrollerer via QEMU Guest Agent:

- cloud-init afsluttet uden fejl eller degraded-status
- INSTALL_COMPLETE-markør fra den eksisterende installer
- Single VM-identitet og korrekt rolle i den lokale HTTPS-health

Kun ved succes udføres almindelig shutdown uden force-stop, efterfulgt af
First_snapshot. VM'en efterlades slukket. Ved timeout, fejl eller afbrydelse
bevares VM'en til inspektion; der køres ingen stop, destroy eller rollback.
En anden timeout kan angives med --timeout (1-7200 sekunder).

Den lokale HTTPS-kontrol bruger som den eksisterende installer et selvsigneret
certifikat uden tillidsvalidering, udelukkende mod 127.0.0.1. Dette fastlægger
ikke TLS-politik for fremtidige agentforbindelser.

Automatisk første-opstart understøtter kun VM'er fra denne version af Single
VM-oprettelsen. Tidligere VM'er uden instance-ID overtages ikke automatisk.

## Det resterende Master-arbejde

Rollen master genkendes af den eksisterende backend/UI, men Master/agent-
kommunikation er fortsat deaktiveret. Provisionering og opstartsforløb skal
stadig afprøves på rigtig Proxmox; de isolerede tests bruger simulerede svar.
