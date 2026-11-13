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

## Hvad dette trin ikke afslutter

Første opstart, cloud-init-verifikation, baseline-snapshot og Master/agent-
kommunikation er separate trin. Rollen master genkendes af den eksisterende
backend/UI, men transport er fortsat deaktiveret. Kapacitet og netværksadgang
er ikke afprøvet af inventory-kontrollen.
