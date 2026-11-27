# Wazuh 5.x and TPOT01 on Ubuntu 26.04

WAZUH installs **Wazuh 5.0.0-rc2** for fresh lab deployments. The 4.x files are archived in
WAZUH_OLD. To replace an existing VM, back up and retire it before provisioning the new VM.
Plan agent re-enrollment and any data migration separately.

## Version and installation evidence

- [Official RC2 release](https://github.com/wazuh/wazuh-installation-assistant/releases/tag/v5.0.0-rc2).
- [RC2 supported platforms](https://github.com/wazuh/wazuh-installation-assistant/blob/v5.0.0-rc2/docs/ref/introduction/compatibility.md): Ubuntu 24.04 and 26.04.
- [RC2 all-in-one instructions](https://github.com/wazuh/wazuh-installation-assistant/blob/v5.0.0-rc2/docs/guide/installation-assistant-deployments/all-in-one.md): use the matching prerelease assistant and `-a -id -d pre-release`.
- [Official RC2 package manifest](https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/artifact-urls/artifact_urls_5.0.0-rc2.yaml) references manager, indexer and dashboard `5.0.0-rc2` packages.
- [Ubuntu image](https://cloud-images.ubuntu.com/resolute/20261108/) and [checksums](https://cloud-images.ubuntu.com/resolute/20261108/SHA256SUMS): `resolute-server-cloudimg-amd64.img`, a QCOW2 cloud image imported with `qm importdisk`, not an installation ISO.
- [Inspected T-Pot installer](https://github.com/telekom-security/tpotce/blob/9c3ae4aea976a63ef1f655598a4383c0cb7e140c/install.sh) explicitly requires Ubuntu 26.04 and supports unattended `-s` and commit selection `-b`.

The downloaded RC2 assistant was inspected, including OS checks, artifact selection,
package-signature verification, per-package credentials and service startup. Its SHA256
is pinned in userdata. No Wazuh repository main branch is cloned, no 4.x assistant is reused,
and signature/OS checks are not disabled. The installed DEB versions must be `5.0.0-1`:
the official RC2 files are named `5.0.0-rc2`, but their internal Debian version is
`5.0.0-1`, as recorded in the [official RC2 UX test](https://github.com/wazuh/wazuh/issues/41041).
This metadata distinction must not be used to select a different assistant or release.
The assistant downloads signed packages through its official RC2 manifest; package bytes
are authenticated by the upstream pinned Wazuh signing-key fingerprint.

## Files and choices

| File | Change |
|---|---|
| `WAZUH/WAZUH_installer.sh` | New independent Proxmox installer |
| `WAZUH/WAZUH_userdata.yaml` | New automatic RC2 bootstrap and health checker |
| `WAZUH/SHA256SUMS` | Component source integrity manifest (run from INSTALLFILES) |
| `ubuntu2604-image.sh` | Dedicated checksum-verified, atomic image cache shared only by WAZUH/TPOT01 |
| `installer_menu.py` | WAZUH in Single VM and optional Big/Mini components |
| `deploy.sh` | Component dispatch, resource validation, explicit tmux environment |
| `../install.sh` | Mini WAZUH resources and separate image-source display |
| `TPOT01/TPOT01_installer.sh` | Ubuntu 26.04 image, selected snippet/disk storage resolution, bounded wait |
| `TPOT01/TPOT01_userdata.yaml` | OS guard, pinned T-Pot commit, protected random web password, error status |
| `GUACVM/nat.sh` | TCP 3001 to WAZUH OOBM HTTPS |
| `GUACVM/nginx/web/sessions.js` | Existing Wazuh dashboard and SSH links |
| `tests/installer/test_wazuh5x.py` and CI workflow | Offline regression coverage |

WAZUH uses `labN-WAZUH`, LAN2 `192.168.2.20/24`, gateway/DNS `192.168.2.1`,
OOBM `172.20.0.20/24`, and bridges `labN_lan2` / `labN_oobm`. Each lab has separate
bridges and uses the same addresses. GUACVM forwards external TCP 3001 to the OOBM dashboard.
Agent TLS SANs include both IPs. Use the 5.x dashboard to enroll agents.

VMID selection starts at `lab number × 1000`: lab1 starts at 1000, lab2 at 2000, etc.
It selects the first free ID in that lab's 1000-ID block, checking cluster inventory
including containers and guests on other nodes. An exhausted block fails before VM
creation. The global `/cluster/nextid` allocator is not used. Existing guests, including
an earlier legacy test VM created as VM 100, are never renumbered or removed automatically.

Big: 4 vCPU / 16 GiB / +100 GiB disk. Mini: 4 vCPU / 8 GiB / +100 GiB.
Overrides: `WAZUH_CPU`, `WAZUH_MEM`, `WAZUH_HDD`. Less than 4 vCPU/8 GiB is rejected.
`LOCAL` selects snippet storage; `LVM` selects VM disks, including ZFS-style volume names.

The default image for all other Ubuntu guests remains the existing Noble 24.04 image.
WAZUH and TPOT01 ignore `LINUX_IMG`. To use a CyberRepo mirror of the 26.04 image,
set **both** `UBUNTU2604_IMG` and `UBUNTU2604_SHA256`. A cached image is rehashed before
reuse. Corrupt/partial downloads are never imported. No unrelated ATTACKER update
manifest is changed; that manifest does not cover these files.

## Fresh Single VM test on Proxmox

1. Check out this change on the Proxmox host. Use an existing lab with LAN2/OOBM bridges,
   working DNS/internet, and available addresses `.20`. The installer rejects existing lab Wazuh VMs,
   including historical Wazuh 5.x test VMs and suffixed duplicates.
2. The `ubuntu` SSH login uses the lab password `Password1?`.
   Guacamole's existing Wazuh SSH link uses the preserved `wazuh` account.
   The RC2 installer generates the dashboard admin password because its policy requires
   12–64 characters and excludes `?`.
3. Run `bash install.sh`, choose image/storage/network options, then
   **Single VM → Wazuh (5.0 RC2) → Big or Mini → lab number**. Only WAZUH is created.
   Direct equivalent from INSTALLFILES: `bash WAZUH/WAZUH_installer.sh 1` with storage variables exported.
4. Wait for the explicit healthy result, baseline snapshot and restart (default limit 3600 s;
   override `WAZUH_BOOT_TIMEOUT`). The host checks manager daemons/API, indexer cluster and
   dashboard readiness, with CA validation. A single-node indexer may be yellow due to replicas.
5. SSH to `ubuntu@172.20.0.20`; run `sudo cloud-init status --long`,
   `sudo /usr/local/sbin/wazuh5x-healthcheck`, and
   `sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard`.

The healthcheck trusts each component's published CA at
`/etc/wazuh-{indexer,manager,dashboard}/export/ca.pem`. In particular, a local RC2
dashboard publishes `export/ca.pem`; `certs/root-ca.pem` is not its dashboard CA
location. See the [tagged RC2 usage guide](https://github.com/wazuh/wazuh-installation-assistant/blob/v5.0.0-rc2/docs/ref/getting-started/usage.md)
and [manager installation reference](https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/docs/ref/getting-started/installation.md).
TLS chain and hostname validation remain enabled. Errors name the failed component
and missing file or HTTP/command status; credentials, tokens and response bodies are
never included in diagnostic output.
6. Open `https://<GUACVM-external-IP>:3001` or direct `https://172.20.0.20`.
   Login is `admin`. Read the password **inside the guest as root**:
   `sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env`.
   Do not paste it into logs, tickets or chat. Import the dashboard CA if desired.
7. Verify the existing Guacamole SSH link and dashboard port 3001. Re-run Single VM WAZUH in
   the same lab and confirm it refuses the duplicate. Reboot WAZUH and repeat health checks.
8. Separately choose **Single VM → T-Pot → Big → lab number** on a fresh TPOT01.
   Check `/etc/os-release` is 26.04, `cloud-init status --long`,
   `/var/log/tpot-install-status.log` and T-Pot containers/UI after its baseline restart.
   Its generated web password is in `/root/tpot01/web-password`; tracing is disabled.
   Upstream T-Pot requires a password CLI argument during installation; it can be visible
   to local process inspection. The VM must remain a controlled installation environment.

TPOT01 bootstrap explicitly changes to `/opt/tpotce` before running the upstream
installer as `ubuntu`, sets the target HOME with `sudo -H`, and passes noninteractive
APT configuration through sudo. This fixes the observed `tpot.yml: Permission denied`
fallback download when the installer inherited root-owned `/opt` as cwd.

TPOT01 and WAZUH disable recurring systemd OSC 3008 shell/command markers using the
[upstream opt-out](https://github.com/systemd/systemd/blob/main/profile.d/80-systemd-osc-context.sh):
remove the profile hook and mask `20-systemd-osc-context.conf`. Reconnect existing SSH
sessions after applying it. This preserves TERM, other prompt hooks and PAM/session
management. A separate one-time PAM `type=session` marker on sudo/login is outside this
shell opt-out; clients need OSC 3008 support to hide that marker. The installer does
not disable PAM or session registration to suppress it.
WAZUH applies its terminal compatibility helper before bootstrap so an installation
failure does not leave the repeated prompt markers enabled on a fresh VM.

For an already-installed GUACVM, deploy the updated `nat.sh` and `sessions.js` to
`/opt/guacamole/nat.sh` and `/opt/guacamole/nginx/web/sessions.js`, then run
`sudo bash /opt/guacamole/nat.sh apply` and reload the portal. A fresh GUACVM fetches them
after merge. Single VM WAZUH does not modify an existing GUACVM automatically.
The existing Guacamole SSH session ID is preserved.

## Logs, retries and secrets

Host logs: `LOGS/WAZUH_labN_<UTC>.<unique>.log` (0600).
Guest logs: `/var/log/wazuh5x/bootstrap-<UTC>-<unique>.log` (0600),
`/var/log/wazuh-install.log`, cloud-init status/output, and systemd journals.
State: `/var/lib/wazuh5x/{assistant.started,assistant.complete,bootstrap.complete,bootstrap.failed}`.
Bootstrap is locked; successful repeat runs only check health. Failure retains the VM and
returns an error. An interrupted assistant is **not** automatically rerun with overwrite:
inspect logs and repair manually or rebuild that new VM. Retry repaired service/health
failures with `sudo /usr/local/sbin/wazuh5x-bootstrap`. No failed baseline is snapshotted.
Credentials stay in root-only package export files; the assistant runs with redirected
output so its interactive password summary is suppressed. Back up package CA directories
and credential files securely; a baseline snapshot contains secrets and needs restricted access.

## Validation boundary

Offline tests exercise menu/hardware selection, Single VM dispatch, simulated Proxmox
creation/storage/snapshot flow, duplicate refusal, bootstrap-failure and timeout paths,
image checksums/cache/corruption, YAML parsing and embedded script syntax.
They do **not** establish that real Wazuh or T-Pot services work on a booted 26.04 guest.
The fresh-VM acceptance procedure above must be run on Proxmox before treating this RC2
component as validated for teaching. No real Proxmox VM was available for this implementation.

The user's subsequent RC2 test VM log confirmed that the RC2 assistant installed and
started all three components, then the wrapper rejected its DEB metadata at the old
`5.0.0-rc2` equality check. The corrected `5.0.0-1` check is covered by fixture tests,
including rejection of 4.14.1 and 5.0.1; the corrected complete flow still needs a real
VM acceptance test. Existing VM 100 keeps its original userdata/scripts until updated.

A subsequent VM 1010 log passed the package-version checks and then repeatedly
reported `FileNotFoundError` in the healthcheck. The old helper referenced the
dashboard CA through the wrong `certs/root-ca.pem` path. New tests execute the actual
helper against local authenticated TLS endpoints with the export-only CA layout;
they check readiness, missing-file diagnostics, wrong trust roots, authentication
failures and secret redaction. These are real local HTTPS requests, not live Wazuh
services or a Proxmox VM test.

### Existing VM with completed RC2 installation

When the assistant already reports `Installation finished` and
`/var/lib/wazuh5x/assistant.complete` exists, the existing services need not be
reinstalled to correct the old helper's CA paths. Inside that VM:

```bash
sudo cp -p /usr/local/sbin/wazuh5x-healthcheck /root/wazuh5x-healthcheck.before-ca-fix
sudo sed -i \
  -e 's@/etc/wazuh-indexer/certs/root-ca.pem@/etc/wazuh-indexer/export/ca.pem@g' \
  -e 's@/etc/wazuh-manager/certs/root-ca.pem@/etc/wazuh-manager/export/ca.pem@g' \
  -e 's@/etc/wazuh-dashboard/certs/root-ca.pem@/etc/wazuh-dashboard/export/ca.pem@g' \
  /usr/local/sbin/wazuh5x-healthcheck
sudo /usr/local/sbin/wazuh5x-healthcheck --bootstrap
```

If that health probe succeeds, `sudo /usr/local/sbin/wazuh5x-bootstrap` reruns the
post-install checks, enables the services, marks bootstrap complete and clears its
failure marker. The completed-assistant marker prevents a reinstall. This does not
erase cloud-init's historical failed-run status or create a baseline snapshot after
the original host installer has exited. Normal host acceptance still requires a
completed, error-free cloud-init run on a fresh installation.
