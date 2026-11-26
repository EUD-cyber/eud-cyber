# WAZUH5X and TPOT01 on Ubuntu 26.04

Verified 2026-11-26. WAZUH5X is a separate **Wazuh 5.0.0-rc2 prerelease lab VM**,
not a migration of WAZUH 4.14.1. Existing WAZUH files and agent destinations are unchanged.

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
and signature/OS checks are not disabled. The installed package versions must match RC2.
The assistant downloads signed packages through its official RC2 manifest; package bytes
are authenticated by the upstream pinned Wazuh signing-key fingerprint.

## Files and choices

| File | Change |
|---|---|
| `WAZUH5X/wazuh5x_install.sh` | New independent Proxmox installer |
| `WAZUH5X/WAZUH5X_userdata.yaml` | New automatic RC2 bootstrap and health checker |
| `WAZUH5X/SHA256SUMS` | Component source integrity manifest (run from INSTALLFILES) |
| `ubuntu2604-image.sh` | Dedicated checksum-verified, atomic image cache shared only by WAZUH5X/TPOT01 |
| `installer_menu.py` | WAZUH5X in Single VM and optional Big/Mini components |
| `deploy.sh` | Component dispatch, resource validation, explicit tmux environment |
| `../install.sh` | Mini WAZUH5X resources and separate image-source display |
| `TPOT01/TPOT01_installer.sh` | Ubuntu 26.04 image, selected snippet/disk storage resolution, bounded wait |
| `TPOT01/TPOT01_userdata.yaml` | OS guard, pinned T-Pot commit, protected random web password, error status |
| `GUACVM/nat.sh` | TCP 3003 to WAZUH5X OOBM HTTPS |
| `GUACVM/nginx/web/sessions.js` | Separate WAZUH5X portal card |
| `tests/installer/test_wazuh5x.py` and CI workflow | Offline regression coverage |

WAZUH5X uses `labN-WAZUH5X`, LAN2 `192.168.2.21/24`, gateway/DNS `192.168.2.1`,
OOBM `172.20.0.21/24`, and bridges `labN_lan2` / `labN_oobm`. WAZUH retains `.20`
and external TCP 3001. WAZUH5X uses TCP 3003 through GUACVM. Indexer and manager API
are not forwarded externally. Agent TLS SANs include both WAZUH5X IPs. Existing agents
are not automatically repointed; use the 5.x dashboard's enrollment flow when testing.

Big: 4 vCPU / 16 GiB / +100 GiB disk. Mini: 4 vCPU / 8 GiB / +100 GiB.
Overrides: `WAZUH5X_CPU`, `WAZUH5X_MEM`, `WAZUH5X_HDD`. Less than 4 vCPU/8 GiB is rejected.
`LOCAL` selects snippet storage; `LVM` selects VM disks, including ZFS-style volume names.

The default image for all other Ubuntu guests remains the existing Noble 24.04 image.
WAZUH5X and TPOT01 ignore `LINUX_IMG`. To use a CyberRepo mirror of the 26.04 image,
set **both** `UBUNTU2604_IMG` and `UBUNTU2604_SHA256`. A cached image is rehashed before
reuse. Corrupt/partial downloads are never imported. No unrelated ATTACKER update
manifest is changed; that manifest does not cover these files.

## Fresh Single VM test on Proxmox

1. Check out this change on the Proxmox host. Use an existing lab with LAN2/OOBM bridges,
   working DNS/internet, and available addresses `.21`. Ensure no existing `labN-WAZUH5X`.
2. Set `export WAZUH5X_SSH_PUBLIC_KEY_FILE=/root/.ssh/id_ed25519.pub` to an existing public
   key whose private key you control. Alternatively set it to another public-key file.
   WAZUH5X has no shared/default login password. The key logs in as `ubuntu` with sudo.
3. Run `bash install.sh`, choose image/storage/network options, then
   **Single VM → WAZUH5X (5.0 RC2) → Big or Mini → lab number**. Only WAZUH5X is created.
   Direct equivalent from INSTALLFILES: `bash WAZUH5X/wazuh5x_install.sh 1` with storage variables exported.
4. Wait for the explicit healthy result, baseline snapshot and restart (default limit 3600 s;
   override `WAZUH5X_BOOT_TIMEOUT`). The host checks manager daemons/API, indexer cluster and
   dashboard readiness, with CA validation. A single-node indexer may be yellow due to replicas.
5. SSH to `ubuntu@172.20.0.21`; run `sudo cloud-init status --long`,
   `sudo /usr/local/sbin/wazuh5x-healthcheck`, and
   `sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard`.
6. Open `https://<GUACVM-external-IP>:3003` or direct `https://172.20.0.21`.
   Login is `admin`. Read the password **inside the guest as root**:
   `sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env`.
   Do not paste it into logs, tickets or chat. Import the dashboard CA if desired.
7. Verify WAZUH 4.x still runs on `.20` / TCP 3001. Re-run Single VM WAZUH5X in the same
   lab: it must refuse a duplicate without writing to that VM. Reboot WAZUH5X and repeat health checks.
8. Separately choose **Single VM → T-Pot → Big → lab number** on a fresh TPOT01.
   Check `/etc/os-release` is 26.04, `cloud-init status --long`,
   `/var/log/tpot-install-status.log` and T-Pot containers/UI after its baseline restart.
   Its generated web password is in `/root/tpot01/web-password`; tracing is disabled.
   Upstream T-Pot requires a password CLI argument during installation; it can be visible
   to local process inspection. The VM must remain a controlled installation environment.

For an already-installed GUACVM, deploy the updated `nat.sh` and `sessions.js` to
`/opt/guacamole/nat.sh` and `/opt/guacamole/nginx/web/sessions.js`, then run
`sudo bash /opt/guacamole/nat.sh apply` and reload the portal. A fresh GUACVM fetches them
after merge. Single VM WAZUH5X does not modify an existing GUACVM automatically.
No Guacamole SSH session ID is invented: use SSH with your key or create a Guacamole
connection with that key explicitly.

## Logs, retries and secrets

Host logs: `LOGS/WAZUH5X_labN_<UTC>.<unique>.log` (0600).
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
