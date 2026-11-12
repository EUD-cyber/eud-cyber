# Archived installation files

The files below are retained for manual deletion and are not called by the current
`install.sh -> INSTALLFILES/deploy.sh` workflow.

The four former Big/Mini launchers were replaced by the common deployment flow.
Legacy Mini VM scripts were replaced by the shared lab-aware VM installers plus
hardware overrides. Existing `.archive` files retain their archival status.
`finish.sh` was a standalone snapshot helper; current VM scripts create their own
baseline snapshots. The old main-installer backup is also retained.

| Previous path | Archived path (relative to INSTALLFILES) |
|---|---|
| `APPSRV01/APPSRV01_installer.sh.archive` | `APPSRV01/APPSRV01_installer.sh_archive` |
| `APPSRV01/APPSRV01_mini_install.sh` | `APPSRV01/APPSRV01_mini_install.sh_archive` |
| `CLIENT01/CLIENT01_installer.sh.archive` | `CLIENT01/CLIENT01_installer.sh_archive` |
| `CLIENT01/CLIENT01_mini_installer.sh` | `CLIENT01/CLIENT01_mini_installer.sh_archive` |
| `KALI01/KALI01_mini_multi_installer.sh` | `KALI01/KALI01_mini_multi_installer.sh_archive` |
| `OPNSENSE/OPNSENSE_installer.sh.archive` | `OPNSENSE/OPNSENSE_installer.sh_archive` |
| `OPNSENSE/OPNSENSE_mini_installer.sh` | `OPNSENSE/OPNSENSE_mini_installer.sh_archive` |
| `OPNSENSE/OPNSENSE_mini_multi_installer.sh` | `OPNSENSE/OPNSENSE_mini_multi_installer.sh_archive` |
| `OPNSENSE/generate_config.sh.archive` | `OPNSENSE/generate_config.sh_archive` |
| `VULNSRV01/VULNSRV01_installer.sh.archive` | `VULNSRV01/VULNSRV01_installer.sh_archive` |
| `VULNSRV01/VULNSRV01_mini_installer.sh` | `VULNSRV01/VULNSRV01_mini_installer.sh_archive` |
| `VULNSRV01/VULNSRV01_mini_multi_installer.sh` | `VULNSRV01/VULNSRV01_mini_multi_installer.sh_archive` |
| `VULNSRV02/VULNSRV02_installer.sh.archive` | `VULNSRV02/VULNSRV02_installer.sh_archive` |
| `VULNSRV02/VULNSRV02_mini_installer.sh` | `VULNSRV02/VULNSRV02_mini_installer.sh_archive` |
| `VULNSRV02/VULNSRV02_mini_multi_installer.sh` | `VULNSRV02/VULNSRV02_mini_multi_installer.sh_archive` |
| `WAZUH/WAZUH_installer.sh.archive` | `WAZUH/WAZUH_installer.sh_archive` |
| `WAZUH/WAZUH_mini_installer.sh` | `WAZUH/WAZUH_mini_installer.sh_archive` |
| `WAZUH/WAZUH_mini_multi_installer.sh` | `WAZUH/WAZUH_mini_multi_installer.sh_archive` |
| `WAZUH/WAZUH_multi_installer2.sh.archive` | `WAZUH/WAZUH_multi_installer2.sh_archive` |
| `big_install.sh` | `big_install.sh_archive` |
| `finish.sh` | `finish.sh_archive` |
| `install.sh_bck` | `install.sh_bck_archive` |
| `mini_install.sh` | `mini_install.sh_archive` |
| `multi_big_install.sh` | `multi_big_install.sh_archive` |
| `multi_mini_install.sh` | `multi_mini_install.sh_archive` |

Active standalone Image Server and PacketFence tools, lab datasets, Docker files,
documentation and tests have not been declared obsolete merely because they are
not part of the default Big/Mini selection.

GitHub workflows remain in the root `.github/`; moving that folder would prevent
GitHub from discovering them.
