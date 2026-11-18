# Lab access safety validation — 2026-11-18

Base: main `2fe2ed9cd6c7f39dc1862018d13ad3463c36197d`, merged PR #117.
Scope and blocking requirements:
[preinstall gate](../TESTFILES/ATTACKER-V2/docs/lab-access-preinstall.md).

## Result

290 top-level Python tests passed in 22 relevant suites on Linux as root.
The fresh-install suite also invokes nested suites; those are not added to
the 290 count. Eight headless Edge browser suites passed. All 70 distributed
SHA256 manifest entries match the staged Git blob bytes. These are regression
and simulated deployment checks, not a real fresh Master/Slave installation
or a complete test of every suite in the repository.

Python suites: lab_mode (34), master_registry (26), agent_client (33),
master_admin (26), master_jobs (21), master_receiver (11), p06_live_lab (8),
p06_standalone (3), p11_live_lab (11), p11_campaign (10), campaign_live_lab (7),
campaign_live_lab_controls (12), full_incident (5), persistence_dns (9),
standalone_ports (4), update_agent (7), update_nginx (8), single_vm_create (16),
installer_roles (6), install (13), installer/test_lab_mrnobody (8),
installer/test_single_vm_install (12).

Browser suites: lab_mode, lab_access_status, master_admin, p06_live_lab,
p11_live_lab, campaign_live_lab, master_overview, detection_validation.
The lab_mode suite includes a real Flask/Linux boundary and browser navigation;
the other suites use controlled API responses to test GUI interactions.

Security coverage includes rejected unknown Agent identities for 16 lab labels,
forged proxy/teacher/lab headers, valid-token/wrong-ID rejection, revoked
credentials, Master versus Slave roles, read-session versus operator authority,
Origin/CSRF, cross-installation ticket/cookie rejection, NAT/IP/DNS protocol
requests, P06/P11 receipts and Receiver, job idempotency and confirmed Stop.
The normal GUI no longer links to the handoff path and makes no mutation when
operator authority is absent or unavailable. A privileged compatibility handoff
still works and remains explicitly outside the zero-interaction claim.

## Corrections and reproducibility

An initial fresh-install contract failed because the new distributed guide was
missing from the explicit cloud-init download list. The list was corrected and
the fresh-install and updater suites passed on the updated export. A test-host
interruption stopped an earlier aggregate run; remaining suites were rerun and
all final per-suite logs report OK. No unchanged suite was counted as failing.

Tests used an exact staged Git-tree export to Linux, preserving repository
line endings and Linux ownership semantics. Run Python suites from INSTALLFILES
with `python3 tests/mrnobody/<suite>.py -q`; installer suites live under
`tests/installer/`. Browser suites require Playwright and a Chromium executable
via `MRN_CHROME_PATH`. `lab_mode.cjs` supports `MRN_FIXTURE_COMMAND` for a Linux
Python boundary process. Rebuild with `tools/build-manifest.sh` on an exact
Git export; verify SHA256 against the committed blob bytes, not a CRLF-converted
checkout. The manifest includes the new guide, and fresh-install downloads it.

## Not verified / not delivered

No VM was created or reinstalled. Actual Guacamole account/console permissions,
hypervisor provisioning, student routing and NAT, trusted TLS, 16 real lab
assignments, and full P01–P11 execution on fresh machines were not verified.
The portal lacks verified student/lab/teacher identity. Automatic trusted
pairing, scoped zero-interaction browser control and isolation of anonymous
read APIs are not implemented. Existing registrations are preserved, not
retroactively proven to belong to a trusted lab. Audit the registry before reuse.

Do not use a passing offline installer contract as approval to reinstall for
the requested ZTD access model. No deployment or main merge is included.
