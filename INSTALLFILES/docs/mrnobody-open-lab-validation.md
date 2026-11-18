# Open Lab Mode validation — 2026-11-18

Base: main 2fe2ed9cd6c7f39dc1862018d13ad3463c36197d, merged PR #117.
Selected behavior: [open Lab access](../TESTFILES/ATTACKER-V2/docs/lab-access-preinstall.md).

## Implemented behavior

All visitors to an explicitly configured Lab Mode Master can control every
Slave registered on it. Slave local GUI controls also open automatically.
There is no portal identity, teacher/student role, browser activation,
control-key read, login session, absolute login expiry or manual pairing step.
Protected/non-Lab authentication remains in its existing separate path.

The browser automatically obtains CSRF state before writes. This is request
integrity, not operator authorization. State survives a web-service restart
and has no absolute timeout; a new browser receives it automatically.
Origin/Fetch-Metadata, schema, payload bounds and execution bounds remain.
Request/job rate capacity was adjusted for 16 active lab users.

Agent first registration automatically pins the per-VM persistent ID/token.
Existing bindings cannot be replaced or unrevoked by registration. Subsequent
heartbeat, report transfer, jobpolling, P06/P11 and Receiver authenticate that
binding. A separate Master keeps its own registry. This is automatic lab
enrollment, not verified portal assignment; access to another Master also
permits control of that Master under the selected policy.

## Automated verification

280 top-level Python tests passed in 22 relevant Linux suites; nested suites
inside the fresh-install contract are not added to that count. Eight headless
Edge suites passed. This is not a complete run of every repository test.
All 70 distributed SHA256 manifest entries match the staged Git blob bytes.

Python: lab_mode (24), master_registry (26), agent_client (33), master_admin
(26), master_jobs (21), master_receiver (11), p06_live_lab (8), p06_standalone
(3), p11_live_lab (11), p11_campaign (10), campaign_live_lab (7),
campaign_live_lab_controls (12), full_incident (5), persistence_dns (9),
standalone_ports (4), update_agent (7), update_nginx (8), single_vm_create (16),
installer_roles (6), install (13), installer/test_lab_mrnobody (8),
installer/test_single_vm_install (12).

Browser: lab_mode, lab_access_status, master_admin, p06_live_lab, p11_live_lab,
campaign_live_lab, master_overview, detection_validation. The lab_mode browser
test uses a real Linux Flask boundary and verifies portal links/redirects,
IP/DNS and immediate Master/Slave writes without activation. Controlled API
browser tests verify no login POST, hidden login/logout, Start/retry/confirmed
Stop, automatic CSRF and three viewport widths.

Protocol tests cover NAT/subnet/IPv6 request simulation, automatic first
binding, mismatched/revoked tokens, 16 separate registries and distinct agent
tokens, automatic job-control access, P06/P11/Receiver and durable worker
receipts without replay. CSRF is tested after a year of clock advance and
against a new service instance with no server login state.

Tests run from an exact Git-tree export on Linux to preserve blob bytes and
Linux ownership semantics. Build the SHA256 manifest using tools/build-manifest.sh
on that export and verify against Git blobs. Fresh-install downloads the new
access guide. Old lab-open is informational only; /lab/control redirects home
and former login/activation POSTs return 410.

No actual VM was created/reinstalled. Real hypervisor/cloud-init boot, routing,
NAT, Guacamole permissions and full P01–P11 execution on fresh machines still
require deployment acceptance. No main merge or deployment is included.
