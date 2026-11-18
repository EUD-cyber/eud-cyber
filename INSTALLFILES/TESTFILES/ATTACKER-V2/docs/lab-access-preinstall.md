# Fresh-install Lab access — 2026-11-18

The selected Lab Mode model is open: every visitor who can reach this Master
can control all Slaves registered on it. There is no teacher/student
authorization split on a Master and no portal identity dependency. Each
separate Master installation has its own registry. A Slave exposes its own
local controls but does not expose the Master API.

## No manual authentication or pairing

Open the normal Master/Slave web address by IP or DNS, including a NAT port.
No key, password, lab-open, handoff link, /lab/control activation or expiring
login session is needed. Old /lab/control bookmarks redirect home.

The GUI obtains a CSRF token automatically. It prevents cross-site browser
requests; it is not an operator login or permission grant. It is recreated
automatically after a browser restart, without server login state or an
absolute timeout. The optional mrnobody lab-status diagnostic reports
open-lab and exits 0 for a loaded explicit Lab Mode installation.

## Automatic Master–Slave binding

The installer writes the selected role and reachable Master URL. A Slave
creates one random persistent Agent-ID/token in /etc/mrnobody/agent.json.
Its first registration automatically binds that ID/token on the configured
Lab Mode Master. Later registration, heartbeat, report transfer, polling,
P06/P11 and Receiver traffic must match the stored ID/token. Retries cannot
replace a binding or undo revocation. Master stores the token hash only.

First binding is intentionally automatic lab enrollment, not verified ownership
by a portal user. Any reachable new agent may enroll on a Lab Mode Master.
Web visitors may control every agent on that Master. No user/lab/teacher
identity is inferred from IP or headers. Separate Masters keep separate
registries, but a visitor who can reach another Master can also control it.
Normal updates and restarts preserve identity. Each new Slave must have a
unique identity; do not clone an already bootstrapped Slave identity.

## Install/update and acceptance

Main-based fresh installs/updaters receive these changes after merge.
No manual auth file edits are required. Existing control-key files are no
longer read or provisioned; old handoff state is ignored. Protected/non-Lab
authentication remains separate; Standalone has no Master connection.

Routing/DNS/NAT must already make the configured Master address reachable.
This change does not create routes or infer a Master address across networks.
The fixed remote P11 protocol is preserved: Start/Stop, idempotent retry,
bounded duration and Receiver receipts. Local P01–P11 and Full Campaign keep
their existing inputs and execution behavior.

For real deployment acceptance: install fresh Master and Slave, confirm
automatic registration and heartbeat, try IP/DNS from two subnets and NAT,
exercise P06/P11, Full Campaign and Master P11 Start/Stop, restart/update and
compare identities, then check distinct identities for all 16 Slaves.
Automated tests simulate network/registry behavior; actual VM provisioning
and real routing still require deployment validation.
