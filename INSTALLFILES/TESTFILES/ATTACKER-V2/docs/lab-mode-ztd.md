# Sprint 6 — Lab Mode & Zero-Touch Deployment

Lab Mode is a separate, explicit network-trust mode for isolated CyberLabs. It
removes manual web administrator provisioning and permits HTTP for the existing
fixed synthetic P11 job. It does not add remote P01–P11, scenario or multi-Agent
execution. The existing single active job, fixed operation, idempotency key,
durable worker journal, Stop and deadline semantics are retained.

## Trust boundary

The deployment must have all three settings, with a valid Master/Agent role:

```ini
MRNOBODY_LAB_HTTP=1
MRNOBODY_LAB_MODE=1
MRNOBODY_LAB_NETWORKS=192.168.50.0/24
```

Networks are an explicit comma-separated allowlist of RFC1918 IPv4 CIDRs (maximum
16). No public ranges, loopback, CGNAT or IPv6 ranges are accepted in this first
slice. Lab Mode config must be a regular, unlinked root-owned file, not writable
by group/others. Invalid deployment settings block dynamic web access.

**Every client in the configured networks is trusted to administer Master**,
including local campaign/configuration functions already available to an operator.
Use isolated teaching networks with firewall boundaries; do not include an
untrusted/shared network. HTTP exposes Agent tokens, lab sessions, logs and
content to that network. This is not a secure substitute for protected mode.
Agent identity/token binding, strict job schemas, request/rate bounds and
same-origin/CSRF checks remain enabled to prevent mistakes and browser attacks.

Master checks both the actual client IP and a numeric private Host against the
configured allowlist. Only local loopback nginx may provide X-Real-IP and scheme;
its config overwrites those headers. Public clients, other private networks,
DNS-based Host names and cross-origin browser requests are refused. Use the
Master's literal private IPv4 URL. For NAT, allow the source address/subnet that
Master actually observes, plus the subnet containing Master itself. Do not widen
to all private networks just to make a test pass.

The dashboard opens directly on an allowed network. `/master/admin` automatically
obtains an opaque HttpOnly/SameSite=Strict 15-minute lab session for CSRF and shows
fixed P11 control without login. No administrator or Agent token is placed in the
page, URL or browser storage. The HTTP cookie cannot have Secure; HTTPS lab access
uses Secure. Lab access is network-based, so there is no meaningful administrator
logout in this mode. Root configuration and a service reload control the mode.

HTTPS remains available and Agent certificate/hostname verification remains
mandatory when an HTTPS Master URL is configured. There is no TLS fallback or
disabled verification. `MRNOBODY_LAB_HTTP=1` alone continues to mean the existing
limited Agent lab transport; it does not enable credential-free UI or HTTP jobs.
Protected mode still requires the existing root-provisioned administrator.

## New controlled installations

The shared Big/Mini/Custom MrNobody installer writes Lab Mode for an Agent with
an explicit numeric RFC1918 Master URL. Its own lab LAN1/LAN2/OOBM subnets and
that Master /32 form the Agent allowlist. The Single VM renderer similarly uses
the selected private interface subnet (and existing lab interfaces where used),
plus the numeric private Master /32 for Agents. Private Single VM Master plans
with lab HTTP selected enable Lab Mode; `lab_http=false` retains protected mode.
Standalone, public/test-address plans and legacy DNS URL plans do not gain
credential-free access automatically. No shared template is modified in place.

Fresh install bootstraps/reuses the persistent per-VM Agent identity, activates
heartbeat and automatically installs/enables `mrnobody-agent-jobs.service` only
for valid Lab Mode Agents. Starting the service merely polls; it does not start
a job. Registration can retry while Master is offline. No inbound Slave port or
NAT forwarding is added. Existing IDs, tokens, reports and journals are retained.
Master/Standalone do not activate either Agent worker.

nginx's distributed template retains protected HTTP redirects. Installation and
update render the HTTP reverse proxy only for explicit Lab Mode, with backend
network/Host/CSRF enforcement. TLS configuration and the existing Agent-specific
body limits remain. The generated active config is not an update-manifest entry;
the template and renderer are SHA256-verified distributed files.

## Existing installation: Master first, Slave second

Existing installations do not silently lose administrator protection on update.
After this PR is merged into the configured update branch:

1. Run `sudo mrnobody update` on Master. Existing authentication stays in place.
2. To explicitly migrate that isolated Master, run
   `sudo mrnobody lab-mode enable`. It discovers only RFC1918 subnets on local
   global IPv4 interfaces, validates and atomically writes the opt-in settings,
   then runs the updater to activate nginx/services. For routed clients use
   `sudo mrnobody lab-mode enable --network 192.168.50.0/24 --network 10.134.71.0/24`
   with the actual Master/client networks. Supplying networks replaces discovery.
   The command never overwrites an Agent identity or administrator credential.
3. Open `http://<Master-private-IPv4>/` and **Master P11 control**. Verify the Lab
   Mode notice and absence of a login form. An off-allowlist client must fail.
4. On Slave run `sudo mrnobody update`, then explicitly opt into the same mode
   with `sudo mrnobody lab-mode enable`. Its configured numeric Master IP is
   added as /32. No manual systemd configuration or pairing is needed for an
   existing valid lab identity. A DNS HTTP Master URL must first be changed to
   its intended private IPv4 in the root-owned deployment config; it is never
   resolved or guessed by migration.
5. Verify `systemctl is-active mrnobody-agent mrnobody-agent-jobs` on the Slave,
   online heartbeat on Master, an explicit P11 start, exactly three receipts,
   status refresh, confirmed Stop, an offline queued-job deadline, and no replay
   after restarting the worker. Online alone is still heartbeat evidence.

An old updater may need a second `sudo mrnobody update` pass to execute the new
repair logic. The already-current path also repairs units/nginx and reloads Lab
Mode configuration. Job-unit activation failures restore the prior unit and
enabled/active state. Updating/restarting a worker can interrupt an active job;
the journal fails uncertain work rather than rerunning it. Update between jobs.

To return to protected mode, as root set `MRNOBODY_LAB_MODE=0` (or remove it),
retain the administrator credential, provision one if missing using the existing
guide, run `sudo mrnobody update`, and restart `nordic-incident-web.service` to
load the changed mode. Remove/disable the automatic job unit explicitly if it is
no longer desired; protected HTTPS workers remain an explicit existing opt-in.

## Integration & Acceptance Testing

Automated fixtures are not proof of real VM/network acceptance. After Sprint 6,
record **Passed / Failed / Blocked / Not tested**, the exact commit/configuration,
logs, expected result and actual result for each item:

| Area | Actual lab acceptance required | Initial state |
|---|---|---|
| Install/ZTD | Big, Mini, Custom, Single Master/Slave; correct role/IP/services | Not tested |
| Network trust | Allowed UI; disallowed private/public peer; cross-origin rejection | Not tested |
| Agent lifecycle | Offline Master retry, heartbeat, stable ID/token after reboot/update | Not tested |
| Fixed P11 queue | Start/status/Stop/deadline, worker reboot, no duplicate effects | Not tested |
| P01–P11 | Each locally supported phase, prerequisites, actual evidence and cleanup | Not tested |
| P06/P11 Live Lab | Fixed file/hash, HTTP beacon/ACK, DNS/persistence and interruption | Not tested |
| Full Incident | Existing local scenario selections and combined Ground Truth | Not tested |
| Detection | Real Wazuh/Suricata provenance, clocks/NAT, imported correlation limits | Not tested |
| Reports/regression | JSON/HTML/PDF, Master synchronization, update preservation | Not tested |
| General remote phases/scenarios/multi-Agent | Not implemented; do not claim acceptance | Blocked |

Test one approved lab at a time. Fix failures individually and repeat affected
checks. Do not label the platform ready for teaching until the supported flows
have passed actual VM acceptance, especially Stop/cleanup and post-reboot state.
