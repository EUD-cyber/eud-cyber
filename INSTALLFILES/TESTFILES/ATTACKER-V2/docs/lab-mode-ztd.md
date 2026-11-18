# Sprint 6 — Lab Mode & Zero-Touch Deployment

Lab Mode is a separate, explicit opt-in mode for controlled CyberLabs. It
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

**Every client in the configured networks using an approved control Host is trusted to administer Master and Slave**,
including local campaign/configuration functions already available to an operator.
Use isolated teaching networks with firewall boundaries; do not include an
untrusted/shared network. HTTP exposes Agent tokens, lab sessions, logs and
content to that network. This is not a secure substitute for protected mode.
Agent identity/token binding, strict job schemas, request/rate bounds and
same-origin/CSRF checks remain enabled to prevent mistakes and browser attacks.

### TEST-001: UI access and mutation authority are separate

Both Master and Slave UI reads work from **all source networks**, via IP or DNS,
including NAT, routed networks and VPN. The client does not have to be in
`MRNOBODY_LAB_NETWORKS`; a numeric private Host is not required for web reads.
HTTP and automatic sessions remain restricted to explicit, valid Lab Mode.
Protected/Standalone defaults are unchanged. The existing installer opt-in also
applies to existing Lab Mode installations after updating; no new global bypass
is enabled for other installations.

**All unsafe web methods (POST/PUT/PATCH/DELETE, including start, stop, update,
configuration and campaign changes) are separately denied** unless the observed
source is in `MRNOBODY_LAB_NETWORKS` and the Host is either a numeric private
address in those networks or an exact root-provisioned control origin. The
session endpoint reports `web_job_control=false` on read-only connections; the
Master control page disables start and stop there. A session/CSRF token alone
does not grant authority: the source/Host boundary is rechecked on every write.
Exact same-Origin, opaque session, CSRF, rate and request-size limits still apply.

Optional DNS control (add to root-owned `/etc/mrnobody/deployment.conf` on each
VM where needed, then update/restart):

```ini
MRNOBODY_LAB_CONTROL_ORIGINS=http://master.lab,http://slave.lab
```

Use only origins owned by the lab; include the exact scheme and non-default port
when used, with no slash/path/wildcard. This setting permits DNS control from
trusted sources, **never from an arbitrary source network**. Without it, DNS
access is read-only. Numeric private lab control retains the Sprint 6 behavior.
Unapproved DNS origins cannot mutate even from a trusted source (DNS rebinding).

For remote administration, connect through a trusted VPN whose observed private
source subnet is explicitly listed. Another option is a dedicated reverse proxy
that authenticates/authorizes operators **before forwarding**, connects from a
listed private source, and uses an approved backend Host. Never put an
unauthenticated public forwarder in a trusted source network: the backend would
trust all its users. Only local loopback nginx may supply X-Real-IP and scheme;
the supplied nginx template overwrites both headers. Do not trust arbitrary
forwarded headers, widen to all networks, or add public CIDRs to enable writes.

**Public read access is still dangerous**: reports, inventory, logs and lab
configuration can contain sensitive information. HTTP exposes sessions and data
to observers. Lab Mode is for deliberate controlled labs only, not internet
publication. Use a firewall/VPN for confidentiality and protected HTTPS mode for
untrusted environments. UI read access does not make public deployment safe.

### Agent job transport is unchanged

`MRNOBODY_LAB_NETWORKS` still scopes private plaintext Agent transport, including
its numeric private Master Host requirement. DNS browser access does not permit
DNS HTTP job transport. Agent-ID/token binding, job allowlist/idempotency,
Receiver schemas/protocol checks, heartbeat/ZTD and outbound NAT-friendly polling
remain intact. Keep the Master private numeric URL for HTTP Agents, or use the
existing verified HTTPS transport. No inbound Slave job port is added.

The dashboard opens directly from any network. `/master/admin` automatically
obtains an opaque HttpOnly/SameSite=Strict 15-minute lab session for CSRF and shows
fixed P11 control or a read-only notice without login. No administrator or Agent token is placed in the
page, URL or browser storage. The HTTP cookie cannot have Secure; HTTPS lab access
uses Secure. Mutation authority is network-based, so there is no meaningful administrator
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
separate mutation/transport network/Host enforcement and CSRF. TLS configuration and the existing Agent-specific
body limits remain. The generated active config is not an update-manifest entry;
the template and renderer are SHA256-verified distributed files.

## Existing installation: Master first, Slave second

Existing installations do not silently lose administrator protection on update.
After this PR is merged into the configured update branch:

1. Run `sudo mrnobody update` on Master. Existing protected-mode authentication stays in place.
   An already-enabled Lab Mode installation immediately receives all-network UI
   reads with separately protected mutations; keep its existing networks.
2. To explicitly migrate that isolated Master, run
   `sudo mrnobody lab-mode enable`. It discovers only RFC1918 subnets on local
   global IPv4 interfaces, validates and atomically writes the opt-in settings,
   then runs the updater to activate nginx/services. For trusted routed/VPN operators use
   `sudo mrnobody lab-mode enable --network 192.168.50.0/24 --network 10.134.71.0/24`
   with the actual Master/trusted-source networks. UI readers need no added subnet.
   Supplying networks replaces discovery.
   The command never overwrites an Agent identity or administrator credential.
3. Open `http://<Master-IP-or-DNS>/` and **Master P11 control** from another
   subnet, NAT and VPN. Verify no login or numeric-Host JSON error. An off-list
   client must read successfully but show read-only control and fail mutations.
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
| UI/control boundary | All-source IP/DNS reads; off-list writes denied; trusted control; cross-origin rejection | Not tested |
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
