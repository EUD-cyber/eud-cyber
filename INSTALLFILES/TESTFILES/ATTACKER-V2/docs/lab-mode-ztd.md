# TEST-003 â€” Lab Mode network independent operation

**Preinstall gate:** See [lab-access-preinstall.md](lab-access-preinstall.md).
Zero-interaction operator authorization is not implemented. Registration now
requires Master-issued pairing; automatic offline Agent identity creation does
not authorize enrollment.

Explicit Lab Mode permits Master/Slave UI reads, bound Agent traffic and
credential-authorized operator changes across routed subnets and NAT, via IP or
DNS. The server must be reachable; this does not create routes, port forwards,
DNS records or firewall rules.

```ini
MRNOBODY_ROLE=master
MRNOBODY_LAB_MODE=1
MRNOBODY_LAB_HTTP=1
```

Existing `MRNOBODY_LAB_NETWORKS` and `MRNOBODY_LAB_CONTROL_ORIGINS` remain accepted
for configuration compatibility. They grant no authority and are not consulted
for transport or control. Networks may be omitted. Invalid existing values still
fail configuration validation. Protected mode and Standalone defaults remain intact.

## Local browser handoff: safe first step, not portal SSO

The current GUACVM portal is not a delegatable identity provider. In
`INSTALLFILES/GUACVM/nginx/nginx.conf`, `/guacamole/` injects the constant
`X-Remote-User "guacadmin"`. The static portal/session links and NAT routing do
not attest a student, lab assignment or teacher role. MrNobody trusts none of
these headers, source addresses or browser-selected lab/role values.

Manual control-key login has been removed from Lab Mode. On the **specific VM**
whose controls you are authorized to use, run from an already authorized terminal:

```sh
sudo mrnobody lab-open http://slave.lab
# On Master: trusted teacher/administrator only
sudo mrnobody lab-open https://master.lab:8443
```

Use the exact origin shown in the browser, without a trailing slash. Open the
printed link within two minutes. Browser JavaScript removes its fragment from
history before redeeming it via bounded same-origin JSON. It is not sent in the
initial HTTP URL, access-log request target or Referer, and is not stored in
localStorage/sessionStorage. Do not share or record the link: it is a temporary
bearer capability. Reissuing invalidates the previous unused link. Only one
redemption succeeds, including concurrent processes (Linux file lock).

This is an automatic browser handoff after local OS authorization, **not fully
automatic portal login**. Existing labs still require this command once per
browser origin/session. There is no key to retrieve, type or distribute, and no
15-minute re-login. The Lab Mode UI shows the command and hides the old password
form. Protected-mode administrator login remains unchanged.

Fresh install/update provisions and preserves a unique root:root 0600
`/etc/mrnobody/lab-control.key` as an internal installation binding. It is never
accepted as a browser credential. Do not copy this file or access/session state
between labs; cloned VMs need unique installation keys and Agent identities.
Handoff state is root-only under `/etc/mrnobody/lab-access` (0700), created on
first use. Normal/no-change updates preserve the internal key and Agent identity.
No installation link is published automatically, as the installer cannot know
which browser is authorized to receive it.

A handoff binds to the server's private installation key, root-owned deployment
role, exact origin and expiry. An Agent/Slave handoff grants only local controls;
Master APIs remain unavailable on Slaves. A Master handoff is an operator
capability across all registered Agents and must only be issued from a trusted
Master terminal. **Students must have no shell/sudo access to Master or other
students' Slaves.** The current shared Guacamole admin connection is not evidence
of this separation. An administrator must establish per-student remote desktop/
shell permissions before relying on local handoff in a shared portal. No student
identity or scoped student control on Master is claimed or implemented.

Sessions last eight hours (absolute lifetime), bind to the origin/key/role and
are revoked by logout, service restart or key/role change. Changing source IP is
allowed. Each installation holds independent random opaque session IDs. Anonymous
reads remain compatible, including existing inventory/Receiver/job-history reads;
this does not add confidentiality for public read APIs. Operator writes still
require session + exact Origin + CSRF, bounded bodies and rate limits. Agent
endpoints retain their independent ID/token authentication and schema checks.

HTTP Lab Mode is preserved. HTTP cannot protect handoff POSTs/session cookies or
Agent tokens from an on-path observer; use HTTPS where that threat matters. NAT
and routing supply reachability, never identity. This first step does not require
network allowlists or any changes to Guacamole/nginx routing.

### Blocking prerequisites for zero-click portal access

A future trusted portal/broker must authenticate real distinct users, verify lab
assignment and teacher/operator role server-side, and authenticate its backend
to each VM. It must issue short-lived, audience-bound, one-use assertions over a
protected channel, with replay prevention, key rotation and logout/revocation.
Student assertions must never become Master operator assertions. Direct backend
access and forged identity headers must remain harmless. Installers would need
to provision this trust and per-lab assignments for all 16 labs; updates must
preserve them. None of these are available in the inspected current GUACVM
configuration, so no simulated SSO or anonymous write bypass is enabled.

## Agent and exercise protocol

P06 fixture uploads, P11 HTTP-beacon/ACK, Receiver events, reports, heartbeat and
job polling no longer reject a legitimate Agent because of source subnet or a
DNS/public/NAT Host. Each API still checks Agent ID/token, protocol version, exact
schema and size limits. P06 accepts only the fixed synthetic fixture with matching
size/SHA256/content. P11 validates its fixed marker, sequence and ACK. No arbitrary
commands, destinations or shell payloads were added to the job protocol.

Lab Mode requires Master-issued pairing before first registration. The Agent's
offline-generated UUID/token alone is not accepted. Trusted provisioning must
deliver a matching Master-issued identity/token to the assigned Slave; that
automatic provisioning channel is not implemented. Existing bound identities
and issued-token pairing continue to work. Retries never replace an existing
identity/token or undo revocation. Pairing does not grant browser authorization.

Agents initiate polling, beacons and transfers, so Master needs no inbound route
to a Slave behind NAT. Set the Agent's root-owned `MRNOBODY_MASTER_URL` to the
reachable IP or DNS URL (including the external port if translated). HTTPS still
requires a trusted certificate matching that name/IP; redirects and environment
proxies remain disabled. Lab HTTP job polling requires explicit Lab Mode on the
Agent. Big/Mini/Custom and Single VM rendering now enable that mode for DNS URLs
as well as IP URLs. Existing non-Lab Agents can opt in locally using
`sudo mrnobody lab-mode enable`, which also runs the updater.

The fixed remote job remains one Agent/one active synthetic P11 job, with the
existing allowlist, request-key idempotency, durable worker journal, Stop and
180-second deadline. Online proves heartbeat, not worker health. P06/P11 local
and Full Incident pipelines keep their existing verified source/artifact checks.
No general remote phase/scenario execution was added.

P11 exercise DNS is separate from resolving the Master URL. It already sends
outbound UDP to an explicitly selected lab resolver without a local-subnet
check. Keep its dedicated non-forwarding `.test` resolver and RD=0 queries;
private target/fixture validation prevents arbitrary public targeting. Routing
and NAT must allow outbound UDP/53 and the matching reply. This change does not
turn a public recursive DNS service into an exercise receiver.

## Concrete acceptance guide

1. After merging, run `sudo mrnobody update` on Master and Slave. Keep the existing
   deployment role, Agent identity and database. Run update again and confirm the
   key and Agent identity remain unchanged. Check the web, Agent and job-worker
   systemd services on the appropriate roles.
2. From two different routed student subnets and a NAT connection, open both UIs
   by IP and DNS. Anonymous reads must work. Master Start/Stop must remain disabled
   until a local Master handoff has been redeemed. No subnet/origin allowlist edits.
3. Use `sudo mrnobody lab-open <origin>` on Master, open the link, then at `/master/admin` select one online Agent and start the fixed P11 job.
   Verify three authenticated beacons/ACKs in Receiver. Retry the same request key:
   the job ID must be unchanged. Start another job and Stop it; verify terminal
   state or deadline. Restart the worker and check that its journal prevents replay.
4. Issue and redeem a separate local Slave handoff at `/lab/control`. Run explicit P06 Live Lab with its fixed
   generated file; verify content/SHA256 receipt at Master. Run local P11 and Full
   Incident opt-in flows; confirm Receiver evidence. Exercise DNS against the
   dedicated `.test` resolver from another routed subnet and through NAT; inspect
   resolver logs/packet capture for outbound queries and matching replies.
5. Test without login, with an Agent token as the control credential, an invalid/expired/reused handoff,
   missing/wrong CSRF, foreign Origin and after logout/expiry: no job mutation.
   The same valid session from a changed client IP must still work. A session
   copied to a different scheme/Host/port must fail. Replacing the local key must
   revoke old sessions. A changed Agent ID/token and altered P06 content must fail.
6. Fresh Big, Mini, Custom and Single VM deployments: repeat using both numeric
   and DNS Master URLs. Standalone/protected installs must retain their defaults.

Automated contracts: `sudo python3 INSTALLFILES/tests/mrnobody/lab_mode.py` plus the
existing Master/Agent/P06/P11/DNS/installer/updater suites. Browser regression:
`sudo -E node INSTALLFILES/tests/mrnobody/lab_mode.cjs` with Playwright installed
and a headless Chromium/Edge runtime available. Linux/root runs also exercise
real handoff redemption in the browser; other hosts run read-navigation/UI mocks. Tests
simulate remote peers, NAT-visible addresses, IP/DNS Hosts and forwarded headers;
actual student-network routing, packet capture and hypervisor fresh-install
acceptance must still be performed in CyberLab.

### Isolation acceptance (two labs minimum; repeat across 16)

- Issue a link on Slave A. POST its handoff to Slave B and Master: 401; neither
  may mutate jobs/config. Redeem it on A: success once, replay: 401. An Agent
  token or the former control key must also fail browser login.
- Reissue a link, switch the origin or root-owned role/key before redemption:
  reject. Reissue again, wait over 120 seconds: reject. Try concurrent redemption:
  exactly one success. Copy A's session cookie/CSRF to B/Master: no authority.
- On A run local P01-P11/Full Campaign with explicit exercise opt-ins. Its Master
  job endpoints must return 404 even with A's valid session. Test Master Start,
  same request-key retry and confirmed Stop as teacher; no automatic job on login.
- Wait over 15 minutes: session still authorized. At eight hours: writes denied.
  Repeat missing CSRF, wrong Origin, cross-site fetch, logout and service restart.
- Verify real portal permissions separately: a student cannot open Master or
  another student's privileged terminal. If they can, local OS authorization
  cannot distinguish them: fix portal permissions before enabling shared access.

Automated tests model 16 installation bindings, concurrent one-use redemption,
role/key/origin/expiry changes and full Master->worker->Receiver P11 completion.
They do not prove live Guacamole account separation, actual NAT routing or VM
provisioning on a hypervisor. Those require the deployment acceptance steps.
