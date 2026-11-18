# TEST-003 — Lab Mode network independent operation

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

## Operator authorization

Fresh installs and both normal/no-change `sudo mrnobody update` paths generate a
distinct 256-bit random key on each Lab Master and Slave, stored as root:root
0600 `/etc/mrnobody/lab-control.key`. Updates preserve it. It is never downloaded
from GitHub, printed in install logs or returned by a web API.

Read it locally with:

```sh
sudo cat /etc/mrnobody/lab-control.key
```

On Master, enter it at `/master/admin`. On either role, `/lab/control` authorizes
the local dashboard. The dashboard links to that page. A key authenticates only
its own VM. Agent/enrollment tokens are not operator credentials.

Anonymous sessions can read but cannot POST/PUT/PATCH/DELETE to operator APIs.
Successful login rotates the session ID and CSRF value. Sessions expire after
15 minutes and bind to the exact current origin (scheme, Host and port) and key
digest. No manually provisioned origin list is required: logging in separately
via IP and DNS creates separate origin-bound sessions. A changed source IP does
not revoke authority. Changed/missing/unreadable keys fail closed on the next
request. Logout revokes the session server-side.

Cookies remain HttpOnly and SameSite=Strict, with Secure on HTTPS. Writes require
the authenticated session, exact same Origin and CSRF token, bounded bodies and
rate limits. Cross-site fetches, frames and writes remain rejected. Top-level
read navigation from a link/redirect remains supported.

Use HTTPS to protect the key, sessions and Agent tokens in transit. Explicit Lab
HTTP remains available for compatible teaching deployments; HTTP cannot protect
credentials against someone observing the network.

## Agent and exercise protocol

P06 fixture uploads, P11 HTTP-beacon/ACK, Receiver events, reports, heartbeat and
job polling no longer reject a legitimate Agent because of source subnet or a
DNS/public/NAT Host. Each API still checks Agent ID/token, protocol version, exact
schema and size limits. P06 accepts only the fixed synthetic fixture with matching
size/SHA256/content. P11 validates its fixed marker, sequence and ACK. No arbitrary
commands, destinations or shell payloads were added to the job protocol.

Lab Mode retains zero-touch first-binding enrollment, now from any source:
the Agent persists its random per-VM token before registering; retries never
replace an existing identity/token or undo revocation. Enrollment and telemetry
are not proof of operator identity. An untrusted party can enroll a new Lab Agent
and submit synthetic telemetry, but cannot authorize job mutations. Use protected
mode and Master-issued pairing for deployments requiring controlled enrollment.
Existing bound identities and issued-token pairing continue to work.

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
   until the local Master key is entered. No subnet/origin allowlist edits.
3. Login at `/master/admin`, select one online Agent and start the fixed P11 job.
   Verify three authenticated beacons/ACKs in Receiver. Retry the same request key:
   the job ID must be unchanged. Start another job and Stop it; verify terminal
   state or deadline. Restart the worker and check that its journal prevents replay.
4. Authorize the Slave at `/lab/control`. Run explicit P06 Live Lab with its fixed
   generated file; verify content/SHA256 receipt at Master. Run local P11 and Full
   Incident opt-in flows; confirm Receiver evidence. Exercise DNS against the
   dedicated `.test` resolver from another routed subnet and through NAT; inspect
   resolver logs/packet capture for outbound queries and matching replies.
5. Test without login, with an Agent token as the control credential, a wrong key,
   missing/wrong CSRF, foreign Origin and after logout/expiry: no job mutation.
   The same valid key/session from a changed client IP must still work. A session
   copied to a different scheme/Host/port must fail. Replacing the local key must
   revoke old sessions. A changed Agent ID/token and altered P06 content must fail.
6. Fresh Big, Mini, Custom and Single VM deployments: repeat using both numeric
   and DNS Master URLs. Standalone/protected installs must retain their defaults.

Automated contracts: `python3 INSTALLFILES/tests/mrnobody/lab_mode.py` plus the
existing Master/Agent/P06/P11/DNS/installer/updater suites. Browser regression:
`node INSTALLFILES/tests/mrnobody/lab_mode.cjs` with Playwright installed. Tests
simulate remote peers, NAT-visible addresses, IP/DNS Hosts and forwarded headers;
actual student-network routing, packet capture and hypervisor fresh-install
acceptance must still be performed in CyberLab.
