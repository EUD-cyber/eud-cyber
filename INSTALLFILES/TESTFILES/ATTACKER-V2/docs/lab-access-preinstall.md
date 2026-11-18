# Preinstall access gate — 2026-11-18

**Do not reinstall expecting zero-interaction web control. That requirement is blocked.**

Inspected main: `2fe2ed9cd6c7f39dc1862018d13ad3463c36197d` (merged PR #117).
Run `mrnobody lab-status` for a non-secret JSON readiness report. Exit 2 means
the requested zero-interaction authorization is unavailable; this is separate
from service health and from Agent connectivity.

## Concrete architecture blockers

`INSTALLFILES/GUACVM/nginx/nginx.conf` injects the constant
`X-Remote-User "guacadmin"`. `GUACVM_userdata.yaml` configures that header for
Guacamole authentication. The portal's static lab links do not provide a
verified user, lab assignment, or teacher/student role to MrNobody. NAT, DNS,
source addresses, an Agent bearer token, and arbitrary identity headers cannot
substitute for those facts. There is no implemented broker-to-VM trust path.

The old all-network Lab registration also accepted a new self-selected
Agent-ID/token. Persistence proves continuity, not permission to join this
Master. The API now requires an identity already issued by this Master.
This deliberately blocks unprovisioned fresh Slaves instead of claiming
secure zero-touch pairing. Existing valid registry/credential pairs keep working.

## Delivered safe scope

- Registration cannot enroll unknown identities, including from private nets,
  loopback proxies, or requests claiming `guacadmin`/teacher/lab headers.
- Master-issued tokens remain bound to their Agent-ID for registration,
  heartbeat, job polling, P06/P11 and Receiver. Revocation remains enforced.
- Automatic read access remains independent of subnet, IP or DNS origin.
  The GUI explains read-only authority without directing normal use into an
  activation-link workflow. Anonymous Master job Start/Stop remain denied.
- Session responses expose `lab_access` readiness, separately from the opaque
  read session and its CSRF token. Install/update provisioning prints a blocker
  warning; `lab-status` reports it without reading/exporting credentials.
- The existing privileged `lab-open` fallback, `/lab/control`, internal key and
  expiring operator sessions remain for compatibility. They are **not** a
  fulfillment of the requested removal. No automatic privileged browser,
  source-IP authorization, or anonymous global mutation was added.

## Required before the requested fresh install

1. Establish distinct authenticated portal users and server-side assignments
   for each of up to 16 labs; separate teacher Master rights from student rights.
   Restrict privileged VM consoles to their assigned users. Shared `guacadmin`
   access must not be used as evidence of isolation.
2. Implement authenticated provisioning that issues each Agent credential on
   its intended Master and securely installs it only on its assigned Slave.
   The existing `master_registry.py issue <agent-id>` and
   `agent_client.py --pair <private-json>` support explicit pairing; they are
   not an automated provisioning channel. Provisioning must supply the paired
   identity before automatic bootstrap creates its local, unapproved identity;
   `--pair` deliberately refuses to overwrite an existing identity. The current
   installer does not coordinate this ordering. Never clone live identity/key files.
3. Implement and verify a broker assertion or tightly scoped controller path:
   authenticated transport, pinned issuer, installation/lab audience, subject,
   role/capability scope, anti-replay, expiry, revocation and server-side
   target authorization. Student scope must never become Master-wide access.
   Existing browser portal authentication can then supply access without a
   second manual login. Do not trust raw `X-Remote-User` or source IP.
4. Use verified TLS end-to-end. HTTP Lab compatibility sends bearer tokens and
   session cookies in plaintext and is unsuitable on untrusted student networks.
5. Validate two clean real VMs, then all 16 lab assignments: installation,
   updater identity preservation, DNS/IP/NAT access, P01–P11/Full Campaign,
   Master P11 Start/Stop, Receiver and denial of unissued, revoked, cross-lab
   and student-to-Master mutations. Automated request simulations do not prove
   hypervisor, real NAT, Guacamole permissions or real clean installation.

Until those prerequisites are implemented, there is no secure way for the
current public web interface to distinguish an authorized operator from an
arbitrary visitor with zero interaction. This patch is a pairing safety fix
and an explicit readiness gate, not a completed ZTD access redesign.
