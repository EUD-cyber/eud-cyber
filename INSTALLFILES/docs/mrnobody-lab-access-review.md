# Lab Mode access review — 2026-11-18

Historical PR #117 review. Current preinstall status and enrollment policy:
[lab-access-preinstall.md](../TESTFILES/ATTACKER-V2/docs/lab-access-preinstall.md).
The verification counts below describe PR #117, not the later safety patch.

Base main: `6cfdb872b7576c7098be7c964d007d9d519e8ac3`.

## Delivered scope

Manual key login in explicit Lab Mode is replaced by a local root-authorized
one-use browser handoff. `sudo mrnobody lab-open <exact-origin>` prints a link
valid for 120 seconds; redemption establishes an eight-hour absolute session.
The internal installation key remains private and cannot be used as a browser
credential. Fresh install downloads the new module; the updater requires it and
the SHA256 manifest distributes it. No remote trust is enabled during install.

Server verification binds handoffs to the installation key, deployment role,
origin and expiry. Linux file locking serializes issuance/redemption across
processes. Opaque in-memory sessions remain per installation, and now include
role in their binding. CSRF/Origin, body limits and rate limits remain enforced.
Anonymous read sessions retain their previous 15-minute capacity lifetime.

Agent identity/token, polling over NAT, Receiver, job schema/idempotency/Stop,
P06/P11 and campaign execution are unchanged. The local Slave session cannot
access Master APIs. A trusted Master session still controls all registered
Agents; no per-student Master role is claimed. Standalone and protected-mode
authentication retain their existing behavior.

## Blocking deployment prerequisites

The inspected GUACVM nginx configuration supplies the constant `guacadmin`
header. The portal's static links and NAT do not establish user/lab/teacher
identity. Therefore this change does **not** deliver zero-click portal SSO.

Students need existing authorized terminal access only to their own Slave.
Only a teacher/trusted administrator may have a privileged Master terminal.
The current shared Guacamole admin setup must not be treated as proof of that
separation. If students can open other labs' privileged terminals, fix those
portal/OS permissions first. Cloned installations must have distinct internal
keys and Agent identities. HTTP compatibility remains; HTTPS is needed to
protect capabilities/cookies from network interception.

Future SSO needs authenticated distinct users, server-side lab/role assignment,
authenticated portal-to-VM trust, one-use audience-bound assertions, rotation
and revocation. No identity headers or source-IP allowlists substitute for it.

## Verification

287 top-level tests across 22 suites passed (nested suites also run from the
fresh-install suite). Coverage includes 31 Lab Mode tests, 16 distinct lab
bindings, cross-instance ticket/cookie rejection at the same private origin,
Slave versus Master, concurrent redemption in threads and separate processes,
manual-key/Agent-token rejection, CSRF/Origin, expiry/logout/key/role changes,
idempotent Start/confirmed Stop, and Master-worker-Receiver P11 completion.

Regression suites: master_admin, master_jobs, master_registry, master_receiver,
agent_client, p06_live_lab, p06_standalone, p11_live_lab, p11_campaign,
campaign_live_lab, campaign_live_lab_controls, full_incident, persistence_dns,
standalone_ports, update_agent, update_nginx, single_vm_create, installer_roles,
install, installer/test_lab_mrnobody and installer/test_single_vm_install.

Real headless Edge plus Linux Flask verified Master/Slave handoff redemption,
fragment/history removal, session reload, logout and replay rejection. Browser
UI regression covered IP/DNS navigation, anonymous Start/Stop disabled,
no job on login, CSRF, ambiguous-start retry, confirmed Stop and three widths.

One initial tmux test timed out; its complete suite passed on rerun. Windows
checkout line-ending conversion caused initial shell/manifest test failures;
the exact staged Git tree was exported to Linux and those suites passed.

This is not a live hypervisor deployment test or a verification of actual
Guacamole account permissions/NAT routing. After review/merge, use the concrete
acceptance guide in `TESTFILES/ATTACKER-V2/docs/lab-mode-ztd.md` on at least two
real labs, then repeat isolation checks across all 16. Do not run the main-based
updater expecting branch changes before merge.
