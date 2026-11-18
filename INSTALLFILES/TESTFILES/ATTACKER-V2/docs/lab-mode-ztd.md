# Lab Mode: automatic access and Master–Slave binding

See [fresh-install Lab access](lab-access-preinstall.md) for the selected policy
and acceptance checks. In explicit Lab Mode all web visitors use controls
automatically. No login, key, activation link, portal SSO or teacher/student
distinction is required or implemented on that Master.

Fresh Master/Slave rendering enables Lab Mode for the selected roles. The
Slave's Master URL comes from deployment configuration. IP, DNS, routed
subnets, IPv6 clients and NAT ports are accepted. Agents initiate outbound
heartbeat, polling, transfers and beacons; Master needs no inbound route to
a Slave behind NAT. HTTP Lab transport remains supported; configured HTTPS
retains certificate and hostname verification. Routing/DNS remain deployment
prerequisites; the installer cannot discover an unknown Master across NAT.

First registration pins the persistent random Agent-ID/token automatically.
Later requests authenticate that binding. Wrong token, wrong ID or revoked
identity is rejected. Automatic enrollment does not expand the job protocol:
the remote API still supports only its fixed synthetic P11 job. Local P01–P11
and Full Campaign controls retain their existing parameters.

The browser obtains same-origin CSRF state automatically before writes. The
cookie carries no operator role, has no absolute login timeout, and needs no
server-side login session. Wrong Origin, cross-site browser requests and
missing/mismatched CSRF remain rejected. Service/browser restart needs no
manual activation. Old /lab/control bookmarks redirect to the dashboard.
Old login POSTs return 410; the legacy lab-open command only explains that
the normal web address can be opened directly.

Master Job Control automatically loads registered agents and recent jobs.
Select an online Slave and use Start/Stop. Retry identity, Stop confirmation
and execution bounds remain. Capacity limits allow 16 users; they do not
introduce authentication. Readiness does not enqueue a job.

Updates preserve deployment settings, registry, Agent identity and job journal.
No lab-control.key is created or read; old key/ticket files are ignored.
Compatibility modules contain no issuance/redemption implementation. Protected
Master mode retains its administrator credential/session behavior. Standalone
remains independent of Master/Slave transport.
