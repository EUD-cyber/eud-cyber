# Settings → VM Connections

This is an intentionally **login-free lab administration API**. Every visitor
who can reach this portal can create, change and delete managed connections.
This follows the existing header-login lab model and the requested no-login UX.
There are no per-user roles. Put this instance behind the lab network boundary.
Do not present its Guacamole header session as proof of administrator identity.

## Design and existing installation review

The baseline at `d2ad198c7a60b4df63993239893f6de06fc2361a` uses Guacamole 1.6.0,
PostgreSQL 16, Nginx HTTPS, and a Flask/Gunicorn topology service with two workers.
The shipped database dump was made with PostgreSQL 15.2. Its connection ID,
parameter, entity permission and cascading foreign-key schema was reviewed.
The portal's 23 static links refer to fixed PostgreSQL connection IDs encoded as
`base64(connection_id + NUL + c + NUL + postgresql)`. Nginx supplies
`X-Remote-User: guacadmin`; there is no independent portal login. No running lab
database or actual installed VM inventory was available during implementation.

The new backend uses the **same PostgreSQL transaction** for Guacamole connection,
parameters, READ permission, portal metadata, audit and idempotency result.
No runtime JavaScript rewriting, database REST dual-write or compensating delete
is needed. `sessions.js` remains a historical reference; index.html loads sessions
from `/api/sessions`. A failed API request displays an error, never the stale list.

On first access, an advisory transaction lock creates `cyberlab_connection`,
`cyberlab_connection_operation`, `cyberlab_connection_audit` and a per-lab seed
marker. `legacy-sessions.json` preserves the old portal links/IDs. DB-only
RDP/SSH/VNC connections are also imported into Settings, initially hidden.
Existing HTTP/HTTPS links retain their original URLs and ports. Missing legacy
DB connections are marked missing and are omitted from the session API.
No Guacamole connection is recreated automatically if it is missing.

This migration preserves existing installations and their existing visibility;
it does **not** claim the old template VMs are installed or running. Automatic
filtering from actual install selections is a later installer integration.

## Behavior

- “Tilføj forbindelse” works even with an empty list. New protocols: RDP/SSH/VNC.
- Every imported/managed entry has Rediger/Fjern, plus a visibility checkbox.
- New entries get a real Guacamole ID and READ access for `GUACVM_PORTAL_USER`
  (default `guacadmin`), then appear in the portal when it is opened/refreshed.
- Passwords never return from the API. Omit `password` to preserve it; send `""`
  to clear it. The UI has a separate clear checkbox. Host, port, username/domain
  can change; other existing Guacamole parameters and permissions are retained.
- Removing an imported entry only removes its portal registration. Removing a
  newly managed entry deletes its Guacamole connection and cascading parameters/
  permissions. Both leave a tombstone, so first-run seeding cannot resurrect it.
- Shared Guacamole IDs across labs cannot be edited/deleted through this API.
- Changes are serialized across workers with an advisory lock. A `version` is
  mandatory for edit/remove. Stale versions return 409. Mutation retries require
  an `Idempotency-Key`; reusing it with different input returns 409.
- Audit records contain lab, key, action, revision and database timestamp, without
  credentials. There is deliberately no authenticated actor in this lab model.

## API for future install.sh/deploy.sh integration

Each GUACVM instance has `GUACVM_LAB_ID=1..16`. The installer substitutes the
cloud-init placeholder with the selected lab. Connect to the target lab's own
GUACVM URL. A request cannot select another lab. A separate database per GUACVM
remains the deployment model; if a database is deliberately shared, shared IDs
are protected from modification.

`GET /api/vm-connections` returns lab, safe connection fields, connectionId,
owned, visible, version and hasPassword. `GET /api/sessions` returns portal cards.

Create with a stable caller-selected key (keep it in the installation manifest):

```http
PUT /api/vm-connections/mrnobody-slave-ssh
Content-Type: application/json
Idempotency-Key: install-lab3-slave-ssh-v1

{"lab":3,"name":"MrNobody Slave","label":"MrNobody Slave SSH",
 "protocol":"ssh","host":"192.168.1.50","port":22,
 "username":"ubuntu","visible":true,"category":"Linux"}
```

Use the **same operation key and exact body** after an uncertain response.
For a subsequent update, GET the current version and PUT the desired fields plus
`version`, using a new operation key. DELETE the same URL with `{"version":2}`
and a new operation key. Preserve operation keys across deploy retries. GET after
a restart or ambiguous response to reconcile actual state; HTTP 200 means the
database transaction committed, not that the destination VM is reachable.

Rejects unknown fields, invalid hostnames/ports, protocol changes, new web
protocols, cross-lab input and oversized requests. JSON-only writes and Origin/
Sec-Fetch-Site checks prevent browser cross-site writes. No CORS is enabled.
Install scripts without an Origin header can use the same API without login.
Provide credentials through protected files/stdin, never shell command arguments
or logged JSON. Native Guacamole parameters store passwords as **plaintext in
PostgreSQL**, as Guacamole requires; they are not additionally stored in portal
metadata, audit or idempotency results. Request fingerprints are HMACs using a
mode-0600 persistent `/data/connections.key`, not guessable password hashes.
Database passwords are read from a read-only secret-file mount. Existing lab DB
password defaults are unchanged. Protect the Docker host, DB volume and backups.

## Deployment, update and rollback

Fresh installs download the API module, seed JSON and frontend assets via the
existing cloud-init process. Existing GUACVMs need these files copied from the
reviewed release and their Compose topology-api service updated with the new
environment and password-file mount shown in `GUACVM_userdata.yaml`. Set a real
lab number, not the placeholder. Create `/opt/guacamole/postgres-password` as
root, mode 0600, containing the **current** DB password. Do not rotate it merely
by changing this file. Retain `/opt/guacamole/data` and the PostgreSQL volume.
Do not rerun the shipped baseline DB restore as an update: that replaces user data.
Do not overwrite the existing cloud-init snippet unless intentionally rebuilding.

Before update, run `sudo /opt/guacamole/scripts/backup-guacamole-db.sh` and copy
the resulting backup to a protected timestamped path, retaining a copy of the
deployed code/Compose files and `/data/connections.key`. The backup helper now
uses working DB/user defaults rather than sourcing a nonexistent `.env` file.
Restart/recreate topology-api and Nginx after deployment. The first session API
request performs the additive migration atomically, including legacy import.

Any failed mutation rolls back all its DB writes. A sequence ID may be consumed;
this does not create a partial connection. A lost response can be safely retried.
For operator rollback, restore the protected pre-change database backup with
`restore-guacamole-db.sh` **after placing that backup at its configured path**.
The restore helper stops topology-api along with Guacamole/Nginx while replacing
the database, then restarts them. This is whole-database rollback: later changes
are also lost. Restore matching code/Compose and the key if rolling back release.
No automatic audit-based undo or point-in-time history of plaintext passwords
is created. Ordinary backups include portal metadata alongside Guacamole data.

## Validation and remaining lab acceptance

`tests/guacvm/test_connections.py` imports the actual shipped backup into a
**disposable** database; it destroys that database's public schema. Set
`GUACVM_TEST_DSN` to that disposable DB, install topology-api requirements, then
run it with Python 3.12. CI uses native PostgreSQL 16 and tests concurrent
idempotency, all protocols, permissions, migration, safe credential responses,
password preservation/clearing, lab isolation, conflict handling, visibility,
legacy deletion, JSON/origin validation and injected failure after DB writes.
`test_installation.py` checks Compose/cloud-init delivery and portal loading.

Actual end-to-end RDP/SSH/VNC handshakes to running lab VMs and fresh cloud-init
boot/update on Proxmox still require a real lab. A local API/browser test is not
proof that those target VM services are reachable.

## Roadmap (not implemented in this phase)

[Notion roadmap](https://app.notion.com/p/4234642110e6816989ffef1d76f1bb44).
Automatic connection reconciliation from install.sh/deploy.sh selections,
explicit automatic/manual ownership handoff, initial Big/Mini visibility from
the actual installed manifest and automatic MrNobody Slave registration.
HTTP/HTTPS creation must later support automatic NAT **creation/removal**,
port/rule conflict detection and transactional recovery with `nat.sh`.
This phase makes no changes to `nat.sh` or NAT rules.
