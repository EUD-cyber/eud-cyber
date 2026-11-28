# Remove an offline Agent from Master

Source task: https://app.notion.com/p/4234642110e6814194dde25e55e54d6e

## Update Master and use the GUI

After this change has been merged to `main`, run on the **Master VM**:

```sh
sudo mrnobody update
sudo systemctl is-active nordic-incident-web
```

The existing manifest updater verifies file hashes and restarts the web service
when web files change. If the files have updated but the service needs restarting:

```sh
sudo systemctl restart nordic-incident-web
```

No Slave update, reinstall, new port or manual database migration is needed.
Fresh installs download the same backend/GUI modules and this guide. The update
manifest includes them; credentials and `/var/lib/mrnobody` are not distributed.

1. Reload the Master browser with **Ctrl+F5**. Use the existing administrator
   login in protected mode; explicit Lab Mode keeps its current access model.
2. Open **Agents**, then **Refresh agents**. Match the old VM's full Agent ID,
   name and last heartbeat. Do not identify a VM by its list position.
3. Click **Remove** next to that offline Agent. Online, pending and revoked
   entries have disabled Remove buttons. Offline means more than 90 seconds
   since the last heartbeat; it does not prove the VM has been deleted.
4. Read the warning and type that entry's **exact Agent ID**, then confirm.
   Cancel or a mismatched ID leaves the registration untouched.
5. The Agent disappears from the active list after the server commits removal.
   A returning heartbeat or an active job causes a conflict instead. Refresh
   after an error; a repeated confirmed request is idempotent if already removed.
6. Use **Load removed agents**, then **View removed agent …** for the retained
   identity, removal timestamp, operator category and synchronized report links.
   **View retained Receiver events** opens the filtered event API. Existing
   Receiver filters and job history still use the same Agent ID.

If blocked by an active job, use the existing fixed P11 job control at
`/master/admin` to inspect/stop it. A queued job can stop immediately; a delivered
or running job needs a terminal result or deadline reconciliation by the existing
job controls/history. Refresh history and resolve the job before retrying Remove.
Removal never silently stops, expires or edits jobs, including other Agents' jobs.

## If a powered-off VM returns

Removal permanently revokes this registration. Old credentials receive HTTP 401
on registration, heartbeat, report upload, Receiver submission and job polling.
Lab Mode's automatic first-binding cannot revive the ID, even with another token.
The retained ID is reserved; issuing it again is rejected. The Agent client does
not automatically rotate identity after denial. It must be deliberately set up
with a **new ID and token** through the existing pairing/bootstrap procedure if
the operator wants to use the VM again. Historical evidence stays on the old ID.

There is no automatic removal of offline Agents. Leave a temporarily powered-off
VM registered if it should resume using its existing identity.

## Storage, retention and authority

The registry is `/var/lib/mrnobody/master/registry.sqlite3`, outside
`/opt/nordic-attack`. Existing Linux directory/file modes remain 0700/0600.
The existing root web-service identity writes it; there is no new filesystem
permission, service, database daemon or credential.

`POST /api/master/admin/agents/<agent_id>/remove` accepts only bounded JSON:
`{"confirm_agent_id":"<agent_id>"}`. Existing global operator authorization,
HTTPS/session/Origin/CSRF checks in protected mode and existing Origin/CSRF checks
in explicit Lab Mode apply unchanged. Agent bearer tokens grant no operator
authority in protected mode. The route is not an Agent transport exemption.

One SQLite `BEGIN IMMEDIATE` transaction validates the current registered,
non-revoked OFFLINE status and absence of nonterminal `execution_jobs`, inserts
one `agent_removals` audit/tombstone, sets `revoked=1` and destroys `token_hash`.
Unknown future job states also block. Heartbeat, enrollment, removal and enqueue
use the same write lock. Failure rolls back both revocation and audit insertion.
The additive tombstone table is created only on successful removal; older
registries and read-only list operations need no migration.

The original agent row/name/last-seen information remains. Active lists exclude
only IDs with a removal tombstone. `GET /api/master/admin/removed-agents` returns
their retained metadata and report inventory without token hashes. The audit
records the server-selected operator category (`master-operator` or
`lab-operator`), not a named person; the existing authorization model has no
individual operator accounts. Repeated removal preserves the original audit.

Historical jobs, Receiver events and P06/P11 receipts, report inventories and
already synchronized finalized snapshots are retained unchanged. Report viewing
for removed Agents remains behind the existing Master read authorization. An
ordinary CLI-revoked Agent without a removal tombstone keeps its previous report
access behavior. Data never synchronized before removal cannot be recovered.
Nothing is cascaded or physically purged. To preserve revocation and history,
retain/backup the complete registry; manually deleting tombstones or the database
also deletes that protection. Existing job retention and bounded history views
are unchanged.

## Validation

Automated tests use temporary registries and browser fixtures, with no live VM
deletion, lab traffic, campaign execution or production Agent removal:

```sh
cd INSTALLFILES
python3 tests/mrnobody/agent_removal.py -v
node tests/mrnobody/agent_removal.cjs
```

The browser test requires Playwright/Chromium. CI runs both. Backend coverage
includes exact confirmation, offline boundary, active jobs, concurrent heartbeat,
transaction rollback, restart/idempotency, credential denial, Lab re-enrollment
denial, retained evidence, other-Agent isolation, role checks and CSRF. Browser
coverage includes per-row controls, cancellation, wrong ID, conflict, network
failure, stale online status, CSRF forwarding, retained reports, escaped names
and desktop/tablet/mobile widths.

Remaining live acceptance: update a lab Master, register a disposable Agent,
power it off or delete its VM, wait over 90 seconds, remove its exact ID in the
GUI, restart the old VM if available and verify denied credentials, confirm
other Agents/jobs continue, and verify history after a Master service restart.
