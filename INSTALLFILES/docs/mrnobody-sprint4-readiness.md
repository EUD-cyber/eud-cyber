# Sprint 4 prerequisite audit and update guide

Audited main: `6a557e4` (PR #106), 15 November 2026. Recent commits:
`56ac4e0` fresh-install campaign guide, `446530c` campaign CI,
`6cb958d` bounded P11 campaign integration, following P06/P11 PRs #104/#105.

## Result and implemented scope

Sprint 3 remote control is absent. `master_api.py` has identity, heartbeat,
report inventory/transfer and receiver routes only. `agent_client.py` accepts
only registration, heartbeat, reports, report-transfer, fixed P06 file and P11
beacon operations. Report-transfer polling requests a finalized report, never
an execution job. Local phase/scenario endpoints are not remote Master control.

The smallest step implemented here is a read-only prerequisite display in
Master > Agents. `GET /api/master/agents` adds `control_capabilities`, explicitly
false for remote phase/scenario start/stop, execution job polling and multi-agent
campaigns. It is present even before registry initialization. Old/malformed or
unexpected capability values display Unverified. Heartbeat contact never implies
execution support. No submission controls or queue are introduced.

This does not implement remote start/stop or complete Sprint 4. No jobs are
created, so there are no new duplicate, partial-failure, offline-delivery or
cleanup semantics. Those remain prerequisites for any execution feature.
Existing standalone/local runners, credentials, ZTD, heartbeat protocol v1,
P06/P11, DNS, receiver and report synchronization are unchanged.

## Update and manual verification

After this branch is merged into main, use the existing updater on Master:

```sh
sudo mrnobody update
```

1. Open Master over its existing lab HTTPS address; reload the page so the new
   JavaScript is loaded. Open Agents and press Refresh agents.
2. Confirm six prerequisites show Not implemented, including remote start,
   stop and execution job polling. This also works with an empty agent registry.
3. Confirm existing agent details and synchronized report links still work.
4. Slaves require no update for this read-only step. To align versions, run the
   same updater on each Slave, then check the existing pairing and service:

   ```sh
   sudo python3 /opt/nordic-attack/web/agent_client.py --check
   systemctl is-active mrnobody-agent.service
   ```

5. A paired Slave should refresh its heartbeat normally. Stop its agent service
   only on an idle test VM and wait more than 90 seconds: Master should report
   Offline. Restart it and confirm Online returns. This changes contact status
   only; no queued campaign may start. Do not revoke or replace its identity.
6. Existing local runs still use the Slave's existing Stop and phase-specific
   Cleanup. This update starts no remote activity and has no new cleanup action.

## Automated verification

From `INSTALLFILES`, run the existing suites:

```sh
python tests/mrnobody/master_registry.py
python tests/mrnobody/agent_client.py
python tests/mrnobody/master_reports.py
python tests/mrnobody/master_receiver.py
python tests/mrnobody/p06_live_lab.py
python tests/mrnobody/p11_live_lab.py
python tests/mrnobody/campaign_live_lab.py
node tests/mrnobody/master_overview.cjs
```

The browser suite uses Playwright as configured in existing CI. Registry tests
check false capabilities for online and empty registries, existing role/TLS
boundaries and unchanged routes. Browser tests check explicit unsupported states,
missing/future capability fallback, absence of action controls, and the existing
agent/report/contact views. No attacks or network scenarios are run by the tests.

Validation on 15 November 2026: all 103 Python tests in the seven suites above
passed from a temporary Ubuntu filesystem copy with Flask installed; no skips.
The Master Agents Playwright suite passed using local fixtures and blocked writes.
The existing manifest builder regenerated SHA256 entries for the two changed
distributed files. Windows-only database cleanup/file-permission failures were
resolved by validating in Linux; no production behavior was changed for them.
These checks do not replace verification on the actual lab VMs.
