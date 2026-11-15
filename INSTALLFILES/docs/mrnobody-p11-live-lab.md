# P11 Live Lab – bounded HTTP(S) beacons

Live Lab is an explicit, unchecked option in **Attack Techniques → P11** on a
configured Slave Agent. It resets when the form is reopened. Existing P11
standalone/Simulated behavior, persistence methods, DNS activity and Full Campaign
defaults are retained. This sprint adds HTTP training traffic, not remote tasking.

## Behavior

1. Configure P11 Create against an authorized private lab target as before. Select
   the method, artifact suffix, and optional existing DNS settings. Those settings
   are passed to the existing persistence runner without modification.
2. Select **Live Lab**. After successful persistence creation, the **Slave Agent**
   sends a fixed `MRN-EXERCISE-ONLY` JSON beacon to its configured Master at
   `/api/master/agents/p11-beacon`. HTTP traffic originates from the Slave, not
   from the remote SSH/WinRM target. Target DNS traffic still originates on the
   target. Capture/block the corresponding source IP when teaching each activity.
3. First beacon is immediate after creation. Default interval is 30 seconds,
   maximum attempts 6, duration limit 180 seconds. Defaults produce attempts at
   roughly 0, 30, 60, 90, 120 and 150 seconds. Editable limits: interval 10–300s,
   attempts 1–60, duration 60–1800s; interval must fit the duration. First limit
   reached stops the loop. Failed attempts count toward the limit.
4. A temporary network/HTTP 408/425/429/5xx failure consumes one attempt and retries
   at the next interval. There is no immediate replay or catch-up burst. An
   authentication, TLS or ACK protocol error ends the loop. Each attempt runs in
   a disposable child, bounded by 10 seconds or the remaining lifetime; even a
   hung resolver or slow response cannot extend the HTTP activity indefinitely.
5. Master requires its Master role, a private lab source, and a registered,
   non-revoked Agent ID/token. Payload is at most 4096 bytes and has an exact fixed
   schema: agent, campaign, P11, sequence, UTC send timestamp and synthetic marker.
   Extra command/task fields are rejected. There are no inbound agent listeners.
6. Master atomically writes a `beacon` event in existing `receiver_events` and a
   `p11_receipts` record in `/var/lib/mrnobody/master/registry.sqlite3`. Only after
   commit does it return `MRN-EXERCISE-ACK`, event ID, sequence, campaign, agent and
   receipt time. The agent checks the exact ACK schema and matching identity.
   No response content is executed. The Receiver shows P11, verified receipt and
   sequence, with send time and Master receipt time kept separately. The `bytes`
   field is the fixed marker's byte length, not total HTTP wire size.
7. Ground Truth records `P11_BEACON_START`, `P11_BEACON_ACK`,
   `P11_BEACON_RETRY`, and `P11_BEACON_STOP` with counts/reason; ACK events link to
   the Master event ID. A received beacon proves receipt, not a sensor detection.
   Lost ACKs can leave a Master event even when the Slave records failure. Match
   campaign/agent/sequence before interpreting gaps. Attempts are not retransmitted.
   A run with no verified ACK, or a fatal protocol error, fails the phase. Partial
   network loss with at least one verified ACK remains complete with failure counts
   in Ground Truth; it does not claim every attempt arrived.

## Stop and cleanup

The existing **Stop** button stops the local execution process group, including
in-flight HTTP workers. Waiting between beacons is interruptible. No background
beacon daemon, startup entry or persisted Master task is installed. HTTP activity
does not restart after Stop or reboot.

Existing remote persistence/DNS artifacts follow their own fixed deadlines and
ownership checks. Stop of the local job does not remove remote artifacts. Uncheck
Live Lab and select **Cleanup** with the same target, credentials, method and
artifact suffix; then use Inspect/target telemetry to verify cleanup. Live Lab is
rejected for Cleanup and Inspect. Failed persistence creation never starts HTTP.

## Master/Slave update and configuration

`sudo mrnobody update` tracks **main**. A feature branch/PR must first be merged;
running update before merge will not install this sprint. Then update **Master
first, Slave second**:

```sh
sudo mrnobody update
```

If upgrading a very old updater, run update again. Identity, deployment settings
and Master database are retained. The new module is in the SHA256 update manifest
and the fresh-install download list; the new HTTP endpoint is added to nginx.

Use the existing `/etc/mrnobody/deployment.conf` settings and paired Agent identity
described in [Agent configuration](mrnobody-agent-client.md). For example:

```conf
MRNOBODY_ROLE=agent
MRNOBODY_MASTER_URL=https://master.lab.local
MRNOBODY_LAB_HTTP=0
```

An IPv4 URL connects directly; a DNS URL uses the Slave's system resolver.
Include the port in the URL if required. HTTPS checks CA trust and the certificate
name/IP; configure the existing Agent `ca_file` for a lab CA. Do not disable
verification. Plain HTTP requires `MRNOBODY_LAB_HTTP=1` on both Master and Slave
and sends the Agent bearer token in plaintext on the authorized lab network.
There is no automatic downgrade, redirect following or environment proxy use.
The P11 DNS resolver/domain fields control separate target DNS activity and do
not override HTTP destination resolution. Neither the IncidentVM field nor a
target IP changes the configured Master destination.

Check the Slave before testing:

```sh
sudo python3 /opt/nordic-attack/web/agent_client.py --check
systemctl is-active mrnobody-agent.service
```

## Short lab test

1. Confirm Slave appears online on Master. First run ordinary P11 without Live
   Lab and verify existing persistence/DNS behavior and absence of new HTTP beacon
   events. Clean up that artifact before the next run, or use a fresh suffix.
2. On Slave choose P11 Create, an authorized target and a fresh artifact suffix.
   Optionally enable existing target DNS. Check Live Lab, keep 30s/6/180s, run,
   and record the returned Campaign ID.
3. On Master open **Receiver over HTTPS**, filter Agent ID and Campaign ID. Expect
   P11 beacon events, sequences 1–6, verified receipt, send/receipt timestamps.
   Match event IDs with Slave Ground Truth/live output and your sensor capture.
4. In the lab firewall block **Slave → Master** before the next attempt. Master
   receipts should cease; Slave logs retry failures. Unblock before limits expire
   and verify a later sequence arrives. Regular Agent heartbeat/report sync can
   also be affected by this block. Blocking the target alone does not block the
   Slave-origin HTTP beacon.
5. Start another bounded run with a new suffix, press Stop during a wait or
   blocked request, and confirm no further attempts. A request already committed
   on Master can still appear. Uncheck Live Lab, run Cleanup for each created
   artifact, and independently confirm target persistence/DNS has stopped.

## Validation and remaining scope

`tests/mrnobody/p11_live_lab.py` covers real loopback HTTP transport/SQLite receipt,
ACK validation, authorization, schema/size bounds, storage rollback, cadence,
network retry, count/deadline, hung worker termination, API opt-in and unchanged
persistence/DNS/campaign dispatch. `p11_live_lab.cjs` checks the browser selection,
defaults, reset, DNS coexistence and cleanup guard. Existing P06, DNS, Linux/Windows
persistence, Full Campaign, Receiver, updater and installer checks remain required.
Tests use isolated fixtures; physical two-VM HTTPS, firewall and sensor verification
still require the classroom lab. Windows PowerShell/service runtime verification
requires Windows CI or an authorized Windows lab host.

Campaign integration now has a runtime-only API opt-in for Full Incident and
valid custom scenarios. See [Campaign Live Lab](../TESTFILES/ATTACKER-V2/docs/campaign-live-lab.md)
for verified scope, update instructions, Stop/cleanup and lab checks. The campaign
UI and schedules retain their existing defaults. Master-initiated start/stop on
one or multiple Slaves and P06 campaign Live Lab remain separate roadmap work.
