# Campaign Live Lab — first integration step

## Verified baseline

Inspected `main` at `ee9f596` (P11 PR #105), including P06 PR #104.

- P06 standalone creates/transfers its fixed synthetic fixture through the
  existing lab target flow, then forwards the locally verified fixture from the
  Slave to Master. Master checks exact content, size and SHA256, commits the
  receipt and links it to campaign/P06/agent. It accepts no arbitrary file path.
  This is one upload, not a periodic transfer. Campaign P06 still uses P03/P05
  staging, and its Live Lab guard explicitly rejects campaign mode. Existing
  P06 transport has a per-request timeout; it does not have P11's disposable
  worker/whole-attempt DNS deadline. P06 campaign integration remains a separate
  small step requiring a fixed-fixture path and bounded transport first.
- P11 standalone creates the existing persistence/activity, then sends bounded
  Slave-origin HTTP(S) beacons to the paired Master. Defaults: 30 seconds, six
  attempts, 180 seconds maximum. Master returns only a validated fixed ACK.
  Existing target DNS remains separate; HTTP traffic originates on the Slave.

## What this step enables

The existing `POST /api/scenario/<id>/start` endpoint accepts runtime JSON fields
`p11_live_lab: true`, `beacon_interval`, `beacon_count`, `beacon_duration`.
It supports Full Incident and valid custom scenarios with enabled P03 before
P11 Create. These are the same local Slave campaign/scenario runners as before.
This step does not add a campaign UI checkbox or scheduler setting; the selection
is not stored in scenario definitions, exports or schedules. Omission/false
retains the old default. Inherited Live Lab flags are cleared at campaign start.
P06 campaign Live Lab requests are explicitly rejected rather than silently ignored.

One foreground P11 loop starts only after **all** existing P11 target/method
actions succeed. No P03 targets, skipped/colliding artifacts, partial outcomes,
failed actions or Cleanup start HTTP traffic. Failed ACKs fail the phase after
successful target actions; cleanup is still required. One or more valid ACKs
with temporary losses retain existing standalone semantics, with attempt/failure
counts in Ground Truth. A successful receipt proves delivery, not SIEM detection.

The loop uses existing Master URL/IP/DNS, CA trust and paired Agent identity.
There are no new destination or credential settings. Each HTTP attempt is bounded
by 10 seconds or remaining lifetime, including DNS and response reading. Retry
consumes a scheduled attempt; no immediate replay. Authentication, TLS and ACK
schema errors stop the loop. No response is executed and no tasking is added.
Only P11 receives the live configuration from the structured phase adapter.

## Update Master and Slave

The feature branch must be merged into `main` before the normal updater installs
it. Update Master first and then each Slave:

```sh
sudo mrnobody update
sudo python3 /opt/nordic-attack/web/agent_client.py --check
systemctl is-active mrnobody-agent.service
```

Run the agent checks on Slaves. Existing deployment configuration, token/identity
and Master database are retained. Use `/etc/mrnobody/deployment.conf` and existing
Agent configuration to select Master DNS name or IP and optional port. HTTPS
uses certificate validation and the configured lab CA. HTTP requires the existing
explicit lab-HTTP setting on both ends. See `INSTALLFILES/docs/mrnobody-agent-client.md`
and `INSTALLFILES/docs/mrnobody-p11-live-lab.md` in the repository.

## Lab verification

1. On a paired Slave, run an ordinary campaign first. Expect no P11 HTTP beacon
   receipts. Use only your authorized isolated lab; Full Incident still runs its
   existing phases and creates remote exercise artifacts.
2. Open the Slave UI and its browser console. Start Full Incident with an explicit
   runtime choice (substitute lab credentials without saving them in a scenario):

   ```javascript
   const response = await fetch('/api/scenario/full-incident/start', {
     method: 'POST', headers: {'Content-Type':'application/json'},
     body: JSON.stringify({
       ssh_password: prompt('Lab SSH password'),
       rdp_password: prompt('Lab Windows password'),
       p11_live_lab: true,
       beacon_interval: 30, beacon_count: 6, beacon_duration: 180
     })
   });
   console.log(await response.json());
   ```

   For a configured custom scenario, substitute its `custom-…` ID. Keep P03
   before P11 Create. This API path needs the same access as the existing UI.
3. Record the campaign ID from the Slave overview/Ground Truth. On Master Receiver,
   filter campaign and agent. After successful P11 target actions, expect P11
   verified beacon receipts, sequence 1–6 around 30 seconds apart. Correlate each
   Master event ID with `P11_BEACON_ACK` in Slave Ground Truth and sensor capture.
4. Block Slave-to-Master HTTP(S) temporarily. Expect missing Master receipts and
   bounded retry events. Restore connectivity before the limits expire to observe
   a later sequence. Agent heartbeat/report sync may also be affected. Blocking
   only a target does not block the Slave-origin beacon.
5. Repeat with a fresh campaign, press the existing Stop during a wait or request,
   and verify no further beacon attempts after any in-flight receipt. No beacon
   daemon remains or restarts. A receipt already committed on Master can remain.
6. Stop the campaign before cleanup. Use existing standalone P11 Cleanup for each
   created/partial target/method with the exact `fc-…-method` suffix from Ground
   Truth, original account and transport. Leave Live Lab unchecked. Remote
   persistence/DNS follows its own deadline until cleaned up; local Stop does not
   remove it. See `p11-full-campaign.md` for cleanup ownership and verification.

## Tests and remaining roadmap

`INSTALLFILES/tests/mrnobody/campaign_live_lab.py` exercises API selection,
structured phase propagation, actual campaign dispatcher, real loopback HTTP ACK
and SQLite Receiver correlation. Target SSH/WinRM actions are fixture receipts;
this is not a claim of a physical multi-VM run. It also tests old defaults,
inherited flag isolation, custom scenarios, invalid selection, failure/skip/partial,
cleanup guards and actual Linux Stop of a hung HTTP child. Existing P06/P11
protocol, cadence/deadline/retry, DNS, persistence, scenario, updater and agent
tests remain regression gates.

P06 campaign Live Lab, campaign UI controls and Master remote start/stop of
individual phases or complete scenarios on one/multiple Slaves remain roadmap
work. The Master still receives events and heartbeat/report data; it cannot
remotely launch or stop these campaigns through this integration. Physical HTTPS,
firewall, SIEM and Windows service verification still require the classroom lab.
