# P09 independent Full Campaign DC discovery

Full Campaign P09 reads candidates directly from P01's `discovered-hosts.json`, within the current incident's `networks.json` scope. P03 authentication, WinRM service flags, RDP classification and `compromised-hosts.json` do not gate P09. A prior P03 `candidate_probe_timeout` cannot exclude a P01 host.

Candidates must be private IPv4 addresses in the incident-matched P01 networks. Network exclusions, network/broadcast rejection, deduplication, numeric ordering, inventory size limits and the configured host maximum (hard maximum 254) apply. An optional `NORDIC_AD_DC_TARGET` must be present in current P01 scope; no manual pin or fixed DC address is required. Campaign discovery uses HTTP TCP 5985.

For each candidate, a separate bounded P09 worker:
1. Probes TCP 5985 with a two-second connection timeout.
2. Authenticates through WinRM/NTLM with runtime Windows credentials.
3. Executes a fixed read-only query verifying Windows OS, local computer identity, DomainRole 4/5, matching local AD domain/controller identity and `IsReadOnly=false`.
4. Returns only allowlisted outcome and identity fields.

An open port, HTTP 405 from GET /wsman, RDP success or misleading Windows metadata alone cannot qualify a DC. Kali and other non-Windows endpoints are rejected. The lowest numeric successfully verified writable DC is selected; probing stops at that first eligible candidate, and one AD action worker is dispatched. There is a 120-second discovery budget and a maximum 12 seconds per candidate worker. Budget exhaustion records the actual attempted count.

P09 logs `P09_DISCOVERY_START`, `P09_CANDIDATE source=p01_discovered_hosts`, `P09_DC_VERIFICATION` (probe, authentication and verification outcome), and `P09_DC_SELECTED` or `P09_DISCOVERY_EXHAUSTED`. Missing/stale P01 inventory, empty scope, closed ports, credential denial, non-Windows identity, non-DC, read-only/mismatched DC and timeouts have fixed diagnostic reasons. Mixed failures retain their individual candidate reasons and end with `no_verified_writable_dc`. Credentials, raw responses, scripts and exception text are never logged.

The existing P09 ownership checks, idempotent precheck/apply, independent postcheck and timeout recovery remain unchanged. Before writes, the action worker independently rechecks local DC identity and ownership. SUCCESS requires an enabled owned lab account and confirmed direct Domain Admins membership (domain SID plus RID 512). Existing valid state requires no unnecessary writes; uncertain writes are verified without replay.

Standalone P09 continues to use the manually entered endpoint, port and runtime credentials, with TCP preflight and DC-role verification. Campaign ordering and other phases are unchanged. P03 still records its own service evidence, but P09 does not require that evidence.

Offline regression tests reproduce all ten supplied P01 hosts, including a DC with failed P03 WinRM authentication and an RDP-classified Kali false positive. They cover absent/invalid/stale P03 inventories, stale P01, exclusions, no WinRM, non-DC/read-only DC, deterministic multiple DC selection, limits/deadlines, read-only probes, secret-safe evidence and reports. Existing standalone, ownership/idempotence and timeout recovery tests remain in CI. No VM deployment is included.

## Update and verify in the lab

After this change is merged to main, finish or stop the active campaign, then run:

```bash
sudo mrnobody update
```

Start a new Full Campaign with the normal runtime Windows credentials and without a mandatory DC IP. Check the new incident log for `P09_CANDIDATE source=p01_discovered_hosts`, per-host verification reasons, the selected writable DC, and P09's final account/group postverification. Standalone remains available with an explicit target. P11 is outside this fix.
