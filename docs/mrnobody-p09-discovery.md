# P09 Full Campaign DC discovery

Full Campaign uses the current incident's P01 discovered-host and network inventories. It does not consume P03 platform, RDP, compromise or DC metadata. No address is hardcoded.

Candidates must be RFC1918 IPv4 hosts inside an eligible P01 network, outside configured excluded networks, and present in the discovered-host inventory. Network and broadcast addresses are excluded. Missing, stale, malformed or oversized inventories fail closed. An optional NORDIC_AD_DC_TARGET pin must satisfy the same inventory and scope checks.

Candidates are deduplicated and sorted by numeric IPv4 address. At most NORDIC_MAX_DISCOVERED_HOSTS (hard maximum 254) are accepted. Discovery has a 120-second total budget, a 12-second subprocess deadline per candidate, and a two-second TCP connect timeout. Only TCP 5985 is probed. The first authenticated, verified writable DC is selected, so only one DC receives the account reconciliation. If the budget expires before an eligible DC is reached, the phase skips with that reason.

A reachable port is not proof of Windows or a DC. The discovery worker authenticates with the existing runtime Windows username/password using WinRM NTLM. A read-only PowerShell query checks local DomainRole 4/5, loads ActiveDirectory, reads the local domain and controller, rejects read-only DCs, and checks the controller name and domain against the local system. No AD writes occur during selection. Rejected candidates include Kali/non-DC hosts, denied credentials, inaccessible WinRM and unverifiable DC identities.

The selected target then uses the existing P09 independent precheck, ownership and identity checks, idempotent apply, independent postcheck and timeout recovery. SUCCESS still requires a confirmed enabled owned lab account and direct Domain Admins membership (domain SID + RID 512). Existing accounts/membership are verified without unnecessary writes. Standalone keeps the supplied target, protocol, port and runtime credentials, including its existing DC-role verification.

Ground Truth records P09_DISCOVERY_START, P09_CANDIDATE, P09_DC_VERIFICATION, P09_DC_SELECTED or P09_DISCOVERY_EXHAUSTED. Only fixed diagnostics and validated identity fields are emitted; passwords, scripts, exception text and raw remote output are omitted. Reports include discovery evidence alongside the action outcome. Missing prerequisites return the existing skip code 78; uncertain AD actions retain partial results and are never relabeled discovery skips.

Offline regression tests cover P01 discovery of 192.168.2.200, misleading P03 RDP metadata for Kali 192.168.1.120, closed WinRM, non-DCs, denied credentials, read-only DCs, scope and incident isolation, explicit pins, multiple DCs, candidate limits, time budgets, malformed responses and report evidence. Existing reconciliation, rerun, standalone and timeout recovery suites remain enabled. No VM deployment or real AD changes are performed by these tests.
