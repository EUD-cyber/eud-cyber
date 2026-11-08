# P03 WinRM discovery and P09 DC verification

Full Campaign uses this flow: P01 discovers in-scope hosts and networks; P03 checks SSH, RDP and WinRM HTTP; P09 selects authenticated WinRM services and independently verifies the writable DC role before AD changes. A successful RDP login is not evidence of WinRM or a DC.

P03's WinRM check probes TCP 5985 on current P01 hosts within their authorized RFC1918 networks, honoring network exclusions. Candidates are incident-matched, deduplicated, numerically sorted and bounded to the configured maximum (hard maximum 254). WinRM discovery has a 120-second total budget, 12 seconds per worker and a two-second TCP connection timeout. No other ports are added by this change.

An open port is only a candidate. P03 then authenticates once with the runtime Windows credentials using the existing WinRM NTLM runtime and runs a fixed read-only Windows identity query. It does not change AD, execute operator commands or assume that every Windows host is a DC. Kali/non-Windows responses, denied credentials and unverifiable identities cannot establish authenticated WinRM access.

The existing per-host service model is extended:
- discovered-hosts.json stores services.winrm with protocol, port, reachability, authentication status and a fixed diagnostic.
- compromised-hosts.json stores access_methods.winrm only after successful authenticated Windows identity verification. Its verification is read_only_windows_identity.
- SSH and RDP access methods remain present when WinRM is merged. No passwords, raw output, scripts or exception text are persisted.
- A rerun removes stale WinRM success when the method can no longer be authenticated.
- Standalone P03 accepts winrm-http, an explicit target/port and runtime Windows credentials; the default port is 5985. Existing SSH/RDP standalone behavior is retained.

P09's automatic dependency is P03. It intersects authenticated P03 WinRM services with current P01 scope and reauthenticates candidates to verify local DomainRole 4/5, matching domain/controller identity and IsReadOnly=false. The lowest numeric verified writable DC is chosen deterministically. RDP-only hosts are never candidates, including misleading Windows/RDP metadata for Kali 192.168.1.120. A WinRM-only DC such as 192.168.2.200 is eligible without RDP.

An optional NORDIC_AD_DC_TARGET must satisfy both current P01 scope and P03's authenticated WinRM service checks. No manual pin is required. Standalone P09 still uses its explicit endpoint and credentials and performs DC-role verification itself.

P09's existing ownership checks, idempotent precheck/apply, independent postcheck and timeout recovery are unchanged. SUCCESS requires an enabled owned lab account and confirmed direct Domain Admins membership (domain SID plus RID 512). A prior account or membership is verified without unnecessary writes. Missing candidates or unverifiable DCs skip with concrete evidence; uncertain AD writes retain partial results.

Ground Truth and reports retain P03 service checks and access results, P09 candidate/DC verification/selection, and final account/group evidence. Offline Linux and Windows tests cover the P03-to-P09 handoff, WinRM-only DC, RDP-only Kali, open but non-Windows endpoints, denied credentials, scope and incident isolation, multiple DCs, time budgets, standalone, inventory merging, reruns, PowerShell parsing, reports and AD timeout recovery. No VM deployment is part of this repository change.
