# Full Campaign: producer → validator → consumer

> Repository commands below are run from `INSTALLFILES/` (`cd INSTALLFILES` from the clone root).

P01 owns where and which TCP ports; P03 owns authenticated access; P09 owns AD role validation and the controlled AD action. These are three stages of one pipeline. P09 has no independent host or port discovery path.

## P01: produce the inventory

Existing CyberLab private-network/interface discovery, exclusions, host limits and assigned manual subnets are retained. P01 performs a bounded TCP connect scan on the discovered in-scope hosts. The initial set includes configured SSH (22), RDP (3389), WinRM HTTP (5985) and existing web ports (80,443,3010,8080,8443). `NORDIC_DISCOVERY_TCP_PORTS` supplies additional inventory ports (at most 64 total); service port overrides remain included. No WMI or SMB consumer is implemented.

`discovered-hosts.json` has `schema_version: 2`, `producer: P01`, `incident_id`, a new `inventory_id`, `complete`, `configured_tcp_ports` and `hosts`. Each host has `tcp_ports`, keyed by decimal port number. Each entry records `transport: tcp`, `port`, `state` (open/closed/filtered/timeout), `started`, `observed` and `evidence` (tool/reason). Missing results, malformed scans and scan deadlines become timeout with a diagnostic reason, never open. Nmap explicit filtering remains filtered. The default per-host scan timeout is 20 seconds plus a 3-second process allowance. Interrupted inventory generations remain incomplete. Ground Truth records each port observation.

An open port proves neither login, Windows identity nor DC role. P03 does not write authentication results into this inventory. Future service validators can consume the same TCP facts.

## P03: validate access

Campaign P03 accepts only completed, same-incident P01 schema-v2 inventory within the incident network scope and exclusions. Only an open required port creates an authentication attempt. SSH, RDP and WinRM results are independent. SSH requires a successful session marker; RDP uses the existing FreeRDP auth-only client; WinRM uses runtime Windows credentials with NTLM and a fixed read-only Windows identity response. RDP/OS metadata never establishes WinRM access.

P03 replaces `compromised-hosts.json` with an incomplete empty state before validation, so failed reruns cannot preserve old successes. Completed output has `producer: P03`, `run_mode: campaign`, `source_inventory_id`, `complete`, `results` (including failures and attempts), and `hosts` containing only verified successes with independent `access_methods`. Passwords, raw remote output and exception text are omitted. Each result has a timestamp; Ground Truth includes failures and every WinRM attempt.

The former 12-second WinRM worker limit covered NTLM authentication, shell creation, PowerShell startup, output retrieval and cleanup together. A responsive TCP 5985 or HTTP 405 does not complete those steps. P03 now uses a 20-second SOAP operation timeout, 30-second HTTP read timeout and a 90-second outer worker limit, with one retry only for timeout/transient transport failure. These are configurable with `NORDIC_WINRM_OPERATION_TIMEOUT`, `NORDIC_WINRM_READ_TIMEOUT`, `NORDIC_WINRM_WORKER_TIMEOUT`, and `NORDIC_WINRM_RETRIES` (0–2). Timeouts record the last stage: `ntlm_shell`, `powershell_start`, `identity_read`, or `cleanup`; missing worker progress is `worker`. No-profile, non-interactive PowerShell and a lightweight environment identity check avoid CIM startup in the access stage. Credential denial is not retried. Timeout is always unconfirmed access, including after a failed retry. An authenticated later attempt is required for success.

The timeout mismatch is a code-level diagnosis; actual Server 2025 credentials, WinRM policy and logs must be checked during a new lab run if authentication still times out. No running VM was contacted for this change.

## P09: consume authenticated access

Campaign P09 reads only completed same-incident P03 campaign state. It does not read P01 hosts/networks, scan ports, use RDP as a substitute, or accept a DC/Windows classification as proof. An optional `NORDIC_AD_DC_TARGET` only narrows P03-success candidates; it cannot introduce a target.

P09 checks each numerically ordered authenticated WinRM candidate with a read-only local writable-DC identity query. It continues after a non-DC or rejected candidate. Local DomainRole, AD domain/controller identity and `IsReadOnly=false` must agree before the first eligible DC is selected. Role checks have a 90-second per-worker limit within a 120-second selection budget. Rejection reasons remain visible per host.

No authenticated WinRM targets produces `no_authenticated_winrm_targets`, visible P03 evidence, and a skipped phase. Candidates without a verified writable DC produce `no_writable_dc_verified` and per-candidate reasons. There is no fallback to P01.

On a verified DC, the existing controlled `mrnobody` ownership checks, idempotent account enable/create, domain SID + RID 512 membership action, independent final read and uncertain-write recovery remain unchanged. AD success requires independently proven final account and group state. Account rights are separate from successful WinRM authentication.

Standalone P09 remains independent: the manually supplied IP, WinRM credentials and port are used, followed by its own DC validation. No campaign inventory is required. No lab IP is hardcoded in runtime code.

## Update and verify

After this change reaches main, finish or stop the active campaign and run `sudo mrnobody update`. The manifest installs the new inventory/access module and changed dispatchers. Start a **new** Full Campaign so P01 produces schema-v2 inventory; legacy inventory is deliberately rejected. Supply the normal runtime SSH/Windows credentials. Confirm P01 `PORT_OBSERVATION`, P03 `ACCESS_SUCCESS`/`ACCESS_FAILED` and `WINRM_AUTH_ATTEMPT`, P09 `source=p03_authenticated_winrm`, DC rejection/selection, and the independent final AD account/group evidence.

Offline tests cover the ten-host inventory, all TCP states, scope/incident isolation, forbidden phase crossings, separate protocol evidence, timeout retries/stages, reruns, role rejection, Ground Truth/report exports, actual process dispatch, standalone and existing AD reconciliation/recovery. P11 is untouched; P12–P18 and WMI are not added.
