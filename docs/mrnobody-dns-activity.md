# P18 — Advanced C2 / DNS Activity

P18 generates benign DNS A questions for isolated classroom detection exercises.
It reuses P10–P17 SSH/WinRM execution and compromised-host state; it installs no
agent, service, file, persistence or listener. DNS answers are discarded. It does
not run remote commands supplied through DNS, deliver payloads, read credentials,
or transfer arbitrary data. Encoded labels contain only `MRN-EXERCISE-ONLY` in
Base32. Source IPs, credentials and file contents never become encoded payloads.

## Classroom setup

Use an existing private classroom DNS server with a non-forwarding zone for
`mrnobody.test` (or another `.test`, `.internal` or `.localhost` suffix).
Configure UDP 53 reachability from source hosts and collect DNS query logs.
The default resolver is `192.168.1.1`, matching the fresh-install lab DNS setting.
Set `NORDIC_LAB_DNS_ENDPOINT` in the existing service/runtime environment for a
different Full Incident default, or select `dns_endpoint` per phase. All source
and resolver addresses must be RFC1918 IPv4 addresses. Public DNS names and
public resolver IPs are rejected. P18 does not create or configure a DNS server.

Linux sources need Python 3 and Bash; unsupported Linux sources skip with an
explicit dependency warning. Windows uses PowerShell/.NET `UdpClient`, with the
existing WinRM/NTLM credentials. No new controller package is required.

## Behaviors and timing

| Field | Allowed values / default |
| --- | --- |
| `dns_behavior` | `standard`, `low-and-slow`, `encoded-marker`; standard default |
| `dns_interval` | 1–180 seconds; standard/encoded default 5s, low-and-slow 60s |
| `dns_jitter` | 0–0.5 fraction (builder displays 0–50%); default 0 |
| `dns_count` | 1–40; default 3 |
| `dns_duration` | 3–240 second execution ceiling; default 240 |
| `dns_endpoint` | Private resolver IPv4, UDP 53 |
| `dns_domain` | Lowercase reserved lab suffix; default `mrnobody.test` |
| `dns_pattern` | Lowercase label with one `{seq}`; default `mrn-{seq}` |

Low-and-slow requires an interval of at least 30s. Count, worst-case jittered
sleep intervals and three seconds per DNS attempt must fit the duration ceiling.
The ceiling bounds the run; it does not pad a short run with sleeps. Queries
start immediately, then sleep for interval ± jitter between attempts. DNS RTT
adds to observed inter-arrival times. The UI uses the existing hours/minutes/
seconds inputs. Normal, Slow and Custom profiles affect phase start offsets;
they do not multiply P14/P18 internal timing. Longer hunts can use the existing
recurring scheduler; one run remains bounded to four minutes.

```sh
mrnobody phases
mrnobody run dns --target 192.168.1.20 --protocol ssh --user ubuntu \
  --dns-endpoint 192.168.1.1 --dns-behavior encoded-marker \
  --dns-domain mrnobody.test --dns-pattern 'mrn-{seq}' \
  --dns-interval 5 --dns-jitter 0.2 --dns-count 3 --dns-duration 60
```

Use the existing runtime password input mechanism. Never put secrets in a query
label or domain field. Transport is DNS by definition; SSH/WinRM selects the
source-host execution transport, not the beacon transport.

## Planning and outcomes

Auto builder adds P01 → P03 → P18 and only uses compatible compromised hosts.
An optional Auto target filters that inventory; it cannot invent access. Fixed
mode can target private Linux/Windows lab hosts directly using runtime credentials.
Full Incident order is P14 → **P18** → P16 → P04 → P17 → P05 → P06 → P07.
P14 is an optional ordering predecessor, not an access prerequisite. Both builder
and backend validate relative ordering whenever those phases are selected.

A matching DNS transaction, opcode, echoed question and NOERROR/NXDOMAIN response
counts as successful telemetry, even when there is no A answer. SERVFAIL, REFUSED,
timeouts, wrong IDs/questions and malformed replies count as failed attempts.
This measures query/response telemetry, not domain resolution or sensor detection.

Standalone exits: 0 success, 80 partial success, 1 failure, 78 nonfatal prerequisite
skip. Custom/Full Incident records partial and continues subsequent phases; a DNS
failure remains a failure. Missing compatible access skips. Transport failures
can fall back to another compatible host using the existing selection plumbing.
No temporary helper files are created, so cleanup is not required. A transport
timeout may leave an in-memory client running until its bounded loop ends.

Ground Truth includes source, endpoint/domain, behavior, interval, jitter,
duration/count, generated pattern summary, safe sample queries, attempt completion
timestamps (Unix milliseconds), success/failure/unattempted counts and warnings.
Raw DNS replies, stderr and transport exceptions are omitted. Phase lifecycle
timestamps record start/end; live overview and reports preserve partial status.

Investigation guidance covers DNS server logs, Suricata DNS events/flows, firewall
telemetry and Wazuh/host process evidence. Hunt periodicity, interval variance,
rare suffixes and repeated encoded labels over suitably long observation windows.
These are guidance sources, not proof that a sensor detected the simulation.

MITRE mappings verified on 2026-11-02 against current official pages:
[T1071.004 — DNS](https://attack.mitre.org/techniques/T1071/004/) for all behaviors;
[T1132.001 — Standard Encoding](https://attack.mitre.org/techniques/T1132/001/)
only when encoded-marker action evidence is recorded. No exfiltration or remote
command execution technique is claimed. Historical reports omit absent P18.

## Distribution and validation

Fresh-install cloud-init uses an explicit download list, rather than fetching
new manifest entries automatically. It now downloads `scripts/18-dns.sh` and
`web/dns_actions.py`. Existing package/venv, pywinrm, requests-ntlm, ReportLab,
planning database, nginx/systemd/TLS and updater setup are unchanged. The update
manifest includes both new files and refreshed hashes of modified runtime files.
The Proxmox installer already consumes this userdata and needs no change.

`tests/mrnobody/dns_activity.py` covers validation, both source platforms,
fixed-marker encoding, generated client response validation without networking,
PowerShell parsing, selection/fallback, partial/failure/skip results, API scheduling,
reports, HTML/PDF, live overview, ordering and environment isolation. Builder DOM
and report UI fixtures cover P18 and historical compatibility. CI also runs all
existing phase regressions, install validation, manifest and shell syntax checks.
