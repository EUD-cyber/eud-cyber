# MrNobody P12 / P14 lab simulations

These phases generate teaching telemetry in an isolated RFC1918 lab. They reuse
the existing compromised-host inventory, SSH/WinRM workers, runtime credentials,
scheduler, live overview and Investigation/Ground Truth export pipeline. Nothing
in this change deploys to an existing VM.

## P12 — Credential Access simulation

Windows and Linux create a unique temporary directory and a single
`synthetic-credentials.txt` containing a fixed, invalid lab marker. Choose
`metadata` or `read-test-file` (default). The latter reads and verifies that marker.
Both remove the artifact and directory. Success requires verified cleanup.
Paths, credential stores and operator commands are not accepted. No LSASS,
browser store, private key, user password or home directory is searched.

This is a benign analogue of [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/),
verified against MITRE ATT&CK on 2026-11-02. Metadata mode demonstrates discovery
of a designated test artifact, not extraction. File-read detection requires
Windows object-access auditing/SACLs or Linux auditd rules. Sysmon file-create
and Wazuh FIM alone do not establish that a read occurred. Reports explain this
distinction, investigative sources and mitigations.

An interruption or transport timeout can prevent cleanup. Inspect only the
recorded MrNobody phase namespace; never delete unrelated temporary files.

## P14 — HTTP(S) check-ins

An established Windows or Linux lab host makes a finite series of GET requests
to this MrNobody server. The controller selects its own private routing interface
toward the source host, without sending a discovery packet. No operator URL,
public destination, DNS name, proxy or redirect is accepted. Both nginx listeners
serve `/mrnobody-beacon/heartbeat` and `/mrnobody-beacon/status` as fixed HTTP 204
responses, with RFC1918 source checks and the existing nginx access log. The
endpoint does not execute commands or serve payloads. Clients discard bodies.

Requests carry only the incident ID and sequence. Defaults: HTTP, 5-second
interval, zero jitter, 5 check-ins. Select HTTP/HTTPS, 1–60 seconds, 0–50% jitter,
1–20 check-ins and a predefined URI profile. Count is the duration control:
nominal spacing is `(count-1)*interval`; the upper execution bound is
`(count-1)*interval*(1+jitter)+count*3`, at most 240 seconds. Each request has a
3-second timeout. The worker timeout is 300 seconds, independent of the phase's
start offset. Slow/Custom campaign profiles schedule the phase; they do not
multiply its internal beacon interval. The builder uses hours/minutes/seconds
and a percentage for the internal controls.

HTTPS uses the existing self-signed lab TLS installation: curl `--insecure` or a
fixed certificate callback in the short-lived PowerShell process. Do not treat
this as a production certificate-validation policy. Linux source hosts require
Bash, curl, awk and sleep; missing curl is a controlled unsupported-method skip.
No agent, scheduled task, persistence, executable download, remote command
channel or credential/data transfer is installed by P14.

Mapping: [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/),
verified on 2026-11-02. This models traffic characteristics, not functional C2.
Reports correlate source/destination, start/end timestamps, transport, interval,
jitter, count, duration bound and successful/failed check-ins with Suricata,
firewall/proxy, nginx and host logs. Sequence numbers and nginx timestamps allow
students to reconstruct the individual requests. Partial success records both
counts and is a failed phase; an unavailable endpoint is a failure. Returned
HTTP content, native stderr and transport exception text never enter evidence.

## Ordering and execution

Full Incident: **P01 → P02 → P03 → P08 (optional) → P09 → P10 (optional) → P11 →
P12 → P13 → P14 → P04 → P05 → P06 → P07**.

Auto scenarios insert/validate P01 then P03 before either new phase. Optional
Auto target overrides filter established access, never manufacture compromise
state. Fixed/standalone execution requires a private target and explicit SSH or
WinRM transport, and validates platform consistency. Runtime passwords are
requested separately and never saved in scenario/schedule definitions. Candidate
transport failure can fall back to another compatible host; unresolved transport,
authentication, internal or action failures stay fatal. No compatible host or
unsupported dependency skips nonfatally. P13 retains its existing encoded
PowerShell, certutil-decode and empty BITS-job behavior and technique mappings.

CLI examples (passwords should be supplied through existing runtime inputs):

```sh
mrnobody run credential-access --target 192.168.1.15 --protocol ssh --platform linux --method read-test-file
mrnobody run c2 --target 192.168.1.15 --protocol ssh --platform linux --transport http --beacon-interval 5 --beacon-jitter 0.2 --beacon-count 5
```

The dynamic CLI listing, standalone GUI, custom builder and scheduler discover
both launchers from metadata. Reports and live timelines use the same IDs.

## Fresh install and update

The current userdata explicitly downloads runtime files; it does not bootstrap
the whole manifest on a fresh install. Add exactly these three downloads:

- `scripts/12-credential-access.sh`
- `scripts/14-c2.sh`
- `web/lab_actions.py`

The existing nginx download now contains the fixed beacon locations. No duplicate
download, alternate installer, Python package, daemon, agent or endpoint helper
is needed. Existing P09/P10/P11/P13 modules, report/live assets, ReportLab,
pywinrm/requests-ntlm, venv, planning DB creation, nginx/systemd/TLS, updater and
service names remain in place. The regenerated update manifest includes both
launchers/helper and changed distributed assets. Fresh-install tests reconstruct
only downloaded runtime files, import the helper and smoke-test application APIs.

Validation uses offline transport fixtures, Windows PowerShell parsing, builder
DOM tests, profile/order/scheduler tests and HTML/PDF exports. CI runs the full
existing Python/JS/Bash suite plus the new lab phase contracts. These checks do
not assert that target sensors have been configured or that telemetry was ingested.
