# Sprint 5: passive Detection Validation preview

Master `/master/validation` compares manually imported Wazuh `alerts.json` and
Suricata `eve.json` NDJSON slices with existing verified P06 fixture/P11 HTTP
Receiver receipts. Select one registered Agent (historical offline Agents are
allowed) and one campaign/fixed job ID. A synchronized campaign report, if present,
adds exact ACK references and phase MITRE metadata. Fixed Master P11 jobs currently
do not produce normal campaign reports. Missing reports are displayed explicitly.

This is an **untrusted import preview**, not authenticated SIEM evidence or a
coverage assessment. A Receiver ACK proves receipt, not detection. A Wazuh FIM
hash can show observation of the fixture, not prove network exfiltration detection.
Review the original rule, sensor and log source before interpreting any match.
There is no “not detected” verdict or coverage percentage. Empty slices, missing
sources, HTTPS payload blindness and truncated references keep coverage unknown.
Persistence, DNS, other phases and general P01–P11 execution are outside this slice.

## Access and data handling

Use the existing root-provisioned Master administrator login over verified HTTPS;
see [administrator setup](master-admin-prerequisite.md). The page is authenticated,
and the POST requires the same administrator session, exact configured Host/Origin,
CSRF token and private/lab peer boundary as the existing Master controls. Agent
tokens do not grant preview or administrator access. Preview has an additional
global limit of three attempts/minute, including malformed imports, on top of the
existing request/write limits. The request must be JSON, without query parameters.

Only an explicit **Compare imported evidence** click sends the chosen UTF-8 files
(without a byte-order mark; invalid UTF-8 is rejected).
Combined raw input is limited to 512 KiB, 2000 nonempty records and 64 KiB per
line; encoded JSON request maximum is 1 MiB. Unsupported EVE record types are
counted as ignored; malformed JSON, duplicate keys, invalid timestamps or invalid
supported alert schemas reject the entire slice. Timestamps require an explicit
UTC offset or Z. No partial verdict is returned after a parse/storage error.

Raw content is processed in request/browser memory, never deliberately persisted
or echoed by this feature. Import only filtered lab logs without secrets. Browser,
proxy and host administrators remain responsible for their own memory dumps and
request-body logging policies. The summary includes only allowlisted identifiers,
bindings, timestamps, rule/signature IDs, technique IDs, hashes and counts. No raw
payloads, rule descriptions, arbitrary imported URLs or credentials are returned.
The optional JSON download is local; it still contains operational metadata and
must be handled accordingly. Editing scope or files invalidates the previous
result; Clear removes selected files and the in-memory result. No local/session
storage, server uploads directory, SIEM credentials or external fetch is used.

## Matching contract

Declare the Wazuh observer `agent.id` explicitly: its namespace is different from
the MrNobody Agent ID. For Suricata, declare the exact source/destination IP pair
as seen by that sensor, including NAT translation. These bindings are operator
assertions, not independently verified host identity. Reverse direction does not
match. There are no CIDR/wildcard bindings or network lookups.

Records must fall within the selected 0–300 seconds of Master `received_at`.
Time, IPs, technique IDs or phase alone give **candidates**, never confirmed
attribution. Strong anchors additionally require one of:

- P06: exact synthetic fixture SHA256 (`syscheck.sha256_after` or `fileinfo.sha256`).
- Exact campaign, phase and Receiver event ID supplied explicitly in
  `data.mrnobody.receiver_event_id`, or in an existing `P11_BEACON_ACK event_id=N`
  log line with the campaign/phase markers.
- P11: exact campaign, phase, sequence and `MRN-EXERCISE-ONLY` payload marker.

The optional `data.mrnobody` fields (`campaign_id`, `phase`, `receiver_event_id`,
`sequence`) are a **local import convention**, not standard Wazuh/Suricata fields.
Do not invent these from time/IP matches to manufacture a positive result.
Forwarded Ground Truth can correlate but does not demonstrate independent sensor
observation. Explicit campaign/phase conflicts exclude attribution. An anchor
matching multiple receipts remains a candidate. Identical canonical JSON records
are deduplicated per sensor format; source hashes cover the exact original bytes
and record hashes cover canonical JSON, with original line numbers retained.

Only Wazuh rule level >0 and Suricata `event_type: alert` are treated as imported
alerts. Other supported records are telemetry even with an exact anchor. EVE
flow IDs are references only; no joins across flows, transactions or separate
records are inferred. Under verified HTTPS, Suricata normally cannot read the
campaign/sequence payload: flow/TLS records therefore remain candidates unless
the record contains a legitimate stronger anchor. TLS is never weakened to improve
this preview.

The reference uses the newest 100 matching Receiver rows and at most 5000 report
events; only the first 200 normalized imported records are displayed/downloaded.
All input records still contribute to counts, and all truncation is disclosed.
Narrow the source export/campaign to inspect omitted records. A corrupt cached
report fails closed as reference unavailable. Reads do not alter the registry,
reports or Receiver content. There is no job dispatch, rule deployment, sensor
configuration change, automatic SIEM pull or claim that the live sensor detected
the exercise.

MITRE activity references are P06 T1041 and P11 HTTP T1071.001; these are separately
labelled from imported rule IDs and cached phase metadata. The P11 phase may also
describe persistence (for example T1543.003); that does not establish persistence
detection from an HTTP beacon receipt.

## Master-first / Slave-second update and lab acceptance

After the PR is merged into the configured update branch:

1. On Master run `sudo mrnobody update`. Confirm manifest SHA256 verification
   succeeds and the existing administrator login works using the configured
   HTTPS origin and trusted CA. Unauthenticated preview/page access must fail
   or redirect to login. An Agent bearer token must not grant access.
2. On the single lab Slave run `sudo mrnobody update`. Confirm registration,
   online heartbeat, verified HTTPS and existing Receiver/report synchronization.
   No new Agent port, service or polling protocol is introduced.
3. On Master use the existing explicit fixed P11 start control for that online
   Agent. Confirm one job, polling/status, Receiver receipts, confirmed Stop and
   eventual stopped/deadline state. For P06 or campaign report references, use
   the existing authorized local Full Incident Live Lab controls; this preview
   adds no remote campaign/P06 start route.
4. Export a small time-bounded NDJSON slice from the lab SIEM/sensor; preserve its
   provenance separately. Record clock offsets and the actual observed NAT IP
   direction. Do not upload full production logs. In `/master/validation`, select
   that Agent and job/campaign, declare observer bindings, choose the slice and
   click Compare. Verify each candidate against the original alert/rule.
5. With an empty slice expect coverage unknown, zero correlated alerts and no
   negative detection claim. A plain flow/TLS or forwarded ruleless ACK must stay
   telemetry. Wrong observer/campaign/time must not correlate. Duplicate records
   must not inflate counts. Missing campaign reports must remain explicit.
6. Change the campaign/file: the old result/download must clear. Download a fresh
   summary and verify no raw payload/token/description is present. Clear the files.
   Confirm heartbeat, existing DNS/Live Lab, Receiver/report access and fixed-job
   stop/deadline behavior remain intact. Never disable TLS verification for testing.

Automated tests use synthetic fixtures and isolated registries/browser routes.
They do not certify real Wazuh/Suricata ingestion, NAT, clocks, VM updates or
independent sensor detections; steps above remain live lab acceptance work.

## Format references

- [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
- [Wazuh MITRE fields](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)
- [Suricata EVE JSON format](https://docs.suricata.io/en/suricata-8.0.4/output/eve/eve-json-format.html)
- [MITRE T1041](https://attack.mitre.org/techniques/T1041/) and
  [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
