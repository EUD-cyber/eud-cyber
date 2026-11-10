"""Incident snapshots built from existing campaign state and ground-truth events.

Standard library only: also invoked directly by the scenario's EXIT handler.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import signal
import subprocess
import uuid
import xml.etree.ElementTree as ET
from p04_evidence import address


P10_PREVIEW_LIMIT = 512


def p10_output_preview(value, environ=None):
    """Scrub complete bounded input before taking a display prefix; never raw XML.

    Unknown/broken CLIXML and oversized streams fail closed. Unlabelled secrets
    cannot be recognized reliably; credential/wordlist retrieval is suppressed.
    """
    environ = environ or {}
    command = environ.get('MRN_POWERSHELL_SECRET', '')
    if re.search(r'(?i)password|passwd|secret|token|credential|wordlist|private.?key|\b(?:Get-Content|gc|cat|type)\b', command):
        return '[output withheld: sensitive command]'
    if not isinstance(value, (bytes, str)) or len(value) > 65536:
        return '[output withheld: size or format]'
    text = value.decode('utf-8-sig', errors='replace') if isinstance(value, bytes) else value
    if '#< CLIXML' in text or re.search(r'<(?:\w+:)?Objs\b', text):
        start = text.find('<Objs')
        end = text.find('</Objs>', start)
        if start < 0 or end < 0 or '<!DOCTYPE' in text or '<!ENTITY' in text:
            return '[CLIXML omitted]'
        try:
            root = ET.fromstring(text[start:end + 7])
            records = []
            for node in root:
                # Only string output/warning/error records, never object properties.
                if node.tag.rsplit('}', 1)[-1] == 'S' and node.get('S', 'output').lower() in {'output', 'warning', 'error'}:
                    records.append(node.text or '')
            text = text[:start].replace('#< CLIXML', '') + '\n'.join(records) + text[end + 7:]
            text = re.sub(r'_x([0-9a-fA-F]{4})_', lambda m: chr(int(m[1], 16)), text)
        except (ValueError, ET.ParseError):
            return '[CLIXML omitted]'
    text = '\n'.join(line for line in text.splitlines() if 'Preparing modules for first use' not in line)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    text = redact_environment(text, environ)
    # Reuse export scrubbing (authorization, JSON/colon credentials, PEM keys).
    from report_exports import safe_report
    text = safe_report(text)
    text = re.sub(r'(?i)\b(?:authorization|wordlist|private.?key)\b[^\n]*', '[REDACTED]', text)
    text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_.-]+|[A-Za-z0-9+/=_-]{40,})\b', '[REDACTED]', text)
    text = text.strip()
    return text if len(text) <= P10_PREVIEW_LIMIT else text[:P10_PREVIEW_LIMIT - 1] + '…'


def mitre_url(technique_id):
    """Only construct direct ATT&CK technique URLs from validated IDs."""
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id or ""):
        return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
    return None


# Recommendations, never observations. Sensors/auditing must be configured in the lab.
PHASE_GUIDANCE = {
    "18": (
        "Inspect DNS server query logs, Suricata DNS events/flows, firewall UDP 53 and Wazuh host process telemetry (PowerShell/WinRM or Python/SSH). Correlate source, resolver, query labels and timestamps.",
        "Hunt repeated check-ins, inter-arrival intervals/jitter and low-and-slow patterns over longer windows. Encoded labels contain only the fixed MRN-EXERCISE-ONLY marker. NOERROR or NXDOMAIN with matching transaction/question counts as successful telemetry; answers are discarded. No sensor alert is implied.",
        "Use a private non-forwarding classroom DNS endpoint, baseline periodic queries and unusual label encoding, restrict outbound DNS and compare success/failure/unattempted counts."),
    "15": (
        "Correlate web access/error logs, app logs, reverse proxy/WAF, Suricata HTTP and Wazuh by source, target, path and time.",
        "Check profile, fingerprint, validation outcome and fixed safe evidence. SQLi uses an ephemeral synthetic database; traversal reads only a virtual marker. Findings do not establish host compromise.",
        "Use parameterized queries, canonical path allowlists, least privilege and tested WAF rules; remove the teaching endpoint after the exercise."),
    "16": (
        "Correlate Windows 4688/4104/4663 and FIM with Linux audit file/rename/exec events, journal and Wazuh. Service events 7036 and systemd/journal are relevant when investigating real service impairment; these profiles change synthetic artifacts only.",
        "Compare original/action/restored state and cleanup metadata. Config toggle is an analogue of T1685; reversible synthetic log rename is an analogue of parent T1070, not real log deletion. Re-run cleanup with the same incident and target after interruption.",
        "Restrict service/config write rights, monitor changes and gaps in telemetry, protect logs remotely and verify restoration."),
    "17": (
        "Correlate synthetic source file access, archive creation, process execution, Sysmon 1/11, Windows file auditing, Linux audit and Wazuh FIM; FIM alone cannot prove reads.",
        "Verify selected dataset/count, partial warnings, archive size/hash and staged-data.json producer_phase=17. P05 retains the archive and P06 consumes the same state. No arbitrary user directories are searched.",
        "Restrict source/archive access, monitor archive utilities and staging locations, apply DLP and clean up only the recorded MRN archive."),
    "12": (
        "For Windows correlate Security 4663 only with file object auditing/SACL enabled, 4688, PowerShell 4104 and Sysmon 1/11. Sysmon 11 records creation, not reads. On Linux configure auditd file/open rules and inspect audit/journal and Wazuh FIM. FIM alone does not prove a read.",
        "A unique temporary synthetic-credentials.txt is created, inspected or read, verified and removed. No real credential store is searched. Compare target, platform, method, timestamps, outcome and cleanup evidence. T1552.001 is a benign behavioral analogue; metadata-only does not demonstrate credential extraction.",
        "Avoid plaintext credentials, restrict file permissions, use a secret manager and least privilege. Verify cleanup after interruption; remove only confirmed MrNobody artifacts."),
    "14": (
        "Compare periodic source/destination flows and timestamps in Suricata eve.json, firewall/proxy and nginx access logs. Correlate Windows Sysmon 3/PowerShell 4104/4688 or Linux audit exec and SSH logs where enabled. HTTPS hides URI content from passive network sensors.",
        "Bounded HTTP(S) beacon telemetry. Compare destination, interval, jitter, count, duration bound and success/failure counts. Only HTTP 204 counts as success; partial success remains a failed phase. Response content is discarded. Lab HTTPS uses a self-signed certificate policy in the short-lived client process.",
        "Restrict outbound destinations, baseline periodic traffic, correlate host and network logs, and alert on unusual repeated web connections."),
    "13": (
        "Correlate WinRM, PowerShell Operational 4103/4104, Security 4688 and Sysmon 1 (process), 7 (image load) and 11 (file create) where enabled. For BITS inspect Microsoft-Windows-Bits-Client/Operational. In Wazuh correlate host, win.system.eventID, parent process, command line and timestamps. Check marker.b64/marker.txt and cleanup evidence for certutil.",
        "Which predefined behavior and executable ran? Encoded PowerShell emits a fixed marker; certutil decodes local synthetic text; BITS creates and cancels an empty job. Attackers abuse these native tools to obscure script intent, decode payloads or manage background transfers/persistence. This exercise delivers no malware and demonstrates no transfer or persistent execution. Compare native exit code, artifact path, safe output and cleanup result with target logs. Which telemetry distinguished this action from administration?",
        "Use least privilege and tested application control, restrict WinRM, alert on unexpected encoded PowerShell/certutil decode/BITS job creation and unusual parent processes. Verify cleanup independently after interruption or timeout; remove only recorded MrNobody artifacts."),
    "09": (
        "On the selected lab DC, correlate Security 4720 (account created), 4722 (account enabled), 4724 (password reset), 4728 (member added to a global security group), 4738 (account changed) and 4624/4672 logons. Domain Admins is RID 512. In Wazuh filter win.system.eventID, subject account, target account/SID and time; auditing and collection must be enabled.",
        "Was mrnobody created enabled, enabled from a disabled state, or already enabled? Was membership added or already present? Confirm the subject, domain/DC, group SID and partial failures. Existing membership need not generate a new 4728. Historical created_disabled evidence describes the earlier behavior. P03 access alone does not grant rights to change AD.",
        "Restrict Domain Admin membership and WinRM, separate administrative accounts, alert on privileged group changes and review delegated AD rights. After the exercise remove only lab membership/account changes verified in ground truth; never delete a pre-existing account blindly."),
    "11": (
        "Correlate Security 4698/4702/4699, TaskScheduler Operational 106/140/141/200/201, System 7045/7036 and Security 4697 where audited. Use Sysmon process/DNS events where configured; raw UDP queries may need network telemetry rather than Sysmon DNS API events. On Linux inspect cron/syslog, journalctl --user -u the recorded service, ~/.config/systemd/user and ~/.config/mrnobody; correlate Wazuh FIM/service/process events. Compare DNS/firewall logs and Suricata eve.json only when the resolver path is visible. OVS mirrors and Docker-internal DNS require deliberate capture visibility. These are investigation sources, not detected events.",
        "For process/process-dns, inspect PID, owner, command, kernel start ticks, CPU seconds, deadline and DNS counters. These are bounded executions (T1059.006), with no reboot/login restart or persistence mechanism. For user systemd, connect as the recorded SSH user and use systemctl --user (not the system manager); lack of a user manager is an explicit failure. Which host, account and transport created the artifacts? Verify service active and scheduled trigger configured against target evidence, and compare UTC deadline, fixed domain/resolver, query interval and counters with resolver/packet logs. A matching NOERROR or NXDOMAIN reply confirms DNS exchange, not successful A-record resolution or sensor detection. Benign DNS-beacon-like questions do not establish DNS C2 (T1071.004 is not mapped for P11). Activity outlives phase/campaign completion until the fixed deadline; stop/cancel does not clean up the remote artifacts. Re-run P11 Cleanup on the same target, user, method and suffix; verify task/cron, service, unit/executable and config removal. Failures/timeouts can leave partial artifacts.",
        "Restrict task/service creation and cron/systemd write permissions, monitor configuration changes, use least privilege and remove only verified MrNobody artifacts after the exercise."),
    "10": (
        "For Windows correlate WinRM Operational and PowerShell Operational 4103/4104 with Security 4688 and 4624 where enabled. For Linux correlate SSH auth/journal, shell/auditd exec records and process telemetry. In Wazuh compare win.system.eventID, host, subject and timestamp. Script block logs on the target may contain sensitive command content.",
        "Identify the configured custom action and its recorded transport/exit result. Raw command/output are omitted; P10 can show a redacted stdout/stderr preview capped at 512 characters per stream. A preview verifies returned text, not the intended side effect. Verify target-side artifacts independently.",
        "Restrict WinRM management paths, apply least privilege and application control, enable protected PowerShell logging and alert on unexpected remote script execution."),
    "01": (
        "Correlate Suricata eve.json flow/scan alerts with firewall logs for one source contacting many hosts. Wazuh can ingest these logs; discovery need not create an authentication event.",
        "Compare observed targets and timestamps with the asset inventory. Which probes crossed a segment boundary, and which were blocked?",
        "Segment networks and restrict discovery traffic with firewall rules. Limit management access to approved administration hosts."),
    "02": (
        "Search web server access/error logs for the recorded source, URI, status and time. Compare Suricata HTTP metadata/alerts and Wazuh web log events; a request or HTTP 200 alone does not prove exploitation.",
        "Reconstruct the recorded HTTP requests and responses. Distinguish exposed services, attempted probes and confirmed findings using evidence.",
        "Patch web servers and applications, remove unnecessary endpoints, validate input and apply tested WAF rules. Restrict access with firewalling and least privilege."),
    "03": (
        "In Wazuh, correlate Linux /var/log/auth.log or journalctl -u ssh/-u sshd with Windows Security 4624/4625 where auditing is enabled. Check source IP, account, logon type and time; RDP commonly uses type 10. Compare firewall flows for the recorded SSH/RDP port.",
        "For each access attempt, verify failure or success in the target logs. Check subsequent sudo/journal and Windows process events where collected; authentication alone does not prove later execution.",
        "Use MFA where supported, SSH keys, disable root/password SSH login where feasible, harden RDP with NLA and a managed gateway, restrict management ports and apply least privilege and rate limiting."),
    "04": (
        "Correlate east-west Suricata flows and firewall logs with Wazuh authentication events on source and destination. Check Linux auth/journal, Windows Security 4624/4625 and WinRM Operational logs for the actual recorded protocol.",
        "Build a source-to-target timeline using probe timestamps and Ground Truth lines. T1018 covers remote system discovery; T1082 and T1016 are phase metadata and require separate system-information or network-configuration evidence. SSH/WinRM execution occurs on the source; ICMP/TCP probes scan the target. An open port does not establish authentication or lateral compromise. No-reply/closed may include filtering or timeout.",
        "Segment server and user networks, allowlist SSH/RDP/WinRM management paths, avoid shared administrator credentials and enforce least privilege and MFA at management entry points."),
    "05": (
        "Inspect Wazuh FIM alerts for the recorded staging paths and correlate file size/hash/time with Linux audit/journal or Windows file auditing and EDR-style process/file evidence where enabled. FIM detects changes only in monitored paths.",
        "Locate recorded synthetic staging files and verify hashes, ownership and creation times. Identify the responsible process if process auditing exists.",
        "Limit write permissions and staging locations, monitor relevant directories with FIM, use DLP for sensitive data and restrict archive/tool execution with application control."),
    "06": (
        "Correlate egress firewall/network flow and Suricata eve.json records with the recorded source, destination, protocol, byte counts and time. Compare receiver/web server logs and Wazuh alerts; encrypted payloads may hide content.",
        "Trace each recorded transfer from staging evidence to receiver evidence. Distinguish attempted, rejected and confirmed transfers; compare bytes and hashes when available.",
        "Apply egress allowlists, controlled proxies, destination restrictions and DLP. Segment data stores and alert on unusual outbound volumes or destinations."),
    "07": (
        "Use Wazuh FIM for recorded synthetic file changes and correlate Linux audit/journal or Windows Security 4688 process creation (when enabled) with EDR-style file/process evidence. Look for bursts of changes in the exercise paths.",
        "Identify exactly which synthetic files changed and compare before/after hashes and timestamps. Verify the simulation scope and test recovery from a known good backup.",
        "Keep tested offline/immutable backups, enforce least privilege and application control, monitor with EDR/FIM and segment systems to limit impact."),
    "08": (
        "Use Wazuh to correlate repeated Linux auth/journal failures or Windows Security 4625 events by account, source and time, followed by any recorded success. Compare Suricata and firewall connection rates; do not collect passwords or wordlist contents.",
        "Count attempts and outcomes using redacted evidence. Check for account lockouts (Windows 4740 where enabled) and distinguish password guessing from a confirmed successful login.",
        "Use unique strong credentials and MFA where supported, disable default accounts, apply measured account lockout/rate limiting and harden SSH/RDP access behind management firewall rules."),
}


def p04_summary(events):
    """Project incident-scoped observations, retaining line references and missingness."""
    sources, pairs, probes = {}, {}, []
    for event in events:
        name, fields = event.get('event', ''), event.get('fields', {})
        source, target = fields.get('source', ''), fields.get('target', '')
        if not name.startswith('INTERNAL_DISCOVERY') or not address(source):
            continue
        item = sources.setdefault(source, {'source': source, 'platform': fields.get('platform'),
            'transport': fields.get('protocol'), 'execution': 'unknown'})
        if name == 'INTERNAL_DISCOVERY_EXECUTION_COMPLETE':
            item['execution'] = 'success'
        elif name in {'INTERNAL_DISCOVERY_FAILED', 'INTERNAL_DISCOVERY_SKIPPED'}:
            item['execution'] = 'failure' if name.endswith('FAILED') else 'skipped'
        if not address(target):
            continue
        pair = pairs.setdefault((source, target), {'source': source, 'target': target,
            'platform': item['platform'], 'transport': item['transport'], 'ping': 'unknown',
            'tcp': {}, 'evidence': []})
        status, port = fields.get('status'), fields.get('port', '')
        kind = name.removeprefix('INTERNAL_DISCOVERY_')
        if kind == 'PLAN':
            for planned in fields.get('ports', '').split(',')[:256]:
                if planned.isdigit() and 1 <= int(planned) <= 65535:
                    pair['tcp'].setdefault(planned, 'unknown')
            continue
        if kind == 'PING' and status in {'reachable', 'no-reply', 'unknown', 'error'}:
            pair['ping'] = status
        elif kind == 'TCP' and port.isdigit() and 1 <= int(port) <= 65535 and status in {'open', 'closed', 'unknown', 'error'}:
            pair['tcp'][port] = status
        elif kind != 'DISCOVERY':
            continue
        probe = {'source': source, 'target': target, 'platform': item['platform'],
            'transport': item['transport'], 'kind': kind.lower(), 'status': status,
            'port': int(port) if port.isdigit() else None, 'timestamp': event.get('timestamp'),
            'evidence': event.get('evidence')}
        probes.append(probe)
        pair['evidence'].append({'timestamp': probe['timestamp'], **(probe['evidence'] or {})})
    return {'sources': list(sources.values()), 'targets': list(pairs.values()), 'probes': probes,
        'counts': {'sources': len(sources), 'targets': len({p[1] for p in pairs}),
            'relationships': len(pairs), 'probes': len(probes),
            'open_ports': sum(s == 'open' for p in pairs.values() for s in p['tcp'].values()),
            'execution_success': sum(s['execution'] == 'success' for s in sources.values()),
            'execution_failure': sum(s['execution'] == 'failure' for s in sources.values())},
        'truncated': any(e.get('event') == 'INTERNAL_DISCOVERY_TRUNCATED' for e in events)}


def artifact_evidence(host, name, action, timestamp=None, verification='unverified',
                      purpose=None, inspection=None, cleanup=None, references=None, kind='file', **metadata):
    """Common observation contract. Adapters must not infer creation from completion."""
    item = dict(schema_version=1, host=host, name=name, kind=kind, action=action,
                timestamp=timestamp, verification=verification, purpose=purpose,
                inspection=inspection or [], cleanup=cleanup or 'Not recorded',
                references=references or [], **metadata)
    item['display'] = [[k.replace('_', ' ').title(), str(v) if v is not None else 'Unrecorded'] for k, v in item.items() if k not in {'inspection', 'references', 'schema_version'}]
    item['display'] += [['Evidence', str(r)] for r in item['references']]
    return item


def p05_artifacts(report, phase):
    import ntpath
    import posixpath
    import shlex
    events = phase.get('events', [])
    artifacts, users = {}, {}
    for e in events:
        f = e.get('fields', {})
        if e.get('event') == 'STAGING_START':
            users[f.get('host')] = f.get('user')
    def observe(f, timestamp, ref):
        host, path = f.get('host') or f.get('ip'), f.get('file')
        if not address(host) or not isinstance(path, str) or not path or any(ord(c) < 32 for c in path):
            return
        item = artifacts.setdefault((host, path), dict(host=host, file=path, references=[]))
        if timestamp:
            item['timestamp'] = timestamp
            # A later success may have no hash; do not attach an older hash to new bytes.
            item['sha256'], item['size'] = f.get('sha256'), f.get('size')
        if ref and ref not in item['references']:
            item['references'].append(ref)
        for k in ('platform', 'access', 'user', 'sha256', 'size', 'producer_phase'):
            if f.get(k) is not None and f[k] != '':
                if timestamp or k not in item:
                    item[k] = f[k]
    for e in events:
        if e.get('event') == 'STAGING_SUCCESS':
            observe(e.get('fields', {}), e.get('timestamp'), e.get('evidence'))
    state = (report.get('evidence') or {}).get('staging') or {}
    if state.get('incident_id') == report.get('incident', {}).get('id'):
        for i, h in enumerate(state.get('hosts', [])):
            if h.get('staged') is not False:
                observe(dict(h, user=h.get('ssh_user') or h.get('ssh_username') or h.get('rdp_user') or h.get('rdp_username')), None,
                        dict(path=report.get('sources', {}).get('staging', 'staged-data.json'), pointer=f'/hosts/{i}'))
    result = []
    for item in artifacts.values():
        host, path = item['host'], item['file']
        platform = item.get('platform', 'unknown')
        paths = ntpath if platform == 'windows' else posixpath
        method = item.get('access') or ('WinRM' if platform == 'windows' else 'SSH' if platform == 'linux' else 'unrecorded')
        sha = str(item.get('sha256', ''))
        sha = sha.lower() if re.fullmatch(r'[a-fA-F0-9]{64}', sha) else None
        size = str(item.get('size', ''))
        size = int(size) if re.fullmatch(r'\d{1,18}', size) else None
        if platform == 'windows':
            q = "'" + path.replace("'", "''") + "'"
            commands = [f'Get-Item -LiteralPath {q}', f'Get-Content -LiteralPath {q}', f'Get-FileHash -Algorithm SHA256 -LiteralPath {q}']
        elif platform == 'linux' and path.startswith('/'):
            q = shlex.quote(path)
            commands = [f'ls -lah -- {q}', f'cat -- {q}', f'sha256sum -- {q}']
        else:
            commands = []
        retained = str(item.get('producer_phase')) == '17'
        purpose = ('Retained P17 synthetic collection archive; consult P17 for selected datasets. P05 did not create it.' if retained else
            'P05 generator template: five synthetic customer/order rows (CUSTOMER_ID, NAME, EMAIL, ORDER_VALUE; example.invalid addresses), fictitious NordicERP, NordicMES production and NordicShop webshop information. Markers: SIMULATED INCIDENT DATA and Synthetic CyberLab Training Data. CONFIDENTIAL is a simulated label; no real confidential customer/employee data is collected. Template description, not independent content inspection.')
        a = artifact_evidence(host, path, 'retained for staging' if retained else 'created for staging',
            timestamp=item.get('timestamp'), verification=('Remote staging success recorded' + ('; size recorded' if size is not None else '; size unavailable') + ('; SHA256 recorded' if sha else '; SHA256 unavailable')),
            purpose=purpose, inspection=commands, cleanup='Retained for P06; P05 exposes no cleanup. After the exercise remove only independently confirmed incident artifacts.',
            references=item['references'], platform=platform, method=method.upper(), user=item.get('user') or users.get(host),
            directory=paths.dirname(path), filename=paths.basename(path), size_bytes=size, sha256=sha,
            classification='synthetic-training-data', result='staged', phase='05')
        a['display'] = [[label, str(value) if value is not None else 'Unrecorded'] for label, value in (
            ('Host', host), ('Platform', platform), ('Remote method', a['method']), ('User', a['user']),
            ('Action', a['action']), ('Directory', a['directory']), ('Full path', path), ('Filename', a['filename']),
            ('Size (bytes)', size), ('SHA256', sha), ('Classification', a['classification']), ('Result', a['result']),
            ('Timestamp', a['timestamp']), ('Verification', a['verification']), ('Content / purpose', purpose),
            ('P06 relationship', 'Staging prepares data for P06 Exfiltration; this evidence establishes no transfer or receiver.'),
            ('Investigation', f'On {host}, correlate {a["method"]} execution/account and file creation at the recorded time. Inspect Wazuh FIM/audit, Linux SSH/journal/auditd or Windows WinRM/PowerShell/Sysmon 1/11 where configured. Search synthetic data markers; these are investigation sources, not observed SIEM detections.'),
            ('Inspection caveat', f'Run these read-only commands locally on {host} using an authorized account. Compare the current file with recorded size/hash; it may have changed. Never paste file text into a shell. Reading may update access/audit metadata.'),
            ('Cleanup', a['cleanup']))]
        a['display'] += [['Evidence', f"{r.get('path', 'ground truth')}:{r.get('line', r.get('pointer', '?'))}"] for r in a['references']]
        result.append(a)
    terminal = next((e.get('fields', {}) for e in reversed(events) if e.get('event') == 'PHASE_COMPLETE'), {})
    def count(key, event):
        value = str(terminal.get(key, ''))
        return int(value) if value.isdigit() else sum(e.get('event') == event for e in events) if events else None
    hosts = {a['host'] for a in result} | {e.get('fields', {}).get('host') for e in events if e.get('event') == 'STAGING_SUCCESS' and address(e.get('fields', {}).get('host'))}
    metrics = dict(hosts_staged=len(hosts), artifacts_created=sum(a['action'] == 'created for staging' for a in result),
        artifacts_recorded=len(result), total_bytes_staged=sum(a['size_bytes'] or 0 for a in result),
        unknown_sizes=sum(a['size_bytes'] is None for a in result), failed=count('failed', 'STAGING_FAILED'), skipped=count('skipped', 'STAGING_SKIPPED'))
    return result, metrics


def add_analysis(report):
    """Add a versioned student view without changing the underlying phase evidence."""
    summary = {}
    for phase in report.get("phases", []):
        events = phase.get("events", [])
        guidance = PHASE_GUIDANCE.get(phase["id"], (
            "Correlate collected host and network logs with recorded event times.",
            "Validate each recorded outcome against target evidence.",
            "Apply least privilege, segmentation and monitoring appropriate to the recorded activity."))
        if phase['id'] == '11' and any(e.get('fields', {}).get('method') in {'process', 'process-dns'} for e in events):
            guidance = (
                "Inspect top/htop/ps and /proc for the recorded PID, owner, command and kernel start ticks. Correlate available SSH/audit/process logs. For process-dns compare target packet capture, internal resolver logs and Suricata/Wazuh only where configured and visible; these are sources to investigate, not observed detections.",
                "Distinguish this bounded background execution from reboot persistence: no service, cron or automatic restart is installed. Compare start time, UTC deadline, CPU level/seconds, running state and fixed evilcorp.test A-query counters. A matching NOERROR/NXDOMAIN response proves DNS exchange, not A-record resolution, exfiltration or C2. Use Inspect to refresh counters and Cleanup to stop only the owned PID; verify expiry and file removal separately.",
                "Use least privilege, monitor unexpected processes and lab DNS activity, and remove only the recorded owned exercise process and artifacts.")
        for technique in phase.get("mitre", {}).get("techniques", []):
            technique["url"] = mitre_url(technique.get("id"))
            if phase.get("status") in {"skipped", "not_run"}:
                continue
            tid = technique["id"]
            item = summary.setdefault(tid, {**technique, "mapping": "phase_metadata", "phases": [], "observed_phases": []})
            item["phases"].append(phase["id"])
            if any(e.get("event") not in {"PHASE_START", "PHASE_COMPLETE", "PHASE_FAILED"} for e in events):
                item["observed_phases"].append(phase["id"])
        findings = [
            f"{e.get('timestamp', 'Unknown time')} · {e.get('event')} · {e.get('outcome')} · "
            f"source={e.get('source') or 'unrecorded'} · target={e.get('target') or 'unrecorded'} · "
            f"protocol/method={e.get('protocol') or e.get('method') or 'unrecorded'}"
            for e in events if e.get("event") not in {"PHASE_START", "PHASE_COMPLETE", "PHASE_FAILED"}]
        phase["analysis"] = {
            "what_happened": f"Recorded phase status: {phase.get('status')}. {len(events)} ground-truth events recorded. Phase completion alone does not confirm every attempted action succeeded.",
            "findings": findings or ["No action-level evidence recorded. Do not infer successful activity from phase metadata."],
            "evidence": [e["evidence"] for e in events if e.get("evidence")],
            "detection": [guidance[0]], "investigation_tasks": [guidance[1]], "prevention": [guidance[2]],
            "guidance_notice": "Educational recommendations, not evidence that a sensor detected or a control prevented this activity. Apply only to recorded actions/protocols; logging and audit configuration vary.",
            "mitre_notice": "Mapped from phase metadata, not proof that every technique executed or succeeded.",
        }
        if phase['id'] == '17':
            phase['artifacts'] = [artifact_evidence(
                e.get('target') or e.get('fields', {}).get('target'), e['fields']['archive_path'], 'archive created', kind='archive',
                timestamp=e.get('timestamp'), verification='Remote archive size/hash and selected files recorded',
                purpose='Synthetic collection archive; selected files: ' + e['fields'].get('files_selected', 'unrecorded'),
                cleanup=e['fields'].get('cleanup'), references=[e['evidence']] if e.get('evidence') else [],
                size_bytes=e['fields'].get('size'), sha256=e['fields'].get('sha256'))
                for e in events if e.get('event') == 'COLLECTION_ACTION_SUCCESS' and e.get('fields', {}).get('archive_path')]
        if phase['id'] == '06':
            state = (report.get('evidence') or {}).get('exfiltration') or {}
            records = {}
            if state.get('incident_id') == report.get('incident', {}).get('id'):
                for transfer in state.get('attempts', []) + state.get('transfers', []):
                    records[(transfer.get('source'), transfer.get('remote_file'))] = transfer
            phase['artifacts'] = [artifact_evidence(
                t.get('source'), t.get('remote_file') or 'Remote path unavailable', t.get('result', 'legacy transfer record'),
                timestamp=t.get('ended_at') or t.get('prepared_at') or t.get('started_at'),
                verification='Receiver bytes and SHA256 verified' if t.get('verified') is True and t.get('successful') is True else 'Transfer not verified',
                purpose='Simulated training data only; no real company secrets.',
                cleanup='Retained for investigation. Remove only the recorded generated file and its incident directory after the exercise.',
                incident_id=t.get('incident_id'), source_incident_id=t.get('source_incident_id'),
                source_kind=t.get('source_kind', 'unrecorded'), synthetic=t.get('synthetic'),
                source_name=t.get('source_name'), remote_path=t.get('remote_file'),
                local_destination=t.get('local_destination'), expected_size=t.get('expected_size', t.get('source_size')), source_size=t.get('source_size'),
                received_size=t.get('received_size'), sha256=t.get('sha256'),
                expected_sha256=t.get('expected_sha256', t.get('sha256')), received_sha256=t.get('received_sha256'),
                started_at=t.get('started_at'), prepared_at=t.get('prepared_at'), ended_at=t.get('ended_at'),
                result=t.get('result'), successful=t.get('successful'), verified=t.get('verified'))
                for t in records.values()]
        if phase['id'] == '05':
            phase['artifacts'], phase['artifact_metrics'] = p05_artifacts(report, phase)
            phase['artifact_overview'] = 'Data Staging Findings (T1074): ' + '; '.join(f'{k.replace("_", " ")}: {v if v is not None else "unknown"}' for k, v in phase['artifact_metrics'].items()) + '. Phase completion is separate from host results; staging establishes no new compromise or exfiltration.'
            phase['staging_hosts'] = sorted({a['host'] for a in phase['artifacts']} | {e.get('fields', {}).get('host') for e in events if e.get('event') == 'STAGING_SUCCESS' and address(e.get('fields', {}).get('host'))})
            phase['artifact_outcomes'] = [f"{e.get('timestamp')} · {e.get('message')}" for e in events if e.get('event') in {'STAGING_FAILED', 'STAGING_SKIPPED'}]
            phase['artifact_outcomes'] += [f"Host {host}: staging success recorded, but no artifact path/size/hash was captured; inspect the incident Ground Truth and producer evidence." for host in phase['staging_hosts'] if not any(a['host'] == host for a in phase['artifacts'])]
            phase['analysis']['what_happened'] = phase['artifact_overview']
        if phase['id'] == '04':
            discovery = p04_summary(events)
            phase['discovery'] = discovery
            if discovery['sources']:
                counts = discovery['counts']
                phase['discovery_overview'] = (f"Internal discovery: {counts['sources']} sources / {counts['targets']} targets / "
                    f"{counts['open_ports']} open TCP results across source-target pairs. "
                    "Remote execution success does not establish target reachability or compromise.")
                details = []
                for source in discovery['sources'][:100]:
                    details.append(f"source={source['source']} platform={source['platform']} transport={source['transport']} execution={source['execution']}")
                for pair in discovery['targets'][:100]:
                    ports = ', '.join(f"{port}={status}" for port, status in sorted(pair['tcp'].items(), key=lambda x: int(x[0]))) or 'unknown / no responses recorded'
                    refs = '; '.join(f"{e.get('timestamp')} {e.get('path', 'ground truth')}:{e.get('line', '?')}" for e in pair['evidence'][:10])
                    details.append(f"source={pair['source']} target={pair['target']} platform={pair['platform']} transport={pair['transport']} ping={pair['ping']} TCP: {ports}. Evidence: {refs or 'no probe lines recorded'}")
                if len(discovery['targets']) > 100 or len(discovery['sources']) > 100 or discovery['truncated']:
                    details.append('Detail display capped at 100 sources / 100 pairs; consult structured evidence. Capture limit reached.' if discovery['truncated'] else 'Detail display capped at 100 sources / 100 pairs; aggregate counts include all recorded pairs.')
                phase['discovery_findings'] = details
                phase['analysis']['what_happened'] = phase['discovery_overview']
                phase['analysis']['findings'] = details
                phase['analysis']['evidence'] = phase['analysis']['evidence'][:200]
                if report.get('summary') is not None:
                    involved = {s['source'] for s in discovery['sources']} | {p['target'] for p in discovery['targets']}
                    report['summary']['involved_hosts'] = len(involved | {h.get('ip') for h in (report.get('inventory') or {}).get('hosts', []) if h.get('ip')})
        if phase['id'] == '03':
            checks = [e for e in events if e['event'] in {'ACCESS_SUCCESS', 'ACCESS_FAILED'}]
            successes = sum(e['event'] == 'ACCESS_SUCCESS' for e in checks)
            skipped = sum(e['event'].endswith('AUTH_SKIPPED') for e in events)
            phase['action_result'] = 'authenticated_access_verified' if successes else 'no_authenticated_access' if events else 'not_attempted'
            phase['action_outcome'] = (f'Access validation recorded: {successes} verified protocol successes, {len(checks) - successes} unsuccessful checks, {skipped} skipped checks. Port reachability alone is not authenticated access.'
                                       if events else 'Access validation not attempted; no authenticated protocol evidence recorded.')
            # Preserve historical auth-skip and service evidence as well as v2 attempts.
            phase['action_evidence'] = [str(e.get('message') or e.get('evidence') or e['event']) for e in events if e['event'] not in {'PHASE_START', 'PHASE_COMPLETE', 'PHASE_FAILED'}]
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = phase['action_evidence'] or ['No authenticated protocol success recorded; inspect P01 inventory and P03 configuration.']
        if phase['id'] == '09' and phase.get('status') == 'skipped':
            # Operational prerequisite information belongs in both report views.
            phase['prerequisite_outcome'] = next((e['fields'].get('reason') for e in reversed(events)
                if e['event'] == 'PHASE_SKIPPED' and e['fields'].get('reason')),
                'Active Directory prerequisite unavailable; privileged AD action not attempted')
            details = [e['message'] for e in events if e['event'] == 'WINDOWS_ACTION_SKIPPED' or e['event'].startswith(('P09_', 'P03_'))]
            phase['prerequisite_evidence'] = details
            phase['analysis']['what_happened'] = phase['prerequisite_outcome']
            phase['analysis']['findings'] = details or [phase['prerequisite_outcome']]
        if phase['id'] == '09' and phase.get('status') in {'success', 'failure', 'partial'}:
            details = [e['timestamp'] + ' · ' + e['message'] for e in events
                       if e['event'].startswith(('WINDOWS_ACTION_', 'P09_', 'P03_')) and e['event'] != 'WINDOWS_ACTION_START']
            phase['action_result'] = phase['status']
            phase['action_outcome'] = ('Active Directory account and Domain Admins action completed'
                                       if phase['status'] == 'success' else 'Active Directory action partial; postconditions not confirmed' if phase['status'] == 'partial' else 'Active Directory action failed')
            phase['action_evidence'] = details
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = details or [phase['action_outcome']]
        if phase['id'] == '10':
            phase['actions'] = [dict(timestamp=e['timestamp'], outcome=e['outcome'], **e['fields']) for e in events if e['event'].startswith(('WINDOWS_ACTION_', 'REMOTE_ACTION_')) and not e['event'].endswith(('_START', '_PARTIAL'))]
            details = [e['timestamp'] + ' · ' + e['message'] for e in events if e['event'].startswith(('WINDOWS_ACTION_', 'REMOTE_ACTION_')) and not e['event'].endswith('_START')]
            for event in events:
                for stream in ('stdout', 'stderr'):
                    preview = event['fields'].get(stream + '_preview')
                    if preview:
                        details.append(event['timestamp'] + ' · ' + str(event.get('target') or '') + ' · Safe ' + stream + ' output preview (redacted, max 512 characters): ' + preview)
            phase['action_evidence'] = details
            phase['action_result'] = ('infrastructure_error' if phase.get('status') == 'failure'
                else 'success_with_warning' if any(e['event'] == 'REMOTE_ACTION_PARTIAL' for e in events)
                else 'command_error' if any(e['event'] in {'WINDOWS_ACTION_ERROR', 'REMOTE_ACTION_ERROR'} for e in events)
                else 'success_with_warning' if any(e['fields'].get('execution_status') == 'success_with_warning' for e in events)
                else 'success' if phase.get('status') == 'success' else None)
            phase['action_outcome'] = {
                'infrastructure_error': 'Custom remote command transport/authentication or infrastructure failure',
                'command_error': 'Custom remote command failed',
                'success_with_warning': 'Custom remote command completed with nonfatal stderr/warnings',
                'success': 'Custom remote command completed',
            }.get(phase['action_result'], 'Custom remote command not executed')
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = details or [phase['action_outcome']]
        if phase['id'] in {'15', '16', '17', '18'}:
            prefix = {'15': 'WEB_ACTION_', '16': 'EVASION_ACTION_', '17': 'COLLECTION_ACTION_', '18': 'DNS_ACTION_'}[phase['id']]
            phase['actions'] = [dict(timestamp=e['timestamp'], outcome=e['outcome'], **e['fields']) for e in events if e['event'].startswith(prefix)]
            phase['action_evidence'] = [e['timestamp'] + ' · ' + e['message'] for e in events if e['event'].startswith(prefix)]
            phase['action_outcome'] = phase['name'] + ': ' + str(phase.get('status', 'not_run'))
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = phase['action_evidence'] or ['No action evidence recorded']
        if phase['id'] in {'12', '14'}:
            prefix = 'CREDENTIAL_ACTION_' if phase['id'] == '12' else 'BEACON_ACTION_'
            actions = [dict(timestamp=e['timestamp'], outcome=e['outcome'], **e['fields']) for e in events if e['event'].startswith(prefix)]
            phase['actions'] = actions
            phase['action_evidence'] = [e['timestamp'] + ' · ' + e['message'] for e in events if e['event'].startswith(prefix)]
            phase['action_outcome'] = ('Synthetic Credential Access: ' if phase['id'] == '12' else 'HTTP(S) Beacon Simulation: ') + str(phase.get('status', 'not_run'))
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = phase['action_evidence'] or ['No lab action evidence recorded']
        if phase['id'] in {'11', '13'}:
            details = [e['timestamp'] + ' · ' + e['message'] for e in events
                       if e['event'].startswith('PERSISTENCE_ACTION_' if phase['id'] == '11' else 'NATIVE_ACTION_')]
            phase['actions'] = [dict(timestamp=e['timestamp'], outcome=e['outcome'], **e['fields']) for e in events if e['event'].startswith('PERSISTENCE_ACTION_' if phase['id'] == '11' else 'NATIVE_ACTION_')]
            phase['action_evidence'] = details
            process_execution = phase['id'] == '11' and any(e['fields'].get('method') in {'process', 'process-dns'} for e in events)
            phase['action_outcome'] = ('Bounded process execution (no reboot persistence): ' if process_execution else 'Persistence: ' if phase['id'] == '11' else 'Windows Native Tools / LOLBins: ') + str(phase.get('status', 'not_run')) + '; verify artifact and cleanup metadata'
            phase['analysis']['what_happened'] = phase['action_outcome']
            phase['analysis']['findings'] = details or ['No persistence artifact evidence recorded']
    if any(p.get('id') == '05' and (p.get('events') or p.get('artifacts')) for p in report.get('phases', [])):
        involved = {a['host'] for p in report['phases'] for a in p.get('artifacts', [])}
        involved |= {e.get(k) for p in report['phases'] for e in p.get('events', []) for k in ('source', 'target') if address(e.get(k))}
        involved |= {h.get('ip') for h in (report.get('inventory') or {}).get('hosts', []) if h.get('ip')}
        report.setdefault('summary', {})['involved_hosts'] = len(involved)
    if report.get('report_type') == 'standalone_phase' and report.get('phase_id') == '05':
        unrelated = set(STATE_FILES) - {'staging'}
        report['warnings'] = [w for w in report.get('warnings', []) if not any(w.startswith('Unavailable ' + k + ':') for k in unrelated)]
        for k in unrelated:
            report.setdefault('evidence_availability', {})[k] = 'not applicable / not produced by standalone P05'
    report["analysis_version"] = 3
    report["mitre_summary"] = list(summary.values())
    report.setdefault("report_type", "campaign")
    return report


INCIDENT_ID = re.compile(r"(?:MRN|H3)-[A-Za-z0-9][A-Za-z0-9_-]{0,100}\Z")
PHASE_ORDER = ("01", "02", "15", "03", "08", "09", "10", "11", "12", "13", "14", "18", "16", "04", "17", "05", "06", "07")
STATE_FILES = {
    "networks": ("networks.json", "NORDIC_NETWORK_STATE"),
    "inventory": ("discovered-hosts.json", "NORDIC_DISCOVERED_STATE"),
    "web_targets": ("web-targets.json", "NORDIC_WEB_STATE"),
    "compromised": ("compromised-hosts.json", "NORDIC_COMPROMISED_STATE"),
    "staging": ("staged-data.json", "NORDIC_STAGING_STATE"),
    "exfiltration": ("exfiltration.json", "NORDIC_EXFIL_STATE"),
    "impact": ("impact.json", "NORDIC_IMPACT_STATE"),
    "wordlist": ("wordlist-results.json", None),
}


def read_metadata(path):
    """Read the same declarative ATTACK/MITRE/SCENARIO comments as the GUI."""
    result = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^\s*#+\s*((?:ATTACK|MITRE|SCENARIO)_\w+)\s*=(.*)$", line)
            if match:
                value = match[2].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                result[match[1]] = value
    except OSError:
        pass
    return result


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def redact(value):
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()
                if (not re.search(r"password|passwd|secret|token|credential|wordlist.*(?:content|entries)|^(?:contents|candidates)$", key, re.I)
                    or key == "credential_method" or (key == "candidate_passwords" and type(item) is int))}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)\b[\w-]*(?:password|passwd|secret|token|credential|wordlist_contents)[\w-]*\s*=.*?(?=\s+\w+=|$)", "[REDACTED]", value)
        value = re.sub(r"(?i)--(?:password|passwd|secret|token)\s+(?:\"[^\"]*\"|'[^']*'|\S+)", "[REDACTED]", value)
        value = re.sub(r"(\w+://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    return value


def redact_environment(value, environ):
    # Also remove supplied credentials from free-form values and historic messages.
    secrets = [v for k, v in environ.items() if re.search(r"PASSWORD|PASSWD|SECRET|TOKEN", k) and v]
    def clean(item):
        if isinstance(item, dict):
            # Identifiers are structural, never credential-bearing fields. Preserve
            # them even when a supplied password happens to equal an ID fragment.
            return {k: v if k in {"id", "incident_id", "phase_id"} else clean(v) for k, v in item.items()}
        if isinstance(item, list):
            return [clean(v) for v in item]
        if isinstance(item, str):
            for secret in sorted(secrets, key=len, reverse=True):
                item = item.replace(secret, "[REDACTED]")
        return item
    return clean(redact(value))


def outcome(event):
    upper = event.upper()
    if upper in {"DNS_ACTION_PARTIAL", "WINDOWS_ACTION_PARTIAL", "PHASE_PARTIAL"}:
        return "partial"
    if any(word in upper for word in ("SKIPPED", "EXCLUDED")):
        return "skipped"
    if any(word in upper for word in ("FAILED", "REJECTED", "INVALID", "ACTION_ERROR")):
        return "failure"
    if any(word in upper for word in ("SUCCESS", "COMPLETE", "DISCOVERED")) or upper in {"WEB_TARGET"}:
        return "success"
    return "observed"


def read_events(path, incident_id, started, warnings):
    events = []
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                match = re.match(r"^(\S+) INCIDENT=(\S+) (?:PHASE=(\d+)|CAMPAIGN) (.*)$", line.rstrip())
                if not match or match[2] != incident_id:
                    continue
                try:
                    if started and datetime.fromisoformat(match[1]) < datetime.fromisoformat(started).replace(microsecond=0):
                        continue
                except (ValueError, TypeError):
                    warnings.append(f"Invalid event timestamp at line {number}")
                message = match[4]
                # Values in existing logs may contain unquoted spaces or Windows paths.
                fields = {m[1]: m[2].strip().strip('"') for m in re.finditer(
                    r"\b(\w+)=(.*?)(?=\s+\w+=|$)", message)}
                if match[3] == '11':
                    for key in list(fields):
                        encoded = re.search(r'\b' + re.escape(key) + r'=("(?:\\.|[^"\\])*")(?=\s|$)', message)
                        if encoded:
                            try:
                                fields[key] = json.loads(encoded[1])
                            except (ValueError, TypeError):
                                fields[key] = '[invalid P11 evidence omitted]'
                name = message.split(" ", 1)[0]
                phase = match[3] or fields.get("phase")
                if phase in {'10', '13'}:
                    for key in ('stdout_preview', 'stderr_preview'):
                        encoded = re.search(r'\b' + key + r'=("(?:\\.|[^"\\])*")(?=\s|$)', message)
                        if key in fields:
                            try:
                                fields[key] = p10_output_preview(json.loads(encoded[1])) if encoded else '[invalid preview omitted]'
                            except (ValueError, TypeError):
                                fields[key] = '[invalid preview omitted]'
                protocol = fields.get("protocol") or fields.get("access") or fields.get("service")
                events.append(redact({
                    "timestamp": match[1], "phase": phase, "event": name,
                    "outcome": outcome(name), "source": fields.get("source"),
                    "target": fields.get("target") or fields.get("destination") or fields.get("ip") or fields.get("host"),
                    "protocol": protocol, "method": fields.get("method") or (
                        "wordlist" if name.startswith("WORDLIST_") else protocol),
                    "fields": fields, "message": name + " " + " ".join(
                        f"{key}={value}" for key, value in redact(fields).items()
                        if phase not in {'10', '13'} or key not in {'stdout_preview', 'stderr_preview'}),
                    "evidence": {"path": str(path), "line": number},
                }))
    except OSError:
        warnings.append(f"Missing/unreadable ground truth: {path}")
    return events


def build_report(base, incident_id, exit_code=0, environ=None, standalone=None):
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("Invalid incident ID")
    environ = environ or {}
    state_dir = Path(environ.get("NORDIC_STATE_DIR", base / "state"))
    campaign_path = Path(environ.get("NORDIC_CAMPAIGN_STATE", state_dir / "campaign.json"))
    campaign = standalone if standalone is not None else read_json(campaign_path)
    if not isinstance(campaign, dict) or campaign.get("incident_id") != incident_id:
        raise ValueError("Campaign state does not belong to this incident")
    warnings, snapshots, sources = [], {}, {}
    availability = {}
    for key, (filename, variable) in STATE_FILES.items():
        path = Path(environ.get(variable, state_dir / filename) if variable else state_dir / filename)
        sources[key] = str(path)
        if standalone is not None and (standalone['phase_id'] == '04' or standalone['phase_id'] == '05' and key != 'staging' or standalone['phase_id'] == '06' and key != 'exfiltration'):
            # These standalone phases produce their own evidence; unrelated snapshots
            # are not report inputs. Campaign provenance remains in execution logs.
            snapshots[key] = None
            availability[key] = 'not applicable / not produced by standalone P' + standalone['phase_id']
            continue
        try:
            data = read_json(path)
            if not isinstance(data, dict) or data.get("incident_id") != incident_id:
                raise ValueError("incident ID mismatch")
            snapshots[key] = redact(data)
        except (OSError, ValueError, TypeError) as error:
            snapshots[key] = None
            warnings.append(f"Unavailable {key}: {error}")
    log = Path(environ.get("NORDIC_GROUND_TRUTH_LOG", base / "logs" / "incident-ground-truth.log"))
    events = read_events(log, incident_id, campaign.get("started"), warnings)
    phases = []
    selected = [p['id'] for p in campaign.get('execution', {}).get('phases', [])]
    # Opt-in phases must not appear as new pending actions in legacy campaigns.
    known = set(campaign.get('phases', {})) | {e['phase'] for e in events}
    order = selected + [pid for pid in PHASE_ORDER if pid not in selected and (pid not in {'09', '10', '11', '12', '13', '14', '15', '16', '17', '18'} or pid in known)]
    for phase_id in ([standalone["phase_id"]] if standalone is not None else order):
        script = next(iter(sorted((base / "scripts").glob(phase_id + "-*.sh"))), None)
        metadata = read_metadata(script) if script else {}
        technique_ids = [x.strip() for x in metadata.get("MITRE_TECHNIQUES", "").split(",") if x.strip()]
        names = metadata.get("MITRE_TECHNIQUE_NAMES", "").split("|")
        phase_events = [event for event in events if event["phase"] == phase_id]
        if phase_id in {'15', '16', '17', '18'}:
            # New actions record technique sets per behavior/platform, including Windows library archiving.
            technique_ids = list(dict.fromkeys(t for e in phase_events for t in e['fields'].get('mitre', '').split(',') if mitre_url(t))) or technique_ids
            technique_names = {'T1071.004': 'DNS', 'T1132.001': 'Standard Encoding', 'T1190': 'Exploit Public-Facing Application', 'T1005': 'Data from Local System', 'T1685': 'Disable or Modify Tools', 'T1070': 'Indicator Removal', 'T1560.001': 'Archive via Utility', 'T1560.002': 'Archive via Library'}
            names = [technique_names.get(t, '') for t in technique_ids]
        if phase_id == '11' and phase_events and any(e['fields'].get('method') in {'process', 'process-dns'} for e in phase_events):
            metadata['MITRE_TACTIC'] = 'Execution'
        recorded = {t for e in phase_events for t in e['fields'].get('mitre', '').split(',')} & set(technique_ids)
        if phase_id == '13' or phase_id in {'10', '11'} and recorded:
            named = dict(zip(technique_ids, names))
            technique_ids = [tid for tid in technique_ids if tid in recorded]
            names = [named.get(tid, '') for tid in technique_ids]
        for event in phase_events:
            if phase_id in {'15', '16', '17', '18'}:
                tids = [t for t in event['fields'].get('mitre', '').split(',') if mitre_url(t)]
                event['mitre_technique_ids'] = tids
                event['mitre_mapping'] = 'action_metadata' if tids else 'phase_metadata'
                continue
            if phase_id == '11':
                tids = [t for t in event['fields'].get('mitre', '').split(',') if t in technique_ids]
                event['mitre_technique_ids'] = tids or technique_ids
                event['mitre_mapping'] = 'action_metadata' if tids else 'phase_metadata'
                continue
            action_tid = event['fields'].get('mitre')
            event["mitre_technique_ids"] = [action_tid] if action_tid in technique_ids else technique_ids
            event["mitre_mapping"] = "action_metadata" if action_tid in technique_ids else "phase_metadata"
        state = campaign.get("phases", {}).get(phase_id, "pending")
        status = {"complete": "success", "failed": "failure", "disabled": "skipped",
                  "partial": "partial", "pending": "not_run", "running": "interrupted"}.get(state, state)
        phases.append({
            "id": phase_id, "name": metadata.get("ATTACK_NAME", script.stem[3:] if script else phase_id),
            "status": status, "runtime_status": state,
            "started": next((e["timestamp"] for e in phase_events if e["event"] == "PHASE_START"), campaign.get("started") if standalone is not None else None),
            "ended": next((e["timestamp"] for e in reversed(phase_events) if e["event"] in {"PHASE_COMPLETE", "PHASE_PARTIAL", "PHASE_FAILED", "PHASE_SKIPPED"}), campaign.get("completed") if standalone is not None else None),
            "mitre": {"tactic": metadata.get("MITRE_TACTIC"), "techniques": [
                {"id": tid, "name": names[i] if i < len(names) and names[i] else None}
                for i, tid in enumerate(technique_ids)]},
            "outcomes": dict(Counter(e["outcome"] for e in phase_events)),
            "events": phase_events,
        })
    now = datetime.now(timezone.utc).isoformat()
    prerequisite_skip = standalone is not None and standalone['phase_id'] in {'09', '10', '11', '12', '13', '14', '15', '16', '17', '18'} and exit_code == 78
    status = "partial" if standalone is None and campaign.get("phases", {}).get("09") == "partial" and exit_code == 0 else "complete" if campaign.get("status") == "complete" and (exit_code == 0 or prerequisite_skip) else (
        "partial" if standalone is not None and standalone["phase_id"] in {"09", "18"} and exit_code == 80 else "interrupted" if exit_code in {130, 137, 143} else "failed")
    # A zero process exit does not prove that every selected phase finished.
    # Only explicit plan/state entries count; legacy reports include implicit
    # phase rows that were never selected.
    if standalone is None and status == "complete":
        expected = set(selected) | set(campaign.get("phases", {}))
        unfinished = [p for p in phases if p["id"] in expected
                      and p["runtime_status"] in {"pending", "running"}]
        if unfinished:
            status = "failed"
            for phase in unfinished:
                phase["status_reason"] = (
                    "Campaign ended without a recorded terminal phase status; "
                    "the prerequisite or execution cause is unknown.")
            warnings.append("Campaign completion is inconsistent: selected phases "
                            + ", ".join(p["id"] for p in unfinished)
                            + " have no recorded terminal status.")
    report = {
        "schema_version": 1, "generated_at": now,
        "report_type": "standalone_phase" if standalone is not None else "campaign",
        "incident": {"id": incident_id, "scenario": campaign.get("scenario", "full-incident"),
                     "scenario_name": campaign.get("scenario_name"),
                     "started": campaign.get("started"), "ended": campaign.get("completed") or now,
                     "status": status, "exit_code": exit_code},
        "campaign": redact(campaign), "phases": phases,
        "execution": redact(json.loads(environ["MRN_EXECUTION"])) if environ.get("MRN_EXECUTION") else campaign.get("execution"),
        "inventory": snapshots["inventory"], "compromised_hosts": snapshots["compromised"],
        "evidence": snapshots, "events": events, "sources": sources, "warnings": warnings,
        "evidence_availability": availability,
    }
    if standalone is not None:
        report["phase_id"] = standalone["phase_id"]
    report["summary"] = {
        "hosts": len((snapshots["inventory"] or {}).get("hosts", [])),
        "compromised": len((snapshots["compromised"] or {}).get("hosts", [])),
        "exfiltration": len((snapshots["exfiltration"] or {}).get("transfers", [])),
        "impact": len((snapshots["impact"] or {}).get("hosts", [])),
    }
    return redact_environment(add_analysis(report), environ)


def save_report(base, report):
    """Publish a complete file atomically and never overwrite a previous incident."""
    directory = base / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (report["incident"]["id"] + ".json")
    descriptor, temporary = tempfile.mkstemp(prefix=".report-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)
    return target


def load_report(directory, incident_id, enrich=True):
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("Invalid incident ID")
    path = directory / (incident_id + ".json")
    if path.is_symlink():
        raise ValueError("Report must be a regular file")
    data = read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("incident", {}).get("id") != incident_id:
        raise ValueError("Invalid report")
    # Historical files stay immutable; the read-time view gains educational sections.
    data = redact_environment(data, os.environ)
    return add_analysis(data) if enrich else data


def list_reports(directory):
    result = []
    for path in directory.glob("*.json"):
        try:
            report = load_report(directory, path.stem)
            result.append({**report["incident"], "summary": report.get("summary", {}),
                           "report_type": report.get("report_type", "campaign"), "phase_id": report.get("phase_id"),
                           "techniques": [{"id": p.get("id"), "name": p.get("name", "Unknown"),
                                           "status": p.get("status", "unknown")}
                                          for p in (report.get("phases") or []) if isinstance(p, dict)]})
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return sorted(result, key=lambda item: item.get("started") or "", reverse=True)


def run_phase(base, phase_id, script, environ=None):
    """Wrap one existing phase; preserve its inputs, exit status and campaign state.

    Every invocation has a collision-resistant MRN ID, including state-consuming runs.
    Only snapshots tagged with this ID are accepted; foreign state is never relabelled.
    """
    if not re.fullmatch(r"\d+", phase_id):
        raise ValueError("Invalid phase ID")
    env = dict(os.environ if environ is None else environ)
    requested_id = env.get('NORDIC_INCIDENT_ID', '') if env.get('MRN_OVERVIEW') else ''
    incident_id = requested_id if INCIDENT_ID.fullmatch(requested_id) else "MRN-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]
    env["NORDIC_INCIDENT_ID"] = incident_id
    started = datetime.now(timezone.utc).isoformat()
    received = []
    child = None
    def forward(signum, frame):
        received.append(signum)
        if child is not None and child.poll() is None:
            child.send_signal(signum)
    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGTERM, signal.SIGINT)}
    code = 1
    try:
        try:
            if env.get("MRN_EXECUTION"):
                from execution import phase_environment
                env = phase_environment(phase_id, env)
            child = subprocess.Popen([str(script)], env=env)
            code = child.wait()
            code = 128 + received[-1] if received else (128 - code if code < 0 else code)
        except OSError:
            print("[WARN] Phase could not be started", flush=True)
        finally:
            skipped = (phase_id in {'09', '10', '11', '12', '13', '14', '15', '16', '17', '18'} and code == 78) or (phase_id in {'10', '13'} and code == 79)
            state = {"incident_id": incident_id, "scenario": "standalone-phase", "phase_id": phase_id,
                     "started": started, "completed": datetime.now(timezone.utc).isoformat(),
                     "status": "partial" if phase_id in {"09", "18"} and code == 80 else "complete" if code == 0 or (phase_id in {'09', '10', '11', '12', '13', '14', '15', '16', '17', '18'} and code == 78) else "failed",
                     "phases": {phase_id: "partial" if phase_id in {"09", "18"} and code == 80 else "skipped" if skipped else "complete" if code == 0 else "running" if code in {130, 137, 143} else "failed"}}
            try:
                path = save_report(base, build_report(base, incident_id, code, env, standalone=state))
                print(f"Report: {path}", flush=True)
            except Exception:
                # Reporting failure must not change the phase's result or leak input values.
                print("[WARN] Could not create standalone report", flush=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    # CLI/scheduler conventions: a handled prerequisite skip is nonfatal. Keep
    # the worker's exit 78 in the report and the phase itself explicitly skipped.
    return 0 if phase_id in {'09', '10', '11', '12', '13', '14', '15', '16', '17', '18'} and code == 78 else code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", type=Path, default=Path("/opt/nordic-attack"))
    parser.add_argument("--incident-id")
    parser.add_argument("--run-phase", metavar="PHASE_ID")
    parser.add_argument("--script", type=Path)
    parser.add_argument("--exit-code", type=int, default=0)
    args = parser.parse_args()
    if args.run_phase:
        if not args.script:
            parser.error("--script is required for --run-phase")
        raise SystemExit(run_phase(args.base_dir, args.run_phase, args.script))
    if not args.incident_id:
        parser.error("--incident-id is required")
    print(save_report(args.base_dir, build_report(args.base_dir, args.incident_id, args.exit_code, os.environ)))


if __name__ == "__main__":
    main()
