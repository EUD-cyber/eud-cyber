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


def mitre_url(technique_id):
    """Only construct direct ATT&CK technique URLs from validated IDs."""
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id or ""):
        return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
    return None


# Recommendations, never observations. Sensors/auditing must be configured in the lab.
PHASE_GUIDANCE = {
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
        "Build a source-to-target timeline. Establish whether the record shows internal discovery, authentication or remote execution; do not infer lateral compromise from an open port.",
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


def add_analysis(report):
    """Add a versioned student view without changing the underlying phase evidence."""
    summary = {}
    for phase in report.get("phases", []):
        events = phase.get("events", [])
        guidance = PHASE_GUIDANCE.get(phase["id"], (
            "Correlate collected host and network logs with recorded event times.",
            "Validate each recorded outcome against target evidence.",
            "Apply least privilege, segmentation and monitoring appropriate to the recorded activity."))
        for technique in phase.get("mitre", {}).get("techniques", []):
            technique["url"] = mitre_url(technique.get("id"))
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
    report["analysis_version"] = 2
    report["mitre_summary"] = list(summary.values())
    report.setdefault("report_type", "campaign")
    return report


INCIDENT_ID = re.compile(r"(?:MRN|H3)-[A-Za-z0-9][A-Za-z0-9_-]{0,100}\Z")
PHASE_ORDER = ("01", "02", "03", "08", "04", "05", "06", "07")
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
    if any(word in upper for word in ("SKIPPED", "EXCLUDED")):
        return "skipped"
    if any(word in upper for word in ("FAILED", "REJECTED", "INVALID")):
        return "failure"
    if any(word in upper for word in ("SUCCESS", "COMPLETE", "DISCOVERED")) or upper in {"WEB_TARGET", "INTERNAL_DISCOVERY"}:
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
                name = message.split(" ", 1)[0]
                phase = match[3] or fields.get("phase")
                protocol = fields.get("protocol") or fields.get("access") or fields.get("service")
                events.append(redact({
                    "timestamp": match[1], "phase": phase, "event": name,
                    "outcome": outcome(name), "source": fields.get("source"),
                    "target": fields.get("target") or fields.get("destination") or fields.get("ip") or fields.get("host"),
                    "protocol": protocol, "method": fields.get("method") or (
                        "wordlist" if name.startswith("WORDLIST_") else protocol),
                    "fields": fields, "message": name + " " + " ".join(
                        f"{key}={value}" for key, value in redact(fields).items()),
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
    for key, (filename, variable) in STATE_FILES.items():
        path = Path(environ.get(variable, state_dir / filename) if variable else state_dir / filename)
        sources[key] = str(path)
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
    order = selected + [pid for pid in PHASE_ORDER if pid not in selected]
    for phase_id in ([standalone["phase_id"]] if standalone is not None else order):
        script = next(iter(sorted((base / "scripts").glob(phase_id + "-*.sh"))), None)
        metadata = read_metadata(script) if script else {}
        technique_ids = [x.strip() for x in metadata.get("MITRE_TECHNIQUES", "").split(",") if x.strip()]
        names = metadata.get("MITRE_TECHNIQUE_NAMES", "").split("|")
        phase_events = [event for event in events if event["phase"] == phase_id]
        for event in phase_events:
            event["mitre_technique_ids"] = technique_ids
            event["mitre_mapping"] = "phase_metadata"
        state = campaign.get("phases", {}).get(phase_id, "pending")
        status = {"complete": "success", "failed": "failure", "disabled": "skipped",
                  "pending": "not_run", "running": "interrupted"}.get(state, state)
        phases.append({
            "id": phase_id, "name": metadata.get("ATTACK_NAME", script.stem[3:] if script else phase_id),
            "status": status, "runtime_status": state,
            "started": next((e["timestamp"] for e in phase_events if e["event"] == "PHASE_START"), campaign.get("started") if standalone is not None else None),
            "ended": next((e["timestamp"] for e in reversed(phase_events) if e["event"] in {"PHASE_COMPLETE", "PHASE_FAILED"}), campaign.get("completed") if standalone is not None else None),
            "mitre": {"tactic": metadata.get("MITRE_TACTIC"), "techniques": [
                {"id": tid, "name": names[i] if i < len(names) and names[i] else None}
                for i, tid in enumerate(technique_ids)]},
            "outcomes": dict(Counter(e["outcome"] for e in phase_events)),
            "events": phase_events,
        })
    now = datetime.now(timezone.utc).isoformat()
    status = "complete" if campaign.get("status") == "complete" and exit_code == 0 else (
        "interrupted" if exit_code in {130, 137, 143} else "failed")
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
                           "report_type": report.get("report_type", "campaign"), "phase_id": report.get("phase_id")})
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
    incident_id = "MRN-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]
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
            state = {"incident_id": incident_id, "scenario": "standalone-phase", "phase_id": phase_id,
                     "started": started, "completed": datetime.now(timezone.utc).isoformat(),
                     "status": "complete" if code == 0 else "failed",
                     "phases": {phase_id: "complete" if code == 0 else "running" if code in {130, 137, 143} else "failed"}}
            try:
                path = save_report(base, build_report(base, incident_id, code, env, standalone=state))
                print(f"Report: {path}", flush=True)
            except Exception:
                # Reporting failure must not change the phase's result or leak input values.
                print("[WARN] Could not create standalone report", flush=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return code


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
