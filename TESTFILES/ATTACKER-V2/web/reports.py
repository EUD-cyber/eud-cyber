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
                if not re.search(r"(?:^|_)(?:password|passwd|secret|token|credential)(?:$|_)", key, re.I)
                or key in {"credential_method", "candidate_passwords"}}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


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
                    "fields": fields, "message": message,
                    "evidence": {"path": str(path), "line": number},
                }))
    except OSError:
        warnings.append(f"Missing/unreadable ground truth: {path}")
    return events


def build_report(base, incident_id, exit_code=0, environ=None):
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("Invalid incident ID")
    environ = environ or {}
    state_dir = Path(environ.get("NORDIC_STATE_DIR", base / "state"))
    campaign_path = Path(environ.get("NORDIC_CAMPAIGN_STATE", state_dir / "campaign.json"))
    campaign = read_json(campaign_path)
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
    for phase_id in PHASE_ORDER:
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
            "started": next((e["timestamp"] for e in phase_events if e["event"] == "PHASE_START"), None),
            "ended": next((e["timestamp"] for e in reversed(phase_events) if e["event"] in {"PHASE_COMPLETE", "PHASE_FAILED"}), None),
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
        "incident": {"id": incident_id, "scenario": campaign.get("scenario", "full-incident"),
                     "started": campaign.get("started"), "ended": campaign.get("completed") or now,
                     "status": status, "exit_code": exit_code},
        "campaign": redact(campaign), "phases": phases,
        "inventory": snapshots["inventory"], "compromised_hosts": snapshots["compromised"],
        "evidence": snapshots, "events": events, "sources": sources, "warnings": warnings,
    }
    report["summary"] = {
        "hosts": len((snapshots["inventory"] or {}).get("hosts", [])),
        "compromised": len((snapshots["compromised"] or {}).get("hosts", [])),
        "exfiltration": len((snapshots["exfiltration"] or {}).get("transfers", [])),
        "impact": len((snapshots["impact"] or {}).get("hosts", [])),
    }
    return report


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


def load_report(directory, incident_id):
    if not INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("Invalid incident ID")
    path = directory / (incident_id + ".json")
    if path.is_symlink():
        raise ValueError("Report must be a regular file")
    data = read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("incident", {}).get("id") != incident_id:
        raise ValueError("Invalid report")
    return data


def list_reports(directory):
    result = []
    for path in directory.glob("*.json"):
        try:
            report = load_report(directory, path.stem)
            result.append({**report["incident"], "summary": report.get("summary", {})})
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return sorted(result, key=lambda item: item.get("started") or "", reverse=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", type=Path, default=Path("/opt/nordic-attack"))
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--exit-code", type=int, default=0)
    args = parser.parse_args()
    print(save_report(args.base_dir, build_report(args.base_dir, args.incident_id, args.exit_code, os.environ)))


if __name__ == "__main__":
    main()
