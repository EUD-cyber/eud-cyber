"""Passive, ephemeral correlation of untrusted log slices with verified receipts.

No network, rules, execution, database writes or automatic detection verdicts.
Raw logs/payloads/descriptions never leave this module in the result.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re

from master_registry import validate_id, REPORT_ID, Unavailable

MAX_SOURCE_BYTES = 512 * 1024
MAX_LINES = 2000
MAX_LINE_BYTES = 65536
DISPLAY_ROWS = 200
TECHNIQUE = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?')
REFERENCE_TECHNIQUES = {'P06': ['T1041'], 'P11': ['T1071.001']}
STATES = ('correlated_alert', 'candidate_alert', 'correlated_telemetry', 'candidate_telemetry')


class ValidationError(ValueError):
    """Messages contain only fixed instructions and line numbers, never log text."""


def obj(value):
    return value if isinstance(value, dict) else {}


def array(value):
    return value if isinstance(value, list) else []


def number(value):
    if type(value) is int and 0 < value <= 2**64-1:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,19}', value) and int(value) <= 2**64-1:
        return value
    return None


def instant(value):
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:?\d\d)', value):
        raise ValueError('Timezone-aware ISO timestamp required')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return result.timestamp(), result.astimezone(timezone.utc).isoformat()


def address(value):
    if not isinstance(value, str) or len(value) > 45:
        raise ValidationError('Use a numeric observed source/destination IP, not a URL or hostname.')
    try:
        result = ipaddress.ip_address(value)
        return str(result.ipv4_mapped if result.version == 6 and result.ipv4_mapped else result)
    except ValueError:
        raise ValidationError('Invalid observed IP address.') from None


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValidationError('Duplicate JSON fields are not supported.')
        result[key] = value
    return result


def scope(data):
    if not isinstance(data, dict) or set(data) != {'agent_id', 'campaign_id', 'window_seconds',
            'wazuh_agent_id', 'observed_source_ip', 'observed_destination_ip', 'sources'}:
        raise ValidationError('Invalid validation fields.')
    validate_id(data['agent_id'])
    if not isinstance(data['campaign_id'], str) or not REPORT_ID.fullmatch(data['campaign_id']):
        raise ValidationError('A valid MRN/H3 campaign or fixed job ID is required.')
    if type(data['window_seconds']) is not int or not 0 <= data['window_seconds'] <= 300:
        raise ValidationError('Time window must be 0–300 seconds.')
    if not isinstance(data['sources'], list) or not 1 <= len(data['sources']) <= 2:
        raise ValidationError('Choose one or two log slices.')
    kinds = set(); total = 0
    for source in data['sources']:
        if not isinstance(source, dict) or set(source) != {'kind', 'content'} or not isinstance(source['kind'], str) or source['kind'] not in {'wazuh', 'suricata'}:
            raise ValidationError('Only Wazuh and Suricata NDJSON slices are supported.')
        if source['kind'] in kinds or not isinstance(source['content'], str):
            raise ValidationError('Choose at most one slice per sensor format.')
        kinds.add(source['kind']); total += len(source['content'].encode('utf-8'))
    if total > MAX_SOURCE_BYTES:
        raise ValidationError('Combined log slices exceed 512 KiB. Export a smaller time window.')
    if not isinstance(data['wazuh_agent_id'], str) or (data['wazuh_agent_id'] and not re.fullmatch(r'[0-9]{1,8}', data['wazuh_agent_id'])):
        raise ValidationError('Wazuh observer ID must be 1–8 digits.')
    if 'wazuh' in kinds and not data['wazuh_agent_id']:
        raise ValidationError('Explicitly declare the Wazuh observer ID; it is not a MrNobody Agent ID.')
    if any(not isinstance(data[key], str) for key in ('observed_source_ip', 'observed_destination_ip')):
        raise ValidationError('Observed IP bindings must be strings.')
    if 'suricata' in kinds:
        for key in ('observed_source_ip', 'observed_destination_ip'):
            data[key] = address(data[key])
    elif data['observed_source_ip'] or data['observed_destination_ip']:
        raise ValidationError('Observed IP bindings apply only to Suricata.')
    return data


def reference(store, data):
    agent = next((row for row in store.list_agents() if row['agent_id'] == data['agent_id']), None)
    if not agent or agent['status'] not in {'online', 'offline'}:
        raise ValidationError('A registered, non-revoked Agent is required; offline history is supported.')
    page = store.list_receiver_events(limit=100, agent_id=data['agent_id'], campaign_id=data['campaign_id'])
    receipts = [dict(row) for row in page['events'] if row.get('verified') is True and row.get('phase') in REFERENCE_TECHNIQUES]
    cached = store.read_report(data['agent_id'], data['campaign_id'])
    report = {}
    if cached:
        try:
            if hashlib.sha256(cached['content'].encode()).hexdigest() != cached['sha256']:
                raise ValueError('Digest mismatch')
            report = json.loads(cached['content'], object_pairs_hook=pairs)
            if (not isinstance(report, dict) or report.get('schema_version') != 1
                    or obj(report.get('incident')).get('id') != data['campaign_id']):
                raise ValueError('Report scope mismatch')
        except (ValueError, TypeError, RecursionError):
            raise Unavailable('Cached Ground Truth unavailable.') from None
    events = array(report.get('events'))[:5000]
    p06 = obj(obj(obj(report.get('evidence')).get('exfiltration')).get('live_lab'))
    phase_metadata = {}
    for phase in array(report.get('phases'))[:100]:
        phase = obj(phase)
        if str(phase.get('id')) in {'06', '11'}:
            phase_metadata['P' + str(phase['id'])] = sorted({t['id'] for t in array(obj(phase.get('mitre')).get('techniques'))
                if isinstance(t, dict) and isinstance(t.get('id'), str) and TECHNIQUE.fullmatch(t['id'])})[:32]
    for row in receipts:
        linked = (row['phase'] == 'P06' and number(p06.get('event_id')) == str(row['id'])
                  and p06.get('verified') is True and p06.get('agent_id') == data['agent_id']
                  and p06.get('campaign_id') == data['campaign_id'] and p06.get('sha256') == row.get('sha256'))
        if row['phase'] == 'P11':
            linked = any(obj(event).get('event') == 'P11_BEACON_ACK'
                and str(obj(event).get('phase')) == '11'
                and number(obj(obj(event).get('fields')).get('event_id')) == str(row['id'])
                and number(obj(obj(event).get('fields')).get('sequence')) == str(row.get('sequence'))
                and (obj(obj(event).get('fields')).get('verified') is True
                     or obj(obj(event).get('fields')).get('verified') == 'true') for event in events)
        row['ground_truth_linked'] = bool(linked)
        row['reference_techniques'] = REFERENCE_TECHNIQUES[row['phase']]
        row['phase_metadata_techniques'] = phase_metadata.get(row['phase'], [])
        row['sensor_evidence'] = {state: 0 for state in STATES}
    return receipts, dict(report_status='synchronized' if cached else 'not_synchronized',
        report_sha256=cached['sha256'] if cached else None,
        receiver_page_truncated=page['next_before'] is not None,
        ground_truth_events_truncated=len(array(report.get('events'))) > 5000,
        excluded_unverified_or_unsupported=len(page['events']) - len(receipts))


def normalize(raw, kind, line, data):
    """Internal anchors may use raw text, but only allowlisted metadata is returned."""
    if not isinstance(raw, dict):
        raise ValueError('Object required')
    epoch, stamp = instant(raw.get('timestamp'))
    meta = obj(obj(raw.get('data')).get('mrnobody'))
    if kind == 'wazuh':
        if not isinstance(obj(raw.get('agent')).get('id'), str):
            raise ValueError('Wazuh agent required')
        bound = raw['agent']['id'] == data['wazuh_agent_id']
        rule = obj(raw.get('rule')); rule_id = rule.get('id')
        if rule and (not re.fullmatch(r'[0-9]{1,10}', str(rule_id)) or type(rule.get('level')) is not int or not 0 <= rule['level'] <= 16):
            raise ValueError('Invalid Wazuh rule')
        alert = bool(rule) and rule['level'] > 0
        ids = obj(rule.get('mitre')).get('id', [])
        ids = [ids] if isinstance(ids, str) else array(ids)
        techniques = sorted({value for value in ids if isinstance(value, str) and TECHNIQUE.fullmatch(value)})[:32]
        hashes = [obj(raw.get('syscheck')).get('sha256_after')]
        text = raw.get('full_log', '')
        flow = None
    else:
        event_type = raw.get('event_type')
        if event_type not in {'alert', 'http', 'tls', 'flow', 'fileinfo'}:
            return None
        try:
            bound = address(raw.get('src_ip')) == data['observed_source_ip'] and address(raw.get('dest_ip')) == data['observed_destination_ip']
        except ValidationError:
            bound = False
        rule_id = obj(raw.get('alert')).get('signature_id')
        if event_type == 'alert' and (type(rule_id) is not int or not 1 <= rule_id <= 2**32-1):
            raise ValueError('Invalid Suricata alert')
        alert = event_type == 'alert'; techniques = []
        hashes = [obj(raw.get('fileinfo')).get('sha256')]
        text = raw.get('payload_printable', '')
        flow = number(raw.get('flow_id'))
    text = text if isinstance(text, str) else ''
    campaigns = set(re.findall(r'\bINCIDENT=([^\s|;,]+)', text))
    campaigns.update(re.findall(r'"campaign_id"\s*:\s*"([A-Za-z0-9_-]+)"', text))
    if isinstance(meta.get('campaign_id'), str): campaigns.add(meta['campaign_id'])
    phases = set(re.findall(r'\bPHASE=(?:P)?([0-9]{2})\b', text))
    phases.update(re.findall(r'"phase"\s*:\s*"(?:P)?([0-9]{2})"', text))
    if 'phase' in meta:
        value = meta['phase']
        phases.add(value[-2:] if isinstance(value, str) and re.fullmatch(r'P?[0-9]{2}', value) else 'invalid')
    event_ids = set()
    if number(meta.get('receiver_event_id')): event_ids.add(number(meta['receiver_event_id']))
    if 'P11_BEACON_ACK' in text:
        phases.add('11'); event_ids.update(re.findall(r'\bevent_id=([1-9][0-9]*)\b', text))
    sequences = {str(value) for value in re.findall(r'"sequence"\s*:\s*([1-9][0-9]*)\b', text)}
    if number(meta.get('sequence')): sequences.add(number(meta['sequence']))
    return dict(epoch=epoch, timestamp=stamp, bound=bound, alert=alert, rule_id=str(rule_id) if alert else None,
        rule_techniques=techniques, flow_id=flow, campaigns=campaigns, phases=phases,
        event_ids=event_ids, sequences=sequences, beacon_marker='MRN-EXERCISE-ONLY' in text,
        hashes={value.lower() for value in hashes if isinstance(value, str) and re.fullmatch('[0-9a-fA-F]{64}', value)})


def correlate(store, request_data):
    data = scope(request_data)
    receipts, availability = reference(store, data)
    counts = {state: 0 for state in STATES}; counts.update(unmatched=0, ignored=0, duplicates=0, parsed=0)
    rows = []; manifests = []; seen = set(); total_lines = 0
    for source in data['sources']:
        kind, content = source['kind'], source['content']
        manifests.append(dict(kind=kind, sha256=hashlib.sha256(content.encode()).hexdigest(), bytes=len(content.encode())))
        for line, raw_line in enumerate(content.splitlines(), 1):
            if not raw_line.strip(): continue
            total_lines += 1
            if total_lines > MAX_LINES or len(raw_line.encode()) > MAX_LINE_BYTES:
                raise ValidationError('Slice exceeds 2000 records or a 64 KiB line. Use a smaller export.')
            try:
                raw = json.loads(raw_line, object_pairs_hook=pairs)
                digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
                normalized = normalize(raw, kind, line, data)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise ValidationError('Invalid ' + kind + ' record at line ' + str(line) + '; no partial verdict returned.') from None
            counts['parsed'] += 1
            if (kind, digest) in seen:
                counts['duplicates'] += 1; continue
            seen.add((kind, digest))
            if normalized is None:
                counts['ignored'] += 1; continue
            n = normalized; matches = []; strong = []; reasons = set()
            conflict = bool(n['campaigns'] and n['campaigns'] != {data['campaign_id']}) or len(n['phases']) > 1
            for receipt in receipts:
                if conflict or not n['bound'] or abs(n['epoch'] - receipt['received_at']) > data['window_seconds']:
                    continue
                if n['phases'] and n['phases'] != {receipt['phase'][-2:]}:
                    continue
                matches.append(receipt)
                camp = n['campaigns'] == {data['campaign_id']}
                basis = None
                if receipt['phase'] == 'P06' and receipt.get('sha256') in n['hashes']:
                    basis = 'exact_fixture_hash'
                elif camp and n['phases'] == {receipt['phase'][-2:]} and n['event_ids'] == {str(receipt['id'])}:
                    basis = 'explicit_campaign_phase_receiver_id'
                elif receipt['phase'] == 'P11' and camp and n['phases'] == {'11'} and n['beacon_marker'] and n['sequences'] == {str(receipt.get('sequence'))}:
                    basis = 'synthetic_beacon_campaign_phase_sequence'
                if basis:
                    strong.append(receipt); reasons.add(basis)
            selected = strong or matches
            unambiguous = len(strong) == 1
            if len(strong) > 1: reasons.add('ambiguous_receipt_anchor')
            state = ('correlated_alert' if n['alert'] else 'correlated_telemetry') if unambiguous else (
                ('candidate_alert' if n['alert'] else 'candidate_telemetry') if matches else 'unmatched')
            counts[state] += 1
            for receipt in selected: receipt['sensor_evidence'][state] += 1
            missing = 'explicit_campaign_or_phase_conflict' if conflict else 'observer_binding_mismatch' if not n['bound'] else (
                'no_verified_receiver_reference' if not receipts else 'outside_receipt_window_or_phase')
            row = dict(kind=kind, line=line, sha256=digest, timestamp=n['timestamp'], classification=state,
                rule_id=n['rule_id'], rule_techniques=n['rule_techniques'], flow_id=n['flow_id'],
                basis=sorted(reasons) if strong else ['declared_observer_and_time_only'] if matches else [missing],
                receiver_event_ids=[item['id'] for item in selected[:10]], receiver_match_count=len(selected))
            if len(rows) < DISPLAY_ROWS: rows.append(row)
    # Project even local reference rows: no paths, file bytes or arbitrary report fields.
    fields = ('id', 'phase', 'received_at', 'sequence', 'sha256', 'received_size', 'ground_truth_linked',
              'reference_techniques', 'phase_metadata_techniques', 'sensor_evidence')
    return dict(schema_version=1, mode='untrusted_import_preview', agent_id=data['agent_id'], campaign_id=data['campaign_id'],
        window_seconds=data['window_seconds'], bindings={key:data[key] for key in ('wazuh_agent_id','observed_source_ip','observed_destination_ip')},
        coverage='unknown', verdict='imported_correlated_alerts' if counts['correlated_alert'] else 'no_correlated_alert_in_supplied_slice',
        counts=counts, sources=manifests, rows=rows, rows_truncated=counts['parsed']-counts['duplicates']-counts['ignored']>len(rows),
        reference=availability, receipts=[{key:row[key] for key in fields if key in row} for row in receipts],
        limitations=['Imported sources and observer bindings are operator-supplied, not authenticated SIEM evidence.',
            'Receiver ACKs and phase MITRE metadata are not detections. Empty/missing slices never prove not detected.',
            'Only verified P06 fixture/P11 HTTP receipts are in scope; persistence, DNS and other phases are not evaluated.',
            'Correlation does not validate rule quality, sensor coverage or independent observation. HTTPS may hide payload markers.',
            'Flow IDs are references only; no cross-record or cross-transaction attribution is inferred.'])
