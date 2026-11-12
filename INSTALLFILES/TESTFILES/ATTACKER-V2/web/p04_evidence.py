"""Strict projection of P04 remote stdout; remote text never becomes log syntax."""
import ipaddress
import re
import sys
from datetime import datetime, timezone

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 65536


def address(value):
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        return False


def parse_output(stream, targets, ports):
    """Allowlisted targets/ports, exact grammar, discovery context, first result wins.

    These are source-reported observations, not independently verified host facts.
    Unknown remote lines (including fake INCIDENT/PHASE records) are ignored.
    """
    targets = {x for x in targets if address(x)}
    ports = {str(int(x)) for x in ports if str(x).isdigit() and 1 <= int(x) <= 65535}
    seen, active, size = set(), None, 0
    for line in stream:
        size += len(line.encode('utf-8', errors='replace'))
        if size > MAX_BYTES or len(seen) >= MAX_RECORDS:
            yield 'INTERNAL_DISCOVERY_TRUNCATED', {'reason': 'evidence_limit'}
            break
        line = line.rstrip('\r\n')
        match = re.fullmatch(r'\[(DISCOVERY|PING|TCP)\] target=([0-9a-fA-F:.]+)(?: port=([0-9]{1,5}))?(?: status=(reachable|no-reply|open|closed|unknown|error))?', line)
        if not match or match[2] not in targets:
            continue
        kind, target, port, status = match.groups()
        if kind == 'DISCOVERY':
            if port or status:
                continue
            active = target
        elif active != target:
            continue
        elif kind == 'PING':
            if port or status not in {'reachable', 'no-reply', 'unknown', 'error'}:
                continue
        elif port not in ports or status not in {'open', 'closed', 'unknown', 'error'}:
            continue
        key = kind, target, port
        if key in seen:
            continue
        seen.add(key)
        fields = {'target': target}
        if port:
            fields['port'] = port
        if status:
            fields['status'] = status
        yield 'INTERNAL_DISCOVERY_' + kind, fields


def main():
    incident, source, platform, transport, ports, *targets = sys.argv[1:]
    if not re.fullmatch(r'(?:MRN|H3)-[A-Za-z0-9][A-Za-z0-9_-]{0,100}', incident) or not address(source):
        raise SystemExit(1)
    if (platform, transport) not in {('linux', 'ssh'), ('windows', 'winrm')}:
        raise SystemExit(1)
    for name, fields in parse_output(sys.stdin, targets, ports.split()):
        stamp = datetime.now(timezone.utc).isoformat()
        detail = ' '.join(f'{key}={value}' for key, value in fields.items())
        print(f'{stamp} INCIDENT={incident} PHASE=04 {name} source={source} platform={platform} protocol={transport} {detail}')


if __name__ == '__main__':
    main()
