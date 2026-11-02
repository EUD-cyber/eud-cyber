"""P18 fixed-marker DNS telemetry; no response content is executed or retained."""
import base64
import random
import re
import struct

from lab_actions import number
from scenario_model import private


def configuration(pid, env):
    behavior = env.get('MRNOBODY_DNS_BEHAVIOR') or 'standard'
    if behavior not in {'standard', 'low-and-slow', 'encoded-marker'}:
        raise ValueError('Unsupported DNS behavior')
    interval = number(env.get('MRNOBODY_DNS_INTERVAL', 60 if behavior == 'low-and-slow' else 5), 1, 180)
    jitter = number(env.get('MRNOBODY_DNS_JITTER', 0), 0, .5)
    count = number(env.get('MRNOBODY_DNS_COUNT', 3), 1, 40, True)
    duration = number(env.get('MRNOBODY_DNS_DURATION', 240), 3, 240)
    if behavior == 'low-and-slow' and interval < 30:
        raise ValueError('Low-and-slow requires an interval of at least 30 seconds')
    if (count - 1) * interval * (1 + jitter) + count * 3 > duration:
        raise ValueError('DNS count/interval/jitter must fit duration (maximum 240 seconds)')
    destination = private(env.get('MRNOBODY_DNS_ENDPOINT') or env.get('NORDIC_LAB_DNS_ENDPOINT') or '192.168.1.1')
    domain = env.get('MRNOBODY_DNS_DOMAIN') or 'mrnobody.test'
    # Reserved/private namespaces prevent accidental queries for public C2 names.
    if (not isinstance(domain, str) or len(domain) > 120 or
            not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.)+(?:test|internal|localhost)', domain)):
        raise ValueError('Use a lowercase lab domain ending in .test, .internal or .localhost')
    pattern = env.get('MRNOBODY_DNS_PATTERN') or 'mrn-{seq}'
    if not isinstance(pattern, str) or not re.fullmatch(r'[a-z0-9-]{1,20}\{seq\}[a-z0-9-]{0,20}', pattern):
        raise ValueError('DNS pattern needs one {seq} placeholder and fixed lowercase letters/digits/hyphens')
    return dict(dns_behavior=behavior, dns_interval=interval, dns_jitter=jitter,
                dns_count=count, dns_duration=duration, dns_endpoint=destination,
                dns_domain=domain, dns_pattern=pattern, transport='dns',
                low_and_slow=behavior == 'low-and-slow', cleanup='not_required',
                mitre='T1071.004,T1132.001' if behavior == 'encoded-marker' else 'T1071.004',
                simulation='fixed_benign_marker_no_remote_control')


def queries(config):
    marker = base64.b32encode(b'MRN-EXERCISE-ONLY').decode().rstrip('=').lower()
    return [config['dns_pattern'].replace('{seq}', str(i)) + '.' +
            (marker + '.' if config['dns_behavior'] == 'encoded-marker' else '') + config['dns_domain']
            for i in range(1, config['dns_count'] + 1)]


def schedule(config, rng=None):
    rng = rng or random.SystemRandom()
    return [0] + [round(config['dns_interval'] * (1 + rng.uniform(-config['dns_jitter'], config['dns_jitter'])), 3)
                  for _ in range(config['dns_count'] - 1)]


def packet(name, transaction):
    return struct.pack('!6H', transaction, 0x0100, 1, 0, 0, 0) + b''.join(
        bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0\0\1\0\1'


def script(pid, platform, env):
    config = configuration(pid, env)
    rows = [(i, name, int(delay * 1000), random.SystemRandom().randint(1, 65535))
            for i, (name, delay) in enumerate(zip(queries(config), schedule(config)), 1)]
    # Construct fixed DNS A questions locally. Both clients only validate header,
    # transaction, question and response code; answers are discarded.
    if platform == 'windows':
        actions = []
        for i, name, delay, transaction in rows:
            encoded = base64.b64encode(packet(name, transaction)).decode()
            actions.append("[PSCustomObject]@{sequence=%s;delay=%s;packet='%s'}" % (i, delay, encoded))
        return "$ErrorActionPreference = 'Stop'\n$rows = @(\n" + ',\n'.join(actions) + "\n)\nforeach ($row in $rows) {\n" + """
Start-Sleep -Milliseconds $row.delay
$status = 'failed'; $client = New-Object Net.Sockets.UdpClient
try {
  $client.Connect('__DEST__', 53); $client.Client.ReceiveTimeout = 3000
  $q = [Convert]::FromBase64String($row.packet)
  $null = $client.Send($q, $q.Length)
  $peer = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
  $r = $client.Receive([ref]$peer)
  $valid = $r.Length -ge $q.Length -and $r[0] -eq $q[0] -and $r[1] -eq $q[1] -and ($r[2] -band 128) -ne 0 -and ($r[2] -band 120) -eq 0 -and $r[4] -eq 0 -and $r[5] -eq 1
  for ($j=12; $valid -and $j -lt $q.Length; $j++) { if ($r[$j] -ne $q[$j]) { $valid = $false } }
  if ($valid -and (($r[3] -band 15) -eq 0 -or ($r[3] -band 15) -eq 3)) { $status = 'ok' }
} catch {} finally { $client.Close() }
Write-Output ('MRN_DNS=' + $row.sequence + ',' + $status + ',' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
}
""".replace('__DEST__', config['dns_endpoint'])
    data = [(i, delay, base64.b64encode(packet(name, tx)).decode()) for i, name, delay, tx in rows]
    return "command -v python3 >/dev/null || exit 78\npython3 - <<'MRN_DNS_PY'\n" + """import base64, socket, time
rows = __ROWS__
for sequence, delay, encoded in rows:
    time.sleep(delay / 1000)
    status = 'failed'
    question = base64.b64decode(encoded)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect(('__DEST__', 53))
            client.send(question)
            reply = client.recv(4096)
            if (len(reply) >= len(question) and reply[:2] == question[:2] and
                reply[2] & 128 and not reply[2] & 120 and reply[4:6] == b'\\x00\\x01' and
                reply[12:len(question)] == question[12:] and reply[3] & 15 in (0, 3)):
                status = 'ok'
    except OSError:
        pass
    print('MRN_DNS=%s,%s,%s' % (sequence, status, int(time.time()*1000)), flush=True)
MRN_DNS_PY
""".replace('__ROWS__', repr(data)).replace('__DEST__', config['dns_endpoint'])


def evidence(pid, output, config):
    rows = re.findall(r'(?m)^MRN_DNS=(\d+),(ok|failed),(\d{13})\r?$', output)
    expected = config['dns_count']
    valid = [int(r[0]) for r in rows] == list(range(1, len(rows) + 1)) and len(rows) <= expected
    if not valid:
        return dict(result='failed', warning='invalid_dns_worker_response')
    success = sum(r[1] == 'ok' for r in rows)
    complete = len(rows) == expected
    result = 'success' if complete and success == expected else 'partial' if success else 'failed'
    return dict(result=result, success_count=success, failure_count=len(rows)-success,
                unattempted_count=expected-len(rows), attempt_timestamps=','.join(r[2] for r in rows),
                sample_queries=','.join(queries(config)[:3]),
                query_pattern_summary=config['dns_pattern'] + '.' + ('<fixed-base32-marker>.' if config['dns_behavior'] == 'encoded-marker' else '') + config['dns_domain'],
                warning='none' if result == 'success' else 'partial_dns_success' if success else 'dns_endpoint_unavailable_or_no_valid_response',
                evidence='matching_DNS_NOERROR_or_NXDOMAIN_response_answers_discarded')
