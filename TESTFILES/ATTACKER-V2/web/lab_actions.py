"""Fixed, bounded P12/P14 lab telemetry. Never accept paths or command bodies."""
import math
import re
import socket
from urllib.parse import urlsplit

from scenario_model import private


def number(value, low, high, integer=False):
    if isinstance(value, bool):
        raise ValueError('Invalid beacon number')
    try:
        result = float(value)
    except (ValueError, TypeError):
        raise ValueError('Invalid beacon number') from None
    if not math.isfinite(result) or not low <= result <= high or integer and not result.is_integer():
        raise ValueError('Beacon value outside supported range')
    return int(result) if integer else result


def configuration(pid, env):
    if pid == '12':
        method = env.get('MRNOBODY_METHOD') or 'read-test-file'
        if method not in {'metadata', 'read-test-file'}:
            raise ValueError('Unsupported synthetic credential method')
        return dict(method=method, mitre='T1552.001', artifact='unique_temporary_synthetic_credentials.txt',
                    simulation='benign_synthetic_data_only')
    transport = env.get('MRNOBODY_TRANSPORT') or 'http'
    profile = env.get('MRNOBODY_URI_PROFILE') or 'heartbeat'
    if transport not in {'http', 'https'} or profile not in {'heartbeat', 'status'}:
        raise ValueError('Unsupported beacon transport/profile')
    interval = number(env.get('MRNOBODY_BEACON_INTERVAL') or 5, 1, 60)
    jitter = number(env.get('MRNOBODY_BEACON_JITTER') or 0, 0, .5)
    count = number(env.get('MRNOBODY_BEACON_COUNT') or 5, 1, 20, True)
    budget = (count - 1) * interval * (1 + jitter) + count * 3
    if budget > 240:
        raise ValueError('Beacon interval/count/jitter must fit a 240 second execution budget')
    return dict(transport=transport, uri_profile=profile, beacon_interval=interval,
                beacon_jitter=jitter, beacon_count=count, duration_bound=budget,
                mitre='T1071.001', simulation='benign_checkins_no_remote_control')


def endpoint(target, transport, profile):
    # UDP connect selects OUR routing interface without sending packets. No
    # destination override, DNS, redirect, public host or proxy is permitted.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((private(target['target']), 9))
        host = private(route.getsockname()[0])
    return f'{transport}://{host}/mrnobody-beacon/{profile}'


def script(pid, platform, env):
    config = configuration(pid, env)
    if pid == '12':
        read = config['method'] == 'read-test-file'
        if platform == 'windows':
            action = "if ([IO.File]::ReadAllText($file) -ne 'MrNobody synthetic credential - NOT VALID') { throw 'verification' }" if read else '$null = Get-Item -LiteralPath $file'
            return r'''
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('MrNobody-P12-' + [Guid]::NewGuid().ToString('N'))
$created = $false
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $created = $true
    $file = Join-Path $root 'synthetic-credentials.txt'
    [IO.File]::WriteAllText($file, 'MrNobody synthetic credential - NOT VALID')
    __ACTION__
} finally {
    if ($created) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
Write-Output 'MRN_P12_OK'
'''.replace('__ACTION__', action)
        action = '[ "$(cat "$root/synthetic-credentials.txt")" = "MrNobody synthetic credential - NOT VALID" ]' if read else 'stat "$root/synthetic-credentials.txt" >/dev/null'
        return '''set -eu
command -v mktemp >/dev/null || exit 78
command -v stat >/dev/null || exit 78
umask 077
root=$(mktemp -d /tmp/MrNobody-P12-XXXXXXXXXX)
trap 'rm -f -- "$root/synthetic-credentials.txt"; rmdir -- "$root"' EXIT
printf %s 'MrNobody synthetic credential - NOT VALID' > "$root/synthetic-credentials.txt"
''' + action + '''
rm -f -- "$root/synthetic-credentials.txt"
rmdir -- "$root"
trap - EXIT
printf 'MRN_P12_OK\\n'
'''
    url = env['MRN_BEACON_ENDPOINT']
    parsed = urlsplit(url)
    if (parsed.scheme != config['transport'] or parsed.netloc != private(parsed.hostname)
            or parsed.path != '/mrnobody-beacon/' + config['uri_profile'] or parsed.query or parsed.fragment):
        raise ValueError('Invalid internal beacon endpoint')
    # Internal endpoint is built above; incident ID is validated by the runner.
    iid = env['NORDIC_INCIDENT_ID']
    if not re.fullmatch(r'MRN-[A-Za-z0-9_-]+', iid):
        raise ValueError('Invalid beacon incident ID')
    count, interval, jitter = config['beacon_count'], config['beacon_interval'], config['beacon_jitter']
    if platform == 'windows':
        return r'''
$ErrorActionPreference = 'Stop'
# Certificate relaxation is confined to this short-lived lab PowerShell process.
Add-Type -TypeDefinition @'
public static class MrNobodyLabTLS {
    public static bool Accept(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert,
        System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors errors) { return true; }
}
'@
[Net.ServicePointManager]::ServerCertificateValidationCallback = [Net.Security.RemoteCertificateValidationCallback][MrNobodyLabTLS]::Accept
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
for ($i=1; $i -le __COUNT__; $i++) {
    if ($i -gt 1) { Start-Sleep -Milliseconds ([int](1000 * __INTERVAL__ * (1 + __JITTER__ * ((Get-Random -Minimum 0 -Maximum 2001) / 1000.0 - 1)))) }
    $status = 'failed'
    $response = $null
    try {
        $r = [Net.HttpWebRequest]::Create('__URL__?incident=__IID__&sequence=' + $i)
        $r.Proxy = $null; $r.AllowAutoRedirect = $false; $r.Timeout = 3000; $r.ReadWriteTimeout = 3000
        $response = $r.GetResponse()
        if ([int]$response.StatusCode -eq 204) { $status = 'ok' }
    } catch {} finally { if ($null -ne $response) { $response.Close() } }
    Write-Output ('MRN_BEACON=' + $i + ',' + $status)
}
'''.replace('__COUNT__', str(count)).replace('__INTERVAL__', str(interval)).replace('__JITTER__', str(jitter)).replace('__URL__', url).replace('__IID__', iid)
    return '''set -eu
command -v curl >/dev/null || exit 78
for ((i=1; i<=__COUNT__; i++)); do
    if ((i>1)); then
        delay=$(awk -v r="$RANDOM" 'BEGIN { print __INTERVAL__ * (1 + __JITTER__ * (r / 16383.5 - 1)) }')
        sleep "$delay"
    fi
    code=$(curl --noproxy '*' --silent --insecure --max-time 3 --max-redirs 0 --output /dev/null --write-out '%{http_code}' '__URL__?incident=__IID__&sequence='"$i" 2>/dev/null) || code=000
    status=failed
    [[ "$code" == 204 ]] && status=ok
    printf 'MRN_BEACON=%s,%s\\n' "$i" "$status"
done
'''.replace('__COUNT__', str(count)).replace('__INTERVAL__', str(interval)).replace('__JITTER__', str(jitter)).replace('__URL__', url).replace('__IID__', iid)


def evidence(pid, output, config):
    # Fail closed: no remote text, exception or HTTP body enters evidence.
    if pid == '12':
        return dict(result='success', cleanup='complete', cleanup_required='false', evidence='synthetic_artifact_verified_and_removed') if output.strip() == 'MRN_P12_OK' else dict(result='failed', cleanup='required_or_unverified', cleanup_required='true', warning='synthetic_action_or_cleanup_unverified')
    rows = re.findall(r'(?m)^MRN_BEACON=(\d+),(ok|failed)\r?$', output)
    count = config['beacon_count']
    if [int(row[0]) for row in rows] != list(range(1, count + 1)):
        return dict(result='failed', warning='invalid_or_incomplete_beacon_response')
    success = sum(row[1] == 'ok' for row in rows)
    return dict(result='success' if success == count else 'failed', success_count=success,
                failure_count=count-success, evidence='controlled_204_checkins',
                warning='none' if success == count else 'partial_beacon_success' if success else 'endpoint_unavailable')
