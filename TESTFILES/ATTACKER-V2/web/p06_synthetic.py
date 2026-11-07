"""Create exactly one fixed, simulated P06 fixture; never read user-selected data."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

from exfil_validation import IID, validate


def now():
    return datetime.now(timezone.utc).isoformat()


def fixture(incident):
    if not IID.fullmatch(incident):
        raise ValueError('Invalid P06 incident ID')
    return ('SIMULATED COMPANY DATA - MRNOBODY TRAINING ONLY\n'
            'This file contains invented exercise data, never real company secrets.\n'
            'Company: Example Training Company (fictional)\n'
            'Project: Practice Widget; budget: 12345 simulated credits\n'
            f'Incident: {incident}\n').encode('utf-8')


def linux_script(incident, suffix, raw):
    # Every interpolated value is generated locally and restricted to ASCII.
    path = f'/tmp/mrnobody-p06-{incident}-{suffix}/corporate-secret-data.txt'
    encoded = base64.b64encode(raw).decode('ascii')
    script = f'''set -eu
umask 077
mkdir -- '{path.rsplit('/', 1)[0]}'
set -C
printf '%s' '{encoded}' | base64 -d > '{path}'
test ! -L '{path}'
printf 'P06_CREATED|%s|%s|%s\\n' '{path}' "$(wc -c < '{path}' | tr -d ' ')" "$(sha256sum -- '{path}' | cut -d ' ' -f 1)"
'''
    return script


def windows_script(incident, suffix, raw):
    encoded = base64.b64encode(raw).decode('ascii')
    return f'''$ErrorActionPreference = 'Stop'
$dir = Join-Path ([IO.Path]::GetTempPath()) 'mrnobody-p06-{incident}-{suffix}'
if (Test-Path -LiteralPath $dir) {{ throw 'P06 directory already exists' }}
$null = New-Item -ItemType Directory -Path $dir
if ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) {{ throw 'P06 reparse point rejected' }}
$path = Join-Path $dir 'corporate-secret-data.txt'
$raw = [Convert]::FromBase64String('{encoded}')
$stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {{ $stream.Write($raw, 0, $raw.Length) }} finally {{ $stream.Dispose() }}
$item = Get-Item -LiteralPath $path
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output ('P06_CREATED|' + $path + '|' + $item.Length + '|' + $hash)
'''


def create(data, incident, state_path, runner=subprocess.run, session_factory=None):
    validate(data, None)  # No staging inventory is read in default mode.
    if data.get('file') or data.get('staging_incident'):
        raise ValueError('Synthetic default does not accept a source path or staging incident')
    raw = fixture(incident)
    suffix = uuid.uuid4().hex
    protocol = data['protocol']
    platform = 'linux' if protocol == 'ssh' else 'windows'
    entry = dict(incident_id=incident, source_incident_id=incident, source=data['target'],
                 platform=platform, source_kind='synthetic-default', synthetic=True,
                 source_name='corporate-secret-data.txt', remote_file=None,
                 expected_size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                 started_at=now(), result='preparation_failed', successful=False,
                 verified=False, scope='One generated simulated file; no existing files or directories are collected.')
    state_path = Path(state_path)
    upload = Path(os.environ.get('NORDIC_UPLOAD_DIR', state_path.parent.parent/'uploads'))
    entry['local_destination'] = str(upload/f'{incident}-{platform}-{data["target"]}.bin')

    def save():
        state_path.write_text(json.dumps(dict(incident_id=incident, count=0, transfers=[], attempts=[entry]), indent=2))

    save()
    try:
        port = str(data.get('port') or (22 if platform == 'linux' else 5986 if protocol == 'winrm-https' else 5985))
        if platform == 'linux':
            script = linux_script(incident, suffix, raw)
            entry['remote_file'] = f'/tmp/mrnobody-p06-{incident}-{suffix}/corporate-secret-data.txt'
            env = dict(os.environ, SSHPASS=data['password'])
            result = runner(['sshpass', '-e', 'ssh', '-p', port, '-o', 'StrictHostKeyChecking=no',
                             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
                             '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                             '-o', 'NumberOfPasswordPrompts=1', '--', data['username']+'@'+data['target'], 'bash', '-s'],
                            input=script, text=True, capture_output=True, timeout=30, env=env)
            if result.returncode:
                raise ValueError('P06 synthetic file creation failed on SSH target')
            output = result.stdout
        else:
            if session_factory is None:
                import winrm
                session_factory = winrm.Session
            scheme = 'https' if protocol == 'winrm-https' else 'http'
            session = session_factory(f'{scheme}://{data["target"]}:{port}/wsman',
                                      auth=(data['username'], data['password']), transport='ntlm',
                                      server_cert_validation='ignore', operation_timeout_sec=15, read_timeout_sec=25)
            result = session.run_ps(windows_script(incident, suffix, raw))
            if result.status_code:
                raise ValueError('P06 synthetic file creation failed on WinRM target')
            output = result.std_out.decode('utf-8', errors='replace')
        lines = [line.strip() for line in output.splitlines() if line.startswith('P06_CREATED|')]
        if len(lines) != 1:
            raise ValueError('Missing P06 creation evidence')
        _, path, size, digest = lines[0].split('|')
        if platform == 'linux':
            valid = path == entry['remote_file']
        else:
            valid = bool(re.fullmatch(r'[A-Za-z]:\\[^|\r\n\x00]*\\mrnobody-p06-' + re.escape(incident+'-'+suffix) + r'\\corporate-secret-data\.txt', path))
        if not valid or size != str(len(raw)) or digest.lower() != entry['sha256']:
            raise ValueError('P06 generated file path/size/SHA256 verification failed')
        entry.update(remote_file=path, source_size=int(size), prepared_at=now(), result='prepared')
        save()
        return entry
    except Exception:
        # Transport errors can contain credentials. Never copy them into logs/evidence.
        entry.update(ended_at=now(), result='preparation_failed')
        save()
        raise ValueError('P06 synthetic preparation failed; check target access, permissions and transport dependencies') from None


if __name__ == '__main__':
    try:
        data = {key: os.environ.get('MRNOBODY_'+key.upper(), '') for key in
                ('target', 'protocol', 'port', 'username', 'password', 'file', 'staging_incident')}
        entry = create(data, os.environ['NORDIC_INCIDENT_ID'], sys.argv[1])
        print(str(entry['source_size'])+'|'+entry['sha256']+'|'+entry['remote_file'])
    except (ValueError, KeyError, OSError):
        print('[ERROR] P06 synthetic preparation failed; no verified transfer recorded', file=sys.stderr)
        raise SystemExit(1)
