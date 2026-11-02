"""P16/P17 fixed synthetic actions. No operator paths or executable bodies."""
import json
import re

DATASETS = {'finance': ['customers.txt', 'invoices.txt'], 'engineering': ['design.txt', 'inventory.txt']}
BEHAVIORS = {'config-toggle': ('T1685', 'Disable or Modify Tools'),
             'log-rename': ('T1070', 'Indicator Removal')}


def configuration(pid, env):
    iid = env.get('NORDIC_INCIDENT_ID', 'MRN-validation')
    if not re.fullmatch(r'MRN-[A-Za-z0-9][A-Za-z0-9_-]{0,100}', iid):
        raise ValueError('A namespaced MRN incident is required')
    action = env.get('MRNOBODY_ACTION') or 'run'
    if action not in {'run', 'cleanup'}:
        raise ValueError('Choose run or cleanup')
    if pid == '16':
        behavior = env.get('MRNOBODY_BEHAVIOR') or 'config-toggle'
        if behavior not in BEHAVIORS:
            raise ValueError('Unsupported reversible behavior')
        return dict(behavior=behavior, action=action, incident=iid,
                    mitre=BEHAVIORS[behavior][0], simulation='synthetic_artifacts_only')
    dataset = env.get('MRNOBODY_DATASET') or 'finance'
    name = env.get('MRNOBODY_ARCHIVE_NAME') or 'collection'
    if dataset not in DATASETS or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', name):
        raise ValueError('Unsupported dataset or archive name')
    return dict(dataset=dataset, archive_name=name, action=action, incident=iid,
                mitre='T1005,T1560.002', simulation='synthetic_artifacts_only')


def paths(config, platform):
    root = ('C:\\ProgramData\\MrNobody\\Exercises\\' if platform == 'windows' else '/var/tmp/MrNobody-exercises/') + config['incident']
    if 'dataset' in config:
        return root, root + ('\\' if platform == 'windows' else '/') + config['archive_name'] + ('.zip' if platform == 'windows' else '.tar.gz')
    return root, root + ('\\' if platform == 'windows' else '/') + ('monitor.conf' if config['behavior'] == 'config-toggle' else 'exercise.log')


LINUX = r'''
import hashlib, json, os, stat, sys, tarfile
from pathlib import Path
c = json.loads(__CONFIG__)
root = Path('/var/tmp/MrNobody-exercises') / c['incident']
def safe(p):
    for part in [p, *p.parents]:
        if part.is_symlink(): raise ValueError('symlink')
    return p
def fixed(p, expected):
    safe(p)
    if not p.exists(): return False
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 4096: raise ValueError('scope')
    if p.read_bytes() != expected: raise ValueError('synthetic marker mismatch')
    return True
safe(root)
if c['action'] == 'cleanup' and not root.exists():
    print('MRN_EXERCISE=skipped'); sys.exit(0)
root.mkdir(mode=0o700, parents=True, exist_ok=True)
if __PID__ == '16':
    p = root / ('monitor.conf' if c['behavior'] == 'config-toggle' else 'exercise.log')
    backup = p.with_name(p.name + '.mrn-restore')
    safe(backup)
    original = b'MrNobody synthetic monitor enabled\n' if c['behavior'] == 'config-toggle' else b'MrNobody synthetic exercise log\n'
    changed = b'MrNobody synthetic monitor disabled\n'
    # Recovery of an interrupted run uses a fixed marker, never arbitrary bytes.
    if backup.exists():
        fixed(backup, original)
        if p.exists(): fixed(p, changed if c['behavior'] == 'config-toggle' else original)
        os.replace(backup, p)
    if not p.exists() and c['action'] != 'cleanup':
        template = root.parent / 'templates' / p.name
        if not fixed(template, original):
            print('MRN_EXERCISE=skipped'); sys.exit(0)
        p.write_bytes(original)
    if not fixed(p, original):
        print('MRN_EXERCISE=skipped'); sys.exit(0)
    if c['action'] != 'cleanup':
        if c['behavior'] == 'config-toggle':
            backup.write_bytes(original)
            try:
                p.write_bytes(changed); fixed(p, changed)
            finally: os.replace(backup, p)
        else:
            os.replace(p, backup)
            try: fixed(backup, original)
            finally: os.replace(backup, p)
    fixed(p, original)
    print('MRN_EXERCISE=restored')
else:
    archive = safe(root / (c['archive_name'] + '.tar.gz'))
    if archive.exists():
        if not archive.is_file() or archive.stat().st_nlink != 1: raise ValueError('archive scope')
        with tarfile.open(archive) as prior:
            members = prior.getmembers()
            if not 1 <= len(members) <= 2: raise ValueError('archive scope')
            for member in members:
                if member.name not in __FILES__ or not member.isfile() or member.size > 4096: raise ValueError('archive scope')
                if prior.extractfile(member).read() != ('MrNobody synthetic ' + c['dataset'] + ' ' + member.name + '\n').encode(): raise ValueError('archive marker')
        archive.unlink()
    if c['action'] == 'cleanup':
        print('MRN_EXERCISE=cleaned'); sys.exit(0)
    names = __FILES__
    selected = []
    for name in names:
        p = root.parent / 'datasets' / c['dataset'] / name
        if fixed(p, ('MrNobody synthetic ' + c['dataset'] + ' ' + name + '\n').encode()): selected.append(p)
    if not selected:
        print('MRN_EXERCISE=skipped'); sys.exit(0)
    try:
        with tarfile.open(archive, 'x:gz') as out:
            for p in selected: out.add(p, arcname=p.name, recursive=False)
        with tarfile.open(archive) as check:
            if check.getnames() != [p.name for p in selected]: raise ValueError('verification')
        payload = archive.read_bytes()
        print('MRN_ARCHIVE=%d,%d,%s' % (len(selected), len(payload), hashlib.sha256(payload).hexdigest()) + ',' + ';'.join(p.name for p in selected))
    except BaseException:
        if archive.exists(): archive.unlink()
        raise
'''

WINDOWS = r'''
$ErrorActionPreference = 'Stop'
$c = '__CONFIG__' | ConvertFrom-Json
$root = 'C:\ProgramData\MrNobody\Exercises\' + $c.incident
function Safe($p) {
    $q = $p
    while ($q) {
        if (Test-Path -LiteralPath $q) {
            if ((Get-Item -LiteralPath $q -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse' }
        }
        $q = Split-Path -Parent $q
    }
}
function Fixed($p, $expected) {
    Safe $p
    if (!(Test-Path -LiteralPath $p)) { return $false }
    $f = Get-Item -LiteralPath $p -Force
    if ($f.PSIsContainer -or $f.Length -gt 4096 -or [IO.File]::ReadAllText($p) -cne $expected) { throw 'marker' }
    return $true
}
Safe $root
if ($c.action -eq 'cleanup' -and !(Test-Path -LiteralPath $root)) { Write-Output 'MRN_EXERCISE=skipped'; exit 0 }
if (!(Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
if ('__PID__' -eq '16') {
    $name = if ($c.behavior -eq 'config-toggle') { 'monitor.conf' } else { 'exercise.log' }
    $p = Join-Path $root $name
    $backup = $p + '.mrn-restore'
    Safe $backup
    $original = if ($c.behavior -eq 'config-toggle') { "MrNobody synthetic monitor enabled`n" } else { "MrNobody synthetic exercise log`n" }
    $changed = "MrNobody synthetic monitor disabled`n"
    if (Test-Path -LiteralPath $backup) {
        $null = Fixed $backup $original
        if (Test-Path -LiteralPath $p) { $null = Fixed $p $(if ($c.behavior -eq 'config-toggle') { $changed } else { $original }) }
        Move-Item -LiteralPath $backup -Destination $p -Force
    }
    if (!(Test-Path -LiteralPath $p) -and $c.action -ne 'cleanup') {
        $template = Join-Path (Join-Path (Split-Path -Parent $root) 'templates') $name
        if (!(Fixed $template $original)) { Write-Output 'MRN_EXERCISE=skipped'; exit 0 }
        [IO.File]::WriteAllText($p, $original)
    }
    if (!(Fixed $p $original)) { Write-Output 'MRN_EXERCISE=skipped'; exit 0 }
    if ($c.action -ne 'cleanup') {
        if ($c.behavior -eq 'config-toggle') {
            [IO.File]::WriteAllText($backup, $original)
            try { [IO.File]::WriteAllText($p, $changed); $null = Fixed $p $changed }
            finally { Move-Item -LiteralPath $backup -Destination $p -Force }
        } else {
            Move-Item -LiteralPath $p -Destination $backup
            try { $null = Fixed $backup $original }
            finally { Move-Item -LiteralPath $backup -Destination $p }
        }
    }
    $null = Fixed $p $original
    Write-Output 'MRN_EXERCISE=restored'
} else {
    $archive = Join-Path $root ($c.archive_name + '.zip')
    Safe $archive
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $archive) {
        $old = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            if ($old.Entries.Count -lt 1 -or $old.Entries.Count -gt 2) { throw 'archive scope' }
            foreach ($entry in $old.Entries) {
                if ($entry.FullName -notin @(__FILES__) -or $entry.Length -gt 4096) { throw 'archive scope' }
                $reader = New-Object IO.StreamReader($entry.Open())
                try { if ($reader.ReadToEnd() -cne ("MrNobody synthetic " + $c.dataset + ' ' + $entry.FullName + "`n")) { throw 'archive marker' } } finally { $reader.Dispose() }
            }
        } finally { $old.Dispose() }
        Remove-Item -LiteralPath $archive -Force
    }
    if ($c.action -eq 'cleanup') { Write-Output 'MRN_EXERCISE=cleaned'; exit 0 }
    $selected = @()
    foreach ($name in @(__FILES__)) {
        $p = Join-Path (Join-Path (Join-Path (Split-Path -Parent $root) 'datasets') $c.dataset) $name
        if (Fixed $p ("MrNobody synthetic " + $c.dataset + ' ' + $name + "`n")) { $selected += $p }
    }
    if (!$selected.Count) { Write-Output 'MRN_EXERCISE=skipped'; exit 0 }
    try {
        $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
        try { foreach ($item in $selected) { $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $item, [IO.Path]::GetFileName($item)) } } finally { $zip.Dispose() }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead($archive)
        try { if ($z.Entries.Count -ne $selected.Count) { throw 'verification' } } finally { $z.Dispose() }
        $size = (Get-Item -LiteralPath $archive).Length
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output ('MRN_ARCHIVE=' + $selected.Count + ',' + $size + ',' + $hash + ',' + (($selected | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ';'))
    } catch { if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }; throw }
}
'''


def script(pid, platform, env):
    config = configuration(pid, env)
    files = DATASETS.get(config.get('dataset'), [])
    if platform == 'windows':
        return WINDOWS.replace('__CONFIG__', json.dumps(config)).replace('__PID__', pid).replace('__FILES__', ','.join("'" + f + "'" for f in files))
    source = LINUX.replace('__CONFIG__', repr(json.dumps(config))).replace('__PID__', repr(pid)).replace('__FILES__', repr(files))
    return "command -v python3 >/dev/null || exit 78\npython3 - <<'MRN_PY'\n" + source + '\nMRN_PY\n'


def evidence(pid, output, config, platform):
    text = output.strip()
    root, path = paths(config, platform)
    common = dict(artifact=path, host_compromise_changed='false')
    if text == 'MRN_EXERCISE=skipped':
        return dict(result='skipped', warning='designated_synthetic_artifact_missing', **common)
    if pid == '16' and text == 'MRN_EXERCISE=restored':
        return dict(result='success', pre_state='synthetic_original', post_state='synthetic_original',
                    action_state='synthetic_disabled' if config['behavior'] == 'config-toggle' else 'synthetic_renamed',
                    cleanup='restored_verified', cleanup_required='false', **common)
    if pid == '17' and text == 'MRN_EXERCISE=cleaned':
        return dict(result='success', cleanup='complete', cleanup_required='false', **common)
    match = re.fullmatch(r'MRN_ARCHIVE=([12]),([1-9][0-9]{0,5}),([a-f0-9]{64}),([a-z.;]+)', text)
    if pid == '17' and config['action'] == 'run' and match:
        count, size, sha, selected = match.groups()
        names = selected.split(';')
        if len(names) != int(count) or len(set(names)) != len(names) or not set(names) <= set(DATASETS[config['dataset']]):
            return dict(result='failed', warning='invalid_archive_selection')
        return dict(result='success', file=path, archive_path=path, size=int(size), sha256=sha,
                    files_count=int(count), files_selected=','.join(names),
                    warning='partial_collection' if int(count) < 2 else 'none', cleanup='retained_for_staging',
                    cleanup_required='true', downstream='staged-data.json:P05:P06', **common)
    return dict(result='failed', warning='action_or_restore_unverified_output_omitted', cleanup='required_or_unverified',
                cleanup_required='true', **common)
