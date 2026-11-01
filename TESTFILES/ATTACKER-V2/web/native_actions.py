"""Controlled P13 telemetry; no operator payloads, URLs or executable downloads."""
import base64

BEHAVIORS = {
    'encoded-powershell': ('powershell.exe', 'T1059.001', 'PowerShell'),
    'certutil-decode': ('certutil.exe', 'T1140', 'Deobfuscate/Decode Files or Information'),
    'bits-job': ('bitsadmin.exe', 'T1197', 'BITS Jobs'),
}


def metadata(env):
    behavior = env.get('MRNOBODY_BEHAVIOR') or 'encoded-powershell'
    if behavior not in BEHAVIORS:
        raise ValueError('Unsupported native-tool behavior')
    tool, technique, _ = BEHAVIORS[behavior]
    return dict(behavior=behavior, executable=tool, mitre=technique,
                artifact='unique_target_temp_directory', cleanup='finally_attempted',
                simulation='benign_telemetry_no_payload_delivery')


def script(env):
    behavior = metadata(env)['behavior']
    encoded = base64.b64encode("Write-Output 'MrNobody telemetry'".encode('utf-16-le')).decode('ascii')
    actions = {
        'encoded-powershell': "& \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -EncodedCommand '" + encoded + "'\n$code = $LASTEXITCODE",
        'certutil-decode': r"""
$inputFile = Join-Path $root 'marker.b64'
$outputFile = Join-Path $root 'marker.txt'
[IO.File]::WriteAllText($inputFile, 'TXJOb2JvZHkgdGVsZW1ldHJ5')
& "$env:SystemRoot\System32\certutil.exe" -f -decode $inputFile $outputFile | Out-Null
$code = $LASTEXITCODE
if ($code -eq 0 -and [IO.File]::ReadAllText($outputFile) -ne 'MrNobody telemetry') { $code = 1 }
""",
        'bits-job': r"""
$job = [IO.Path]::GetFileName($root)
Write-Output ('job_name: ' + $job)
try {
    & "$env:SystemRoot\System32\bitsadmin.exe" /create /download $job | Out-Null
    $code = $LASTEXITCODE
} finally {
    & "$env:SystemRoot\System32\bitsadmin.exe" /cancel $job | Out-Null
    if ($LASTEXITCODE -ne 0) { $code = 1; $cleanupOk = $false }
}
""",
    }
    # Unique names avoid overwriting pre-existing files/jobs or concurrent runs.
    # Emit only controlled artifact metadata; no native output leaves the target.
    return r"""
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('MrNobody-P13-' + [Guid]::NewGuid().ToString('N').Substring(0,24))
$code = 1
$cleanupOk = $true
$createdRoot = $false
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $createdRoot = $true
    Write-Output ('artifact_path=' + $root)
__ACTION__
} catch { $code = 1 }
finally {
    try {
        if ($createdRoot -and (Test-Path -LiteralPath $root)) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        if ($cleanupOk) { Write-Output 'cleanup=complete' }
        else { Write-Output 'cleanup=required' }
    } catch { Write-Output 'cleanup=required'; $code = 1 }
}
exit $code
""".replace('__ACTION__', actions[behavior])
