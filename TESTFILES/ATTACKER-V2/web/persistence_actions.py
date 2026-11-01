"""Visible, fixed-payload lab persistence. No arbitrary persistence payloads.

All artifacts share a deterministic namespace and ownership marker. Cleanup is
explicit and idempotent; privileges are never elevated and logging stays enabled.
"""
import re

MARKER = 'MrNobody controlled lab P11'
METHODS = {'scheduled-task': ('windows', 'T1053.005', 'Scheduled Task'),
           'service': ('windows', 'T1543.003', 'Windows Service'),
           'cron': ('linux', 'T1053.003', 'Cron'),
           'systemd': ('linux', 'T1543.002', 'Systemd Service')}


def configuration(env, platform):
    method = env.get('MRNOBODY_METHOD') or 'auto'
    if method == 'auto':
        method = 'scheduled-task' if platform == 'windows' else 'cron'
    if method not in METHODS or METHODS[method][0] != platform:
        raise ValueError('Persistence method is incompatible with platform')
    action = env.get('MRNOBODY_ACTION') or 'create'
    artifact = env.get('MRNOBODY_ARTIFACT') or 'telemetry'
    if action not in {'create', 'cleanup'} or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', artifact):
        raise ValueError('Invalid persistence action/artifact')
    return method, action, 'mrnobody-p11-' + artifact


def metadata(env, platform):
    method, action, name = configuration(env, platform)
    location = {'scheduled-task': 'TaskScheduler/' + name,
                'service': 'ProgramData/MrNobody/P11/' + name + '/' + name + '.exe',
                'cron': 'user-crontab/' + name,
                'systemd': '~/.config/systemd/user/' + name + '.service'}[method]
    return dict(platform=platform, method=method, action=action, artifact=name,
                artifact_path=location, cleanup_action='P11_action_cleanup_same_target_method_artifact',
                cleanup_artifact=name.removeprefix('mrnobody-p11-'),
                cleanup_required='true' if action == 'create' else 'false',
                mitre=METHODS[method][1])


def script(env, platform):
    method, action, name = configuration(env, platform)
    if platform == 'windows':
        prelude = "$ErrorActionPreference = 'Stop'\n$name = '" + name + "'\n$marker = '" + MARKER + "'\n"
        if method == 'scheduled-task':
            body = r'''
$old = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($old -and $old.Description -ne $marker) { throw 'artifact_ownership_conflict' }
'''
            if action == 'cleanup':
                body += r'''
if ($old) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'cleanup_verification_failed' }
'''
            else:
                body += r'''
# Harmless fixed action: a process launch once a day; never operator shell input.
$a = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/c echo MrNobody controlled lab P11'
$t = New-ScheduledTaskTrigger -Daily -At '12:00'
Register-ScheduledTask -TaskName $name -Description $marker -Action $a -Trigger $t -Force | Out-Null
if (-not (Get-ScheduledTask -TaskName $name -ErrorAction Stop)) { throw 'create_verification_failed' }
'''
        else:
            body = r'''
$dir = Join-Path $env:ProgramData ('MrNobody\P11\' + $name)
$exe = Join-Path $dir ($name + '.exe')
$owner = Join-Path $dir 'owner.txt'
$old = Get-CimInstance Win32_Service -Filter "Name='$name'"
if ((Test-Path $dir) -and ((-not (Test-Path $owner)) -or (Get-Content $owner -Raw) -ne $marker)) { throw 'artifact_ownership_conflict' }
if ($old -and ($old.Description -ne $marker -or $old.PathName -ne ('"' + $exe + '"'))) { throw 'artifact_ownership_conflict' }
'''
            if action == 'cleanup':
                body += r'''
if ($old) {
    if ($old.State -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
    $deleted = Invoke-CimMethod -InputObject $old -MethodName Delete
    if ($deleted.ReturnValue -ne 0) { throw 'service_delete_failed' }
}
if (Get-CimInstance Win32_Service -Filter "Name='$name'") { throw 'cleanup_verification_failed' }
if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
'''
            else:
                body += r'''
if (-not $old) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($owner, $marker)
    if (-not (Test-Path $exe)) {
        $source = @'
using System;
using System.ServiceProcess;
public class MrNobodyLabService : ServiceBase {
    public MrNobodyLabService() { ServiceName = "__NAME__"; AutoLog = true; }
    protected override void OnStart(string[] args) { }
    public static void Main() { ServiceBase.Run(new MrNobodyLabService()); }
}
'@
        Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.ServiceProcess.dll' -OutputAssembly $exe -OutputType ConsoleApplication
    }
    New-Service -Name $name -BinaryPathName ('"' + $exe + '"') -DisplayName $name -Description $marker -StartupType Automatic | Out-Null
}
Start-Service -Name $name
if ((Get-Service -Name $name).Status -ne 'Running') { throw 'create_verification_failed' }
'''.replace('__NAME__', name)
        return prelude + body + "\nWrite-Output 'MrNobody P11 verified'\n"
    if method == 'cron':
        # Hold a per-user lock for the read/modify/write; preserve unrelated jobs.
        prelude = f'''set -eu
command -v crontab >/dev/null || exit 78
command -v logger >/dev/null || exit 78
command -v flock >/dev/null || exit 78
mkdir -p "$HOME/.config/mrnobody"
exec 9>"$HOME/.config/mrnobody/p11-cron.lock"
flock -x 9
name='{name}'
marker='# {MARKER} {name}'
'''
        body = r'''
if current=$(crontab -l 2>/dev/null); then :
else
    # Absence is expected on a fresh user; other errors must not erase a table.
    check=$(LC_ALL=C crontab -l 2>&1) || true
    case "$check" in *"no crontab for"*) current='' ;; *) exit 1 ;; esac
fi
filtered=$(printf '%s\n' "$current" | awk -v marker="$marker" 'length && substr($0,length($0)-length(marker)+1) != marker')
'''
        if action == 'create':
            body += r'''
{ test -z "$filtered" || printf '%s\n' "$filtered"; printf '*/5 * * * * logger -t mrnobody-p11 "MrNobody controlled lab P11" %s\n' "$marker"; } | crontab -
crontab -l | grep -F -- "$marker" >/dev/null
'''
        else:
            body += r'''
printf '%s\n' "$filtered" | crontab -
remaining=$(crontab -l)
if printf '%s\n' "$remaining" | grep -F -- "$marker" >/dev/null; then exit 1; fi
'''
        return prelude + body + "\nprintf 'MrNobody P11 verified\\n'\n"
    prelude = f'''set -eu
command -v systemctl >/dev/null || exit 78
test -x /usr/bin/true || exit 78
systemctl --user show-environment >/dev/null 2>&1 || exit 78
name='{name}'
dir="$HOME/.config/systemd/user"
unit="$dir/$name.service"
if [ -L "$unit" ]; then exit 1; fi
if [ -e "$unit" ] && ! grep -Fx '# {MARKER}' "$unit" >/dev/null; then exit 1; fi
'''
    if action == 'cleanup':
        body = '''if [ -e "$unit" ]; then
    systemctl --user disable --now "$name.service"
    rm -- "$unit"
    systemctl --user daemon-reload
fi
test ! -e "$unit"
'''
    else:
        body = f'''mkdir -p "$dir"
umask 077
cat > "$unit" <<'MRN_UNIT'
# {MARKER}
[Unit]
Description={MARKER}
[Service]
Type=oneshot
ExecStart=/usr/bin/true
RemainAfterExit=yes
[Install]
WantedBy=default.target
MRN_UNIT
systemctl --user daemon-reload
systemctl --user enable --now "$name.service"
systemctl --user is-enabled "$name.service" >/dev/null
systemctl --user is-active "$name.service" >/dev/null
'''
    return prelude + body + "printf 'MrNobody P11 verified\\n'\n"
