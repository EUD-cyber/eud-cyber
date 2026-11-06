"""Visible, fixed-payload lab persistence. No arbitrary persistence payloads.

All artifacts share a deterministic namespace and ownership marker. Cleanup is
explicit and idempotent; privileges are never elevated and logging stays enabled.
"""
import re
import base64
import struct


MARKER = 'MrNobody controlled lab P11'
METHODS = {'scheduled-task': ('windows', 'T1053.005', 'Scheduled Task'),
           'service': ('windows', 'T1543.003', 'Windows Service'),
           'cron': ('linux', 'T1053.003', 'Cron'),
           'systemd': ('linux', 'T1543.002', 'Systemd Service'),
           'task-service': ('windows', 'T1053.005,T1543.003', 'Scheduled Task + Windows Service'),
           'cron-systemd': ('linux', 'T1053.003,T1543.002', 'Cron + Systemd Service')}


def configuration(env, platform):
    method = env.get('MRNOBODY_METHOD') or 'auto'
    if method == 'auto':
        method = 'task-service' if platform == 'windows' else 'cron-systemd'
    if method not in METHODS or METHODS[method][0] != platform:
        raise ValueError('Persistence method is incompatible with platform')
    action = env.get('MRNOBODY_ACTION') or 'create'
    artifact = env.get('MRNOBODY_ARTIFACT') or 'telemetry'
    if action not in {'create', 'cleanup'} or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', artifact):
        raise ValueError('Invalid persistence action/artifact')
    activity_configuration(env, method, action)
    return method, action, 'mrnobody-p11-' + artifact


def metadata(env, platform):
    method, action, name = configuration(env, platform)
    if method in PAIRED:
        return paired_metadata(env, platform, method, action, name)
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
    if method in PAIRED:
        return paired_script(env, platform, method, action, name)
    if platform == 'windows':
        prelude = "$ErrorActionPreference = 'Stop'\n$name = '" + name + "'\n$marker = '" + MARKER + "'\n"
        if method == 'scheduled-task':
            body = r'''
$old = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
if ($old -and $old.Description -ne $marker) { throw 'artifact_ownership_conflict' }
'''
            if action == 'cleanup':
                body += r'''
if ($old) { Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false }
if (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue) { throw 'cleanup_verification_failed' }
'''
            else:
                body += r'''
# Harmless fixed action: a process launch once a day; never operator shell input.
$a = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/c echo MrNobody controlled lab P11'
$t = New-ScheduledTaskTrigger -Daily -At '12:00'
Register-ScheduledTask -TaskName $name -TaskPath '\' -Description $marker -Action $a -Trigger $t -Force | Out-Null
if (-not (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop)) { throw 'create_verification_failed' }
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


# Explicit legacy methods retain their original payloads and cleanup identities.
PAIRED = {'task-service', 'cron-systemd'}


def activity_configuration(env, method, action='create'):
    enabled = env.get('MRNOBODY_PERSISTENCE_DNS') or 'disabled'
    if enabled not in {'enabled', 'disabled'}:
        raise ValueError('DNS activity must be enabled or disabled')
    domain = env.get('MRNOBODY_PERSISTENCE_DOMAIN') or 'evilcorp.test'
    if (not isinstance(domain, str) or len(domain) > 120 or
            not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.)+test', domain)):
        raise ValueError('P11 requires a lowercase reserved .test domain')
    def integer(key, default, low, high):
        value = env.get('MRNOBODY_' + key) or default
        if isinstance(value, bool) or not re.fullmatch(r'[0-9]{1,6}', str(value)) or not low <= int(value) <= high:
            raise ValueError('Invalid P11 interval/duration')
        return int(value)
    interval = integer('PERSISTENCE_INTERVAL', 60, 10, 3600)
    duration = integer('PERSISTENCE_DURATION', 3600, 60, 14400)
    if interval > duration:
        raise ValueError('P11 interval must fit the duration')
    resolver = env.get('MRNOBODY_PERSISTENCE_RESOLVER') or ''
    if resolver:
        from scenario_model import private
        resolver = private(resolver)
        if resolver.split('.')[-1] in {'0', '255'}:
            raise ValueError('Use a unicast private lab resolver')
    if action == 'create' and enabled == 'enabled' and (method not in PAIRED or not resolver):
        raise ValueError('DNS requires a paired method and an explicit internal lab resolver')
    return dict(persistence_dns=enabled, dns_domain=domain, dns_resolver=resolver or 'none',
                query_interval=interval, activity_duration=duration,
                cleanup_policy='manual_artifacts_automatic_activity_stop')


def paired_metadata(env, platform, method, action, name):
    c = activity_configuration(env, method, action)
    directory = ('%ProgramData%/MrNobody/P11/' if platform == 'windows' else '~/.config/mrnobody/') + name
    return dict(c, platform=platform, method=method, action=action, artifact=name,
                artifact_path=directory, service_name=name if platform == 'windows' else name + '.service',
                service_path=directory + '/' + name + '.exe' if platform == 'windows' else '~/.config/systemd/user/' + name + '.service',
                scheduled_trigger='TaskScheduler/' + name if platform == 'windows' else 'user-crontab/# ' + MARKER + ' ' + name,
                trigger_schedule='every_minute_until_deadline',
                service_scope='LocalSystem' if platform == 'windows' else 'existing_user_manager_no_linger',
                activity_lifetime='independent_of_phase_completion_fixed_UTC_deadline_no_extension_on_rerun',
                cleanup_action='P11_action_cleanup_same_target_user_method_artifact',
                cleanup_artifact=name.removeprefix('mrnobody-p11-'),
                cleanup_required='true' if action == 'create' else 'false',
                dns_activity='benign_fixed_DNS_A_questions_no_C2_no_exfiltration',
                network_detection='not_assessed_requires_sensor_evidence', mitre=METHODS[method][1])


def evidence(output, env, platform):
    """Only fixed counters/status escape the remote action; never raw output."""
    method, action, _ = configuration(env, platform)
    if method not in PAIRED:
        return dict(result='success')
    paths = {}
    for key, encoded in re.findall(r'(?m)^MRN_P11_PATH=(artifact_path|service_path),([A-Za-z0-9+/=]{1,1024})\r?$', output):
        try:
            value = base64.b64decode(encoded, validate=True).decode('utf-8')
        except (ValueError, UnicodeError):
            return dict(result='failed', warning='invalid_path_evidence', cleanup_required='true')
        if len(value) > 512 or any(ord(c) < 32 for c in value) or not (value.startswith('/') or re.match(r'^[A-Za-z]:\\', value)):
            return dict(result='failed', warning='invalid_path_evidence', cleanup_required='true')
        paths[key] = value
    if action == 'cleanup':
        if re.search(r'(?m)^MRN_P11_CLEANUP=complete\r?$', output):
            return dict(paths, result='success', cleanup='complete', cleanup_required='false',
                        service_active='false', trigger_configured='false')
        return dict(result='failed', warning='cleanup_verification_missing', cleanup_required='true')
    rows = re.findall(r'(?m)^MRN_P11=1,1,([0-9]{10}),([0-9]{1,6}),([0-9]{1,6}),([0-9]{1,13}),(-?[0-9]{1,2})\r?$', output)
    if len(rows) != 1:
        return dict(result='failed', warning='paired_verification_missing', cleanup_required='true')
    deadline, attempts, responses, last, rcode = map(int, rows[0])
    if responses > attempts or attempts > 1440 or rcode not in {-1, 0, 3}:
        return dict(result='failed', warning='invalid_persistence_evidence', cleanup_required='true')
    enabled = activity_configuration(env, method)['persistence_dns'] == 'enabled'
    return dict(paths, result='success', service_active='true', trigger_configured='true',
                activity_deadline_utc_epoch=deadline, dns_attempts=attempts, dns_responses=responses,
                last_query_utc_epoch_ms=last, last_dns_rcode=rcode,
                dns_verification='matching_NOERROR_or_NXDOMAIN_response' if responses else 'not_observed',
                warning='dns_response_unverified_check_resolver_and_visibility' if enabled and not responses else 'none',
                cleanup='manual_required', cleanup_required='true',
                verification_scope='target_status_and_fixed_counters_not_network_sensor_detection')


def question(domain):
    # RD=0: the dedicated resolver must serve the .test zone without forwarding.
    return struct.pack('!6H', 19794, 0, 1, 0, 0, 0) + b''.join(
        bytes([len(label)]) + label.encode('ascii') for label in domain.split('.')) + b'\0\0\1\0\1'


def paired_script(env, platform, method, action, name):
    c = activity_configuration(env, method, action)
    settings = '|'.join([c['persistence_dns'], c['dns_domain'], c['dns_resolver'],
                         str(c['query_interval']), str(c['activity_duration'])])
    packet = base64.b64encode(question(c['dns_domain'])).decode('ascii')
    if platform == 'windows':
        return windows_pair(name, action, settings, packet)
    return linux_pair(name, action, settings, packet)


# Native ServiceBase compiled using the existing Windows .NET Framework compiler.
# No downloaded wrapper, external executable, interpreter or command input.
WINDOWS_SERVICE = r'''
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;
using System.Diagnostics;
public class MrNobodyLabService : ServiceBase {
    private Thread worker;
    private readonly ManualResetEvent stopped = new ManualResetEvent(false);
    public MrNobodyLabService() { ServiceName = "__NAME__"; AutoLog = true; }
    protected override void OnStart(string[] args) {
        worker = new Thread(Run); worker.IsBackground = true; worker.Start();
    }
    protected override void OnStop() { stopped.Set(); if(worker != null) worker.Join(4000); }
    private void Run() {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        try {
            string[] config = File.ReadAllLines(Path.Combine(dir, "config.txt"));
            if(config.Length != 2 || config[0] != "__SETTINGS__") throw new Exception("configuration_mismatch");
            long deadline = long.Parse(config[1]);
            string[] fields = config[0].Split('|');
            int interval = int.Parse(fields[3]), duration = int.Parse(fields[4]);
            int attempts = 0, responses = 0, rcode = -1; long last = 0;
            Stopwatch elapsed = Stopwatch.StartNew();
            while(DateTimeOffset.UtcNow.ToUnixTimeSeconds() < deadline && elapsed.Elapsed.TotalSeconds < duration && attempts < 1440 && !stopped.WaitOne(0)) {
                if(fields[0] == "enabled") {
                    attempts++; last = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); rcode = -1;
                    byte[] q = Convert.FromBase64String("__PACKET__");
                    byte[] tx = Guid.NewGuid().ToByteArray(); q[0] = tx[0]; q[1] = tx[1];
                    using(UdpClient client = new UdpClient()) {
                        try {
                            client.Connect(IPAddress.Parse(fields[2]), 53); client.Client.ReceiveTimeout = 2000;
                            client.Send(q, q.Length); IPEndPoint peer = new IPEndPoint(IPAddress.Any, 0);
                            byte[] r = client.Receive(ref peer);
                            bool valid = r.Length >= q.Length && r[0] == q[0] && r[1] == q[1] && (r[2] & 128) != 0 && (r[2] & 120) == 0 && r[4] == 0 && r[5] == 1;
                            for(int i = 12; valid && i < q.Length; i++) if(r[i] != q[i]) valid = false;
                            if(valid && ((r[3] & 15) == 0 || (r[3] & 15) == 3)) { responses++; rcode = r[3] & 15; }
                        } catch(SocketException) {}
                    }
                }
                string status = Path.Combine(dir, "status.txt"), temporary = Path.Combine(dir, "status.tmp");
                File.WriteAllText(temporary, attempts + "," + responses + "," + last + "," + rcode);
                if(File.Exists(status)) File.Replace(temporary, status, null); else File.Move(temporary, status);
                int remaining = (int)Math.Max(0, deadline - DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                if(stopped.WaitOne(Math.Min(interval, remaining) * 1000)) return;
            }
        } catch(Exception) { EventLog.WriteEntry(ServiceName, "MrNobody P11 safe worker stopped; check owned configuration.", EventLogEntryType.Warning); }
        ThreadPool.QueueUserWorkItem(delegate { Stop(); });
    }
    public static void Main() { ServiceBase.Run(new MrNobodyLabService()); }
}
'''


def windows_pair(name, action, settings, packet):
    prelude = r"""
$ErrorActionPreference = 'Stop'
$name = '__NAME__'
$marker = 'MrNobody controlled lab P11'
$dir = Join-Path $env:ProgramData ('MrNobody\P11\' + $name)
$exe = Join-Path $dir ($name + '.exe')
$owner = Join-Path $dir 'owner.txt'
$config = Join-Path $dir 'config.txt'
$task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
$old = Get-CimInstance Win32_Service -Filter "Name='$name'"
if ((Test-Path $dir) -and ((Get-Item $dir).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'artifact_ownership_conflict' }
if ((Test-Path $dir) -and ((-not (Test-Path $owner)) -or (Get-Content $owner -Raw) -ne $marker)) { throw 'artifact_ownership_conflict' }
if ($task -and $task.Description -ne $marker) { throw 'artifact_ownership_conflict' }
if ($old -and ($old.Description -ne $marker -or $old.PathName -ne ('"' + $exe + '"'))) { throw 'artifact_ownership_conflict' }
if (Test-Path $dir) {
    foreach ($item in Get-ChildItem -LiteralPath $dir -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer -or $item.Name -notin @('owner.txt','config.txt','maintain.ps1','status.txt','status.tmp',($name + '.exe'))) { throw 'artifact_ownership_conflict' }
    }
}
"""
    if action == 'cleanup':
        body = r"""
if ($task) { Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop; Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false }
if ($old) {
    if ($old.State -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
    $deleted = Invoke-CimMethod -InputObject $old -MethodName Delete
    if ($deleted.ReturnValue -ne 0) { throw 'service_delete_failed' }
}
for ($i=0; $i -lt 20; $i++) {
    if (-not (Get-CimInstance Win32_Service -Filter "Name='$name'")) { break }
    Start-Sleep -Milliseconds 250
}
if ((Get-CimInstance Win32_Service -Filter "Name='$name'") -or (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue)) { throw 'cleanup_verification_failed' }
if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
if (Test-Path $dir) { throw 'cleanup_verification_failed' }
Write-Output 'MRN_P11_CLEANUP=complete'
"""
    else:
        code = WINDOWS_SERVICE.replace('__NAME__', name).replace('__SETTINGS__', settings).replace('__PACKET__', packet)
        body = r"""
if ($old -and -not (Test-Path $config)) { throw 'legacy_service_cleanup_before_paired_create' }
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
# Rebuild the directory DACL, including removal of previous explicit grants.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
[IO.Directory]::SetAccessControl($dir, $acl)
# Existing files must inherit only this protected parent DACL.
foreach ($child in Get-ChildItem -LiteralPath $dir -Force) {
    & "$env:SystemRoot\System32\icacls.exe" $child.FullName /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'artifact_acl_failed' }
}
[IO.File]::WriteAllText($owner, $marker)
$settings = '__SETTINGS__'
if (Test-Path $config) {
    $lines = @(Get-Content $config)
    if ($lines.Count -ne 2 -or $lines[0] -ne $settings) { throw 'configuration_changed_cleanup_before_reconfigure' }
    $deadline = [long]$lines[1]
} else {
    $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + [int]($settings.Split('|')[4])
    [IO.File]::WriteAllLines($config, [string[]]@($settings, [string]$deadline))
}
if ($deadline -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { throw 'exercise_expired_cleanup_before_recreate' }
if ($old -and -not (Test-Path $config)) { throw 'configuration_missing_cleanup_before_recreate' }
if (-not (Test-Path $exe)) {
    $source = @'
__SOURCE__
'@
    Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.ServiceProcess.dll' -OutputAssembly $exe -OutputType ConsoleApplication
}
if (-not $old) {
    New-Service -Name $name -BinaryPathName ('"' + $exe + '"') -DisplayName ($name + ' visible DNS simulation') -Description $marker -StartupType Manual | Out-Null
}
$maintain = @'
$ErrorActionPreference = 'Stop'
$lines = @(Get-Content -LiteralPath '__CONFIG__')
if ($lines.Count -eq 2 -and [long]$lines[1] -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { Start-Service -Name '__NAME__' }
'@
$maintain = $maintain.Replace('__CONFIG__', $config.Replace("'", "''"))
[IO.File]::WriteAllText((Join-Path $dir 'maintain.ps1'), $maintain)
$a = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -File "' + (Join-Path $dir 'maintain.ps1') + '"')
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Seconds ([Math]::Max(60, $deadline - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())))
Register-ScheduledTask -TaskName $name -TaskPath '\' -Description $marker -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-Service -Name $name
for ($i=0; $i -lt 20 -and -not (Test-Path (Join-Path $dir 'status.txt')); $i++) { Start-Sleep -Milliseconds 250 }
$verified = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
if ((Get-Service -Name $name).Status -ne 'Running' -or -not $verified.Triggers -or -not $verified.Actions) { throw 'create_verification_failed' }
$status = [IO.File]::ReadAllText((Join-Path $dir 'status.txt'))
Write-Output ('MRN_P11=1,1,' + $deadline + ',' + $status)
""".replace('__SOURCE__', code).replace('__SETTINGS__', settings)
    paths = r"""
Write-Output ('MRN_P11_PATH=artifact_path,' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dir)))
Write-Output ('MRN_P11_PATH=service_path,' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($exe)))
"""
    return (prelude + body + paths).replace('__NAME__', name)


LINUX_WORKER = r"""import base64, os, pathlib, socket, subprocess, sys, time
base = pathlib.Path(__file__).resolve().parent
lines = (base / 'config.txt').read_text().splitlines()
if len(lines) != 2 or lines[0] != '__SETTINGS__':
    raise SystemExit('MrNobody P11 configuration mismatch')
fields = lines[0].split('|')
deadline = int(lines[1])
if len(sys.argv) == 2 and sys.argv[1] == '--maintain':
    if time.time() < deadline:
        os.environ['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
        subprocess.run(['/usr/bin/systemctl', '--user', 'start', '__NAME__.service'], check=True)
    raise SystemExit(0)
attempts = responses = last = 0
rcode = -1
start = time.monotonic()
while time.time() < deadline and time.monotonic()-start < int(fields[4]) and attempts < 1440:
    if fields[0] == 'enabled':
        attempts += 1
        last = int(time.time()*1000)
        rcode = -1
        q = os.urandom(2) + base64.b64decode('__PACKET__')[2:]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.connect((fields[2], 53))
                client.send(q)
                r = client.recv(4096)
                if (len(r) >= len(q) and r[:2] == q[:2] and r[2] & 128 and not r[2] & 120
                        and r[4:6] == b'\x00\x01' and r[12:len(q)] == q[12:] and r[3] & 15 in (0, 3)):
                    responses += 1
                    rcode = r[3] & 15
        except OSError:
            pass
    status = base / 'status.txt'
    temporary = base / 'status.tmp'
    temporary.write_text('%s,%s,%s,%s' % (attempts, responses, last, rcode))
    temporary.replace(status)
    time.sleep(max(0, min(int(fields[3]), deadline-time.time())))
"""


def linux_pair(name, action, settings, packet):
    # Serialize cron RMW; quote user paths with the appropriate cron/systemd
    # rules. No sudo, implicit package installation, linger or stored secrets.
    worker = LINUX_WORKER.replace('__NAME__', name).replace('__SETTINGS__', settings).replace('__PACKET__', packet)
    setup = r"""import fcntl, os, pathlib, shlex, subprocess, time
name = '__NAME__'
marker = 'MrNobody controlled lab P11'
root = pathlib.Path.home() / '.config/mrnobody'
directory = root / name
unitdir = pathlib.Path.home() / '.config/systemd/user'
unit = unitdir / (name + '.service')
for path in (root, directory, unitdir, unit):
    if path.is_symlink():
        raise SystemExit('artifact_ownership_conflict')
root.mkdir(parents=True, exist_ok=True, mode=0o700)
lockpath = root / 'p11-cron.lock'
if lockpath.is_symlink():
    raise SystemExit('artifact_ownership_conflict')
lock = lockpath.open('a')
fcntl.flock(lock, fcntl.LOCK_EX)
owner = directory / 'owner.txt'
if directory.exists() and (not owner.is_file() or owner.read_text() != marker):
    raise SystemExit('artifact_ownership_conflict')
if unit.exists() and ('# ' + marker) not in unit.read_text().splitlines():
    raise SystemExit('artifact_ownership_conflict')
if directory.exists():
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file() or path.name not in {'owner.txt', 'config.txt', 'worker.py', 'status.txt', 'status.tmp'}:
            raise SystemExit('artifact_ownership_conflict')
def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout
def systemctl(*args):
    return run(['/usr/bin/systemctl', '--user', *args])
cron = subprocess.run(['crontab', '-l'], capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
if cron.returncode and 'no crontab for' not in cron.stderr:
    raise SystemExit('crontab_read_failed')
tag = '# ' + marker + ' ' + name
old = cron.stdout.splitlines()
filtered = [line for line in old if not line.endswith(tag)]
def setcron(lines):
    subprocess.run(['crontab', '-'], input='\n'.join(lines) + '\n', text=True, check=True)
if '__ACTION__' == 'cleanup':
    setcron(filtered)
    if unit.exists():
        systemctl('disable', '--now', name + '.service')
        unit.unlink()
        systemctl('daemon-reload')
    elif directory.exists():
        # Recover a unit removed after a partial install while still loaded.
        loaded = systemctl('show', name + '.service', '--property=LoadState', '--value').strip()
        if loaded != 'not-found':
            systemctl('stop', name + '.service')
            systemctl('daemon-reload')
    active = subprocess.run(['/usr/bin/systemctl', '--user', 'is-active', name + '.service'], capture_output=True, text=True)
    if active.returncode == 0 or active.returncode not in (3, 4):
        raise SystemExit('cleanup_service_verification_failed')
    if unit.exists() or any(line.endswith(tag) for line in run(['crontab', '-l']).splitlines()):
        raise SystemExit('cleanup_verification_failed')
    if directory.exists():
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()
    print('MRN_P11_CLEANUP=complete')
else:
    systemctl('show-environment')
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    owner.write_text(marker)
    config = directory / 'config.txt'
    settings = '__SETTINGS__'
    if config.exists():
        lines = config.read_text().splitlines()
        if len(lines) != 2 or lines[0] != settings:
            raise SystemExit('configuration_changed_cleanup_before_reconfigure')
        deadline = int(lines[1])
    else:
        deadline = int(time.time()) + int(settings.split('|')[4])
        config.write_text(settings + '\n' + str(deadline) + '\n')
    if deadline <= time.time():
        raise SystemExit('exercise_expired_cleanup_before_recreate')
    worker = directory / 'worker.py'
    worker.write_text(__WORKER__)
    unitdir.mkdir(parents=True, exist_ok=True)
    def unitquote(value):
        return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'
    if any(c in str(worker) for c in '\n\r%'):
        raise SystemExit('unsupported_home_path')
    unit.write_text('# ' + marker + '\n[Unit]\nDescription=' + marker +
        '\n[Service]\nType=simple\nExecStart=/usr/bin/python3 ' + unitquote(worker) +
        '\nRestart=no\nUMask=0077\nNoNewPrivileges=yes\n[Install]\nWantedBy=default.target\n')
    systemctl('daemon-reload')
    systemctl('enable', '--now', name + '.service')
    entry = '* * * * * /usr/bin/python3 ' + shlex.quote(str(worker)) + ' --maintain ' + tag
    setcron(filtered + [entry])
    systemctl('is-active', name + '.service')
    systemctl('is-enabled', name + '.service')
    if run(['crontab', '-l']).splitlines().count(entry) != 1:
        raise SystemExit('trigger_verification_failed')
    status = directory / 'status.txt'
    for _ in range(20):
        if status.exists():
            break
        time.sleep(.25)
    print('MRN_P11=1,1,%s,%s' % (deadline, status.read_text()))
"""
    setup += "\nimport base64\nfor key, path in [('artifact_path', directory), ('service_path', unit)]:\n    print('MRN_P11_PATH=%s,%s' % (key, base64.b64encode(str(path).encode()).decode()))\n"
    setup = setup.replace('__NAME__', name).replace('__ACTION__', action).replace('__SETTINGS__', settings).replace('__WORKER__', repr(worker))
    return ("set -eu\ncommand -v python3 >/dev/null || exit 78\ncommand -v crontab >/dev/null || exit 78\n"
            "test -x /usr/bin/systemctl || exit 78\numask 077\n"
            "systemctl --user show-environment >/dev/null 2>&1 || exit 78\n"
            "python3 - <<'MRN_P11_SETUP'\n" + setup + "\nMRN_P11_SETUP\n")
