"""Visible, fixed-payload lab persistence. No arbitrary persistence payloads.

All artifacts share a deterministic namespace and ownership marker. Cleanup is
explicit and idempotent; privileges are never elevated and logging stays enabled.
"""
import re
import base64
import struct
import json
from types import SimpleNamespace


WINDOWS_STAGES = {'ownership', 'acl', 'configuration', 'compile', 'service_create',
                  'service_start', 'task_create', 'verify', 'cleanup_task',
                  'cleanup_service', 'cleanup_files'}
WINDOWS_ERRORS = {'artifact_ownership_conflict', 'artifact_acl_failed',
                  'service_delete_failed', 'cleanup_verification_failed',
                  'create_verification_failed', 'legacy_service_cleanup_before_paired_create',
                  'configuration_changed_cleanup_before_reconfigure',
                  'exercise_expired_cleanup_before_recreate',
                  'configuration_missing_cleanup_before_recreate', 'persistence_action_busy'}


def windows_diagnostic_script(source):
    # Only these fixed codes leave PowerShell. Never serialize an ErrorRecord,
    # exception, source, compiler output, credentials or raw stderr.
    stages = ','.join("'" + value + "'" for value in sorted(WINDOWS_STAGES))
    errors = ','.join("'" + value + "'" for value in sorted(WINDOWS_ERRORS))
    return ("$p11Stage='ownership'\ntry {\n" + source + "\n} catch {\n"
            "$safeStage='ownership'; $safeError='persistence_action_failed'\n"
            "if ($p11Stage -cin @(" + stages + ")) { $safeStage=$p11Stage }\n"
            "if ($_.Exception.Message -cin @(" + errors + ")) { $safeError=$_.Exception.Message }\n"
            "Write-Output ('MRN_P11_ERROR=' + $safeStage + ',' + $safeError)\nexit 1\n}\n")


def perform_windows(target, env, session_factory=None):
    """P11 service methods only; reuse P09's bounded, hashed WinRS stdin framing.

    No retries of ambiguous Send/Receive calls. The loader creates no staging
    file and closes its shell even on failure. Manual reruns use owned artifacts.
    P10 and the independently working scheduled-task path are unchanged.
    """
    from p09_actions import run_powershell, PayloadError
    from scenario_model import private
    from windows_actions import timeout_value
    method, action, _ = configuration(env, 'windows')
    if method not in {'service', 'task-service'}:
        raise ValueError('P11 service transport requires a service method')
    failure = dict(result='failed', cleanup_required='true')
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD')
    if not password:
        return dict(failure, stage='session', warning='missing_runtime_windows_credentials')
    limit = timeout_value(env.get('MRNOBODY_TIMEOUT') or 60)
    stage = 'session'

    class TrackedProtocol:
        def __init__(self, protocol):
            self.protocol = protocol

        def __getattr__(self, name):
            call = getattr(self.protocol, name)
            stages = {'open_shell': 'winrm_shell', 'run_command': 'process_launch',
                      'send_command_input': 'payload_send', 'get_command_output': 'process_receive'}
            if name not in stages:
                return call
            def invoke(*args, **kwargs):
                nonlocal stage
                stage = stages[name]
                return call(*args, **kwargs)
            return invoke

    try:
        if session_factory is None:
            import winrm
            session_factory = winrm.Session
        scheme = 'https' if target['protocol'] == 'winrm-https' else 'http'
        session = session_factory(f"{scheme}://{private(target['target'])}:{target['port']}/wsman",
            auth=(target['username'], password), transport='ntlm', message_encryption='always',
            server_cert_validation='ignore', operation_timeout_sec=min(limit, 60), read_timeout_sec=limit + 10)
        stage = 'payload_prepare'
        response = run_powershell(SimpleNamespace(protocol=TrackedProtocol(session.protocol)),
                                  windows_diagnostic_script(script(env, 'windows')))
    except Exception as error:
        # Type classification only: exception messages can contain secrets.
        timed_out = isinstance(error, TimeoutError) or type(error).__name__ in {'ReadTimeout', 'ConnectTimeout', 'WinRMOperationTimeoutError'}
        return dict(failure, stage=stage, warning='powershell_payload_too_large' if isinstance(error, PayloadError)
                    else 'timeout_remote_action_may_still_be_running' if timed_out
                    else 'transport_error_details_omitted')
    counts = dict(exit_code=response.status_code, stdout_bytes=len(response.std_out), stderr_bytes=len(response.std_err))
    if len(response.std_out) > 8192:
        return dict(failure, **counts, stage='verify', warning='oversized_persistence_evidence')
    output = response.std_out.decode('utf-8-sig', errors='replace')
    match = re.fullmatch(r'MRN_P11_ERROR=([a-z_]+),([a-z_]+)\s*', output)
    if match and match[1] in WINDOWS_STAGES and match[2] in WINDOWS_ERRORS | {'persistence_action_failed'}:
        return dict(failure, **counts, stage=match[1], warning=match[2])
    # The shared loader has a fixed failure envelope for decode/parse failures.
    try:
        data = json.loads(output)
    except ValueError:
        data = None
    if isinstance(data, dict) and data.get('protocol') == 'p09_failure' and data.get('stage') in {'payload_decode', 'payload_parse', 'payload_execute'}:
        return dict(failure, **counts, stage=data['stage'], warning='powershell_payload_failed')
    if response.status_code != 0:
        return dict(failure, **counts, stage='process', warning='remote_powershell_nonzero_exit')
    if method == 'task-service':
        result = evidence(output, env, 'windows')
    else:
        verified = output.strip() == 'MrNobody P11 verified'
        result = dict(result='success' if verified else 'failed',
                      warning='none' if verified else 'invalid_persistence_evidence',
                      cleanup_required='false' if verified and action == 'cleanup' else 'true')
    return dict(result, **counts, stage='complete' if result['result'] == 'success' else 'verify')


LINUX_ERRORS = {'user_manager_unavailable', 'artifact_ownership_conflict', 'crontab_read_failed',
                'systemctl_failed', 'cleanup_service_verification_failed', 'cleanup_verification_failed',
                'configuration_changed_cleanup_before_reconfigure', 'exercise_expired_cleanup_before_recreate',
                'trigger_verification_failed', 'unsupported_home_path', 'worker_status_missing',
                'process_identity_conflict', 'process_start_failed', 'process_stop_failed',
                'configuration_missing', 'invalid_configuration', 'action_busy', 'action_failed'}

MARKER = 'MrNobody controlled lab P11'
METHODS = {'scheduled-task': ('windows', 'T1053.005', 'Scheduled Task'),
           'service': ('windows', 'T1543.003', 'Windows Service'),
           'process': ('linux', 'T1059.006', 'Bounded Python Process'),
           'process-dns': ('linux', 'T1059.006', 'Bounded Python Process with lab DNS'),
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
    if action not in ({'create', 'inspect', 'cleanup'} if method in {'systemd', 'cron-systemd', 'process', 'process-dns'} else {'create', 'cleanup'}) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', artifact):
        raise ValueError('Invalid persistence action/artifact')
    activity_configuration(env, method, action)
    return method, action, 'mrnobody-p11-' + artifact


def metadata(env, platform):
    method, action, name = configuration(env, platform)
    if method in {'process', 'process-dns'}:
        c = activity_configuration(env, method, action)
        return dict(c, platform=platform, method=method, action=action, artifact=name,
                    artifact_path='~/.config/mrnobody/' + name, persistence='false',
                    execution_scope='bounded_background_process_no_reboot_or_login_restart',
                    cpu_level=env.get('MRNOBODY_PERSISTENCE_CPU') or 'idle',
                    cleanup_artifact=name.removeprefix('mrnobody-p11-'),
                    cleanup_action='P11_action_cleanup_same_target_user_method_artifact',
                    mitre=METHODS[method][1], cleanup_required='false' if action == 'cleanup' else 'true')
    if method in PAIRED | {'systemd'}:
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
    if method in {'process', 'process-dns'}:
        from linux_process import render
        return render(name, action, activity_configuration(env, method, action), env.get('MRNOBODY_PERSISTENCE_CPU') or 'idle')
    if method == 'systemd':
        return paired_script(env, platform, method, action, name)
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
'''
            body += windows_directory_guard(False)
            body += r'''
$old = Get-CimInstance Win32_Service -Filter "Name='$name'"
if ((Test-Path $dir) -and ((-not (Test-Path $owner)) -or (Get-Content $owner -Raw) -ne $marker)) { throw 'artifact_ownership_conflict' }
if ($old -and ($old.Description -ne $marker -or $old.PathName -ne ('"' + $exe + '"'))) { throw 'artifact_ownership_conflict' }
'''
            if action == 'cleanup':
                body += r'''
$p11Stage = 'cleanup_service'
if ($old) {
    if ($old.State -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
    $deleted = Invoke-CimMethod -InputObject $old -MethodName Delete
    if ($deleted.ReturnValue -ne 0) { throw 'service_delete_failed' }
}
for ($i=0; $i -lt 20; $i++) {
    if (-not (Get-CimInstance Win32_Service -Filter "Name='$name'")) { break }
    Start-Sleep -Milliseconds 250
}
if (Get-CimInstance Win32_Service -Filter "Name='$name'") { throw 'cleanup_verification_failed' }
$p11Stage = 'cleanup_files'
if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
if (Test-Path $dir) { throw 'cleanup_verification_failed' }
'''
            else:
                body += WINDOWS_SERVICE_ACL
                body += r'''
if (-not $old) {
    [IO.File]::WriteAllText($owner, $marker)
    # An owned orphan binary may be an interrupted compiler output. Rebuild it.
    $p11Stage = 'compile'
    if (Test-Path $exe) { Remove-Item -LiteralPath $exe -Force }
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
    $p11Stage = 'service_create'
    New-Service -Name $name -BinaryPathName ('"' + $exe + '"') -DisplayName $name -Description $marker -StartupType Automatic | Out-Null
}
$p11Stage = 'service_start'
Start-Service -Name $name
$p11Stage = 'verify'
if ((Get-Service -Name $name).Status -ne 'Running') { throw 'create_verification_failed' }
'''.replace('__NAME__', name)
        source = prelude + body + "\nWrite-Output 'MrNobody P11 verified'\n"
        return windows_lock(source, name) if method == 'service' else source
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
# Explicit legacy methods retain their original payloads and cleanup identities.
PAIRED = {'task-service', 'cron-systemd'}


def activity_configuration(env, method, action='create'):
    enabled = 'enabled' if method == 'process-dns' else env.get('MRNOBODY_PERSISTENCE_DNS') or 'disabled'
    if method == 'process' and enabled != 'disabled':
        raise ValueError('Choose process-dns for process DNS activity')
    if method in {'process', 'process-dns'}:
        if (env.get('MRNOBODY_PERSISTENCE_CPU') or 'idle') not in {'idle', 'low', 'medium'}:
            raise ValueError('Process CPU level must be idle, low or medium')
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
    if method in {'process', 'process-dns'} and action == 'create' and duration not in {300, 900, 1800, 3600}:
        raise ValueError('Process lifetime must be 300, 900, 1800 or 3600 seconds')
    if method == 'process-dns' and domain != 'evilcorp.test':
        raise ValueError('Process DNS uses only evilcorp.test')
    if interval > duration:
        raise ValueError('P11 interval must fit the duration')
    resolver = env.get('MRNOBODY_PERSISTENCE_RESOLVER') or ''
    if resolver:
        from scenario_model import private
        resolver = private(resolver)
        if resolver.split('.')[-1] in {'0', '255'}:
            raise ValueError('Use a unicast private lab resolver')
    if action == 'create' and enabled == 'enabled' and (method not in PAIRED | {'process-dns', 'systemd'} or not resolver):
        raise ValueError('DNS requires a supported service/process-dns method and an explicit internal lab resolver')
    return dict(persistence_dns=enabled, dns_domain=domain, dns_resolver=resolver or 'none',
                query_interval=interval, activity_duration=duration,
                cleanup_policy='manual_artifacts_automatic_activity_stop')


def paired_metadata(env, platform, method, action, name):
    c = activity_configuration(env, method, action)
    if action == 'cleanup':
        c.update(persistence_dns='not_assessed_during_cleanup', dns_domain='see_original_create_evidence',
                 dns_resolver='see_original_create_evidence', query_interval='not_assessed', activity_duration='not_assessed')
    directory = ('%ProgramData%/MrNobody/P11/' if platform == 'windows' else '~/.config/mrnobody/') + name
    return dict(c, platform=platform, method=method, action=action, artifact=name,
                artifact_path=directory, service_name=name if platform == 'windows' else name + '.service',
                service_path=directory + '/' + name + '.exe' if platform == 'windows' else '~/.config/systemd/user/' + name + '.service',
                scheduled_trigger='none' if method == 'systemd' else 'TaskScheduler/' + name if platform == 'windows' else 'user-crontab/# ' + MARKER + ' ' + name,
                trigger_schedule='none' if method == 'systemd' else 'every_minute_until_deadline',
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
    diagnostic = re.findall(r'(?m)^MRN_P11_ERROR=([a-z_]+),([a-z_]+)\r?$', output)
    if diagnostic:
        stage, warning = diagnostic[-1]
        if stage in {'manager', 'ownership', 'configuration', 'create', 'verify', 'cleanup', 'inspect'} and warning in LINUX_ERRORS:
            return dict(result='failed', stage=stage, warning=warning, cleanup_required='true')
    if method in {'process', 'process-dns'}:
        from linux_process import evidence as process_evidence
        return process_evidence(output, action)
    if method not in PAIRED | {'systemd'}:
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
    return dict(paths, result='success', service_active='true', trigger_configured='false' if method == 'systemd' else 'true',
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
    return linux_pair(name, action, settings, packet, method)


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
    public static int Main(string[] args) {
        if(args.Length == 1 && args[0] == "--maintain") {
            try {
                string[] config = File.ReadAllLines(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.txt"));
                if(config.Length != 2 || config[0] != "__SETTINGS__") return 1;
                if(DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= long.Parse(config[1])) return 0;
                using(ServiceController service = new ServiceController("__NAME__")) {
                    if(service.Status == ServiceControllerStatus.Stopped) service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                }
                return 0;
            } catch(Exception) { return 1; }
        }
        if(args.Length != 0) return 1;
        ServiceBase.Run(new MrNobodyLabService());
        return 0;
    }
}
'''


def windows_directory_guard(paired):
    allowed = "'owner.txt',($name + '.exe')"
    if paired:
        allowed += ",'config.txt','maintain.ps1','status.txt','status.tmp'"
    return r'''
$p11Stage = 'ownership'
# Check ancestors too: a protected leaf under a junction is not an owned path.
$ancestor = $dir
while ($ancestor) {
    if (Test-Path -LiteralPath $ancestor) {
        $entry = Get-Item -LiteralPath $ancestor -Force
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'artifact_ownership_conflict' }
    }
    $ancestor = Split-Path -Parent $ancestor
}
if (Test-Path -LiteralPath $dir) {
    foreach ($item in Get-ChildItem -LiteralPath $dir -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer -or $item.Name -notin @(__ALLOWED__)) { throw 'artifact_ownership_conflict' }
    }
}
'''.replace('__ALLOWED__', allowed)


WINDOWS_SERVICE_ACL = r'''
$p11Stage = 'acl'
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
Set-Acl -LiteralPath $dir -AclObject $acl
foreach ($child in Get-ChildItem -LiteralPath $dir -Force) {
    & "$env:SystemRoot\System32\icacls.exe" $child.FullName /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'artifact_acl_failed' }
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
""" + windows_directory_guard(True) + r"""
$task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
$old = Get-CimInstance Win32_Service -Filter "Name='$name'"
if ((Test-Path $dir) -and ((Get-Item $dir).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'artifact_ownership_conflict' }
if ((Test-Path $dir) -and ((-not (Test-Path $owner)) -or (Get-Content $owner -Raw) -ne $marker)) { throw 'artifact_ownership_conflict' }
if ($task -and $task.Description -ne $marker) { throw 'artifact_ownership_conflict' }
if ($old -and ($old.Description -ne $marker -or $old.PathName -ne ('"' + $exe + '"'))) { throw 'artifact_ownership_conflict' }
if ($task -and ($task.Actions.Execute -ne $exe -or $task.Actions.Arguments -ne '--maintain')) { throw 'artifact_ownership_conflict' }
"""
    if action == 'cleanup':
        body = r"""
$p11Stage = 'cleanup_task'
if ($task) { Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop; Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false }
$p11Stage = 'cleanup_service'
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
$p11Stage = 'cleanup_files'
if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
if (Test-Path $dir) { throw 'cleanup_verification_failed' }
Write-Output 'MRN_P11_CLEANUP=complete'
"""
    else:
        code = WINDOWS_SERVICE.replace('__NAME__', name).replace('__SETTINGS__', settings).replace('__PACKET__', packet)
        body = r"""
if (($old -or $task) -and -not (Test-Path $config)) { throw 'legacy_service_cleanup_before_paired_create' }
$p11Stage = 'acl'
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
Set-Acl -LiteralPath $dir -AclObject $acl
# Existing files must inherit only this protected parent DACL.
foreach ($child in Get-ChildItem -LiteralPath $dir -Force) {
    & "$env:SystemRoot\System32\icacls.exe" $child.FullName /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'artifact_acl_failed' }
}
[IO.File]::WriteAllText($owner, $marker)
$settings = '__SETTINGS__'
$p11Stage = 'configuration'
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
$p11Stage = 'compile'
if ($old -and -not (Test-Path $exe)) { throw 'configuration_missing_cleanup_before_recreate' }
if (-not $old) {
    # Recover an owned binary left behind by a failed compilation/registration.
    if (Test-Path $exe) { Remove-Item -LiteralPath $exe -Force }
    $source = @'
__SOURCE__
'@
    Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.ServiceProcess.dll' -OutputAssembly $exe -OutputType ConsoleApplication
}
if (-not $old) {
    $p11Stage = 'service_create'
    New-Service -Name $name -BinaryPathName ('"' + $exe + '"') -DisplayName ($name + ' visible DNS simulation') -Description $marker -StartupType Manual | Out-Null
}
# Same native executable supports a fixed deadline-checked maintenance mode.
# This avoids dependence on PowerShell script execution policy for the task.
$p11Stage = 'task_create'
$a = New-ScheduledTaskAction -Execute $exe -Argument '--maintain'
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Seconds ([Math]::Max(60, $deadline - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())))
Register-ScheduledTask -TaskName $name -TaskPath '\' -Description $marker -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
$p11Stage = 'service_start'
Start-Service -Name $name
$p11Stage = 'verify'
for ($i=0; $i -lt 20 -and -not (Test-Path (Join-Path $dir 'status.txt')); $i++) { Start-Sleep -Milliseconds 250 }
$verified = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
if ((Get-Service -Name $name).Status -ne 'Running' -or -not $verified.Triggers -or $verified.Actions.Execute -ne $exe -or $verified.Actions.Arguments -ne '--maintain') { throw 'create_verification_failed' }
$status = [IO.File]::ReadAllText((Join-Path $dir 'status.txt'))
Write-Output ('MRN_P11=1,1,' + $deadline + ',' + $status)
""".replace('__SOURCE__', code).replace('__SETTINGS__', settings)
    paths = r"""
Write-Output ('MRN_P11_PATH=artifact_path,' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dir)))
Write-Output ('MRN_P11_PATH=service_path,' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($exe)))
"""
    source = (prelude + body + paths).replace('__NAME__', name)
    return windows_lock(source, name)


def windows_lock(source, name):
    return ("$mutex = New-Object Threading.Mutex($false, 'Global\\" + name + "')\n"
            "if (-not $mutex.WaitOne(30000)) { $mutex.Dispose(); throw 'persistence_action_busy' }\n"
            "try {\n" + source + "\n} finally { $mutex.ReleaseMutex(); $mutex.Dispose() }\n")


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
        os.environ['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + os.environ['XDG_RUNTIME_DIR'] + '/bus'
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


def linux_pair(name, action, settings, packet, method='cron-systemd'):
    # Serialize cron RMW; quote user paths with the appropriate cron/systemd
    # rules. No sudo, implicit package installation, linger or stored secrets.
    worker = LINUX_WORKER.replace('__NAME__', name).replace('__SETTINGS__', settings).replace('__PACKET__', packet)
    setup = r"""import fcntl, os, pathlib, shlex, subprocess, time
name = '__NAME__'
paired = '__METHOD__' == 'cron-systemd'
stage = 'ownership'
os.environ['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
os.environ['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + os.environ['XDG_RUNTIME_DIR'] + '/bus'
marker = 'MrNobody controlled lab P11'
root = pathlib.Path.home() / '.config/mrnobody'
directory = root / name
unitdir = pathlib.Path.home() / '.config/systemd/user'
unit = unitdir / (name + '.service')
for path in (root, directory, unitdir, unit, *root.parents, *unitdir.parents):
    if path.is_symlink() or (path.exists() and path.stat().st_uid not in {0, os.getuid()}):
        raise SystemExit('artifact_ownership_conflict')
root.mkdir(parents=True, exist_ok=True, mode=0o700)
lockpath = root / 'p11-cron.lock'
if lockpath.is_symlink() or (lockpath.exists() and lockpath.stat().st_uid != os.getuid()):
    raise SystemExit('artifact_ownership_conflict')
lock = lockpath.open('a')
fcntl.flock(lock, fcntl.LOCK_EX)
owner = directory / 'owner.txt'
if directory.exists() and (not owner.is_file() or owner.read_text() != marker):
    raise SystemExit('artifact_ownership_conflict')
if (unitdir / (name + '.service.d')).exists() or (unitdir / (name + '.service.d')).is_symlink():
    raise SystemExit('artifact_ownership_conflict')
if unit.exists() and (unit.stat().st_uid != os.getuid() or ('# ' + marker) not in unit.read_text().splitlines()):
    raise SystemExit('artifact_ownership_conflict')
if directory.exists():
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid() or path.name not in {'owner.txt', 'config.txt', 'worker.py', 'status.txt', 'status.tmp', 'method.txt'}:
            raise SystemExit('artifact_ownership_conflict')
methodfile = directory / 'method.txt'
if methodfile.exists() and methodfile.read_text() != '__METHOD__':
    raise SystemExit('artifact_ownership_conflict')
if not paired and directory.exists() and not methodfile.exists() and (directory / 'config.txt').exists():
    raise SystemExit('artifact_ownership_conflict')
def run(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('systemctl_failed' if args[0] == '/usr/bin/systemctl' else 'crontab_read_failed')
    return result.stdout
def systemctl(*args):
    return run(['/usr/bin/systemctl', '--user', *args])
stage = 'manager'
try:
    systemctl('show-environment')
except SystemExit:
    raise SystemExit('user_manager_unavailable')
stage = 'ownership'
fragment = systemctl('show', name + '.service', '--property=FragmentPath', '--value').strip()
dropins = systemctl('show', name + '.service', '--property=DropInPaths', '--value').strip()
if fragment and fragment != str(unit) or dropins:
    raise SystemExit('artifact_ownership_conflict')
cron = subprocess.run(['crontab', '-l'], capture_output=True, text=True, env=dict(os.environ, LC_ALL='C')) if paired else None
if paired and cron.returncode and 'no crontab for' not in cron.stderr:
    raise SystemExit('crontab_read_failed')
tag = '# ' + marker + ' ' + name
old = cron.stdout.splitlines() if paired else []
filtered = [line for line in old if not line.endswith(tag)]
def setcron(lines):
    subprocess.run(['crontab', '-'], input='\n'.join(lines) + '\n', text=True, check=True)
if '__ACTION__' == 'inspect':
    stage = 'inspect'
    config = directory / 'config.txt'
    status = directory / 'status.txt'
    if not config.exists() or not status.exists():
        raise SystemExit('configuration_missing')
    lines = config.read_text().splitlines()
    systemctl('is-active', name + '.service')
    systemctl('is-enabled', name + '.service')
    if paired and not any(line.endswith(tag) for line in old):
        raise SystemExit('trigger_verification_failed')
    print('MRN_P11=1,1,%s,%s' % (int(lines[1]), status.read_text()))
    raise SystemExit(0)
if '__ACTION__' == 'cleanup':
    stage = 'cleanup'
    if paired:
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
    if unit.exists() or (paired and any(line.endswith(tag) for line in run(['crontab', '-l']).splitlines())):
        raise SystemExit('cleanup_verification_failed')
    if directory.exists():
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()
    print('MRN_P11_CLEANUP=complete')
else:
    stage = 'configuration'
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    owner.write_text(marker)
    methodfile.write_text('__METHOD__')
    config = directory / 'config.txt'
    settings = '__SETTINGS__'
    if config.exists():
        lines = config.read_text().splitlines()
        if len(lines) != 2 or lines[0] != settings:
            raise SystemExit('configuration_changed_cleanup_before_reconfigure')
        deadline = int(lines[1])
    else:
        if unit.exists() or (directory / 'worker.py').exists():
            raise SystemExit('configuration_missing')
        deadline = int(time.time()) + int(settings.split('|')[4])
        config.write_text(settings + '\n' + str(deadline) + '\n')
    if deadline <= time.time():
        raise SystemExit('exercise_expired_cleanup_before_recreate')
    worker = directory / 'worker.py'
    stage = 'create'
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
    if paired:
        setcron(filtered + [entry])
    stage = 'verify'
    systemctl('is-active', name + '.service')
    systemctl('is-enabled', name + '.service')
    if paired and run(['crontab', '-l']).splitlines().count(entry) != 1:
        raise SystemExit('trigger_verification_failed')
    status = directory / 'status.txt'
    for _ in range(20):
        if status.exists():
            break
        time.sleep(.25)
    if not status.exists():
        raise SystemExit('worker_status_missing')
    print('MRN_P11=1,1,%s,%s' % (deadline, status.read_text()))
"""
    setup += "\nimport base64\nfor key, path in [('artifact_path', directory), ('service_path', unit)]:\n    print('MRN_P11_PATH=%s,%s' % (key, base64.b64encode(str(path).encode()).decode()))\n"
    setup = setup.replace('__METHOD__', method).replace('__NAME__', name).replace('__ACTION__', action).replace('__SETTINGS__', settings).replace('__WORKER__', repr(worker))
    # Fixed diagnostics only; raw subprocess errors can contain target secrets.
    allowed = repr(LINUX_ERRORS)
    setup = ("try:\n" + '\n'.join('    ' + line for line in setup.splitlines()) +
             "\nexcept SystemExit as error:\n    if error.code not in (None, 0):\n"
             "        warning = str(error.code) if str(error.code) in " + allowed + " else 'action_failed'\n"
             "        print('MRN_P11_ERROR=%s,%s' % (globals().get('stage', 'ownership'), warning))\n"
             "    raise\nexcept Exception:\n"
             "    print('MRN_P11_ERROR=%s,action_failed' % globals().get('stage', 'ownership'))\n"
             "    raise SystemExit(1)\n")
    return ("set -eu\ncommand -v python3 >/dev/null || exit 78\numask 077\n"
            "python3 - <<'MRN_P11_SETUP'\n" + setup + "\nMRN_P11_SETUP\n")
