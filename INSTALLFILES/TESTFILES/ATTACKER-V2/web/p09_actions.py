"""P09 only: bounded, independently verified lab AD account reconciliation.

All remote output is an allowlisted protocol. Never log scripts or exceptions.
"""
import base64
import hashlib
import json
import re
from types import SimpleNamespace


# The legacy description is deliberately accepted for accounts created by older
# P09 releases. An equal name or existing privileged membership is NOT ownership.
AD_ACTION = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$r = @{domain='unknown'; dc='unknown'; domain_sid='unknown'; account_sid='none'; group_sid='unknown';
    account='not_attempted'; group='not_attempted'; exists=$false; enabled=$false; member=$false;
    owned=$false; verified=$false; result='failed'; warning='none'; stage='dc'}
function Read-P09Account {
    # Each invocation reads AD again; never infer postconditions from write calls.
    $users = @(Get-ADUser -Filter "SamAccountName -eq 'mrnobody'" -Properties Enabled,Description,MemberOf -Server localhost)
    if ($users.Count -gt 1) { throw 'ambiguous_account' }
    $r.exists=$false; $r.enabled=$false; $r.owned=$false; $r.member=$false
    $r.account_sid='none'; $r.account='missing'; $r.group='missing'; $r.verified=$false
    if ($users.Count -eq 0) { return $null }
    $user = $users[0]
    $r.exists=$true; $r.enabled=[bool]$user.Enabled; $r.account_sid=[string]$user.SID.Value
    $r.owned=[bool]($user.SamAccountName -ceq 'mrnobody' -and $user.Name -ceq 'mrnobody' -and
        $user.Description -ceq 'MrNobody controlled lab account' -and
        $r.account_sid.StartsWith($r.domain_sid + '-'))
    $r.member=[bool](@($user.MemberOf) -icontains $g.DistinguishedName)
    $r.account='already_enabled'; if (-not $r.enabled) { $r.account='existing_disabled' }
    if ($r.member) { $r.group='already_member' }
    if (-not $r.owned) { $r.warning='account_ownership_conflict'; throw 'ownership_conflict' }
    $r.verified=[bool]($r.exists -and $r.owned -and $r.enabled -and $r.member)
    return $user
}
try {
    $r.stage='cim'
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($system.Domain) { $r.domain = [string]$system.Domain }
    if ($system.DomainRole -notin @(4,5)) {
        $r.result='skipped'; $r.warning='target_must_be_domain_controller'; throw 'not_dc'
    }
    $r.stage='module'
    Import-Module ActiveDirectory -ErrorAction Stop
    $r.stage='domain'
    $d = Get-ADDomain -Server localhost
    $r.stage='controller'
    $controller = Get-ADDomainController -Identity $env:COMPUTERNAME -Server localhost
    if ($controller.IsReadOnly -ne $false -or $controller.Domain -ine $d.DNSRoot -or
        $system.Domain -ine $d.DNSRoot -or $controller.Name -ine $env:COMPUTERNAME) {
        $r.warning='dc_identity_mismatch_or_read_only'; throw 'dc_mismatch'
    }
    $r.domain=[string]$d.DNSRoot; $r.dc=[string]$controller.HostName; $r.domain_sid=[string]$d.DomainSID.Value
    $r.stage='group'
    $g = Get-ADGroup -Identity ($d.DomainSID.Value + '-512') -Server localhost
    if ($g.SID.Value -ne ($d.DomainSID.Value + '-512')) { throw 'wrong_group' }
    $r.group_sid=[string]$g.SID.Value
    $r.stage='account'
    $u = Read-P09Account
    # __MODE__ is a fixed internal literal, never operator-provided PowerShell.
    if ('__MODE__' -eq 'apply') {
        # Recheck identity and ownership immediately before any write. A change
        # between the independent precheck and apply must fail closed.
        if ($r.domain_sid -ne '__DOMAIN_SID__' -or $r.dc -ine '__DC__' -or
            $r.account_sid -ne '__ACCOUNT_SID__') {
            $r.warning='precheck_identity_changed'; throw 'identity_changed'
        }
        $r.stage='account_write'
        if ($null -eq $u -or -not $u.Enabled) {
            $password = ConvertTo-SecureString -AsPlainText -Force ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__ACCOUNT_PASSWORD__')))
            if ($null -eq $u) {
                $u = New-ADUser -Name 'mrnobody' -SamAccountName 'mrnobody' -AccountPassword $password -Enabled $true -Description 'MrNobody controlled lab account' -Server localhost -PassThru
                $r.account='created_enabled'
            } else {
                Set-ADAccountPassword -Identity $u.ObjectGUID -Reset -NewPassword $password -Server localhost
                Enable-ADAccount -Identity $u.ObjectGUID -Server localhost
                $r.account='enabled_existing'
            }
        }
        $accountAction=$r.account
        $writtenGuid=$u.ObjectGUID
        $writtenSid=[string]$u.SID.Value
        $u = Read-P09Account
        if ($null -eq $u -or $u.ObjectGUID -ne $writtenGuid -or $r.account_sid -ne $writtenSid -or
            -not $r.owned -or -not $r.enabled) { throw 'account_changed' }
        $r.stage='group_write'
        if (-not (@($u.MemberOf) -icontains $g.DistinguishedName)) {
            Add-ADGroupMember -Identity $g -Members $u -Server localhost
            $r.group='added'
        } else { $r.group='already_member' }
        $groupAction=$r.group
        $r.stage='postread'
        $u = Read-P09Account
        if ($null -eq $u -or $u.ObjectGUID -ne $writtenGuid -or $r.account_sid -ne $writtenSid -or
            -not $r.verified) { throw 'postconditions_missing' }
        $r.account=$accountAction; $r.group=$groupAction
    }
    $r.stage='complete'; $r.result='ready'
    if ($r.verified) { $r.result='success' }
} catch {
    if ($r.result -ne 'skipped') { $r.result='failed' }
    if ($r.warning -eq 'none') { $r.warning='ad_action_failed_check_rights_module_and_dc_logs' }
    # Only fixed category codes cross the boundary; never exception text/IDs.
    $category = [string]$_.CategoryInfo.Category
    $r.error_kind='other'
    if ($category -in @('PermissionDenied','ObjectNotFound','InvalidArgument',
        'InvalidOperation','ResourceUnavailable','NotSpecified')) { $r.error_kind=$category }
    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { $r.error_kind='command_not_found' }
}
$r | ConvertTo-Json -Compress
'''

STATES = {'created_enabled', 'enabled_existing', 'already_enabled'}
WARNINGS = {'none', 'target_must_be_domain_controller', 'dc_identity_mismatch_or_read_only',
            'account_ownership_conflict', 'precheck_identity_changed',
            'ad_action_failed_check_rights_module_and_dc_logs'}


def validate_password(password):
    if not isinstance(password, str) or not password or len(password) > 4096 or '\x00' in password:
        raise ValueError('P09 requires a valid runtime Windows password')
    return password


def script(mode='read', password='', before=None):
    if mode not in {'read', 'apply'}:
        raise ValueError('Invalid P09 mode')
    value = AD_ACTION.replace('__MODE__', mode)
    if mode == 'apply':
        validate_password(password)
        for key in ('domain_sid', 'account_sid', 'dc'):
            item = (before or {}).get(key, '')
            pattern = r'(?:S-1-[0-9-]+|none)' if key.endswith('sid') else r'[A-Za-z0-9_.-]{1,253}'
            if not isinstance(item, str) or not re.fullmatch(pattern, item):
                raise ValueError('Invalid P09 precheck identity')
            value = value.replace('__' + key.upper() + '__', item)
        value = value.replace('__ACCOUNT_PASSWORD__', base64.b64encode(password.encode('utf-16-le')).decode('ascii'))
    return value


MAX_SCRIPT_BYTES = 256 * 1024
INPUT_CHUNK_BYTES = 16 * 1024
# Includes executable, switches, separators and a conservative WinRS allowance.
# Stay below cmd.exe's 8191 as well as CreateProcess's 32767 UTF-16 units.
MAX_COMMAND_CHARS = 8000


def invocation():
    """Fixed, secret-free loader. Script data travels only over WinRS stdin.

    No AD code runs until bounded framing, EOF and SHA-256 have been checked.
    No remote file, environment variable or payload-bearing command line exists.
    """
    return r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$stage='payload_decode'
$inputReader=$null; $bytes=$null; $sha=$null
try {
    $inputReader=New-Object IO.StreamReader([Console]::OpenStandardInput(),[Text.Encoding]::ASCII)
    $header=New-Object char[] 73
    if ($inputReader.ReadBlock($header,0,73) -ne 73) { throw 'header' }
    $match=[regex]::Match((-join $header),'\A([0-9]{7}):([a-f0-9]{64})\n\z')
    if (-not $match.Success) { throw 'header' }
    $length=[int]$match.Groups[1].Value
    if ($length -lt 4 -or $length -gt 349528 -or $length % 4 -ne 0) { throw 'size' }
    $chars=New-Object char[] $length
    if ($inputReader.ReadBlock($chars,0,$length) -ne $length) { throw 'truncated' }
    if ($inputReader.Read() -ne -1) { throw 'trailing' }
    $bytes=[Convert]::FromBase64String((-join $chars))
    if ($bytes.Length -gt 262144) { throw 'size' }
    $sha=[Security.Cryptography.SHA256]::Create()
    $digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()
    if ($digest -cne $match.Groups[2].Value) { throw 'integrity' }
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $source=$utf8.GetString($bytes)
    $stage='payload_parse'
    $block=[ScriptBlock]::Create($source)
    $stage='payload_execute'
    & $block
    exit 0
} catch {
    @{protocol='p09_failure'; stage=$stage; result='failed'; warning='powershell_payload_failed'} | ConvertTo-Json -Compress
    exit 0
} finally {
    if ($inputReader) { $inputReader.Dispose() }
    if ($sha) { $sha.Dispose() }
    if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
    if ($chars) { [Array]::Clear($chars,0,$chars.Length) }
    $source=$null; $block=$null
}
'''


class PayloadError(ValueError):
    pass


def run_powershell(session, command):
    source = command.encode('utf-8')
    if not source or len(source) > MAX_SCRIPT_BYTES:
        raise PayloadError()
    payload = base64.b64encode(source)
    frame = f'{len(payload):07d}:{hashlib.sha256(source).hexdigest()}\n'.encode('ascii') + payload
    encoded = base64.b64encode(invocation().encode('utf-16-le')).decode('ascii')
    arguments = ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
    if 100 + len('powershell.exe ' + ' '.join(arguments)) > MAX_COMMAND_CHARS:
        raise PayloadError()
    protocol = session.protocol
    # Bound orphaned in-memory staging if the parent worker is killed before
    # finally can run. Active Send/Receive requests keep the shell in use.
    # pywinrm forwards IdleTimeOut verbatim as an XML duration, not milliseconds.
    shell = protocol.open_shell(noprofile=True, idle_timeout='PT60S')
    command_id = None
    try:
        command_id = protocol.run_command(shell, 'powershell.exe', arguments,
            console_mode_stdin=False, skip_cmd_shell=True)
        # No retries: a lost Send response is ambiguous. Close this process and
        # let perform() independently verify state; never replay an apply.
        for offset in range(0, len(frame), INPUT_CHUNK_BYTES):
            chunk = frame[offset:offset + INPUT_CHUNK_BYTES]
            protocol.send_command_input(shell, command_id, chunk,
                end=offset + len(chunk) == len(frame))
        stdout, stderr, code = protocol.get_command_output(shell, command_id)
        return SimpleNamespace(status_code=code, std_out=stdout, std_err=stderr)
    finally:
        # Cleanup cannot turn an uncertain write into a replay or hide its result.
        try:
            if command_id is not None:
                protocol.cleanup_command(shell, command_id)
        except Exception:
            pass
        try:
            protocol.close_shell(shell)
        except Exception:
            pass


class RemoteProcessError(RuntimeError):
    """A genuine remote nonzero exit, never a JSON schema error."""
    def __init__(self, response):
        super().__init__('P09 remote process failed')
        self.diagnostic = dict(exit_code=response.status_code, remote_stage='process',
            stdout_bytes=len(response.std_out) if isinstance(response.std_out, bytes) else 0,
            stderr_bytes=len(response.std_err) if isinstance(response.std_err, bytes) else 0)


class SchemaError(ValueError):
    """Fixed field/reason/type codes only: never retain remote values or text."""
    def __init__(self, field, reason, value=None):
        super().__init__('Invalid P09 response')
        kind = {str: 'string', bool: 'boolean', int: 'integer', float: 'number',
                dict: 'object', list: 'array', type(None): 'null'}.get(type(value), 'other')
        self.diagnostic = dict(schema_field=field, schema_reason=reason, schema_type=kind)


def parse(response):
    if type(response.status_code) is not int:
        raise SchemaError('status_code', 'invalid_status_type', response.status_code)
    if response.status_code != 0:
        raise RemoteProcessError(response)
    if not isinstance(response.std_out, bytes) or len(response.std_out) > 8192:
        raise SchemaError('stdout', 'invalid_type_or_size')
    if not isinstance(response.std_err, bytes):
        raise SchemaError('stderr', 'invalid_type')
    try:
        data = json.loads(response.std_out.decode('utf-8-sig'))
    except (ValueError, UnicodeError):
        raise SchemaError('json', 'invalid_json') from None
    if not isinstance(data, dict):
        raise SchemaError('json', 'expected_object', data)
    if data.get('protocol') == 'p09_failure':
        if (set(data) != {'protocol', 'stage', 'result', 'warning'} or
                data.get('stage') not in {'payload_decode', 'payload_parse', 'payload_execute'} or
                data.get('result') != 'failed' or data.get('warning') != 'powershell_payload_failed'):
            raise SchemaError('protocol', 'invalid_failure_envelope')
        return dict(result='failed', warning='powershell_payload_failed',
                    stage=data['stage'], verified=False, exit_code=0)
    safe = {}
    for key in ('exists', 'enabled', 'member', 'owned', 'verified'):
        if type(data.get(key)) is not bool:
            raise SchemaError(key, 'expected_boolean', data.get(key))
        safe[key] = data[key]
    for key in ('domain', 'dc', 'domain_sid', 'account_sid', 'group_sid'):
        val = data.get(key)
        pattern = (r'S-1-5-21-\d+-\d+-\d+' if key == 'domain_sid' else
                   r'S-1-5-21-\d+-\d+-\d+-\d+' if key.endswith('_sid') else
                   r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}')
        sentinel = val in ('unknown', 'none') if isinstance(val, str) else False
        if not isinstance(val, str) or not (sentinel or re.fullmatch(pattern, val)):
            raise SchemaError(key, 'invalid_identity', val)
        safe[key] = val
    for key, allowed in {
        'result': {'ready', 'success', 'failed', 'skipped'}, 'warning': WARNINGS,
        'stage': {'dc', 'cim', 'module', 'domain', 'controller', 'group', 'account', 'account_write', 'group_write', 'postread', 'complete'},
        'account': STATES | {'missing', 'existing_disabled', 'not_attempted'},
        'group': {'added', 'already_member', 'missing', 'not_attempted'},
    }.items():
        if not isinstance(data.get(key), str) or data[key] not in allowed:
            raise SchemaError(key, 'invalid_enum', data.get(key))
        safe[key] = data[key]
    if 'error_kind' in data:
        if not isinstance(data['error_kind'], str) or data['error_kind'] not in {'other', 'PermissionDenied', 'ObjectNotFound', 'InvalidArgument',
                'InvalidOperation', 'ResourceUnavailable', 'NotSpecified', 'command_not_found'}:
            raise SchemaError('error_kind', 'invalid_enum')
        safe['error_kind'] = data['error_kind']
    safe.update(exit_code=0, stdout_bytes=len(response.std_out), stderr_bytes=len(response.std_err))
    if safe['result'] == 'skipped' and not (
            safe['warning'] == 'target_must_be_domain_controller'
            and safe['account'] == safe['group'] == 'not_attempted'
            and safe['dc'] == 'unknown'):
        raise SchemaError('result', 'inconsistent_prerequisite')
    if safe['result'] in {'ready', 'success'}:
        if not dc_valid(safe):
            raise SchemaError('domain_sid', 'inconsistent_dc_identity')
        if safe['exists'] != (safe['account_sid'] != 'none') or (
                not safe['exists'] and any(safe[k] for k in ('owned', 'enabled', 'member'))):
            raise SchemaError('exists', 'inconsistent_account_state')
        if safe['verified'] != all(safe[k] for k in ('exists', 'owned', 'enabled', 'member')):
            raise SchemaError('verified', 'inconsistent_postconditions')
        if safe['result'] == 'success' and not confirmed(safe):
            raise SchemaError('result', 'unconfirmed_success')
        if safe['result'] == 'ready' and safe['verified']:
            raise SchemaError('result', 'inconsistent_ready')
    return safe


def dc_valid(data):
    sid = data.get('domain_sid', '')
    return (data.get('stage') == 'complete' and data.get('warning') == 'none'
            and re.fullmatch(r'S-1-5-21-\d+-\d+-\d+', sid) is not None
            and data.get('group_sid') == sid + '-512'
            and (data.get('account_sid') == 'none' or
                 re.fullmatch(re.escape(sid) + r'-\d+', data.get('account_sid', '')) is not None)
            and all(data.get(k) not in {'', 'unknown', 'none', None} for k in ('domain', 'dc')))


def confirmed(data):
    sid = data.get('domain_sid', '')
    return (data.get('result') == 'success' and dc_valid(data) and data.get('warning') == 'none'
            and type(data.get('exit_code')) is int and data['exit_code'] == 0
            and data.get('account') in STATES and data.get('group') in {'added', 'already_member'}
            and all(data.get(k) is True for k in ('exists', 'enabled', 'owned', 'member', 'verified'))
            and re.fullmatch(r'S-1-5-21-\d+-\d+-\d+', sid) is not None
            and data.get('group_sid') == sid + '-512'
            and re.fullmatch(re.escape(sid) + r'-\d+', data.get('account_sid', '')) is not None
            and all(data.get(k) not in {'', 'unknown', None} for k in ('domain', 'dc')))


def perform(target, env, session_factory, limit, verify_only=False):
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_RDP_PASSWORD')
    if not password:
        return dict(result='failed', warning='missing_runtime_windows_credentials')
    scheme = 'https' if target['protocol'] == 'winrm-https' else 'http'

    def execute(command):
        # Every read, write and postcheck uses an independent authenticated session.
        session = session_factory(f"{scheme}://{target['target']}:{target['port']}/wsman",
            auth=(target['username'], password), transport='ntlm', message_encryption='always', server_cert_validation='ignore',
            operation_timeout_sec=min(limit, 60), read_timeout_sec=limit + 10)
        return parse(run_powershell(session, command))

    before = None
    action = None
    attempted = False
    diagnostic = 'none'
    schema_diagnostic = {}
    try:
        before = execute(script())
        if before['result'] not in {'ready', 'success'}:
            return before
        if not dc_valid(before):
            raise SchemaError('domain_sid', 'inconsistent_dc_identity')
        if not verify_only and not confirmed(before):
            attempted = True
            action = execute(script('apply', password, before))
    except Exception as error:
        # Never serialize exception text: transport errors can contain secrets.
        diagnostic = ('remote_powershell_nonzero_exit' if isinstance(error, RemoteProcessError) else
                      'powershell_payload_too_large' if isinstance(error, PayloadError) else
                      'invalid_ad_response' if isinstance(error, (ValueError, UnicodeError, TypeError)) else
                      'transport_error_details_omitted')
        if isinstance(error, (SchemaError, RemoteProcessError)):
            schema_diagnostic = error.diagnostic
        if before is None:
            return dict(result='failed', warning=diagnostic, stage='precheck', verified=False, **schema_diagnostic)
    try:
        after = execute(script())
    except Exception as error:
        return dict(result='partial' if attempted or verify_only else 'failed',
                    warning='postcheck_unavailable_state_unknown', stage='postcheck', verified=False,
                    **(error.diagnostic if isinstance(error, (SchemaError, RemoteProcessError)) else schema_diagnostic))
    same = (before is not None and all(before[k] == after.get(k) for k in ('domain_sid', 'group_sid', 'dc'))
            and (before['account_sid'] == 'none' or before['account_sid'] == after.get('account_sid')))
    after['transport_diagnostic'] = diagnostic
    # Keep a failed write's process status separate from the independent read.
    after.update({('remote_' + key if key in {'exit_code', 'stdout_bytes', 'stderr_bytes'} else key): value
                  for key, value in schema_diagnostic.items()})
    if action:
        after.update(action_account=action.get('account', 'not_attempted'), action_group=action.get('group', 'not_attempted'),
                     action_stage=action['stage'], action_warning=action['warning'])
        if 'error_kind' in action:
            after['action_error_kind'] = action['error_kind']
    if after['result'] not in {'ready', 'success'}:
        # Preserve the independently observed failing PowerShell/AD stage.
        after.update(result='partial' if attempted or verify_only else 'failed',
                     verified=False, verification='independent_read_only')
        return after
    if confirmed(after) and same:
        after.update(result='success', verified=True, verification='independent_read_only',
                     recovery='state_verified_after_uncertain_action' if diagnostic != 'none' or verify_only else 'none')
        if action and action['result'] == 'success':
            after.update(account=action['account'], group=action['group'])
        else:
            after.update(account='already_enabled', group='already_member')
        return after
    uncertain = verify_only or diagnostic != 'none' or attempted and (not same or action is None or action['result'] == 'success')
    after.update(result='partial' if uncertain or after.get('exists') and after.get('owned') else 'failed',
                 verified=False, warning='postconditions_not_confirmed' if same else 'postcheck_identity_changed',
                 verification='independent_read_only')
    return after
