"""P09 only: bounded, independently verified lab AD account reconciliation.

All remote output is an allowlisted protocol. Never log scripts or exceptions.
"""
import base64
import json
import re


# The legacy description is deliberately accepted for accounts created by older
# P09 releases. An equal name or existing privileged membership is NOT ownership.
AD_ACTION = r'''
$ErrorActionPreference = 'Stop'
$r = @{domain='unknown'; dc='unknown'; domain_sid='unknown'; account_sid='none'; group_sid='unknown';
    account='not_attempted'; group='not_attempted'; exists=$false; enabled=$false; member=$false;
    owned=$false; verified=$false; result='failed'; warning='none'; stage='dc'}
try {
    $system = Get-CimInstance Win32_ComputerSystem
    $r.domain = $system.Domain
    if ($system.DomainRole -notin @(4,5)) {
        $r.result='skipped'; $r.warning='target_must_be_domain_controller'; throw 'not_dc'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $d = Get-ADDomain -Server localhost
    $controller = Get-ADDomainController -Identity $env:COMPUTERNAME -Server localhost
    if ($controller.IsReadOnly -or $controller.Domain -ine $d.DNSRoot -or
        $system.Domain -ine $d.DNSRoot -or $controller.Name -ine $env:COMPUTERNAME) {
        $r.warning='dc_identity_mismatch_or_read_only'; throw 'dc_mismatch'
    }
    $r.domain=$d.DNSRoot; $r.dc=$controller.HostName; $r.domain_sid=$d.DomainSID.Value
    $r.stage='group'
    $g = Get-ADGroup -Identity ($d.DomainSID.Value + '-512') -Server localhost
    if ($g.SID.Value -ne ($d.DomainSID.Value + '-512')) { throw 'wrong_group' }
    $r.group_sid=$g.SID.Value
    $r.stage='account'
    $u = Get-ADUser -Filter "SamAccountName -eq 'mrnobody'" -Properties Enabled,Description,MemberOf -Server localhost
    if ($null -ne $u) {
        $r.exists=$true; $r.enabled=[bool]$u.Enabled; $r.account_sid=$u.SID.Value
        $r.owned=($u.SamAccountName -ceq 'mrnobody' -and $u.Name -ceq 'mrnobody' -and
            $u.Description -ceq 'MrNobody controlled lab account' -and
            $u.SID.Value.StartsWith($d.DomainSID.Value + '-'))
        $r.member=(@($u.MemberOf) -icontains $g.DistinguishedName)
        $r.account='already_enabled'; if (-not $u.Enabled) { $r.account='existing_disabled' }
        $r.group='missing'; if ($r.member) { $r.group='already_member' }
        if (-not $r.owned) { $r.warning='account_ownership_conflict'; throw 'ownership_conflict' }
    } else { $r.account='missing'; $r.group='missing' }
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
        $u = Get-ADUser -Identity $u.ObjectGUID -Properties Enabled,Description,MemberOf -Server localhost
        if ($u.Description -cne 'MrNobody controlled lab account' -or -not $u.Enabled) { throw 'account_changed' }
        $r.stage='group_write'
        if (-not (@($u.MemberOf) -icontains $g.DistinguishedName)) {
            Add-ADGroupMember -Identity $g -Members $u -Server localhost
            $r.group='added'
        } else { $r.group='already_member' }
    }
    $r.verified=($r.owned -and $r.enabled -and $r.member)
    $r.stage='complete'; $r.result='success'
} catch {
    if ($r.warning -eq 'none') { $r.warning='ad_action_failed_check_rights_module_and_dc_logs' }
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


def parse(response):
    if response.status_code != 0 or len(response.std_out) > 8192:
        raise ValueError('Invalid P09 response')
    data = json.loads(response.std_out.decode('utf-8-sig'))
    safe = {}
    for key in ('exists', 'enabled', 'member', 'owned', 'verified'):
        if type(data.get(key)) is not bool:
            raise ValueError('Invalid P09 boolean')
        safe[key] = data[key]
    for key in ('domain', 'dc', 'domain_sid', 'account_sid', 'group_sid'):
        val = data.get(key)
        if not isinstance(val, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', val):
            raise ValueError('Invalid P09 identity')
        safe[key] = val
    for key, allowed in {
        'result': {'success', 'failed', 'skipped'}, 'warning': WARNINGS,
        'stage': {'dc', 'group', 'account', 'account_write', 'group_write', 'complete'},
        'account': STATES | {'missing', 'existing_disabled', 'not_attempted'},
        'group': {'added', 'already_member', 'missing', 'not_attempted'},
    }.items():
        if data.get(key) not in allowed:
            raise ValueError('Invalid P09 evidence')
        safe[key] = data[key]
    safe.update(exit_code=0, stdout_bytes=len(response.std_out), stderr_bytes=len(response.std_err))
    if safe['result'] == 'skipped' and not (
            safe['warning'] == 'target_must_be_domain_controller'
            and safe['account'] == safe['group'] == 'not_attempted'
            and safe['dc'] == 'unknown'):
        raise ValueError('Invalid P09 prerequisite evidence')
    return safe


def confirmed(data):
    sid = data.get('domain_sid', '')
    return (data.get('result') == 'success' and data.get('warning') == 'none'
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
            auth=(target['username'], password), transport='ntlm', server_cert_validation='ignore',
            operation_timeout_sec=min(limit, 60), read_timeout_sec=limit + 10)
        return parse(session.run_ps(command))

    before = None
    action = None
    attempted = False
    diagnostic = 'none'
    try:
        before = execute(script())
        if before['result'] != 'success':
            return before
        if not verify_only and not confirmed(before):
            attempted = True
            action = execute(script('apply', password, before))
    except Exception as error:
        # Never serialize exception text: transport errors can contain secrets.
        diagnostic = 'invalid_ad_response' if isinstance(error, (ValueError, UnicodeError, TypeError)) else 'transport_error_details_omitted'
        if before is None:
            return dict(result='failed', warning=diagnostic, stage='precheck', verified=False)
    try:
        after = execute(script())
    except Exception:
        return dict(result='partial' if attempted or verify_only else 'failed',
                    warning='postcheck_unavailable_state_unknown', stage='postcheck', verified=False)
    same = (before is not None and all(before[k] == after[k] for k in ('domain_sid', 'group_sid', 'dc'))
            and (before['account_sid'] == 'none' or before['account_sid'] == after['account_sid']))
    after['transport_diagnostic'] = diagnostic
    if action:
        after.update(action_account=action['account'], action_group=action['group'],
                     action_stage=action['stage'], action_warning=action['warning'])
    if confirmed(after) and same:
        after.update(result='success', verified=True, verification='independent_read_only',
                     recovery='state_verified_after_uncertain_action' if diagnostic != 'none' or verify_only else 'none')
        if action and action['result'] == 'success':
            after.update(account=action['account'], group=action['group'])
        else:
            after.update(account='already_enabled', group='already_member')
        return after
    after.update(result='partial' if attempted or verify_only or after.get('exists') and after.get('owned') else 'failed',
                 verified=False, warning='postconditions_not_confirmed' if same else 'postcheck_identity_changed',
                 verification='independent_read_only')
    return after
