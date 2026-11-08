"""Offline P09 regressions. PowerShell AD cmdlets are local in-memory doubles.

Never contacts Windows/AD, creates real accounts, or starts campaign payloads.
"""
import base64
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from p09_fixtures import p09_factory
from unittest.mock import Mock, patch

from pypdf import PdfReader

sys.path.insert(0, str(Path(__file__).parent))
import ad_prerequisite as prerequisite
from ad_prerequisite import DC, WORKGROUP, TRANSPORT
import windows_actions as actions
from reports import build_report
from report_exports import export_html, export_pdf
from execution import record, snapshot, phase_environment


class EnabledResults(prerequisite.Prerequisite):
    def test_transport_fallback_and_stderr_complete(self):
        for results in ([TRANSPORT, dict(DC, stderr_bytes=2248)],
                        [DC, TRANSPORT], [WORKGROUP, TRANSPORT, DC]):
            with self.subTest(results=results):
                code, log = self.run_candidates(results)
                self.assertEqual(code, 0)
                self.assertIn('PHASE_COMPLETE phase=09', log)
                self.assertNotIn('PHASE_FAILED', log)

    def test_ad_failures_and_internal_errors_override_other_results(self):
        for error in (dict(DC, result='failed', group='not_attempted'),
                      dict(DC, result='failed', account='not_attempted'),
                      dict(TRANSPORT, warning='worker_execution_failed'),
                      dict(TRANSPORT, warning='invalid_or_missing_runtime_configuration')):
            for results in ([error], [DC, error], [error, DC]):
                with self.subTest(results=results):
                    self.assertEqual(self.run_candidates(results)[0], 1)
        with patch.object(actions, 'targets', side_effect=RuntimeError('PRIVATE_INTERNAL_ERROR')):
            self.assertEqual(actions.run('09', self.env), 1)
        self.assertNotIn('PRIVATE_INTERNAL_ERROR', (self.base / 'logs/incident-ground-truth.log').read_text())

    def test_verified_final_state_required_for_success(self):
        for change in ({'account': 'created_disabled'}, {'account': 'unknown'},
                       {'group': 'not_attempted'}, {'exit_code': 1}, {'exit_code': False},
                       {'domain': 'unknown'}, {'dc': 'unknown'}, {'warning': 'unknown'}):
            with self.subTest(change=change):
                self.assertEqual(self.run_candidates([dict(DC, **change)])[0], 1)

    def test_worker_validates_states_and_ignores_stderr(self):
        factory = p09_factory()
        for account in actions.AD_ENABLED_STATES:
            for group in ('added', 'already_member'):
                data = dict(DC, account=account, group=group, password='PRIVATE_OUTPUT')
                factory.return_value.run_ps.return_value = Mock(status_code=0,
                    std_out=json.dumps(data).encode(), std_err=b'#< CLIXML PRIVATE_STDERR')
                result = actions.perform('09', actions.targets(self.env)[0], self.env, factory)
                self.assertEqual((result['result'], result['account'], result['group']), ('success', 'already_enabled', 'already_member'))
                self.assertGreater(result['stderr_bytes'], 0)
                self.assertNotIn('PRIVATE_', json.dumps(result))
                self.assertNotIn('DO_NOT_PERSIST', json.dumps(result))
                self.assertEqual(self.run_candidates([result])[0], 0)
        for change in ({'account': 'created_disabled'}, {'group': 'not_attempted'}, {'domain': None}):
            factory.return_value.run_ps.return_value.std_out = json.dumps(dict(DC, **change)).encode()
            self.assertIn(actions.perform('09', actions.targets(self.env)[0], self.env, factory)['result'], {'failed', 'partial'})

    def test_reports_exports_and_live_timeline_after_fallback(self):
        self.assertEqual(self.run_candidates([TRANSPORT, dict(DC, account='created_enabled', group='added', stderr_bytes=2248)])[0], 0)
        (self.base / 'scripts').mkdir()
        shutil.copy(Path(actions.__file__).parents[1] / 'scripts/09-ad-privilege.sh', self.base / 'scripts')
        state = dict(incident_id=self.env['NORDIC_INCIDENT_ID'], phase_id='09', status='complete', phases={'09': 'complete'})
        report = build_report(self.base, state['incident_id'], 0, self.env, standalone=state)
        phase = report['phases'][0]
        self.assertEqual((report['incident']['status'], phase['status'], phase['action_result']), ('complete', 'success', 'success'))
        self.assertTrue(phase['started'] and phase['ended'])
        self.assertEqual([t['id'] for t in phase['mitre']['techniques']], ['T1136.002', 'T1098.007', 'T1078.002'])
        for view in ('investigation', 'ground-truth'):
            html = export_html(report, view)
            pdf = export_pdf(report, view)
            pdf_text = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
            for evidence in ('Active Directory account and Domain Admins action completed',
                             'account=created_enabled', 'group=added', 'domain=lab.example',
                             'dc=dc.lab.example', 'exit_code=0', 'stderr_bytes=2248',
                             'protocol=winrm-http', 'method=winrm_ntlm', '192.168.2.201'):
                self.assertIn(evidence, html)
                self.assertIn(evidence, pdf_text)
        overview = json.dumps(dict(type='campaign', id='full-incident', phases=[{'id': '09'}, {'id': '04'}]))
        record(self.base, dict(self.env, MRN_OVERVIEW=overview), 123)
        (self.base / 'state').mkdir()
        (self.base / 'state/campaign.json').write_text(json.dumps(dict(state,
            status='running', phases={'09': 'complete', '04': 'running'})))
        live = snapshot(self.base, {}, Mock(poll=Mock(return_value=None)))
        self.assertEqual((live['timeline'][0]['status'], live['current_phase']['id']), ('complete', '04'))
        self.assertTrue(any('Phase Complete' in line for line in live['logs']))
        # Seed the final-report fixture; publication atomicity has separate tests.
        (self.base / 'reports').mkdir()
        (self.base / 'reports' / (state['incident_id'] + '.json')).write_text(json.dumps(report))
        live = snapshot(self.base, {})
        self.assertEqual((live['status'], live['timeline'][0]['status']), ('complete', 'complete'))
        secret = self.env['MRNOBODY_PASSWORD'].encode()
        encoded = base64.b64encode(secret.decode().encode('utf-16-le'))
        for file in self.base.rglob('*'):
            if file.is_file():
                self.assertNotIn(secret, file.read_bytes())
                self.assertNotIn(encoded, file.read_bytes())

    def test_profiles_keep_credentials_runtime_only(self):
        for mode in ('normal', 'slow', 'custom'):
            spec = dict(target_mode='fixed', profile={'mode': mode}, phases=[dict(id='09', parameters={})])
            env = phase_environment('09', dict(MRN_EXECUTION=json.dumps(spec), MRN_STARTED='0',
                NORDIC_RDP_PASSWORD='RUNTIME_ONLY'), sleep=lambda _: None, clock=lambda: 0)
            self.assertEqual(env['MRNOBODY_PASSWORD'], 'RUNTIME_ONLY')
            self.assertNotIn('RUNTIME_ONLY', env['MRN_EXECUTION'])


# Actual P09 PowerShell runs against these doubles, including post-action reads.
AD_DOUBLES = r'''
function Get-CimInstance { [pscustomobject]@{ Domain='lab.example'; DomainRole=$script:role } }
function Import-Module { param($Name, $ErrorAction) }
function Get-ADDomain { [pscustomobject]@{ DNSRoot='lab.example'; DomainSID=[pscustomobject]@{Value='S-1-5-21-123-456-789'} } }
$env:COMPUTERNAME='dc'
function Get-ADDomainController { [pscustomobject]@{Name='dc'; HostName='dc.lab.example'; Domain=$(if ($script:failure -eq 'domain_mismatch') {'other.example'} else {'lab.example'}); IsReadOnly=($script:failure -eq 'read_only')} }
function Get-ADGroup { [pscustomobject]@{SID=[pscustomobject]@{Value='S-1-5-21-123-456-789-512'}; DistinguishedName='CN=Domain Admins,DC=lab,DC=example'} }
function Get-ADUser {
    if ($script:exists) { [pscustomobject]@{ SID=[pscustomobject]@{Value='S-1-5-21-123-456-789-1001'}; ObjectGUID='fixture-guid'; SamAccountName='mrnobody'; Name='mrnobody'; Description=$script:description; Enabled=$script:enabled; MemberOf=@(if ($script:member) {'CN=Domain Admins,DC=lab,DC=example'}) } }
}
function Assert-Password($Secure) {
    $actual = [System.Net.NetworkCredential]::new('', $Secure).Password
    if ($actual -cne $script:expected) { throw 'wrong_password' }
}
function New-ADUser {
    param($Name, $SamAccountName, $AccountPassword, $Enabled, $Description, $Server, [switch]$PassThru)
    $script:created++
    if ($script:failure -eq 'create') { throw 'PRIVATE_CREATE_FAILURE' }
    Assert-Password $AccountPassword
    $script:exists = $true
    $script:description = $Description
    $script:enabled = $Enabled
    Get-ADUser
}
function Set-ADAccountPassword {
    param($Identity, [switch]$Reset, $NewPassword, $Server)
    $script:reset++
    if ($script:failure -eq 'password') { throw 'PRIVATE_PASSWORD_FAILURE' }
    Assert-Password $NewPassword
}
function Enable-ADAccount {
    $script:enableCalls++
    if ($script:failure -eq 'enable') { throw 'PRIVATE_ENABLE_FAILURE' }
    if ($script:failure -ne 'verify_account') { $script:enabled = $true }
}
function Get-ADGroupMember {
    if ($script:member) { [pscustomobject]@{SID='S-1-5-21-123-1001'} }
}
function Add-ADGroupMember {
    $script:added++
    if ($script:failure -eq 'group') { throw 'PRIVATE_GROUP_FAILURE' }
    if ($script:failure -ne 'verify_group') { $script:member = $true }
}
'''


@unittest.skipUnless(shutil.which('pwsh') or shutil.which('powershell'), 'PowerShell unavailable')
class AccountAction(unittest.TestCase):
    def invoke(self, exists=False, enabled=False, member=False, failure='', twice=False, description='MrNobody controlled lab account', role=5, mode='apply'):
        # Non-secret fixture includes quotes, unicode and PowerShell metacharacters.
        password = "Lab'\";$(throw 'injected')&æ_TEST_ONLY"
        setup = "$script:exists=$%s; $script:enabled=$%s; $script:member=$%s; $script:failure='%s'; $script:created=0; $script:reset=0; $script:enableCalls=0; $script:added=0; $script:expected=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('%s'))\n" % (
            str(exists).lower(), str(enabled).lower(), str(member).lower(), failure,
            base64.b64encode(password.encode('utf-16-le')).decode())
        from p09_actions import script as ad_script
        before = dict(domain_sid='S-1-5-21-123-456-789', dc='dc.lab.example', account_sid='S-1-5-21-123-456-789-1001' if exists else 'none')
        def cycle(identity):
            # Parse the actual generated protocol without repairing/masking it.
            return '\n& {\n' + ad_script(mode, password, identity) + '\n}\n'
        script = setup + "$script:role=%d; $script:description='%s'\n" % (role, description) + AD_DOUBLES + cycle(before)
        if twice:
            script += cycle(dict(before, account_sid='S-1-5-21-123-456-789-1001'))
        script += "\n@{created=$script:created; reset=$script:reset; enabled=$script:enabled; enableCalls=$script:enableCalls; added=$script:added; member=$script:member} | ConvertTo-Json -Compress"
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as tmp:
            fixture = Path(tmp) / 'fixture.ps1'
            fixture.write_text(script, encoding='utf-8-sig')
            child = subprocess.run([shutil.which('pwsh') or shutil.which('powershell'),
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(fixture)], capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        rows = [json.loads(line) for line in child.stdout.decode('utf-8-sig').splitlines() if line.startswith('{')]
        self.assertEqual(len(rows), 3 if twice else 2, child.stdout)
        from p09_actions import parse
        for row in rows[:-1]:
            parse(Mock(status_code=0, std_out=json.dumps(row).encode(), std_err=b''))
        return rows

    def test_read_precheck_is_accurate_and_never_writes(self):
        for exists, enabled, member in ((False, False, False), (True, True, False),
                                         (True, False, True), (True, True, True)):
            result, state = self.invoke(exists=exists, enabled=enabled, member=member, mode='read')
            self.assertEqual((result['exists'], result['enabled'], result['member']), (exists, enabled, member))
            self.assertEqual(result['verified'], exists and enabled and member)
            self.assertEqual(result['result'], 'success' if result['verified'] else 'ready')
            self.assertEqual((state['created'], state['added'], state['reset'], state['enableCalls']), (0, 0, 0, 0))

    def test_new_account_enabled_and_added(self):
        result, state = self.invoke()
        self.assertTrue(all(result[k] is True for k in ('exists', 'owned', 'enabled', 'member', 'verified')))
        self.assertEqual((result['result'], result['account'], result['group']), ('success', 'created_enabled', 'added'))
        self.assertEqual(state, dict(created=1, reset=0, enabled=True, enableCalls=0, added=1, member=True))

    def test_existing_disabled_enabled_with_runtime_password(self):
        result, state = self.invoke(exists=True)
        self.assertEqual((result['result'], result['account']), ('success', 'enabled_existing'))
        self.assertEqual((state['created'], state['reset'], state['enableCalls'], state['enabled']), (0, 1, 1, True))

    def test_existing_enabled_preserves_password_and_adds_membership(self):
        result, state = self.invoke(exists=True, enabled=True)
        self.assertEqual((result['account'], result['group']), ('already_enabled', 'added'))
        self.assertEqual((state['created'], state['reset'], state['enableCalls']), (0, 0, 0))

    def test_already_member_and_repeat_are_idempotent(self):
        first, second, state = self.invoke(twice=True)
        self.assertEqual(first['account'], 'created_enabled')
        self.assertEqual((second['result'], second['account'], second['group']), ('success', 'already_enabled', 'already_member'))
        self.assertEqual((state['created'], state['added'], state['reset']), (1, 1, 0))
        result, state = self.invoke(exists=True, enabled=True, member=True)
        self.assertEqual((result['group'], state['added']), ('already_member', 0))

    def test_unrelated_account_and_non_dc_make_no_changes(self):
        for options, warning in ((dict(exists=True, description='Unrelated account'), 'account_ownership_conflict'),
                                 (dict(role=3), 'target_must_be_domain_controller')):
            result, state = self.invoke(**options)
            self.assertEqual(result['warning'], warning)
            self.assertEqual((state['created'], state['reset'], state['enableCalls'], state['added']), (0, 0, 0, 0))

    def test_authenticated_read_only_or_mismatched_dc_never_writes(self):
        for failure in ('read_only', 'domain_mismatch'):
            result, state = self.invoke(failure=failure)
            self.assertEqual(result['result'], 'failed')
            self.assertEqual(result['warning'], 'dc_identity_mismatch_or_read_only')
            self.assertEqual((state['created'], state['reset'], state['enableCalls'], state['added']), (0, 0, 0, 0))

    def test_account_group_and_verification_failures(self):
        for failure in ('create', 'password', 'enable', 'group', 'verify_account', 'verify_group'):
            with self.subTest(failure=failure):
                result, _ = self.invoke(exists=failure in {'password', 'enable', 'verify_account'}, failure=failure)
                self.assertEqual(result['result'], 'failed')
                self.assertEqual(result['warning'], 'ad_action_failed_check_rights_module_and_dc_logs')
                self.assertNotIn('PRIVATE_', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
