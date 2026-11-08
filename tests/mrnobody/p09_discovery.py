"""P09 is a P03 consumer: negative evidence, role checks and final reporting."""
import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch
from pipeline_fixtures import *
from ad_prerequisite import DC
from reports import build_report
from report_exports import export_html


class Consumer(Fixture):
    def test_reads_only_p03_not_p01_and_ignores_rdp_windows_dc_hints(self):
        self.p03([dict(ip='192.168.1.120',platform='windows',domain_controller=True,access='rdp',
                       access_methods={'rdp':{'authenticated':True}}),
                  dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        (self.base/'state/discovered-hosts.json').unlink()
        (self.base/'state/networks.json').unlink()
        self.assertEqual([t['target'] for t in actions.targets(self.env,'09')],['192.168.2.200'])
        code,log,invoke=self.campaign([ELIGIBLE,DC])
        self.assertEqual(code,0); self.assertEqual(invoke.call_count,2)
        self.assertIn('source=p03_authenticated_winrm',log)
        self.assertNotIn('P09_CANDIDATE target=192.168.1.120',log)

    def test_no_successful_winrm_skips_with_p03_timeout_visible(self):
        self.p03(results=[dict(target='192.168.2.200',access='winrm',authenticated=False,warning='candidate_probe_timeout')])
        code,log,invoke=self.campaign([])
        self.assertEqual(code,78); invoke.assert_not_called()
        self.assertIn('no_authenticated_winrm_targets',log)
        self.assertIn('P03_WINRM_EVIDENCE target=192.168.2.200 authenticated=False warning=candidate_probe_timeout',log)
        self.assertNotIn('WINDOWS_ACTION_SUCCESS',log)

    def test_stale_missing_incomplete_legacy_and_standalone_p03_fail_closed(self):
        for change in ({'complete':False},{'producer':'P01'},{'schema_version':1},{'run_mode':'standalone'},
                       {'source_inventory_id':''}):
            self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})],**change)
            code,_,invoke=self.campaign([])
            self.assertEqual(code,78); invoke.assert_not_called()
        state=self.read('compromised-hosts.json'); state['incident_id']='MRN-old'
        pipeline.write(self.base/'state/compromised-hosts.json',state)
        self.assertEqual(self.campaign([])[0],78)
        (self.base/'state/compromised-hosts.json').unlink()
        self.assertEqual(self.campaign([])[0],78)

    def test_non_dc_continues_then_actual_writable_dc_runs_once(self):
        self.p03([dict(ip=ip,access_methods={'winrm':method()}) for ip in ('192.168.2.200','192.168.1.120')])
        code,log,invoke=self.campaign([NON_DC,ELIGIBLE,DC])
        self.assertEqual(code,0)
        self.assertEqual([json.loads(c.kwargs['env']['MRN_WINDOWS_TARGET'])['target'] for c in invoke.call_args_list],
                         ['192.168.1.120','192.168.2.200','192.168.2.200'])
        self.assertTrue(all(c.kwargs['env'].get('MRN_P09_DISCOVERY_ONLY')=='1' for c in invoke.call_args_list[:2]))
        self.assertNotIn('MRN_P09_DISCOVERY_ONLY',invoke.call_args_list[-1].kwargs['env'])
        self.assertIn('target_must_be_domain_controller',log)

    def test_no_writable_dc_has_stable_reason_and_per_host_rejections(self):
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        for response in (NON_DC,dict(NON_DC,warning='dc_identity_mismatch_or_read_only'),
                         dict(NON_DC,warning='credentials_denied',auth='denied'),
                         subprocess.TimeoutExpired('worker',90)):
            code,log,invoke=self.campaign([response])
            self.assertEqual(code,78); self.assertEqual(invoke.call_count,1)
            self.assertIn('no_writable_dc_verified',log)
            self.assertNotIn('WINDOWS_ACTION_START',log)

    def test_false_worker_eligibility_and_unverified_final_success_fail(self):
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        code,log,_=self.campaign([dict(ELIGIBLE,auth='unconfirmed')])
        self.assertEqual(code,78)
        code,log,_=self.campaign([ELIGIBLE,dict(DC,verified=False)])
        self.assertEqual(code,1)
        self.assertNotIn('WINDOWS_ACTION_SUCCESS',log)

    def test_probe_is_read_only_and_does_not_scan_tcp(self):
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        target=actions.targets(self.env,'09')[0]
        factory,connect=Mock(),Mock()
        factory.return_value.run_ps.return_value=Mock(status_code=0,std_out=json.dumps(ELIGIBLE).encode())
        result=actions.probe_dc(target,self.env,factory,connect)
        self.assertEqual(result,ELIGIBLE); connect.assert_not_called()
        script=factory.return_value.run_ps.call_args.args[0]
        for token in ('IsReadOnly','DomainRole','Get-ADDomainController'): self.assertIn(token,script)
        self.assertFalse(any(verb in script for verb in ('New-AD','Set-AD','Add-AD','Enable-AD')))

    def test_override_can_only_narrow_p03_candidates(self):
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        self.env['NORDIC_AD_DC_TARGET']='192.168.1.120'
        self.assertEqual(actions.targets(self.env,'09'),[])

    def test_selection_deadline_never_dispatches_an_action(self):
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})])
        with patch.object(actions.time,'monotonic',side_effect=[0,121]):
            code,log,invoke=self.campaign([])
        self.assertEqual(code,78); invoke.assert_not_called()
        self.assertIn('attempted=0',log)
        self.assertIn('no_writable_dc_verified',log)

    def test_candidate_limit_and_non_boolean_success_fail_closed(self):
        self.p03([dict(ip=ip,access_methods={'winrm':method()}) for ip in ('192.168.1.120','192.168.2.200')])
        self.env['NORDIC_MAX_DISCOVERED_HOSTS']='1'
        self.assertEqual(self.campaign([])[0],78)
        self.env.pop('NORDIC_MAX_DISCOVERED_HOSTS')
        self.p03([dict(ip='192.168.2.200',access_methods={'winrm':dict(method(),authenticated=1)})])
        self.assertEqual(actions.targets(self.env,'09'),[])

    def test_success_and_skip_reports_match_evidence_and_are_secret_safe(self):
        (self.base/'scripts').mkdir()
        (self.base/'scripts/09-ad-privilege.sh').write_bytes((PLATFORM/'scripts/09-ad-privilege.sh').read_bytes())
        for present in (False,True):
            (self.base/'logs/incident-ground-truth.log').unlink(missing_ok=True)
            self.p03([dict(ip='192.168.2.200',access_methods={'winrm':method()})] if present else [])
            code,log,_=self.campaign([ELIGIBLE,DC] if present else [])
            report=build_report(self.base,self.env['NORDIC_INCIDENT_ID'],code,self.env,
                standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'],phase_id='09',status='complete' if present else 'skipped',phases={'09':'complete' if present else 'skipped'}))
            self.assertEqual(report['phases'][0]['status'],'success' if present else 'skipped')
            html=export_html(report,'ground-truth')
            self.assertIn('P09_DC_SELECTED' if present else 'no_authenticated_winrm_targets',html)
            self.assertNotIn('NEVER_PERSIST',html)

    def test_report_does_not_call_p03_completion_authenticated_success(self):
        self.p01([('192.168.2.200',{5985:'open'})])
        self.access([DENIED])
        (self.base/'scripts').mkdir()
        (self.base/'scripts/03-access.sh').write_bytes((PLATFORM/'scripts/03-access.sh').read_bytes())
        report=build_report(self.base,self.env['NORDIC_INCIDENT_ID'],0,self.env,
            standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'],phase_id='03',status='complete',phases={'03':'complete'}))
        phase=report['phases'][0]
        self.assertEqual(phase['action_result'],'no_authenticated_access')
        self.assertIn('0 verified protocol successes',phase['action_outcome'])
        self.assertIn('credentials_denied',export_html(report,'ground-truth'))


if __name__=='__main__': unittest.main()
