"""Offline P15-P17 contracts: transports are fixtures; artifacts stay in temp dirs."""
import contextlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import exercise_actions as exercise
import web_profiles as web
import remote_actions as remote
import collection_state
from scenario_model import catalogue, validate, plan, needs_password
from reports import read_metadata, build_report, PHASE_ORDER
from report_exports import export_html, export_pdf
from execution import phase_environment, snapshot
import app
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(BASE / 'scripts', read_metadata)


def definition(pid, mode='fixed', platform='linux'):
    params = dict(target='192.168.1.20', protocol='http' if pid == '15' else 'ssh' if platform == 'linux' else 'winrm-http')
    if pid != '15': params['platform'] = platform
    if mode == 'auto': params.pop('target'); params.pop('protocol')
    prereq = ['01', '02'] if pid == '15' else ['01', '03']
    return dict(version=1, name='Application and collection', target_mode=mode, profile={'mode': 'normal'},
                phases=([{'id': p} for p in prereq] if mode == 'auto' else []) + [dict(id=pid, parameters=params)])


class Phases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-offline', MRNOBODY_RUN_MODE='standalone',
                        MRNOBODY_TARGET='192.168.1.20', MRNOBODY_PROTOCOL='ssh', NORDIC_SSH_PASSWORD='FIXTURE_SECRET')
        self.target = dict(target='192.168.1.20', platform='linux', protocol='ssh', port=22, username='lab')

    def test_registry_profiles_timing_auto_fixed_and_validation(self):
        self.assertEqual(CAPS['15']['dependencies'], ['02'])
        for pid in ('15','16','17'):
            for mode in ('auto','fixed'):
                for platform in ('windows','linux'):
                    for timing in ('normal','slow','custom'):
                        d = definition(pid, mode, platform); d['profile'] = {'mode': timing}
                        planned = plan(validate(d, CAPS))
                        self.assertEqual(planned['phases'][-1]['id'], pid)
                        self.assertEqual(needs_password(planned, platform == 'windows'), pid != '15')
            bad = definition(pid); bad['phases'][0]['parameters']['target'] = '8.8.8.8'
            with self.assertRaises(ValueError): validate(bad, CAPS)
        for params in ({'web_profile':'command'}, {'web_path':'/../etc'}, {'web_path':'https://evil'}):
            d=definition('15'); d['phases'][0]['parameters'].update(params)
            with self.assertRaises(ValueError): validate(d,CAPS)
        for key,value in [('dataset','home'),('archive_name','../secrets'),('action','delete')]:
            d=definition('17'); d['phases'][0]['parameters'][key]=value
            with self.assertRaises(ValueError): validate(d,CAPS)

    def test_web_mismatch_success_failure_and_redaction(self):
        for profile,spec in web.PROFILES.items():
            env=dict(self.env, MRNOBODY_WEB_PROFILE=profile)
            send=Mock(side_effect=[(200,{'app':'MrNobody Web Lab v1','synthetic':True}), (200,{'evidence':spec['verification'],'synthetic':True})])
            result=web.perform(dict(self.target,protocol='http'),env,send)
            self.assertEqual(result['result'],'success'); self.assertEqual(result['host_compromise_changed'],'false')
            self.assertEqual(result['mitre'],spec['mitre'])
            for response in [(200,{'password':'FIXTURE_SECRET'}),(302,{}),(500,None)]:
                send=Mock(return_value=response)
                result=web.perform(self.target,env,send)
                self.assertEqual(result['result'],'skipped'); self.assertEqual(send.call_count,1)
                self.assertNotIn('FIXTURE_SECRET',json.dumps(result))
            send=Mock(side_effect=[(200,{'app':'MrNobody Web Lab v1','synthetic':True}),(403,{'secret':'FIXTURE_SECRET'})])
            self.assertEqual(web.perform(self.target,env,send)['result'],'failed')
        env=dict(self.env,MRNOBODY_PROTOCOL='http')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(web.run(env,Mock(return_value=(200,{}))),78)
        (self.base/'state').mkdir(exist_ok=True)
        (self.base/'state/web-targets.json').write_text(json.dumps(dict(incident_id='MRN-offline',targets=[dict(ip='192.168.1.20',port=8088,protocol='http'),dict(ip='192.168.1.21',port=8088,protocol='http')])))
        send=Mock(side_effect=[(200,{}),(200,{'app':'MrNobody Web Lab v1','synthetic':True}),(200,{'evidence':'MRN_SYNTHETIC_SQLI','synthetic':True})])
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(web.run(dict(env, MRNOBODY_RUN_MODE='campaign',MRNOBODY_TARGET=''),send),0)

    def linux_action(self,pid,**overrides):
        config=exercise.configuration(pid,dict(self.env,**overrides))
        source=exercise.LINUX.replace('__CONFIG__',repr(json.dumps(config))).replace('__PID__',repr(pid)).replace('__FILES__',repr(exercise.DATASETS.get(config.get('dataset'),[])))
        source=source.replace("Path('/var/tmp/MrNobody-exercises')", 'Path('+repr(str(self.base))+')')
        child=subprocess.run([sys.executable,'-c',source],capture_output=True,text=True,timeout=15)
        return child,exercise.evidence(pid,child.stdout,config,'linux')

    def fixture(self):
        root=self.base/'MRN-offline'; root.mkdir(exist_ok=True)
        (root/'monitor.conf').write_text('MrNobody synthetic monitor enabled\n',newline='\n')
        (root/'exercise.log').write_text('MrNobody synthetic exercise log\n',newline='\n')
        templates=self.base/'templates'; templates.mkdir(exist_ok=True)
        for name in ('monitor.conf','exercise.log'): (templates/name).write_bytes((root/name).read_bytes())
        dataset=self.base/'datasets/finance'; dataset.mkdir(parents=True,exist_ok=True)
        for name in exercise.DATASETS['finance']:
            (dataset/name).write_text('MrNobody synthetic finance '+name+'\n',newline='\n')
        return root

    def test_reversible_actions_idempotency_recovery_and_missing_artifacts(self):
        self.assertEqual(self.linux_action('16')[1]['result'],'skipped')
        root=self.fixture()
        for behavior in exercise.BEHAVIORS:
            for action in ('run','run','cleanup'):
                child,result=self.linux_action('16',MRNOBODY_BEHAVIOR=behavior,MRNOBODY_ACTION=action)
                self.assertEqual(child.returncode,0,child.stderr); self.assertEqual(result['cleanup'],'restored_verified')
                self.assertEqual((root/'monitor.conf').read_text(),'MrNobody synthetic monitor enabled\n')
                self.assertTrue((root/'exercise.log').exists())
        (root/'monitor.conf.mrn-restore').write_text('MrNobody synthetic monitor enabled\n',newline='\n')
        (root/'monitor.conf').write_text('MrNobody synthetic monitor disabled\n',newline='\n')
        self.assertEqual(self.linux_action('16',MRNOBODY_ACTION='cleanup')[1]['result'],'success')
        (root/'monitor.conf').write_text('unrelated real config')
        self.assertNotEqual(self.linux_action('16')[0].returncode,0)
        self.assertEqual((root/'monitor.conf').read_text(),'unrelated real config')

    def test_collection_archive_partial_cleanup_guardrails_and_state(self):
        root=self.fixture()
        for _ in range(2):
            child,result=self.linux_action('17')
            self.assertEqual(child.returncode,0,child.stderr); self.assertEqual(result['result'],'success')
            self.assertEqual(result['files_count'],2)
            collection_state.update(self.env,self.target,result)
            data=json.loads((self.base/'state/staged-data.json').read_text())
            self.assertEqual(len(data['hosts']),1); self.assertEqual(data['hosts'][0]['producer_phase'],'17')
            self.assertNotIn('FIXTURE_SECRET',json.dumps(data))
        (self.base/'datasets/finance/invoices.txt').unlink()
        child,result=self.linux_action('17'); self.assertEqual(result['warning'],'partial_collection')
        child,result=self.linux_action('17',MRNOBODY_ACTION='cleanup')
        collection_state.update(dict(self.env,MRNOBODY_ACTION='cleanup'),self.target,result)
        self.assertFalse((root/'collection.tar.gz').exists())

        self.assertEqual(json.loads((self.base/'state/staged-data.json').read_text())['hosts'],[])
        (self.base/'datasets/finance/customers.txt').write_text('real unrelated text')
        self.assertNotEqual(self.linux_action('17')[0].returncode,0)
        self.assertFalse((root/'collection.tar.gz').exists())

    def test_actual_p05_merge_and_p06_inventory_consumer(self):
        self.fixture()
        _, result = self.linux_action('17')
        collection_state.update(self.env,self.target,result)
        staging=self.base/'state/staged-data.json'
        incoming=self.base/'staging-results.txt'; incoming.write_text('')
        blocks=re.findall(r"<<'PY'\n(.*?)\nPY",(BASE/'scripts/05-staging.sh').read_text(),re.S)
        merge=next(code for code in blocks if 'source_file = sys.argv[1]' in code)
        child=subprocess.run([sys.executable,'-c',merge,str(incoming),str(staging),'MRN-offline'],capture_output=True,text=True)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(json.loads(staging.read_text())['hosts'][0]['file'],result['file'])
        inventory=self.base/'access.json'; inventory.write_text(json.dumps({'hosts':[dict(ip=self.target['target'],compromised=True)]}))
        blocks=re.findall(r"<<'PY'\n(.*?)\nPY",(BASE/'scripts/06-exfil.sh').read_text(),re.S)
        consume=next(code for code in blocks if 'compromised_by_ip = ' in code)
        child=subprocess.run([sys.executable,'-c',consume,str(staging),str(inventory)],capture_output=True,text=True)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertIn(result['file'],child.stdout)
        self.assertIn(result['sha256'],child.stdout)

    def test_transport_allowlist_windows_linux_and_worker_skip_failure(self):
        for pid,output in [('16','MRN_EXERCISE=restored'),('17','MRN_ARCHIVE=2,123,'+'a'*64+',customers.txt;invoices.txt')]:
            for platform in ('linux','windows'):
                target=dict(self.target,platform=platform,protocol='ssh' if platform=='linux' else 'winrm-http')
                session=Mock(); session.run_ps.return_value=SimpleNamespace(status_code=0,std_out=output.encode(),std_err=b'FIXTURE_SECRET')
                ssh=Mock(return_value=(0,((output+'\nMRN_REMOTE_EXIT=0__MRN_END__\n').encode(),100),(b'FIXTURE_SECRET',14)))
                result=remote.perform(pid,target,dict(self.env,MRNOBODY_PASSWORD='FIXTURE_SECRET'),Mock(return_value=session),ssh)
                self.assertEqual(result['result'],'success'); self.assertNotIn('FIXTURE_SECRET',json.dumps(result))
                self.assertNotIn('stdout_preview',result)
            invoke=Mock(return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'result':'skipped'})))
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(remote.run(pid,self.env,invoke),78)
            invoke.return_value.stdout=json.dumps({'result':'failed'})
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(remote.run(pid,self.env,invoke),1)

    def test_windows_scripts_in_isolated_fixture_directory(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell: self.skipTest('PowerShell unavailable')
        root = self.fixture()
        for pid, behavior in [('16','config-toggle'), ('16','log-rename'), ('17','config-toggle')]:
            for action in ('run','run','cleanup'):
                env = dict(self.env, MRNOBODY_BEHAVIOR=behavior, MRNOBODY_ACTION=action)
                source = exercise.script(pid,'windows',env)
                source = source.replace("'C:\\ProgramData\\MrNobody\\Exercises\\' + $c.incident", "'" + str(root).replace("'","''") + "'")
                path=self.base/'fixture.ps1'; path.write_text(source,encoding='utf-8')
                child=subprocess.run([shell,'-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,text=True,timeout=20)
                self.assertEqual(child.returncode,0,child.stdout+child.stderr)
                result=exercise.evidence(pid,child.stdout,exercise.configuration(pid,env),'windows')
                self.assertEqual(result['result'],'success',result)
        self.assertFalse((root/'collection.zip').exists())
        self.assertEqual((root/'monitor.conf').read_text(),'MrNobody synthetic monitor enabled\n')

    def test_full_order_reports_exports_and_live(self):
        expected=('01','02','15','03','08','09','10','11','12','13','14','16','04','17','05','06','07')
        self.assertEqual(PHASE_ORDER,expected)
        self.assertEqual(read_metadata(BASE/'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(','),list(expected))
        validate(dict(version=1,name='Full',target_mode='auto',profile={'mode':'normal'},phases=[{'id':p} for p in expected]),CAPS)
        for pid in ('15','16','17'):
            d=definition(pid); env=phase_environment(pid,dict(self.env,MRN_EXECUTION=json.dumps(plan(validate(d,CAPS))),MRN_STARTED='0'),clock=lambda:1)
            self.assertEqual(env['MRNOBODY_RUN_MODE'],'standalone')
        for pid in ('15','16','17'):
            script=next((BASE/'scripts').glob(pid+'-*.sh'))
            (self.base/'scripts').mkdir(exist_ok=True)
            (self.base/'scripts'/script.name).write_bytes(script.read_bytes())
        with contextlib.redirect_stdout(io.StringIO()): web.run(dict(self.env,MRNOBODY_PROTOCOL='http'),Mock(side_effect=[(200,{'app':'MrNobody Web Lab v1','synthetic':True}),(200,{'evidence':'MRN_SYNTHETIC_SQLI','synthetic':True})]))
        # Report reads shared ground truth and keeps raw fixed evidence in both exports.
        report=build_report(self.base,'MRN-offline',0,self.env,standalone=dict(incident_id='MRN-offline',phase_id='15',status='complete',phases={'15':'complete'}))
        self.assertTrue(any(p['id']=='15' for p in report['phases']))
        self.assertNotIn('FIXTURE_SECRET',json.dumps(report))
        self.assertEqual(report['phases'][0]['actions'][-1]['fingerprint'],'matched')
        for view in ('investigation','ground-truth'):
            self.assertIn('T1190',export_html(report,view))
            self.assertTrue(export_pdf(report,view).startswith(b'%PDF'))
        for pid, output, tid in [('16','MRN_EXERCISE=restored','T1685'),('17','MRN_ARCHIVE=2,123,'+'a'*64+',customers.txt;invoices.txt','T1560.002')]:
            result=exercise.evidence(pid,output,exercise.configuration(pid,self.env),'linux')
            invoke=Mock(return_value=SimpleNamespace(returncode=0,stdout=json.dumps(result)))
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(remote.run(pid,self.env,invoke),0)
            state=dict(incident_id='MRN-offline',phase_id=pid,status='complete',phases={pid:'complete'})
            report=build_report(self.base,'MRN-offline',0,self.env,standalone=state)
            self.assertTrue(report['phases'][0]['actions'])
            self.assertIn(tid,export_html(report,'ground-truth'))
            self.assertTrue(export_pdf(report,'ground-truth').startswith(b'%PDF'))
            (self.base/'runtime').mkdir(exist_ok=True)
            (self.base/'runtime/execution-overview.json').write_text(json.dumps(dict(incident_id='MRN-offline',type='phase',id=pid,phases=[{'id':pid}])))
            with patch('execution.report_for',return_value=report):
                self.assertEqual(snapshot(self.base,CAPS,None,0)['timeline'][0]['id'],pid)


class Integration(API):
    def test_new_phase_api_builder_scheduler_contract(self):
        for pid in ('15','16','17'):
            self.assertIn(pid,{p['id'] for p in self.client.get('/api/phases').get_json()['phases']})
            d=definition(pid)
            result=self.client.post('/api/custom-scenarios',json=d)
            self.assertEqual(result.status_code,201,result.get_data(as_text=True))
            for profile in ('normal','slow','custom'):
                spec=dict(type='phase',id=pid,target_mode='fixed',parameters=d['phases'][0]['parameters'],profile={'mode':profile})
                app.planning.execution(spec)
            spec['profile']={'mode':'normal'}
            app.campaign_process=None
            result=self.client.post('/api/executions/run',json=dict(execution=spec,credentials={'ssh_password':'FIXTURE_SECRET','rdp_password':'FIXTURE_SECRET'}))
            self.assertEqual(result.status_code,200,result.get_json())
            schedule=self.client.post('/api/schedules',json=dict(version=1,execution=spec,at='2099-01-01T00:00:00Z',interval=86400,enabled=False))
            self.assertEqual(schedule.status_code,201,schedule.get_json())
            self.assertNotIn(b'FIXTURE_SECRET',app.planning.store.path.read_bytes())


if __name__=='__main__': unittest.main()
