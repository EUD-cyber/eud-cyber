"""Offline Full Campaign contracts. No target deployment or network calls."""
import base64
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace as Response
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'TESTFILES/ATTACKER-V2/web'))
import p11_campaign as campaign
import persistence_actions as p
import remote_actions as remote

ENV = dict(NORDIC_INCIDENT_ID='MRN-p11-campaign-test', MRNOBODY_RUN_MODE='campaign',
           NORDIC_SSH_USERNAME='ubuntu', NORDIC_SSH_PASSWORD='LINUX_RUNTIME_PASSWORD',
           NORDIC_RDP_USERNAME='Administrator', NORDIC_RDP_PASSWORD='WINDOWS_RUNTIME_PASSWORD')


def host(ip, platform, protocol=None):
    kind = 'ssh' if platform == 'linux' else 'winrm'
    return dict(ip=ip, platform=platform, authenticated=True, compromised=True,
        access_methods={kind: dict(authenticated=True, protocol=protocol or ('ssh' if kind=='ssh' else 'winrm-http'),
            port=22 if kind=='ssh' else 5986 if protocol=='winrm-https' else 5985,
            user='ubuntu' if kind=='ssh' else 'Administrator',
            verification='ssh_session_marker' if kind=='ssh' else 'read_only_windows_identity')})


def inventory(base, hosts, **options):
    data=dict(producer='P03', schema_version=2, complete=True, run_mode='campaign',
              incident_id=ENV['NORDIC_INCIDENT_ID'], hosts=hosts)
    data.update(options)
    path=base/'access.json';path.write_text(json.dumps(data))
    return dict(ENV, NORDIC_BASE_DIR=str(base), NORDIC_COMPROMISED_STATE=str(path))


class Access(unittest.TestCase):
    def test_requires_completed_same_incident_p03(self):
        for options in (dict(producer='P01'),dict(schema_version=1),dict(complete=False),
                        dict(run_mode='untrusted'),dict(incident_id='MRN-other')):
            with self.subTest(options=options),tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    campaign.targets(inventory(Path(tmp),[host('192.168.1.20','linux')],**options))

    def test_verified_protocol_account_and_runtime_password_only(self):
        linux=host('192.168.1.20','linux');win=host('192.168.1.21','windows','winrm-https')
        rdp=dict(ip='192.168.1.22',platform='windows',authenticated=True,compromised=True,
                 access='rdp',access_methods={'rdp':dict(authenticated=True)})
        invalid=[]
        for field,value in [('authenticated',False),('authenticated','true'),('verification','none'),
                            ('protocol','rdp'),('user','unverified'),('port',True),('port',0)]:
            h=host('192.168.1.30','linux');h['access_methods']['ssh'][field]=value;invalid.append(h)
        h=host('8.8.8.8','linux');invalid.append(h)
        h=host('192.168.1.31','linux');h['compromised']=False;invalid.append(h)
        with tempfile.TemporaryDirectory() as tmp:
            env=inventory(Path(tmp),[linux,win,rdp,*invalid,linux])
            selected=campaign.targets(env)
            self.assertEqual([x['target'] for x in selected],['192.168.1.20','192.168.1.21'])
            self.assertEqual((selected[1]['protocol'],selected[1]['port']),('winrm-https',5986))
            self.assertEqual(campaign.targets(dict(env,NORDIC_SSH_PASSWORD='',NORDIC_RDP_USERNAME='different')),[])
            # Overrides cannot invent access or replace verified ports/accounts.
            self.assertEqual(campaign.targets(dict(env,MRNOBODY_TARGET='192.168.1.99',MRNOBODY_PORT='9999',
                MRNOBODY_USERNAME='wrong',MRNOBODY_PROTOCOL='rdp')),selected)


class Orchestration(unittest.TestCase):
    def execute(self,replies, hosts=None):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            env=inventory(base,hosts or [host('192.168.1.20','linux'),host('192.168.1.21','linux'),
                host('192.168.2.20','windows'),host('192.168.2.21','windows','winrm-https')])
            calls=[]
            def invoke(argv,**kwargs):
                runtime=kwargs['env'];calls.append(runtime)
                value=replies[len(calls)-1] if isinstance(replies,list) else replies
                if isinstance(value,Exception):raise value
                return Response(returncode=0,stdout=json.dumps(value).encode())
            with contextlib.redirect_stdout(io.StringIO()):code=remote.run('11',env,invoke)
            truth=(base/'logs/incident-ground-truth.log').read_text()
            from reports import build_report
            (base/'state').mkdir(exist_ok=True)
            (base/'state/campaign.json').write_text(json.dumps(dict(
                incident_id=ENV['NORDIC_INCIDENT_ID'], status='partial' if code == 80 else 'complete' if code in {0,78} else 'failed',
                phases={'11':'partial' if code == 80 else 'complete' if code == 0 else 'skipped' if code == 78 else 'failed'})))
            self.report=build_report(base,ENV['NORDIC_INCIDENT_ID'],exit_code=1 if code == 1 else 0,environ=env)
            return code,calls,truth

    def test_all_methods_on_all_hosts_with_distinct_deterministic_names(self):
        code,calls,truth=self.execute(dict(result='success',activity_deadline_utc_epoch=1900000000))
        self.assertEqual(code,0);self.assertEqual(len(calls),14)
        for address,methods in [('192.168.1.20',campaign.LINUX),('192.168.1.21',campaign.LINUX),
                                ('192.168.2.20',campaign.WINDOWS),('192.168.2.21',campaign.WINDOWS)]:
            rows=[r for r in calls if json.loads(r['MRN_REMOTE_TARGET'])['target']==address]
            self.assertEqual([r['MRNOBODY_METHOD'] for r in rows],list(methods))
            self.assertEqual(len(set(r['MRNOBODY_ARTIFACT'] for r in rows)),len(methods))
        for row in calls:
            self.assertLessEqual(len(row['MRNOBODY_ARTIFACT']),32)
            self.assertEqual(row['MRNOBODY_ARTIFACT'],campaign.suffix(ENV['NORDIC_INCIDENT_ID'],row['MRNOBODY_METHOD']))
            self.assertEqual(row['MRNOBODY_PERSISTENCE_DNS'],'disabled')
            self.assertEqual(row['MRNOBODY_PERSISTENCE_DURATION'],'300')
        self.assertIn('PHASE_COMPLETE',truth)
        self.assertNotIn('LINUX_RUNTIME_PASSWORD',truth)
        self.assertNotIn('WINDOWS_RUNTIME_PASSWORD',truth)

    def test_collision_timeout_malformed_and_failure_do_not_stop_other_actions(self):
        collision=p.collision_evidence('MRN_P11_EXISTS=artifact_already_exists\n',{},'linux')
        replies=[collision,dict(result='failed'),subprocess.TimeoutExpired('worker',1),dict(result='partial'),
                 dict(result='wrong'),*([dict(result='success')]*9)]
        code,calls,truth=self.execute(replies)
        self.assertEqual((code,len(calls)),(80,14))
        self.assertIn('PHASE_PARTIAL',truth)
        self.assertIn('P11_ARTIFACT_EXISTS',truth)
        self.assertIn('cleanup_required=false',truth.replace('"',''))
        self.assertIn('worker_execution_failed',truth)
        self.assertIn('partial=1',truth.replace('"',''))
        self.assertIn('target_verification=p03_ssh_session_marker',truth.replace('"',''))
        self.assertIn('not_assessed_requires_sensor_evidence',truth)
        phase=next(row for row in self.report['phases'] if row['id']=='11')
        self.assertEqual(phase['status'],'partial')
        self.assertEqual(self.report['incident']['status'],'partial')
        self.assertEqual(len(phase['method_results']),14)
        self.assertEqual([row['status'] for row in phase['method_results'][:4]],
                         ['skipped','failure','failure','partial'])
        self.assertEqual(len({(row['target'],row['method']) for row in phase['method_results']}),14)
        for reply,expected in [(collision,78),(dict(result='failed'),1)]:
            code,calls,truth=self.execute(reply)
            self.assertEqual((code,len(calls)),(expected,14))
            self.assertNotIn('PHASE_COMPLETE',truth)

    def test_cleanup_uses_same_host_method_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=inventory(Path(tmp),[host('192.168.1.20','linux')]);calls=[]
            def invoke(argv,**kw):
                calls.append(kw['env']);return Response(returncode=0,stdout=b'{"result":"success"}')
            with contextlib.redirect_stdout(io.StringIO()):
                remote.run('11',env,invoke);remote.run('11',dict(env,MRNOBODY_ACTION='cleanup'),invoke)
            self.assertEqual([r['MRNOBODY_ARTIFACT'] for r in calls[:4]],[r['MRNOBODY_ARTIFACT'] for r in calls[4:]])
            self.assertTrue(all(r['MRNOBODY_ACTION']=='cleanup' for r in calls[4:]))

    @unittest.skipUnless(shutil.which('bash') and os.name!='nt','Bash campaign fixture on Linux CI')
    def test_wholly_failed_p11_continues_independent_phases_and_fails_campaign(self):
        sys.path.insert(0,str(Path(__file__).parent))
        from full_incident import FullIncidentTests,IDS
        result,dispatched,state,truth=FullIncidentTests().run_campaign(child_code=1)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(dispatched,IDS)
        self.assertEqual(state['phases']['11'],'failed')
        self.assertEqual(state['status'],'failed')
        self.assertNotIn('CAMPAIGN_COMPLETE',truth)

    @unittest.skipUnless(shutil.which('bash') and os.name!='nt','Bash campaign fixture on Linux CI')
    def test_partial_campaign_continues_and_remains_partial(self):
        sys.path.insert(0,str(Path(__file__).parent))
        from full_incident import FullIncidentTests,IDS
        result,dispatched,state,truth=FullIncidentTests().run_campaign(child_code=80)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(dispatched,IDS)
        self.assertEqual(state['phases']['11'],'partial')
        self.assertEqual(state['status'],'partial')
        self.assertNotIn('PHASE_COMPLETE phase=11',truth)


class Payloads(unittest.TestCase):
    def test_combined_worker_cpu_expiry_and_expired_cron_without_network(self):
        source=p.linux_pair('mrnobody-p11-test','create','disabled|evilcorp.test|none|60|300','', 'cron-systemd-process')
        setup=source.split("python3 - <<'MRN_P11_SETUP'\n",1)[1].rsplit('\nMRN_P11_SETUP',1)[0]
        worker=next(node.args[0].value for node in ast.walk(ast.parse(setup))
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='write_text'
            and node.args and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str)
            and node.args[0].value.startswith('import hashlib'))
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);now=[1800000000.];cpu=[0.]
            (base/'config.txt').write_text('disabled|evilcorp.test|none|60|300\n1800000003\n')
            def process_time():cpu[0]+=.001;now[0]+=.001;return cpu[0]
            with patch('time.time',side_effect=lambda:now[0]),patch('time.monotonic',side_effect=lambda:now[0]),\
                 patch('time.process_time',side_effect=process_time),patch('time.sleep',side_effect=lambda s:now.__setitem__(0,now[0]+s)),\
                 patch('socket.socket',side_effect=AssertionError('network forbidden')),patch('subprocess.run') as run,\
                 patch.object(sys,'argv',['worker.py']):
                exec(worker,{'__file__':str(base/'worker.py')})
                self.assertLess(cpu[0],.10);self.assertLess(now[0],1800000003.1)
                run.assert_not_called()
                with patch.object(sys,'argv',['worker.py','--maintain']):
                    with self.assertRaises(SystemExit) as stopped:exec(worker,{'__file__':str(base/'worker.py')})
                    self.assertEqual(stopped.exception.code,0)
                run.assert_not_called()
            self.assertTrue((base/'status.txt').exists())

    def test_bounded_actions_and_standalone_cleanup_identity(self):
        for method in campaign.LINUX+campaign.WINDOWS:
            platform=p.METHODS[method][0]
            env=dict(ENV,MRNOBODY_METHOD=method,MRNOBODY_ARTIFACT=campaign.suffix(ENV['NORDIC_INCIDENT_ID'],method),
                     MRNOBODY_PERSISTENCE_DURATION='300')
            for action in ('create','cleanup'):
                row=dict(env,MRNOBODY_ACTION=action)
                source=p.script(row,platform)
                self.assertEqual(source,p.script(dict(row,MRNOBODY_RUN_MODE='standalone'),platform))
                self.assertNotIn('LINUX_RUNTIME_PASSWORD',source)
                self.assertNotIn('WINDOWS_RUNTIME_PASSWORD',source)
            if method=='scheduled-task':
                self.assertIn('EndBoundary',p.script(env,platform));self.assertNotIn('-Daily',p.script(env,platform))
            if method=='service':
                source=p.script(env,platform)
                self.assertIn('StartupType Manual',source);self.assertIn('ThreadPool.QueueUserWorkItem',source)
                self.assertNotIn('Register-ScheduledTask',source)
                self.assertNotIn('StartupType Automatic',source)
            if method=='cron':
                source=p._script(env,platform)
                self.assertIn('$(date +\\%%s)',source);self.assertIn('"$deadline" "$marker"',source)
        self.assertIn('-Daily',p.script({'MRNOBODY_METHOD':'scheduled-task'},'windows'))
        self.assertIn('StartupType Automatic',p.script({'MRNOBODY_METHOD':'service'},'windows'))

    def test_service_and_combined_receipts_require_lifecycle_evidence(self):
        env=dict(ENV,MRNOBODY_METHOD='service')
        self.assertEqual(campaign.legacy_evidence('MrNobody P11 verified',env,'windows')['result'],'failed')
        result=campaign.legacy_evidence('MRN_P11=1,1,1900000000,0,0,0,-1\nMRN_P11_SERVICE_PID=1234\n',env,'windows')
        self.assertEqual((result['result'],result['trigger_configured']),('success','false'))
        cleanup=campaign.legacy_evidence('MRN_P11_CLEANUP=complete\n',dict(env,MRNOBODY_ACTION='cleanup'),'windows')
        self.assertEqual((cleanup['cleanup'],cleanup['cleanup_required']),('complete','false'))
        env=dict(ENV,MRNOBODY_METHOD='cron-systemd-process')
        receipt='MRN_P11=1,1,1900000000,0,0,0,-1\n'
        self.assertEqual(p.evidence(receipt,env,'linux')['result'],'partial')
        result=p.evidence(receipt+'MRN_P11_PID=1234\n',env,'linux')
        self.assertEqual((result['result'],result['process_pid']),('success',1234))


if __name__=='__main__':unittest.main()
