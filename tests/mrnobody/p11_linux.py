"""P11 Linux tests run only in GitHub CI; no SSH, lab host or real DNS traffic."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace as Response
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import persistence_actions as p
import linux_process as process
import remote_actions as remote

ENV = dict(MRNOBODY_METHOD='process', MRNOBODY_PERSISTENCE_DURATION='300')
TARGET = dict(platform='linux', target='192.168.1.20', port=22, protocol='ssh', username='ubuntu')


class Configuration(unittest.TestCase):
    def test_lifetimes_cpu_dns_and_unchanged_legacy(self):
        for duration in (300,900,1800,3600):
            for cpu in process.CPU:
                p.configuration(dict(ENV, MRNOBODY_PERSISTENCE_DURATION=str(duration), MRNOBODY_PERSISTENCE_CPU=cpu), 'linux')
        for options in (
            dict(MRNOBODY_PERSISTENCE_DURATION='60'),
            dict(MRNOBODY_PERSISTENCE_CPU='high'),
            dict(MRNOBODY_PERSISTENCE_DNS='enabled'),
            dict(MRNOBODY_METHOD='process-dns'),
            dict(MRNOBODY_METHOD='process-dns', MRNOBODY_PERSISTENCE_RESOLVER='8.8.8.8'),
            dict(MRNOBODY_METHOD='process-dns', MRNOBODY_PERSISTENCE_RESOLVER='192.168.1.53', MRNOBODY_PERSISTENCE_DOMAIN='other.test'),
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                p.configuration(dict(ENV, **options), 'linux')
        meta = p.metadata(ENV, 'linux')
        self.assertEqual(meta['persistence'], 'false')
        self.assertEqual(meta['mitre'], 'T1059.006')
        self.assertIn('logger -t mrnobody-p11', p.script({'MRNOBODY_METHOD':'cron'}, 'linux'))
        with self.assertRaises(ValueError):
            p.configuration(dict(MRNOBODY_METHOD='service', MRNOBODY_ACTION='inspect'), 'windows')

    def test_api_environment_and_report_mapping(self):
        from reports import read_metadata, build_report
        from scenario_model import catalogue, validate, plan
        from execution import phase_environment
        caps = catalogue(ROOT/'TESTFILES/ATTACKER-V2/scripts', read_metadata)
        for method in ('process','process-dns'):
            params = dict(target='192.168.1.20',protocol='ssh',platform='linux',method=method,
                          persistence_cpu='low',persistence_duration=300,
                          persistence_resolver='192.168.1.53')
            spec = dict(version=1,name='Process fixture',target_mode='fixed',profile={'mode':'normal'},
                        phases=[dict(id='11',parameters=params)])
            spec = plan(validate(spec,caps))
            env = phase_environment('11',dict(MRN_EXECUTION=json.dumps(spec),MRN_STARTED='0'),sleep=lambda _:None)
            self.assertEqual(env['MRNOBODY_PERSISTENCE_CPU'],'low')
            self.assertEqual(p.configuration(env,'linux')[0],method)

    def test_process_ground_truth_html_pdf_mapping_is_execution(self):
        from reports import build_report
        from report_exports import export_html, export_pdf
        from pypdf import PdfReader
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'scripts').mkdir()
            shutil.copy(ROOT/'TESTFILES/ATTACKER-V2/scripts/11-persistence.sh',base/'scripts/11-persistence.sh')
            env=dict(ENV,NORDIC_BASE_DIR=tmp,NORDIC_INCIDENT_ID='MRN-process-report',
                     MRNOBODY_RUN_MODE='standalone',MRNOBODY_TARGET=TARGET['target'],
                     MRNOBODY_PROTOCOL='ssh',MRNOBODY_USERNAME='ubuntu')
            reply=dict(result='success',process_pid=1234,owner='ubuntu',start_ticks='99',
                       command='/usr/bin/python3 worker.py',persistence=False,
                       process_running='true',cpu_seconds=.2)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote.run('11',env,Mock(return_value=Response(returncode=0,stdout=json.dumps(reply).encode()))),0)
            report=build_report(base,env['NORDIC_INCIDENT_ID'],environ=env,standalone=dict(
                incident_id=env['NORDIC_INCIDENT_ID'],scenario='standalone-phase',phase_id='11',
                status='complete',phases={'11':'complete'}))
            phase=report['phases'][0]
            self.assertEqual(phase['mitre']['tactic'],'Execution')
            self.assertEqual([item['id'] for item in phase['mitre']['techniques']],['T1059.006'])
            self.assertIn('no reboot persistence',phase['action_outcome'])
            for view in ('ground-truth','investigation'):
                html=export_html(report,view)
                pdf=''.join(page.extract_text() for page in PdfReader(io.BytesIO(export_pdf(report,view))).pages)
                for content in (html,pdf):
                    self.assertIn('1234',content)
                    self.assertIn('ubuntu',content)


@unittest.skipIf(os.name == 'nt', 'Linux procfs/pidfd lifecycle')
class Lifecycle(unittest.TestCase):
    def invoke(self, home, action='create', **options):
        env = dict(ENV, MRNOBODY_ACTION=action, **options)
        result = subprocess.run(['bash'], input=p.script(env,'linux'), text=True,
                                env=dict(os.environ, HOME=str(home)),capture_output=True,timeout=15)
        evidence = p.evidence(result.stdout,env,'linux')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(evidence['result'],'success',evidence)
        return evidence

    def test_real_visible_process_rerun_inspect_cleanup_and_foreign_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)
            base=home/'.config/mrnobody/mrnobody-p11-telemetry'
            try:
                first=self.invoke(home)
                result=subprocess.run(['bash'],input=p.script(ENV,'linux'),text=True,env=dict(os.environ,HOME=tmp),capture_output=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(p.collision_evidence(result.stdout,ENV,'linux')['result'],'skipped')
                again=self.invoke(home,'inspect')
                self.assertEqual(first['process_pid'],again['process_pid'])
                self.assertEqual(first['deadline'],again['deadline'])
                ps=subprocess.check_output(['ps','-p',str(first['process_pid']),'-o','user=,comm=,args='],text=True)
                self.assertIn('mrn-p11-worker',ps)
                self.assertIn('mrnobody-p11-telemetry/worker.py',ps)
                self.assertFalse(first['persistence'])
                self.assertFalse((home/'.config/systemd').exists())
                inspected=self.invoke(home,'inspect')
                self.assertEqual(first['process_pid'],inspected['process_pid'])
                original=(base/'pid.json').read_text()
                (base/'pid.json').unlink()  # interrupted spawn receipt can be recovered
                recovered=self.invoke(home,'inspect')
                self.assertEqual(first['process_pid'],recovered['process_pid'])
                bad=json.loads(original);bad['start_ticks']='0'
                (base/'pid.json').write_text(json.dumps(bad))
                result=subprocess.run(['bash'],input=p.script(dict(ENV,MRNOBODY_ACTION='cleanup'),'linux'),
                    text=True,env=dict(os.environ,HOME=tmp),capture_output=True,timeout=10)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('process_identity_conflict',result.stdout)
                self.assertTrue(process.identity(first['process_pid']))
                (base/'pid.json').write_text(original)
                (base/'foreign.txt').write_text('keep')
                result=subprocess.run(['bash'],input=p.script(dict(ENV,MRNOBODY_ACTION='cleanup'),'linux'),
                    text=True,env=dict(os.environ,HOME=tmp),capture_output=True,timeout=10)
                self.assertIn('artifact_ownership_conflict',result.stdout)
                self.assertEqual((base/'foreign.txt').read_text(),'keep')
                (base/'foreign.txt').unlink()
                self.invoke(home,'cleanup')
                self.invoke(home,'cleanup')
                self.assertIsNone(process.identity(first['process_pid']))
                self.assertFalse(base.exists())
            finally:
                if base.exists():
                    self.invoke(home,'cleanup')

    def test_real_cpu_levels_remain_bounded(self):
        for level in ('idle','low','medium'):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as tmp:
                home=Path(tmp)
                options=dict(MRNOBODY_PERSISTENCE_CPU=level)
                try:
                    self.invoke(home,**options)
                    start=self.invoke(home,'inspect',**options)
                    time.sleep(2.2)
                    end=self.invoke(home,'inspect',**options)
                    delta=end['cpu_seconds']-start['cpu_seconds']
                    self.assertLess(delta,.55)  # <25% of one core including overhead
                    if level=='medium':
                        self.assertGreater(delta,.03)
                finally:
                    self.invoke(home,'cleanup',**options)

    def test_missing_owner_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);base=home/'.config/mrnobody/mrnobody-p11-telemetry'
            base.mkdir(parents=True)
            with patch('pathlib.Path.home',return_value=home), contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaises(SystemExit):
                    process.manager('mrnobody-p11-telemetry','cleanup',{},'')
            self.assertIn('artifact_ownership_conflict',out.getvalue())
            base.rmdir()
            foreign=home/'foreign';foreign.mkdir()
            base.symlink_to(foreign)
            with patch('pathlib.Path.home',return_value=home), contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaises(SystemExit):
                    process.manager('mrnobody-p11-telemetry','cleanup',{},'')
            self.assertTrue(foreign.exists())


@unittest.skipIf(os.name == 'nt', 'Linux service setup uses flock')
class Services(unittest.TestCase):
    def test_user_manager_lifecycle_rerun_inspect_cleanup_and_errors(self):
        for method in ('systemd','cron-systemd','cron-systemd-process'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as tmp:
                home=Path(tmp);base=home/'.config/mrnobody/mrnobody-p11-telemetry'
                cron=['0 1 * * * echo keep'];state={'active':False,'fail':False};calls=[]
                def provider(argv,**kw):
                    calls.append(argv)
                    if argv[:2]==['crontab','-l']:
                        return Response(returncode=0,stdout='\n'.join(cron)+'\n',stderr='')
                    if argv==['crontab','-']:
                        cron[:]=kw['input'].splitlines()
                        return Response(returncode=0,stdout='',stderr='')
                    self.assertEqual(argv[:2],['/usr/bin/systemctl','--user'])
                    self.assertEqual(os.environ['XDG_RUNTIME_DIR'],'/run/user/'+str(os.getuid()))
                    self.assertEqual(os.environ['DBUS_SESSION_BUS_ADDRESS'],'unix:path=/run/user/'+str(os.getuid())+'/bus')
                    op=argv[2]
                    if state['fail'] and op=='show-environment':
                        return Response(returncode=1,stdout='',stderr='PRIVATE_ERROR')
                    if op=='show':
                        if '--property=MainPID' in argv:
                            return Response(returncode=0,stdout=str(os.getpid()),stderr='')
                        return Response(returncode=0,stdout='',stderr='')
                    if op=='enable':
                        state['active']=True
                        (base/'status.txt').write_text('0,0,0,-1')
                    if op=='disable':state['active']=False
                    if op=='is-active':
                        return Response(returncode=0 if state['active'] else 3,stdout='active' if state['active'] else 'inactive',stderr='')
                    return Response(returncode=0,stdout='active',stderr='')
                env=dict(MRNOBODY_METHOD=method)
                def execute(action):
                    source=p.script(dict(env,MRNOBODY_ACTION=action),'linux')
                    setup=source.split("python3 - <<'MRN_P11_SETUP'\n",1)[1].rsplit('\nMRN_P11_SETUP',1)[0]
                    ns={}
                    with patch.dict(os.environ,{},clear=False), patch('pathlib.Path.home',return_value=home), patch('subprocess.run',side_effect=provider), contextlib.redirect_stdout(io.StringIO()) as out:
                        try:
                            try:
                                exec(compile(setup,'<service>','exec'),ns)
                            except SystemExit as error:
                                if error.code != 0:
                                    raise
                        finally:
                            if 'lock' in ns:ns['lock'].close()
                    return out.getvalue()
                state['fail']=True
                with self.assertRaises(SystemExit):execute('create')
                self.assertFalse(base.exists())
                state['fail']=False
                first=execute('create');deadline=(base/'config.txt').read_text()
                execute('create');self.assertEqual((base/'config.txt').read_text(),deadline)
                before=list(cron);execute('inspect');self.assertEqual(cron,before)
                self.assertEqual(p.evidence(first,env,'linux')['result'],'success')
                self.assertEqual(sum('MrNobody' in row for row in cron),int(method in {'cron-systemd','cron-systemd-process'}))
                if method=='systemd':self.assertFalse(any(c[0]=='crontab' for c in calls))
                unit=home/'.config/systemd/user/mrnobody-p11-telemetry.service'
                original_unit=unit.read_text()
                unit.write_text('unrelated service')
                with self.assertRaises(SystemExit):execute('cleanup')
                self.assertTrue(state['active'])
                unit.write_text(original_unit)
                (base/'owner.txt').write_text('foreign')
                with self.assertRaises(SystemExit):execute('cleanup')
                self.assertTrue(state['active'])
                (base/'owner.txt').write_text(p.MARKER)
                execute('cleanup');execute('cleanup')
                self.assertFalse(state['active']);self.assertFalse(base.exists())
                self.assertEqual(cron,['0 1 * * * echo keep'])

    def test_diagnostics_survive_nonzero_exit_without_raw_errors(self):
        for stage,warning in [('manager','user_manager_unavailable'),('ownership','artifact_ownership_conflict'),('verify','systemctl_failed')]:
            output=('MRN_P11_ERROR='+stage+','+warning+'\n').encode()
            framed=output+b'\nMRN_REMOTE_EXIT=1__MRN_END__\n'
            result=remote.perform('11',TARGET,dict(MRNOBODY_METHOD='systemd'),
                ssh=Mock(return_value=(0,(framed,len(framed)),(b'PRIVATE_ERROR',13))))
            self.assertEqual(result['stage'],stage)
            self.assertEqual(result['warning'],warning)
            self.assertNotIn('PRIVATE_ERROR',str(result))


class Worker(unittest.TestCase):
    def test_fixed_dns_questions_counters_cpu_and_expiry_without_network(self):
        for level in process.CPU:
            for mode in ('reply','unavailable','mismatch'):
                with self.subTest(level=level,mode=mode), tempfile.TemporaryDirectory() as tmp:
                    base=Path(tmp)
                    now=[1800000000.];cpu=[0.]
                    config=dict(token='token',duration=300,deadline=now[0]+25,cpu=level,dns=True,
                                resolver='192.168.1.53',interval=10)
                    (base/'config.txt').write_text(json.dumps(config))
                    packets=[]
                    class Socket:
                        def __enter__(self):return self
                        def __exit__(self,*_):pass
                        def settimeout(self,value):assert 0<value<=1
                        def connect(self,address):assert address==('192.168.1.53',53)
                        def send(self,q):self.q=q;packets.append(q)
                        def recv(self,_):
                            if mode=='unavailable':raise OSError()
                            reply=bytearray(self.q);reply[2]=128;reply[3]=3
                            if mode=='mismatch':reply[0]^=1
                            return bytes(reply)
                    def cpu_time():
                        cpu[0]+=.001;now[0]+=.001
                        return cpu[0]
                    def sleep(seconds):now[0]+=seconds
                    with patch.object(process,'__file__',str(base/'worker.py')), patch('socket.socket',return_value=Socket()), patch('ctypes.CDLL'), patch('signal.signal'), patch('time.monotonic',side_effect=lambda:now[0]), patch('time.time',side_effect=lambda:now[0]), patch('time.process_time',side_effect=cpu_time), patch('time.sleep',side_effect=sleep), patch.object(process,'identity',return_value=dict(pid=1,uid=1,start_ticks='1')):
                        process.worker_main('token')
                    state=json.loads((base/'status.json').read_text())
                    self.assertEqual(state['state'],'expired')
                    self.assertEqual(len(packets),3)
                    self.assertEqual(state['dns_responses'],3 if mode=='reply' else 0)
                    self.assertTrue(all(q[2:]==p.question('evilcorp.test')[2:] for q in packets))
                    self.assertLess(cpu[0],3.)  # bounded CPU even at medium over 25s
                    self.assertLess(now[0],1800000025.1)

    def test_forged_evidence_refused(self):
        for output in ('configured','MRN_P11_PROCESS=bad','MRN_P11_PROCESS='+base64.b64encode(b'{}').decode()):
            self.assertEqual(process.evidence(output,'create')['result'],'failed')


if __name__=='__main__':
    unittest.main()
