"""Offline P10/P11 contracts and real runner fixtures. Never contacts a lab host."""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import remote_actions as remote
import persistence_actions as persistence
import ssh_actions
from reports import build_report, read_metadata, save_report, load_report
from scenario_model import catalogue, validate, plan
from execution import phase_environment, snapshot
from report_exports import export_html, export_pdf
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)
TARGET = dict(target='192.168.1.10', platform='linux', protocol='ssh', port=22, username='ubuntu')


def definition(pid='11', mode='fixed', **params):
    return dict(version=1, name='Remote lab', target_mode=mode, profile={'mode': 'normal'},
                phases=[dict(id=pid, parameters=dict(target=TARGET['target'], protocol='ssh', **params) if mode == 'fixed' else params, timing={})])


def framed(code=0, output=b'lab output', stderr=b''):
    data = output + b'\nMRN_REMOTE_EXIT=' + str(code).encode() + b'__MRN_END__\n'
    return 0, (data, len(data)), (stderr, len(stderr))


class Contracts(unittest.TestCase):
    def test_modes_methods_dependencies_and_fixed_targets(self):
        for pid in ('10', '11'):
            self.assertEqual(CAPS[pid]['dependencies'], ['03'])
            self.assertIn('ssh', CAPS[pid]['fields']['protocol']['options'])
            validate(definition(pid, platform='linux'), CAPS)
            auto = definition(pid, 'auto', platform='auto')
            with self.assertRaises(ValueError): validate(auto, CAPS)
            auto['phases'] = [dict(id='01'), dict(id='03')] + auto['phases']
            validate(auto, CAPS)
            for mode in ('normal', 'slow', 'custom'):
                auto['profile'] = {'mode': mode}
                self.assertIn(pid, [p['id'] for p in plan(validate(auto, CAPS))['phases']])
        for method, (platform, _, _) in persistence.METHODS.items():
            value = definition(method=method, platform=platform, action='cleanup', artifact='exercise-1')
            value['phases'][0]['parameters']['protocol'] = 'ssh' if platform == 'linux' else 'winrm-http'
            validate(value, CAPS)
        for params in ({'platform':'windows'}, {'method':'service'}, {'artifact':'../bad'}, {'action':'destroy'}, {'password':'secret'}):
            value = definition()
            value['phases'][0]['parameters'].update(params)
            with self.assertRaises(ValueError): validate(value, CAPS)

    def test_auto_overrides_survive_validation_and_environment(self):
        value = definition('11', 'auto', platform='linux', method='systemd', target=TARGET['target'])
        value['phases'] = [dict(id='01'), dict(id='03')] + value['phases']
        value = validate(value, CAPS)
        env = phase_environment('11', {'MRN_EXECUTION':json.dumps(value), 'MRN_STARTED':'0',
                                       'MRNOBODY_METHOD':'service', 'MRNOBODY_ACTION':'cleanup'}, sleep=lambda _:None)
        self.assertEqual(env['MRNOBODY_METHOD'], 'systemd')
        self.assertNotIn('MRNOBODY_ACTION', env)

    def test_generated_script_syntax(self):
        for method, (platform, _, _) in persistence.METHODS.items():
            for action in ('create', 'cleanup'):
                source = persistence.script({'MRNOBODY_METHOD':method,'MRNOBODY_ACTION':action, 'MRNOBODY_PERSISTENCE_RESOLVER':'192.168.1.53'},platform)
                if platform == 'linux':
                    if os.name == 'nt': continue
                    argv = ['bash','-n']
                else:
                    shell = shutil.which('pwsh') or shutil.which('powershell')
                    if not shell: continue
                    argv = [shell,'-NoProfile','-NonInteractive','-Command',
                            '$s=[Console]::In.ReadToEnd(); $t=$null; $e=$null; [System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null; if($e.Count){$e|ForEach-Object {$_.Message};exit 1}']
                result = subprocess.run(argv,input=source,text=True,capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_full_order_and_manifest_contract(self):
        ids = read_metadata(PLATFORM / 'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
        self.assertEqual(ids, ['01','02','03','08','09','10','11','04','05','06','07'])
        validate(dict(version=1,name='Full',target_mode='auto',profile={'mode':'normal'},phases=[dict(id=p) for p in ids]), CAPS)
        manifest = (PLATFORM / 'update-manifest.txt').read_text()
        for name in ('web/remote_actions.py','web/ssh_actions.py','web/persistence_actions.py','scripts/11-persistence.sh'):
            self.assertIn('|' + name, manifest)


class Actions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-remote-fixture',
                        MRNOBODY_RUN_MODE='standalone', MRNOBODY_TARGET=TARGET['target'],
                        MRNOBODY_PROTOCOL='ssh', MRNOBODY_PASSWORD='RUNTIME_PASSWORD',
                        MRN_POWERSHELL_SECRET='printf lab')

    def test_linux_success_warnings_invalid_and_exit_255(self):
        for code in (0, 2, 255):
            result = remote.perform('10', TARGET, self.env, ssh=Mock(return_value=framed(code, stderr=b'warning')))
            self.assertEqual(result['result'], 'success' if code == 0 else 'action_error')
            self.assertEqual(result['exit_code'], code)
            if code == 0: self.assertEqual(result['execution_status'], 'success_with_warning')
        result = remote.perform('10', TARGET, self.env, ssh=Mock(return_value=(255,(b'',0),(b'auth',4))))
        self.assertEqual(result['result'], 'failed')
        self.assertEqual(result['execution_status'], 'transport_auth_error')

    def test_windows_regression_reuses_ntlm_and_preview(self):
        factory = Mock()
        factory.return_value.run_ps.return_value = SimpleNamespace(status_code=0,std_out=b'lab RUNTIME_PASSWORD',std_err=b'warning')
        target = dict(TARGET, platform='windows',protocol='winrm-https',port=5986)
        result = remote.perform('10',target,self.env,session_factory=factory)
        self.assertEqual(result['result'],'success')
        self.assertEqual(factory.call_args.kwargs['transport'],'ntlm')
        self.assertNotIn('RUNTIME_PASSWORD',json.dumps(result))

    def test_each_persistence_method_cleanup_and_stable_identity(self):
        for method, (platform, technique, _) in persistence.METHODS.items():
            env = dict(self.env, MRNOBODY_METHOD=method,MRNOBODY_ARTIFACT='lesson',MRNOBODY_PERSISTENCE_RESOLVER='192.168.1.53')
            create = persistence.script(env,platform)
            again = persistence.script(dict(env,NORDIC_INCIDENT_ID='MRN-next-run'),platform)
            cleanup = persistence.script(dict(env,MRNOBODY_ACTION='cleanup'),platform)
            self.assertEqual(create,again)
            self.assertIn('mrnobody-p11-lesson',create)
            self.assertIn('mrnobody-p11-lesson',cleanup)
            self.assertNotIn('RUNTIME_PASSWORD',create)
            meta = persistence.metadata(env,platform)
            self.assertEqual(meta['mitre'],technique)
            self.assertEqual(meta['cleanup_artifact'],'lesson')
            if platform == 'windows':
                factory=Mock()
                factory.return_value.run_ps.return_value=SimpleNamespace(status_code=0,std_out=b'MrNobody P11 verified\n',std_err=b'')
                target=dict(TARGET,platform=platform,protocol='winrm-http')
                for action in ('create','create','cleanup','cleanup'):
                    if method in persistence.PAIRED:
                        factory.return_value.run_ps.return_value.std_out = b'MRN_P11_CLEANUP=complete' if action == 'cleanup' else b'MRN_P11=1,1,1900000000,0,0,0,-1'
                    factory.return_value.protocol.get_command_output.return_value = (factory.return_value.run_ps.return_value.std_out if method in persistence.PAIRED else b'MrNobody P11 verified\n', b'', 0)
                    result=remote.perform('11',target,dict(env,MRNOBODY_ACTION=action),session_factory=factory)
                    self.assertEqual(result['result'],'success')
                self.assertIn('artifact_ownership_conflict',create)
                self.assertIn('cleanup_verification_failed',cleanup)
            elif method not in {'process', 'process-dns'}:
                receipt = b'MRN_P11=1,1,1900000000,0,0,0,-1'
                if method == 'cron-systemd-process':
                    receipt += b'\nMRN_P11_PID=1234\n'
                self.assertEqual(remote.perform('11',TARGET,env,ssh=Mock(return_value=framed(output=receipt) if method in persistence.PAIRED | {'systemd'} else framed()))['result'],'success')
        self.assertNotIn('sudo ',persistence.script(dict(self.env,MRNOBODY_METHOD='systemd'),'linux'))
        unsupported = remote.perform('11',TARGET,self.env,ssh=Mock(return_value=framed(78)))
        self.assertEqual(unsupported['result'],'skipped')

    def inventory(self, hosts):
        p=self.base/'hosts.json'
        p.write_text(json.dumps({'producer':'P03','schema_version':2,'complete':True,
            'run_mode':'campaign','incident_id':self.env['NORDIC_INCIDENT_ID'],'hosts':hosts}))
        self.env.update(MRNOBODY_RUN_MODE='campaign',NORDIC_COMPROMISED_STATE=str(p))
        self.env.pop('MRNOBODY_TARGET',None)
        self.env.pop('MRNOBODY_PROTOCOL',None)
        return p

    def test_auto_platform_selection_overrides_and_foreign_inventory(self):
        p=self.inventory([dict(ip='192.168.1.8',platform='freebsd',compromised=True),dict(ip='192.168.1.9',platform='windows',compromised=True,rdp_password='DO_NOT_USE'),dict(ip=TARGET['target'],platform='linux',access='ssh',ssh_port=2222,compromised=True,ssh_password='DO_NOT_USE')])
        values=remote.targets(self.env)
        self.assertEqual([v['platform'] for v in values],['windows','linux'])
        self.assertNotIn('DO_NOT_USE',json.dumps(values))
        self.assertEqual(values[1]['port'],2222)
        self.assertEqual(remote.targets(dict(self.env,MRNOBODY_PLATFORM='linux')),[values[1]])
        self.assertEqual(remote.targets(dict(self.env,MRNOBODY_METHOD='systemd')),[values[1]])
        self.assertEqual(remote.targets(dict(self.env,MRNOBODY_TARGET=TARGET['target'])),[values[1]])
        p.write_text(json.dumps({'incident_id':'MRN-foreign','hosts':[]}))
        with self.assertRaises(ValueError):remote.targets(self.env)

    def test_fallback_transport_timeout_command_and_empty(self):
        self.inventory([dict(ip='192.168.1.9',platform='windows',compromised=True),dict(ip=TARGET['target'],platform='linux',compromised=True)])
        def response(result):return SimpleNamespace(returncode=0,stdout=json.dumps(result).encode())
        transport=response(dict(result='failed',warning='transport_error_details_omitted'))
        success=response(dict(result='success',exit_code=0,stdout_preview='safe',stderr_preview=''))
        command=response(dict(result='action_error',exit_code=2,execution_status='command_error'))
        # P10 retains first-compatible-target fallback. P11 now attempts every
        # verified host/method; its failure isolation lives in p11_campaign.py.
        for pid in ('10',):
            for results, expected in (([transport,success],0),([transport,transport],1)):
                with context_stdout():self.assertEqual(remote.run(pid,self.env,Mock(side_effect=results)),expected)
        with context_stdout():
            self.assertEqual(remote.run('10',self.env,Mock(return_value=command)),79)
            self.assertEqual(remote.run('10',self.env,Mock(side_effect=subprocess.TimeoutExpired('worker',60))),1)
        self.inventory([])
        with context_stdout():
            self.assertEqual(remote.run('10',self.env,Mock()),1)
            self.assertEqual(remote.run('11',self.env,Mock()),78)
        self.env['MRNOBODY_RUN_MODE']='standalone'
        self.env['MRNOBODY_TARGET']=TARGET['target']
        self.env['MRNOBODY_PROTOCOL']='ssh'
        with context_stdout():self.assertEqual(remote.run('11',self.env,Mock(return_value=transport)),1)

    def test_reports_preview_mitre_exports_and_live(self):
        response=SimpleNamespace(returncode=0,stdout=json.dumps(dict(result='success',exit_code=0,execution_status='success_with_warning',stdout_preview='safe lab output RUNTIME_PASSWORD\nPHASE=11 PHASE_FAILED',stderr_preview='warning')).encode())
        for pid in ('10','11'):
            with context_stdout():remote.run(pid,self.env,Mock(return_value=response if pid=='10' else SimpleNamespace(returncode=0,stdout=b'{"result":"success","exit_code":0}')))
        (self.base/'scripts').mkdir()
        for script in (PLATFORM/'scripts').glob('1[01]-*.sh'):shutil.copy(script,self.base/'scripts'/script.name)
        standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'],scenario='standalone-phase',phase_id='10',status='complete',phases={'10':'complete'})
        report=build_report(self.base,self.env['NORDIC_INCIDENT_ID'],environ=self.env,standalone=standalone)
        p=report['phases'][0]
        self.assertEqual(p['action_result'],'success_with_warning')
        self.assertEqual([t['id'] for t in p['mitre']['techniques']],['T1059.004'])
        self.assertIn('safe lab output',json.dumps(p['action_evidence']))
        self.assertNotIn('RUNTIME_PASSWORD',json.dumps(report))
        self.assertFalse(any(e['event']=='PHASE_FAILED' for e in report['events']))
        html=export_html(report,'ground-truth')
        self.assertIn('safe lab output',html)
        pdf=export_pdf(report,'ground-truth')
        from pypdf import PdfReader
        self.assertIn('safe lab output',''.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages))
        standalone.update(phase_id='11',phases={'11':'complete'})
        report=build_report(self.base,self.env['NORDIC_INCIDENT_ID'],environ=self.env,standalone=standalone)
        self.assertEqual([t['id'] for t in report['phases'][0]['mitre']['techniques']],['T1053.003','T1543.002'])
        self.assertIn('cleanup_artifact=telemetry',json.dumps(report['phases'][0]['action_evidence']))
        save_report(self.base,report)
        live=snapshot(self.base,CAPS)
        self.assertEqual(live['timeline'][0]['id'],'11')
        self.assertEqual(live['timeline'][0]['status'],'complete')


def context_stdout():
    from contextlib import redirect_stdout
    return redirect_stdout(io.StringIO())


class Endpoints(API):
    def test_linux_and_persistence_standalone_scheduler_and_custom(self):
        for pid in ('10','11'):
            import app as web
            web.campaign_process = None
            params=definition(pid,platform='linux')['phases'][0]['parameters']
            if pid=='11':params.update(method='systemd',action='cleanup',artifact='lesson')
            execution=dict(type='phase',id=pid,parameters=params,profile={'mode':'slow'})
            credentials=dict(ssh_password='SSH_RUNTIME',powershell='printf lab')
            self.assertEqual(self.client.post('/api/executions/run',json=dict(execution=execution,credentials=credentials)).status_code,200)
            saved=self.client.post('/api/schedules',json=dict(version=1,execution=execution,interval=0,enabled=True,at='2099-01-01T00:00:00Z')).get_json()
            self.assertEqual(self.client.post('/api/schedules/'+saved['id']+'/arm',json=credentials).status_code,200)
            stored = self.client.get('/api/schedules').get_json()['schedules']
            self.assertEqual(next(s for s in stored if s['id'] == saved['id'])['execution']['parameters'], params)
            import app as web
            web.campaign_process = None
            custom=self.client.post('/api/custom-scenarios',json=definition(pid,platform='linux')).get_json()
            self.assertEqual(self.client.post('/api/executions/run',json=dict(execution=dict(type='custom',id=custom['id']),credentials=credentials)).status_code,200)
            text=''.join(p.read_text() for p in self.base.rglob('*.json'))
            self.assertNotIn('SSH_RUNTIME',text)
            self.assertNotIn('printf lab',text)
            persisted = web.planning.store.path.read_bytes()
            self.assertNotIn(b'SSH_RUNTIME', persisted)
            self.assertNotIn(b'printf lab', persisted)


@unittest.skipIf(os.name=='nt','Real Bash fixtures run in Linux CI')
class BashFixtures(unittest.TestCase):
    def test_shell_commands_and_persistence_lifecycle_without_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base=Path(tmp)
            fake=base/'bin';fake.mkdir()
            home=base/'home';home.mkdir()
            def executable(name,source):
                p=fake/name;p.write_text(source);p.chmod(0o755)
            executable('sshpass','#!/bin/sh\nshift\nexec "$@"\n')
            executable('ssh','#!/bin/sh\nexec bash -s\n')
            executable('curl','#!/bin/sh\nprintf 204\n')
            executable('crontab','''#!/bin/sh
if [ "$1" = -l ]; then
    if [ -f "$HOME/table" ]; then cat "$HOME/table"; else echo 'no crontab for fixture' >&2; exit 1; fi
else cat > "$HOME/table"; fi
''')
            executable('systemctl','''#!/bin/sh
shift
case "$1" in
show-environment|daemon-reload) exit 0;;
show) printf 'not-found\n';;
enable) touch "$HOME/enabled";;
disable) rm -f "$HOME/enabled";;
is-enabled|is-active) test -f "$HOME/enabled";;
*) exit 1;;
esac
''')
            env=dict(os.environ,HOME=str(home),PATH=str(fake)+os.pathsep+os.environ['PATH'],
                     NORDIC_BASE_DIR=tmp,NORDIC_COMPROMISED_STATE=str(base/'state/compromised-hosts.json'),NORDIC_SSH_PASSWORD='SSH_RUNTIME',MRNOBODY_RUN_MODE='standalone',MRNOBODY_PASSWORD='SSH_RUNTIME',
                     MRNOBODY_PROTOCOL='ssh',MRNOBODY_TARGET=TARGET['target'])
            for command,expected in [('printf lab',0),('printf warning >&2',0),('if broken',2),('exit 255',255),('printf '+ 'x'*1000,0),("printf '%070000d' 0",0)]:
                result=remote.perform('10',TARGET,dict(env,MRN_POWERSHELL_SECRET=command))
                self.assertEqual(result['exit_code'],expected)
                self.assertLessEqual(len(result.get('stdout_preview','')),512)
            (home/'table').write_text('0 1 * * * echo preserve\n')
            for method in ('cron',):
                for index,action in enumerate(('create','create','cleanup','cleanup')):
                    result=remote.perform('11',TARGET,dict(env,MRNOBODY_METHOD=method,MRNOBODY_ACTION=action))
                    self.assertEqual(result['result'],'skipped' if index==1 else 'success',result)
                    if index==1:self.assertEqual(result['action'],'not_attempted')
                    if method=='cron':
                        table=(home/'table').read_text()
                        self.assertIn('echo preserve',table)
                        self.assertEqual(table.count('# MrNobody controlled lab P11'),1 if action=='create' else 0)
                    else:self.assertEqual((home/'.config/systemd/user/mrnobody-p11-telemetry.service').exists(),action=='create')
            # User-manager lifecycle and ownership are covered by p11_linux.py.
            # Real standalone runner/report wrapper; only the fake SSH is reachable.
            shutil.copytree(PLATFORM/'web',base/'web')
            shutil.copytree(PLATFORM/'scripts',base/'scripts')
            shutil.copytree(PLATFORM/'scenarios',base/'scenarios')
            (base/'config').mkdir()
            config=(PLATFORM/'config/defaults.conf').read_text().replace('NORDIC_BASE_DIR="/opt/nordic-attack"',f'NORDIC_BASE_DIR="{base}"')
            config+='\nNORDIC_PHASE_DELAY_MIN=0\nNORDIC_PHASE_DELAY_MAX=0\n'
            (base/'config/defaults.conf').write_text(config)
            (base/'venv/bin').mkdir(parents=True)
            (base/'venv/bin/python').symlink_to(sys.executable)
            for p in (base/'scripts').glob('*'):p.chmod(0o755)
            env['MRN_POWERSHELL_SECRET']='printf lab'
            # This existing real-Bash harness retains legacy cron compatibility;
            # paired lifecycle is exercised separately with fake service providers.
            env['MRNOBODY_METHOD']='cron'
            for pid in ('10','11'):
                result=subprocess.run(['bash',str(base/'scripts/run-phase.sh'),pid,'--target',TARGET['target'],'--protocol','ssh'],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            # Full Incident uses real P10/P11 after an inert access fixture.
            for p in (base/'scripts').glob('0[1-9]-*.sh'):p.write_text('#!/bin/sh\nexit 0\n')
            access=next((base/'scripts').glob('03-*.sh'))
            access.write_text('#!/bin/sh\nprintf \'{"producer":"P03","schema_version":2,"complete":true,"run_mode":"campaign","incident_id":"%s","hosts":[{"ip":"192.168.1.10","platform":"linux","access":"ssh","compromised":true}]}\' "$NORDIC_INCIDENT_ID" > "$NORDIC_COMPROMISED_STATE"\n')
            for mode in ('normal','slow','custom'):
                value=definition('10','auto',platform='linux')
                value['profile']={'mode':mode,'duration':60 if mode=='slow' else 0}
                value['phases']=[dict(id='01'),dict(id='03')]+value['phases']+[dict(id='11',parameters={'platform':'linux', 'method':'cron'}),dict(id='04')]
                value=plan(validate(value,CAPS))
                # Offsets were checked by unit tests; do not wait a minute here.
                for p in value['phases']:p['timing']={}
                env.update(NORDIC_INCIDENT_ID='MRN-custom-'+mode,MRN_EXECUTION=json.dumps(value),MRN_STARTED='0')
                result=subprocess.run(['bash',str(base/'scenarios/full-incident.sh')],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            env.update(NORDIC_INCIDENT_ID='MRN-linux-command-error', MRN_POWERSHELL_SECRET='if broken')
            result=subprocess.run(['bash',str(base/'scenarios/full-incident.sh')],env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report=load_report(base/'reports','MRN-linux-command-error')
            self.assertEqual(next(p for p in report['phases'] if p['id']=='10')['action_result'],'command_error')
            self.assertEqual(next(p for p in report['phases'] if p['id']=='04')['status'],'success')
            env['MRN_POWERSHELL_SECRET']='printf lab'
            # Unstructured Full Incident deliberately clears method overrides.
            # Pin legacy cron in this isolated script copy; paired providers are
            # covered by persistence_dns.py without invoking a real user manager.
            p11_phase = base/'scripts/11-persistence.sh'
            p11_phase.write_text(p11_phase.read_text().replace('exec ', 'export MRNOBODY_METHOD=cron\nexec ', 1))
            env.pop('MRN_EXECUTION');env.update(NORDIC_INCIDENT_ID='MRN-full-remote',MRN_POWERSHELL_ENABLED='1',NORDIC_SSH_PASSWORD='SSH_RUNTIME')
            result=subprocess.run(['bash',str(base/'scenarios/full-incident.sh')],env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report=load_report(base/'reports','MRN-full-remote')
            self.assertEqual(next(p for p in report['phases'] if p['id']=='10')['status'],'success')
            p11=next(p for p in report['phases'] if p['id']=='11')
            self.assertEqual(p11['status'],'skipped')
            self.assertEqual(p11.get('method_results'), [])
            self.assertNotIn('artifact_collisions', p11)
            self.assertEqual(next(p for p in report['phases'] if p['id']=='04')['status'],'success')


if __name__=='__main__':unittest.main()
