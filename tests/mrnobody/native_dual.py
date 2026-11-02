"""P13 and dual P10 offline contracts; no lab connections or native actions."""
import contextlib
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
import native_actions as native
import app as web
from execution import record, snapshot, phase_environment
from reports import build_report, read_metadata
from report_exports import export_html, export_pdf
from scenario_model import catalogue, validate, plan
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)


def definition(mode='auto', behavior='certutil-decode'):
    params = {'behavior': behavior}
    if mode == 'fixed': params.update(target='192.168.1.15', protocol='winrm-http')
    return dict(version=1, name='Native lab', target_mode=mode, profile={'mode':'normal'},
                phases=([{'id':'01'}, {'id':'03'}] if mode == 'auto' else []) + [{'id':'13', 'parameters':params}])


class NativeDual(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-native-dual',
                        MRNOBODY_RUN_MODE='campaign', NORDIC_RDP_PASSWORD='PASSWORD_TO_REDACT', NORDIC_SSH_PASSWORD='SSH_SECRET')
        self.inventory(['windows', 'linux'])

    def inventory(self, platforms):
        path=self.base/'state/compromised-hosts.json'; path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(dict(incident_id=self.env['NORDIC_INCIDENT_ID'], hosts=[
            dict(ip=f'192.168.1.{i+15}',platform=p,access='rdp' if p=='windows' else 'ssh',compromised=True)
            for i,p in enumerate(platforms)])))
        self.env['NORDIC_COMPROMISED_STATE']=str(path)

    def invoke(self, results):
        def worker(argv, **kwargs):
            target=json.loads(kwargs['env']['MRN_REMOTE_TARGET'])
            result=dict(results.get(target['platform'], {'result':'success','exit_code':0}))
            return SimpleNamespace(returncode=0,stdout=json.dumps(result))
        return Mock(side_effect=worker)

    def run_phase(self, pid, env, worker):
        with contextlib.redirect_stdout(io.StringIO()): return remote.run(pid,env,worker)

    def report(self, pid, code):
        (self.base/'scripts').mkdir(exist_ok=True)
        shutil.copy(next((PLATFORM/'scripts').glob(pid+'-*.sh')),self.base/'scripts')
        return build_report(self.base,self.env['NORDIC_INCIDENT_ID'],code,self.env,
            standalone=dict(incident_id=self.env['NORDIC_INCIDENT_ID'],phase_id=pid,status='complete' if code in (0,78) else 'failed',phases={pid:'complete' if code==0 else 'skipped' if code in (78,79) else 'failed'}))

    def test_p13_registry_dependencies_order_timing_and_fixed(self):
        self.assertEqual(CAPS['13']['dependencies'],['03'])
        self.assertFalse(CAPS['13']['runtime_powershell'])
        self.assertEqual(CAPS['13']['fields']['behavior']['options'],list(native.BEHAVIORS))
        self.assertNotIn('command',CAPS['13']['fields'])
        self.assertEqual(CAPS['13']['fields']['protocol']['options'],['winrm-http','winrm-https'])
        for behavior in native.BEHAVIORS:
            for mode in ('auto','fixed'):
                for timing in ('normal','slow','custom'):
                    value=definition(mode,behavior);value['profile']={'mode':timing}
                    result=plan(validate(value,CAPS))
                    self.assertEqual(result['phases'][-1]['parameters']['behavior'],behavior)
        for bad in ('powershell', 'regsvr32', '../payload'):
            with self.assertRaises(ValueError): validate(definition(behavior=bad),CAPS)
        for params in ({'command':'Get-Date'}, {'protocol':'ssh'}, {'powershell_windows':'secret'}):
            value=definition('fixed');value['phases'][0]['parameters'].update(params)
            with self.assertRaises(ValueError):validate(value,CAPS)
        value=definition();value['phases'].reverse()
        with self.assertRaises(ValueError):validate(value,CAPS)
        full=read_metadata(PLATFORM/'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
        self.assertLess(full.index('11'),full.index('13'));self.assertLess(full.index('13'),full.index('04'))
        validate(dict(version=1,name='Full',target_mode='auto',profile={'mode':'normal'},phases=[{'id':p} for p in full]),CAPS)
        env=phase_environment('13',dict(self.env,MRN_EXECUTION=json.dumps(definition()),MRN_STARTED='0',MRNOBODY_BEHAVIOR='bits-job'),sleep=lambda _:None)
        self.assertEqual(env['MRNOBODY_BEHAVIOR'],'certutil-decode')
        self.assertEqual(env['MRNOBODY_PASSWORD'],'PASSWORD_TO_REDACT')

    def test_p13_safe_scripts_parse_without_execution(self):
        shell=shutil.which('powershell') or shutil.which('pwsh')
        for behavior in native.BEHAVIORS:
            source=native.script({'MRNOBODY_BEHAVIOR':behavior})
            self.assertIn('finally',source);self.assertIn('Guid',source)
            self.assertNotIn('http',source);self.assertNotIn('SetNotifyCmdLine',source)
            if shell:
                result=subprocess.run([shell,'-NoProfile','-NonInteractive','-Command',
                    '$s=[Console]::In.ReadToEnd();$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null;if($e.Count){exit 1}'],input=source,text=True,capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_p13_real_transport_result_cleanup_redaction_and_mappings(self):
        target=dict(target='192.168.1.15',platform='windows',protocol='winrm-http',port=5985,username='Administrator')
        for behavior,(tool,technique,_) in native.BEHAVIORS.items():
            with self.subTest(behavior=behavior):
                log=self.base/'logs/incident-ground-truth.log'
                if log.exists():log.unlink()
                env=dict(self.env,MRNOBODY_BEHAVIOR=behavior)
                artifact='MrNobody-P13-'+'a'*24
                response=SimpleNamespace(status_code=0,std_out=('artifact_path=C:\\Temp\\'+artifact+'\njob_name: '+artifact+'\ncleanup=complete\nPASSWORD_TO_REDACT').encode(),std_err=b'benign warning')
                session=Mock();session.run_ps.return_value=response
                result=remote.perform('13',target,env,session_factory=Mock(return_value=session))
                self.assertEqual(result['result'],'success');self.assertEqual(result['cleanup'],'complete')
                self.assertEqual(result['artifact_path'],'C:\\Temp\\'+artifact)
                self.assertEqual(result['job_name'],artifact)
                self.assertNotIn('PASSWORD_TO_REDACT',json.dumps(result))
                worker=self.invoke({'windows':result})
                self.assertEqual(self.run_phase('13',env,worker),0)
                self.assertEqual(worker.call_count,1)
                report=self.report('13',0);phase=report['phases'][0]
                self.assertEqual([t['id'] for t in phase['mitre']['techniques']],[technique])
                self.assertEqual(report['mitre_summary'][0]['id'],technique)
                event=next(e for e in phase['events'] if e['event']=='NATIVE_ACTION_SUCCESS')
                for key in ('behavior','executable','method','target','exit_code','cleanup','artifact_path'):
                    self.assertIn(key,event['fields'])
                self.assertEqual(event['fields']['executable'],tool)
                self.assertIn('Attackers abuse',phase['analysis']['investigation_tasks'][0])
                self.assertIn(behavior,export_html(report,'ground-truth'))
                pdf=export_pdf(report,'ground-truth');self.assertTrue(pdf.startswith(b'%PDF'))
                response.status_code=3
                result=remote.perform('13',target,env,session_factory=Mock(return_value=session))
                self.assertEqual(result['result'],'action_error')
                self.assertEqual(self.run_phase('13',env,self.invoke({'windows':result})),79)

    def test_p13_missing_windows_fallback_hard_failure_and_live(self):
        self.inventory(['linux'])
        worker=self.invoke({});self.assertEqual(self.run_phase('13',self.env,worker),78);worker.assert_not_called()
        self.inventory(['windows','windows'])
        worker=Mock(side_effect=[SimpleNamespace(returncode=0,stdout=json.dumps(dict(result='failed',warning='transport_error_details_omitted'))),SimpleNamespace(returncode=0,stdout=json.dumps(dict(result='success',exit_code=0)))])
        self.assertEqual(self.run_phase('13',self.env,worker),0);self.assertEqual(worker.call_count,2)
        self.assertEqual(self.run_phase('13',self.env,self.invoke({'windows':dict(result='failed',warning='transport_error_details_omitted')})),1)
        env=dict(self.env,MRN_OVERVIEW=json.dumps(dict(type='campaign',id='full-incident',phases=[{'id':'13'},{'id':'04'}])))
        record(self.base,env,123)
        (self.base/'state/campaign.json').write_text(json.dumps(dict(incident_id=self.env['NORDIC_INCIDENT_ID'],status='running',phases={'13':'skipped','04':'running'})))
        live=snapshot(self.base,CAPS,Mock(poll=lambda:None))
        self.assertEqual(live['timeline'][0]['name'],CAPS['13']['name']);self.assertEqual(live['current_phase']['id'],'04')
        self.assertEqual(self.run_phase('13',dict(self.env,MRNOBODY_BEHAVIOR='bad'),self.invoke({})),1)

    def test_dual_commands_blank_partial_transport_and_per_platform_evidence(self):
        cases=[('Get-Date','',0,['windows']),('','printf lab',0,['linux']),('Get-Date','printf lab',0,['windows','linux']),(' \n ','printf lab',0,['linux']),('','',78,[]),(' \n ',' \t ',78,[])]
        for ps,bash,code,platforms in cases:
            worker=self.invoke({})
            env=remote.command_environment({'powershell_windows':ps,'bash':bash},dict(self.env),full=True)
            self.assertEqual(self.run_phase('10',env,worker),code)
            self.assertEqual([json.loads(c.kwargs['env']['MRN_REMOTE_TARGET'])['platform'] for c in worker.call_args_list],platforms)
            for call in worker.call_args_list:
                platform=json.loads(call.kwargs['env']['MRN_REMOTE_TARGET'])['platform']
                self.assertEqual(call.kwargs['env']['MRN_POWERSHELL_SECRET'],ps.strip() if platform=='windows' else bash.strip())
        env=remote.command_environment({'powershell_windows':'Get-Date','bash':'printf lab'},dict(self.env),full=True)
        log=self.base/'logs/incident-ground-truth.log';log.unlink()
        self.assertEqual(self.run_phase('10',env,self.invoke({})),0)
        report=self.report('10',0)
        self.assertEqual({a['platform'] for a in report['phases'][0]['actions']},{'windows','linux'})
        self.assertNotIn('Get-Date',json.dumps(report));self.assertNotIn('printf lab',json.dumps(report))
        controlled=dict(result='action_error',exit_code=2,warning='command_error')
        self.assertEqual(self.run_phase('10',env,self.invoke({'linux':controlled})),0)
        self.assertEqual(self.report('10',0)['phases'][0]['action_result'],'success_with_warning')
        transport=dict(result='failed',warning='transport_error_details_omitted')
        self.assertEqual(self.run_phase('10',env,self.invoke({'linux':transport})),1)
        self.inventory(['windows'])
        self.assertEqual(self.run_phase('10',env,self.invoke({})),0)
        self.assertIn('no_compatible_access_targets',log.read_text())
        self.inventory([])
        self.assertEqual(self.run_phase('10',env,self.invoke({})),78)


class NativeDualEndpoints(API):
    def test_p13_standalone_custom_scheduler_serialization(self):
        for behavior in native.BEHAVIORS:
            web.campaign_process=None
            spec=dict(type='phase',id='13',parameters=definition('fixed',behavior)['phases'][0]['parameters'],profile={'mode':'slow'})
            response=self.client.post('/api/executions/run',json=dict(execution=spec,credentials={'rdp_password':'RUNTIME_SECRET'}))
            self.assertEqual(response.status_code,200,response.json)
            self.assertIn('--behavior',self.launch.call_args.args[1])
            saved=self.client.post('/api/schedules',json=dict(version=1,execution=spec,interval=0,enabled=True,at='2099-01-01T00:00:00Z'))
            self.assertEqual(saved.status_code,201,saved.json)
            self.assertIn(behavior,web.planning.store.path.read_text(errors='ignore'))
            custom=self.save(definition('fixed',behavior));web.campaign_process=None
            response=self.client.post('/api/executions/run',json=dict(execution={'type':'custom','id':custom['id']},credentials={'rdp_password':'RUNTIME_SECRET'}))
            self.assertEqual(response.status_code,200,response.json)
            self.assertNotIn(b'RUNTIME_SECRET',web.planning.store.path.read_bytes())

    def test_full_and_scheduled_dual_runtime_fields_never_persist(self):
        for ps,bash in [('Get-Date',''),('','printf lab'),('Get-Date','printf lab'),(' \n ',' \t ')]:
            web.campaign_process=None
            response=self.client.post('/api/start',json=dict(ssh_password='S',rdp_password='R',powershell_enabled=True,powershell_windows=ps,bash=bash))
            self.assertEqual(response.status_code,200,response.json)
            env=self.launch.call_args.kwargs['env']
            self.assertEqual(env['MRN_POWERSHELL_WINDOWS_SECRET'],ps.strip())
            self.assertEqual(env['MRN_BASH_SECRET'],bash.strip())
            self.assertNotIn('Get-Date',env['MRN_OVERVIEW'])
        execution=dict(type='campaign',id='full-incident',powershell_enabled=True,profile={'mode':'slow'})
        schedule=self.client.post('/api/schedules',json=dict(version=1,execution=execution,interval=0,enabled=True,at='2099-01-01T00:00:00Z')).json
        credentials=dict(powershell_windows='WINDOWS_COMMAND_SECRET',bash='BASH_COMMAND_SECRET',ssh_password='S',rdp_password='R')
        self.assertEqual(self.client.post('/api/schedules/'+schedule['id']+'/arm',json=credentials).status_code,200)
        web.campaign_process=None
        web.planning.scheduler.observe=None
        result=self.client.post('/api/schedules/'+schedule['id']+'/run',json=credentials)
        self.assertEqual(result.status_code,200,result.json)
        env=self.launch.call_args.kwargs['env']
        self.assertEqual(env['MRN_BASH_SECRET'],'BASH_COMMAND_SECRET')
        self.assertNotIn(b'COMMAND_SECRET',web.planning.store.path.read_bytes())
        self.assertEqual([p['id'] for p in json.loads(env['MRN_EXECUTION'])['phases']][-9:],['13','14','18','16','04','17','05','06','07'])


@unittest.skipIf(os.name=='nt','Real Bash runners are verified by Linux CI')
class CampaignRunners(unittest.TestCase):
    def test_native_standalone_and_full_dual_skip_continue_without_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base=Path(tmp)
            for directory in ('web','scripts','scenarios'):
                shutil.copytree(PLATFORM/directory,base/directory)
            (base/'config').mkdir()
            config=(PLATFORM/'config/defaults.conf').read_text().replace('NORDIC_BASE_DIR="/opt/nordic-attack"',f'NORDIC_BASE_DIR="{base}"')
            (base/'config/defaults.conf').write_text(config+'\nNORDIC_PHASE_DELAY_MIN=0\nNORDIC_PHASE_DELAY_MAX=0\n')
            (base/'venv/bin').mkdir(parents=True)
            (base/'venv/bin/python').symlink_to(sys.executable)
            fake=base/'fake';fake.mkdir()
            (fake/'winrm.py').write_text('''class Session:
    def __init__(self,*args,**kwargs):pass
    def run_ps(self,source):
        class Result:
            status_code=0
            std_out=b'artifact_path=C:\\\\Temp\\\\MrNobody-P13-fixture\\ncleanup=complete\\n'
            std_err=b''
        import sys
        if sys.argv[1] == '12': Result.std_out=b'MRN_P12_OK\\n'
        if sys.argv[1] == '14': Result.std_out=''.join('MRN_BEACON=%d,ok\\n' % i for i in range(1,6)).encode()
        if sys.argv[1] == '18':
            import os
            mode=os.environ.get('MRN_DNS_FIXTURE','success')
            Result.std_out=''.join('MRN_DNS=%d,%s,1793627656000\\n' % (i,'failed' if mode=='failed' or mode=='partial' and i==2 else 'ok') for i in range(1,4)).encode()
        return Result()
''')
            for name,source in {'sshpass':'#!/bin/sh\nshift\nexec "$@"\n','ssh':'#!/bin/sh\nexec bash -s\n'}.items():
                path=fake/name;path.write_text(source);path.chmod(0o755)
            for path in (base/'scripts').glob('*'):path.chmod(0o755)
            env=dict(os.environ,NORDIC_BASE_DIR=tmp,NORDIC_INCIDENT_ID='MRN-native-runner',MRNOBODY_PASSWORD='RUNTIME',
                     NORDIC_COMPROMISED_STATE=str(base/'state/compromised-hosts.json'),
                     NORDIC_RDP_PASSWORD='RUNTIME',NORDIC_SSH_PASSWORD='RUNTIME',PYTHONPATH=str(fake),PATH=str(fake)+os.pathsep+os.environ['PATH'])
            for outcome,code in [('success',0),('partial',80),('failed',1)]:
                env.update(NORDIC_INCIDENT_ID='MRN-dns-'+outcome,MRN_DNS_FIXTURE=outcome)
                result=subprocess.run(['bash',str(base/'scripts/run-phase.sh'),'dns','--target','192.168.1.15','--protocol','winrm-http','--dns-behavior','encoded-marker','--dns-endpoint','192.168.1.1'],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,code,result.stdout+result.stderr)
                report=json.loads((base/'reports'/('MRN-dns-'+outcome+'.json')).read_text())
                self.assertEqual(report['phases'][0]['status'],{'success':'success','partial':'partial','failed':'failure'}[outcome])
            env['MRN_DNS_FIXTURE']='success'
            for behavior,(_,technique,_) in native.BEHAVIORS.items():
                env['NORDIC_INCIDENT_ID']='MRN-runner-'+behavior
                before=set((base/'reports').glob('*.json'))
                result=subprocess.run(['bash',str(base/'scripts/run-phase.sh'),'13','--target','192.168.1.15','--protocol','winrm-http','--behavior',behavior],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                created=set((base/'reports').glob('*.json'))-before
                self.assertEqual(len(created),1,result.stdout+result.stderr)
                report=json.loads(created.pop().read_text())
                self.assertEqual(report['phases'][0]['mitre']['techniques'][0]['id'],technique)
            # Keep P10/P13 runners real. Every other phase is an inert fixture;
            # P03 creates only a synthetic inventory for the local fake transports.
            for path in (base/'scripts').glob('[0-9][0-9]-*.sh'):
                if path.name[:2] not in {'10','12','13','14','18'}:
                    metadata='\n'.join(line for line in path.read_text().splitlines() if line.startswith('#'))
                    path.write_text(metadata+'\nexit 0\n')
            access=next((base/'scripts').glob('03-*.sh'))
            access.write_text('''#!/bin/sh
python3 - <<'PY'
import json,os
hosts=[dict(ip='192.168.1.15',platform='windows',access='rdp',compromised=True),dict(ip='192.168.1.16',platform='linux',access='ssh',compromised=True)]
with open(os.environ['NORDIC_COMPROMISED_STATE'],'w') as f:json.dump(dict(incident_id=os.environ['NORDIC_INCIDENT_ID'],hosts=hosts),f)
PY
''')
            full=read_metadata(PLATFORM/'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
            for mode in ('normal','slow','custom'):
                for blank in (False,True):
                    env['MRN_DNS_FIXTURE']='partial' if mode=='custom' else 'success'
                    iid='MRN-dual-'+mode+('-blank' if blank else '-both')
                    env.update(NORDIC_INCIDENT_ID=iid,MRN_POWERSHELL_ENABLED='1',MRN_POWERSHELL_WINDOWS_SECRET=' \n ' if blank else 'Get-Date',MRN_BASH_SECRET=' \t ' if blank else 'printf lab')
                    if mode!='normal':
                        value=dict(version=1,name='Full fixture',target_mode='auto',profile={'mode':mode},phases=[dict(id=p) for p in full if p!='08'])
                        value=plan(validate(value,CAPS))
                        for phase in value['phases']:phase['timing']={}
                        env.update(MRN_EXECUTION=json.dumps(value),MRN_STARTED='0')
                    else:env.pop('MRN_EXECUTION',None)
                    result=subprocess.run(['bash',str(base/'scenarios/full-incident.sh')],env=env,capture_output=True,text=True,timeout=30)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    report=json.loads((base/'reports'/(iid+'.json')).read_text())
                    phases={p['id']:p for p in report['phases']}
                    self.assertEqual(phases['10']['status'],'skipped' if blank else 'success')
                    self.assertEqual(phases['13']['status'],'success')
                    self.assertEqual(phases['12']['status'],'success')
                    self.assertEqual(phases['14']['status'],'success')
                    self.assertEqual(phases['18']['status'],'partial' if mode=='custom' else 'success')
                    self.assertEqual(phases['04']['status'],'success')
                    if not blank:self.assertEqual({a['platform'] for a in phases['10']['actions']},{'windows','linux'})
                    else:self.assertIn('NOT_CONFIGURED',json.dumps(phases['10']))


if __name__=='__main__':unittest.main()
