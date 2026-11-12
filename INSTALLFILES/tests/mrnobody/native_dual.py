"""Dual P10 offline contracts; no lab connections or remote actions."""
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
import app as web
from execution import record, snapshot, phase_environment
from reports import build_report, read_metadata
from report_exports import export_html, export_pdf
from scenario_model import catalogue, validate, plan
sys.path.insert(0, str(Path(__file__).parent))
from planning import API

CAPS = catalogue(PLATFORM / 'scripts', read_metadata)




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
        self.assertEqual([p['id'] for p in json.loads(env['MRN_EXECUTION'])['phases']][-4:],['04','05','06','07'])


@unittest.skipIf(os.name=='nt','Real Bash runners are verified by Linux CI')
class CampaignRunners(unittest.TestCase):
    def test_full_dual_skip_continue_without_network(self):
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
            (fake/'winrm.py').write_text("class Session:\n    def __init__(self,*args,**kwargs): pass\n    def run_ps(self,source):\n        class Result:\n            status_code=0\n            std_out=b'fixture'\n            std_err=b''\n        return Result()\n")
            for name,source in {'sshpass':'#!/bin/sh\nshift\nexec "$@"\n','ssh':'#!/bin/sh\nexec bash -s\n'}.items():
                path=fake/name;path.write_text(source);path.chmod(0o755)
            for path in (base/'scripts').glob('*'):path.chmod(0o755)
            env=dict(os.environ,NORDIC_BASE_DIR=tmp,NORDIC_INCIDENT_ID='MRN-native-runner',MRNOBODY_PASSWORD='RUNTIME',
                     NORDIC_COMPROMISED_STATE=str(base/'state/compromised-hosts.json'),
                     NORDIC_RDP_PASSWORD='RUNTIME',NORDIC_SSH_PASSWORD='RUNTIME',PYTHONPATH=str(fake),PATH=str(fake)+os.pathsep+os.environ['PATH'])
            # Keep P10 real; other phases are inert fixtures.
            # P03 creates only a synthetic inventory for the local fake transports.
            for path in (base/'scripts').glob('[0-9][0-9]-*.sh'):
                if path.name[:2] != '10':
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
                    self.assertEqual(phases['04']['status'],'success')
                    if not blank:self.assertEqual({a['platform'] for a in phases['10']['actions']},{'windows','linux'})
                    else:self.assertIn('NOT_CONFIGURED',json.dumps(phases['10']))


if __name__=='__main__':unittest.main()
