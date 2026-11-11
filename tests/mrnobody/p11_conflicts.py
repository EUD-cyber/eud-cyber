"""P11 collision receipts, no-write preflight and runner/report contracts offline."""
import base64
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import persistence_actions as p
import remote_actions as remote
import reports
from execution import snapshot
from p11_windows import factory, TARGET as WINDOWS

LINUX = dict(target='192.168.1.20', platform='linux', protocol='ssh', port=22, username='ubuntu')
RECEIPT = b'MRN_P11_EXISTS=artifact_already_exists\n'


class Receipts(unittest.TestCase):
    def test_windows_all_methods_and_linux_all_methods(self):
        for method, (platform, _, _) in p.METHODS.items():
            env = dict(MRNOBODY_METHOD=method, MRNOBODY_PASSWORD='runtime', MRNOBODY_RUN_MODE='standalone',
                       MRNOBODY_PERSISTENCE_RESOLVER='192.168.1.53')
            if platform == 'windows':
                f = factory(RECEIPT)
                f.return_value.run_ps.return_value = Response(status_code=0, std_out=RECEIPT, std_err=b'')
                result = remote.perform('11', WINDOWS, env, session_factory=f)
            else:
                framed = RECEIPT + b'\nMRN_REMOTE_EXIT=0__MRN_END__\n'
                result = remote.perform('11', LINUX, env, ssh=Mock(return_value=(0,(framed,len(framed)),(b'',0))))
            self.assertEqual(result['result'], 'skipped', (method,result))
            self.assertEqual(result['action'], 'not_attempted')
            self.assertEqual(result['cleanup_required'], 'false')
            self.assertEqual(result['ownership'], 'not_assumed')

    def test_only_complete_prewrite_receipt_can_skip(self):
        for text in (RECEIPT.decode() + 'MRN_P11_ERROR=create,action_failed\n',
                     'MRN_P11=1,1,1900000000,0,0,0,-1\n' + RECEIPT.decode(),
                     'artifact_ownership_conflict', RECEIPT.decode()*2):
            self.assertIsNone(p.collision_evidence(text, {}, 'linux'))
        self.assertIsNone(p.collision_evidence(RECEIPT.decode(), {}, 'linux', 1))
        self.assertIsNone(p.collision_evidence(RECEIPT.decode(), {'MRNOBODY_ACTION':'cleanup'}, 'linux'))
        failed = remote.perform('11', WINDOWS, {'MRNOBODY_METHOD':'service','MRNOBODY_PASSWORD':'runtime'},
            session_factory=factory(b'MRN_P11_ERROR=compile,artifact_ownership_conflict\n',1))
        self.assertEqual(failed['result'],'failed')
        self.assertEqual(failed['cleanup_required'],'true')

    def test_runner_standalone_report_and_gui(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base=Path(tmp); (base/'scripts').mkdir()
            shutil.copy(ROOT/'TESTFILES/ATTACKER-V2/scripts/11-persistence.sh',base/'scripts/11-persistence.sh')
            env=dict(NORDIC_BASE_DIR=tmp,NORDIC_INCIDENT_ID='MRN-p11-collision',MRN_OVERVIEW='1',
                     MRNOBODY_RUN_MODE='standalone',MRNOBODY_TARGET=LINUX['target'],
                     MRNOBODY_PROTOCOL='ssh',MRNOBODY_METHOD='cron',MRNOBODY_ARTIFACT='telemetry')
            receipt=p.collision_evidence(RECEIPT.decode(),env,'linux')
            invoke=Mock(return_value=Response(returncode=0,stdout=json.dumps(receipt).encode()))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote.run('11',env,invoke),78)
            truth=(base/'logs/incident-ground-truth.log').read_text()
            self.assertIn('P11_ARTIFACT_EXISTS',truth)
            for field in ('target=192.168.1.20','method=cron','requested_artifact=telemetry',
                          'reason=artifact_already_exists','action=not_attempted','cleanup_required=false'):
                self.assertIn(field,truth.replace('"',''))
            self.assertNotIn('PHASE_COMPLETE',truth)
            self.assertNotIn('PHASE_FAILED',truth)
            # Exercise the actual standalone finalizer, including exit-78 mapping.
            with patch.object(reports.subprocess,'Popen',return_value=Mock(wait=Mock(return_value=78))), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(reports.run_phase(base,'11','unused',env),0)
            report=json.loads((base/'reports/MRN-p11-collision.json').read_text())
            phase=report['phases'][0]
            self.assertEqual(phase['status'],'skipped')
            self.assertIn('no action attempted',phase['action_outcome'])
            self.assertEqual(phase['artifact_collisions'][0]['requested_artifact'],'telemetry')
            from report_exports import export_html, export_pdf
            self.assertIn('no action attempted',export_html(report,'ground-truth'))
            self.assertTrue(export_pdf(report,'ground-truth').startswith(b'%PDF'))
            # A launch identity is unnecessary when the completed report is discovered.
            overview=snapshot(base,{'11':{'name':'Persistence'}})
            self.assertEqual(overview['timeline'][0]['status'],'skipped')

    def test_skip_does_not_hide_another_target_error_or_retry_collision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            env=dict(NORDIC_BASE_DIR=tmp,NORDIC_INCIDENT_ID='MRN-p11-mixed',MRNOBODY_METHOD='cron')
            receipt=p.collision_evidence(RECEIPT.decode(),env,'linux')
            responses=[Response(returncode=0,stdout=json.dumps(dict(result='failed',warning='transport_error_details_omitted')).encode()),
                       Response(returncode=0,stdout=json.dumps(receipt).encode())]
            invoke=Mock(side_effect=responses)
            with patch.object(remote,'targets',return_value=[LINUX,dict(LINUX,target='192.168.1.21'),dict(LINUX,target='192.168.1.22')]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(remote.run('11',env,invoke),1)
            self.assertEqual(invoke.call_count,2)


@unittest.skipIf(os.name=='nt','Linux flock and uid contracts')
class LinuxPreflight(unittest.TestCase):
    def driver(self,method,home,provider):
        source=p.script(dict(MRNOBODY_METHOD=method,MRNOBODY_PERSISTENCE_RESOLVER='192.168.1.53'),'linux')
        encoded=re.search(r"base64.b64decode\('([A-Za-z0-9+/=]+)'\)",source)[1]
        ns={}
        out=io.StringIO()
        with patch('pathlib.Path.home',return_value=home),patch('shutil.which',return_value='/fake'),patch('subprocess.run',side_effect=provider),patch('sys.stdin',io.StringIO('harmless core')),contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as exited:
                exec(compile(base64.b64decode(encoded),'<preflight>','exec'),ns)
        return exited.exception.code,out.getvalue()

    def test_collisions_across_methods_preserve_unknown_corrupt_and_symlink(self):
        for method in ('cron','systemd','cron-systemd','process','process-dns'):
            for kind in ('unknown-directory','corrupt-config','unit','dropin','broken-symlink','cron','loaded-service'):
                with self.subTest(method=method,kind=kind),tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                    home=Path(tmp);base=home/'.config/mrnobody/mrnobody-p11-telemetry'
                    if kind in {'unknown-directory','corrupt-config'}:
                        base.mkdir(parents=True)
                        (base/'config.txt').write_text('{corrupt' if kind=='corrupt-config' else 'foreign')
                    if kind in {'unit','dropin'}:
                        unit=home/'.config/systemd/user'/('mrnobody-p11-telemetry.service'+('.d' if kind=='dropin' else ''))
                        unit.parent.mkdir(parents=True)
                        unit.write_text('foreign')
                    if kind=='broken-symlink':
                        base.parent.mkdir(parents=True);base.symlink_to(home/'missing')
                    before={str(x.relative_to(home)):x.read_bytes() for x in home.rglob('*') if x.is_file()}
                    def provider(argv,**kwargs):
                        if argv[:2]==['crontab','-l']:
                            return Response(returncode=0,stdout='* * * * * true # mrnobody-p11-telemetry\n' if kind=='cron' else '',stderr='')
                        if argv[:3]==['systemctl','--user','show-environment']:
                            return Response(returncode=0,stdout='',stderr='')
                        if argv[:3]==['systemctl','--user','show']:
                            return Response(returncode=0,stdout='loaded' if kind=='loaded-service' else 'not-found',stderr='')
                        self.fail('Write or core execution during collision: '+str(argv))
                    code,out=self.driver(method,home,provider)
                    self.assertEqual(code,0,out)
                    self.assertEqual(out,RECEIPT.decode())
                    self.assertEqual(before,{str(x.relative_to(home)):x.read_bytes() for x in home.rglob('*') if x.is_file()})
                    self.assertFalse(list(home.rglob('*.create.lock')))

    def test_no_collision_runs_core_once_and_partial_failure_is_not_skipped(self):
        for core_code in (0,1):
            with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                calls=[]
                def provider(argv,**kwargs):
                    calls.append(argv)
                    if argv==['bash']:return Response(returncode=core_code)
                    if argv[:2]==['crontab','-l']:return Response(returncode=0,stdout='# mrnobody-p11-telemetry-other\n',stderr='')
                    if argv[2]=='show-environment':return Response(returncode=0)
                    return Response(returncode=0,stdout='not-found')
                code,out=self.driver('process',Path(tmp),provider)
                self.assertEqual(code,core_code)
                self.assertEqual(calls.count(['bash']),1)
                self.assertNotIn('MRN_P11_EXISTS',out)

    def test_query_error_is_failed_before_core(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            code,out=self.driver('cron',Path(tmp),lambda *a,**k:Response(returncode=2,stdout='',stderr='private'))
            self.assertEqual(code,1)
            self.assertIn('MRN_P11_ERROR=ownership,action_failed',out)
            self.assertNotIn('private',out)

    def test_orphan_process_without_artifact_directory_is_a_collision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            home=Path(tmp); proc=home/'fake-proc'; entry=proc/'1234';entry.mkdir(parents=True)
            worker=home/'.config/mrnobody/mrnobody-p11-telemetry/worker.py'
            (entry/'cmdline').write_bytes(b'/usr/bin/python3\0'+str(worker).encode()+b'\0--worker\0unknown-token\0')
            ns={};exec(p.LINUX_PREFLIGHT,ns)
            real_path=Path
            constructor=Mock(side_effect=lambda value:proc if value=='/proc' else real_path(value))
            constructor.home.return_value=home
            with patch('pathlib.Path',constructor),patch('shutil.which',return_value=None):
                self.assertTrue(ns['p11_exists']('mrnobody-p11-telemetry'))
            self.assertFalse(worker.parent.exists())

    def test_full_campaign_continues_after_p11_skip(self):
        from full_incident import FullIncidentTests, IDS
        fixture=FullIncidentTests()
        result,dispatched,state,truth=fixture.run_campaign(child_code=78)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(dispatched,IDS)
        self.assertEqual(state['phases']['11'],'skipped')
        self.assertEqual(state['phases']['04'],'complete')
        self.assertNotIn('PHASE_COMPLETE phase=11',truth)


@unittest.skipUnless(os.name=='nt','Harmless PowerShell fake providers only')
class WindowsPreflight(unittest.TestCase):
    def test_existing_task_service_files_cross_method_never_write(self):
        for method in ('scheduled-task','service','task-service'):
            for kind in ('task','service','files'):
                with self.subTest(method=method,kind=kind),tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                    base=Path(tmp)/'MrNobody/P11/mrnobody-p11-telemetry'
                    if kind=='files':base.mkdir(parents=True);(base/'foreign.txt').write_text('keep')
                    providers="""$ErrorActionPreference='Stop'
function Get-ScheduledTask { param($TaskPath,$ErrorAction) __TASK__ }
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) __SERVICE__ }
function Set-Acl { throw 'write_attempted' }
function New-Item { throw 'write_attempted' }
function Register-ScheduledTask { throw 'write_attempted' }
function New-Service { throw 'write_attempted' }
function Start-Service { throw 'write_attempted' }
""".replace('__TASK__',"[pscustomobject]@{TaskName='mrnobody-p11-telemetry';Description='unknown'}" if kind=='task' else '$null').replace('__SERVICE__',"[pscustomobject]@{Name='mrnobody-p11-telemetry';Description='unknown'}" if kind=='service' else '$null')
                    source=providers+'\n& {\n'+p.script({'MRNOBODY_METHOD':method},'windows')+'\n}\n'
                    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command','& ([scriptblock]::Create([Console]::In.ReadToEnd()))'],input=source,text=True,capture_output=True,env=dict(os.environ,ProgramData=tmp),timeout=20)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stdout.strip(),RECEIPT.decode().strip())
                    if kind=='files':self.assertEqual((base/'foreign.txt').read_text(),'keep')
                    else:self.assertFalse(base.exists())


if __name__=='__main__':
    unittest.main()
