"""Removal regression: inert scripts and temporary installs; no remote execution."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as web
import remote_actions
from execution import phase_environment
from planning import API
from reports import read_metadata
from retired_files import RETIRED_FILES, migrate
from scenario_model import (ACTIVE_PHASE_IDS, RETIRED_PHASE_IDS, RETIRED_PRESETS,
                            catalogue, import_scenario, preset_cards, validate)


class Retirement(API):
    def test_stale_files_never_reenter_registry_routes_or_presets(self):
        scripts = self.base / 'scripts'
        shutil.copytree(BASE / 'scripts', scripts)
        for pid in RETIRED_PHASE_IDS:
            (scripts / f'{pid}-retired.sh').write_text(
                f'#!/bin/sh\n# ATTACK_ID="{pid}"\n# ATTACK_ALIAS="retired-{pid}"\n# ATTACK_STANDALONE="true"\nexit 99\n')
        with patch.object(web, 'SCRIPT_DIR', scripts):
            caps = web.planning.capabilities()
            self.assertEqual(set(caps), ACTIVE_PHASE_IDS)
            phases = self.client.get('/api/phases').json['phases']
            self.assertEqual({p['id'] for p in phases}, ACTIVE_PHASE_IDS)
            for pid in RETIRED_PHASE_IDS:
                result = self.client.post(f'/api/phase/{pid}/run', json={})
                self.assertEqual(result.status_code, 410)
                self.assertIn('unavailable', result.json['message'])
                result = self.client.post('/api/executions/run', json={'execution': {'type':'phase','id':pid}})
                self.assertEqual(result.status_code, 400)
                self.assertIn('Unavailable:', result.json['message'])
            for key in RETIRED_PRESETS:
                result = self.client.post('/api/executions/run', json={'execution': {'type':'campaign','id':'preset-'+key}})
                self.assertEqual(result.status_code, 400)
                self.assertIn('Unavailable:', result.json['message'])
            self.assertEqual([p['id'] for p in preset_cards(caps)], ['preset-recon-only'])
        self.launch.assert_not_called()

    def test_saved_scenarios_preserved_unavailable_even_when_phase_disabled(self):
        caps = web.planning.capabilities()
        for pid in sorted(RETIRED_PHASE_IDS):
            value = dict(version=1, name='Historical scope', target_mode='auto', profile={'mode':'normal'},
                         phases=[{'id':'01'}, {'id':'03'}, {'id':pid,'enabled':False}])
            saved = web.planning.store.save_scenario(copy.deepcopy(value))
            before = copy.deepcopy(saved)
            listing = self.client.get('/api/custom-scenarios').json
            self.assertIn('Unavailable: P'+pid, listing['readiness'][saved['id']])
            card = next(s for s in self.client.get('/api/scenarios').json['scenarios'] if s['id']==saved['id'])
            self.assertFalse(card['runnable'])
            result = self.client.post('/api/executions/run', json={'execution':{'type':'custom','id':saved['id']}})
            self.assertEqual(result.status_code, 400)
            self.assertIn('Unavailable:', result.json['message'])
            with self.assertRaisesRegex(ValueError, 'Unavailable:'):
                import_scenario(json.dumps(saved).encode(), caps)
            self.assertEqual(web.planning.custom(saved['id']), before)
            job = dict(version=1, execution={'type':'custom','id':saved['id']}, at='2099-01-01T00:00:00Z', interval=0)
            jid = web.planning.store.save_schedule(job)
            result = web.planning.scheduler.run(jid, job)
            self.assertTrue(result.startswith('Unavailable: P'+pid), result)
            status = next(j for j in self.client.get('/api/schedules').json['schedules'] if j['id']==jid)
            self.assertIn('Unavailable:', status['readiness'])
            self.assertEqual(self.client.post('/api/schedules/'+jid+'/enable',json={}).status_code,400)
        self.launch.assert_not_called()

    def test_remaining_phases_validate_and_dispatch_with_mocked_launch(self):
        caps = web.planning.capabilities()
        for pid in sorted(ACTIVE_PHASE_IDS):
            params = {'subnet':'192.168.1.0/24'} if pid=='01' else {'target':'192.168.1.20'}
            if 'protocol' in caps[pid]['fields']:
                params['protocol'] = 'winrm-http' if pid=='09' else caps[pid]['fields']['protocol']['options'][0]
            if pid=='04': params['source']='192.168.1.10'
            spec = dict(type='phase',id=pid,target_mode='fixed',parameters=params)
            self.assertEqual(web.planning.execution(spec)['id'],pid)
        ids = read_metadata(BASE/'scenarios/full-incident.sh')['SCENARIO_PHASES'].split(',')
        self.assertEqual(ids,['01','02','03','08','09','10','11','04','05','06','07'])
        for enabled in (False,True):
            web.campaign_process=None
            result=self.client.post('/api/start',json={'ssh_password':'S','rdp_password':'R','powershell_enabled':enabled,'profile':{'mode':'slow'}})
            self.assertEqual(result.status_code,200,result.json)
            ids={p['id'] for p in json.loads(self.launch.call_args.kwargs['env']['MRN_EXECUTION'])['phases']}
            self.assertFalse(ids & RETIRED_PHASE_IDS)
            self.assertIn('09',ids)
            self.assertEqual('10' in ids,enabled)

    def test_backend_adapters_reject_removed_ids_before_side_effects(self):
        for pid in RETIRED_PHASE_IDS:
            with self.assertRaises(ValueError): remote_actions.run(pid, {})
            with self.assertRaises(ValueError): remote_actions.perform(pid, {}, {})
            with self.assertRaises(ValueError): phase_environment(pid, {})


class Migration(unittest.TestCase):
    def test_exact_code_cleanup_idempotent_preserves_all_user_data(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base=Path(tmp)
            sentinels={}
            for rel in (*RETIRED_FILES, 'scripts/08-wordlist.sh','scripts/09-ad-privilege.sh','scripts/10-powershell.sh',
                        'web/persistence_actions.py','reports/historical-p18.json','state/staged-data.json',
                        'data/planning/execution.sqlite3','logs/history.log','config/local.conf'):
                path=base/rel; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'preserve exact bytes')
                if rel not in RETIRED_FILES: sentinels[rel]=path.read_bytes()
            cache=base/'web/__pycache__'; cache.mkdir()
            (cache/'dns_actions.cpython-312.pyc').write_bytes(b'old cache')
            (base/'web/dns_actions.pyc').write_bytes(b'legacy cache')
            removed=migrate(base)
            self.assertTrue(set(RETIRED_FILES)<=set(removed))
            self.assertFalse(list(cache.iterdir()))
            self.assertEqual(migrate(base),[])
            for rel,content in sentinels.items(): self.assertEqual((base/rel).read_bytes(),content)

    @unittest.skipIf(os.name=='nt','Linux symlink test')
    def test_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            root=Path(tmp); base=root/'install'; base.mkdir(); outside=root/'outside'; outside.mkdir()
            (outside/'12-credential-access.sh').write_bytes(b'preserve')
            (base/'scripts').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError): migrate(base)
            self.assertEqual((outside/'12-credential-access.sh').read_bytes(),b'preserve')

    @unittest.skipIf(os.name=='nt','Linux CLI fixtures')
    def test_cli_hides_and_rejects_ids_aliases_with_leftover_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            base=Path(tmp); scripts=base/'scripts'; shutil.copytree(BASE/'scripts',scripts)
            for pid in RETIRED_PHASE_IDS:
                (scripts/f'{pid}-retired.sh').write_text(f'#!/bin/sh\n# ATTACK_ID="{pid}"\n# ATTACK_ALIAS="retired-{pid}"\nexit 99\n')
            env=dict(os.environ,NORDIC_BASE_DIR=str(base))
            runner=str(BASE/'scripts/run-phase.sh')
            listing=subprocess.run(['bash',runner,'list'],env=env,capture_output=True,text=True,check=True).stdout
            for pid in RETIRED_PHASE_IDS:
                self.assertNotRegex(listing,r'(?m)^'+pid+r'\s')
                for selector in (pid,'retired-'+pid):
                    result=subprocess.run(['bash',runner,selector,'--dry-run'],env=env,capture_output=True,text=True)
                    self.assertNotEqual(result.returncode,0,result.stdout)
            for pid in ACTIVE_PHASE_IDS: self.assertRegex(listing,r'(?m)^'+pid+r'\s')


if __name__=='__main__': unittest.main()
