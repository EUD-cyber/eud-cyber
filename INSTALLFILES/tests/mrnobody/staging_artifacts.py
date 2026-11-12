"""Offline incident-scoped P05 and shared artifact reporting regressions."""
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
from reports import add_analysis, artifact_evidence, build_report, load_report, save_report
from report_exports import export_html, export_pdf, report_document
from pypdf import PdfReader

IID = 'MRN-20261106-150631-3fd8afb0fe32'
LINUX = f'/tmp/.nordic-{IID}/nordic-data-{IID}.txt'
WINDOWS = rf'C:\NordicIncident\{IID}\staging\nordic-data-{IID}.txt'
SHA = '0123456789abcdef' * 4  # representative hash; the verified user's hash was not supplied
TIME = '2026-11-06T15:06:31+01:00'


class StagingReports(unittest.TestCase):
    def fixture(self, base, lines=None, state=None):
        for name in ('state', 'logs', 'scripts'):
            (base / name).mkdir(exist_ok=True)
        shutil.copy(BASE / 'scripts/05-staging.sh', base / 'scripts')
        if lines is None:
            lines = [
                'STAGING_START host=192.168.1.20 platform=linux user=student',
                f'STAGING_SUCCESS host=192.168.1.20 platform=linux file={LINUX} size=1177 sha256={SHA}',
                'STAGING_START host=192.168.1.30 platform=windows user=LAB\\student',
                f'STAGING_SUCCESS host=192.168.1.30 platform=windows file={WINDOWS} size=1180 sha256={SHA}',
                'STAGING_FAILED host=192.168.1.40 platform=linux reason=missing_credentials',
                'STAGING_SKIPPED host=192.168.1.50 platform=windows reason=winrm_unavailable',
                'PHASE_COMPLETE compromised=4 staged=2 linux_staged=1 windows_staged=1 failed=1 skipped=1']
        log = [f'{TIME} INCIDENT={IID} PHASE=05 {line}' for line in lines]
        log += [f'{TIME} INCIDENT={IID}-foreign PHASE=05 STAGING_SUCCESS host=10.0.0.99 platform=linux file=/foreign size=999 sha256={SHA}']
        (base / 'logs/incident-ground-truth.log').write_text('\n'.join(log), encoding='utf-8')
        (base / 'state/discovered-hosts.json').write_text(json.dumps({'incident_id': 'MRN-foreign', 'hosts': [{'ip': '10.0.0.99'}]}))
        if state is not None:
            (base / 'state/staged-data.json').write_text(json.dumps(state))
        standalone = dict(incident_id=IID, phase_id='05', status='complete', started=TIME, completed=TIME, phases={'05': 'complete'})
        return build_report(base, IID, standalone=standalone)

    def test_multiple_hosts_and_exact_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = dict(incident_id=IID, hosts=[dict(ip='192.168.1.20', platform='linux', staged=True, file=LINUX, size=1177, sha256=SHA, ssh_user='student')])
            report = self.fixture(base, state=state)
            phase = report['phases'][0]
            self.assertEqual(phase['artifact_metrics'], dict(hosts_staged=2, artifacts_created=2, artifacts_recorded=2, total_bytes_staged=2357, unknown_sizes=0, failed=1, skipped=1))
            self.assertEqual(report['summary']['compromised'], 0)
            self.assertEqual(report['summary']['involved_hosts'], 4)
            self.assertEqual(report['inventory'], None)
            self.assertEqual(report['warnings'], [])
            a, w = phase['artifacts']
            self.assertEqual(a['name'], LINUX)
            self.assertEqual(a['timestamp'], TIME)
            self.assertEqual(a['sha256'], SHA)
            self.assertEqual(a['references'][0]['line'], 2)
            self.assertEqual(len(a['references']), 2)
            self.assertEqual(a['inspection'], [f'ls -lah -- {LINUX}', f'cat -- {LINUX}', f'sha256sum -- {LINUX}'])
            self.assertEqual(w['method'], 'WINRM')
            self.assertIn(f"Get-Content -LiteralPath '{WINDOWS}'", w['inspection'])
            self.assertIn('NordicMES', a['purpose'])
            self.assertIn('not independent content inspection', a['purpose'])
            self.assertEqual(phase['mitre']['techniques'][0]['id'], 'T1074')
            path = save_report(base, report)
            before = path.read_bytes()
            for _ in range(2):
                reloaded = load_report(base / 'reports', IID)
                self.assertEqual(len(reloaded['phases'][0]['artifacts']), 2)
            self.assertEqual(path.read_bytes(), before)

    def test_missing_failed_and_foreign_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp), lines=['STAGING_FAILED host=192.168.1.20 platform=linux', 'PHASE_COMPLETE staged=0 failed=1 skipped=0'], state={'incident_id': IID+'-other', 'hosts': [{'ip': '10.0.0.99', 'staged': True, 'file': '/foreign'}]})
            phase = report['phases'][0]
            self.assertEqual(phase['status'], 'success')  # completion != host result
            self.assertEqual(phase['artifact_metrics']['failed'], 1)
            self.assertEqual(phase['artifacts'], [])
            self.assertTrue(any('staging: incident ID mismatch' in w for w in report['warnings']))
            self.assertFalse(any('Unavailable inventory' in w for w in report['warnings']))
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp), lines=[])
            self.assertEqual(report['phases'][0]['artifact_metrics']['failed'], None)
            self.assertTrue(any('Unavailable staging' in w for w in report['warnings']))

    def test_historical_state_retention_and_duplicate_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = dict(incident_id=IID, hosts=[dict(ip='192.168.1.20', platform='linux', staged=True, producer_phase='17', file='/tmp/archive.tar.gz', size=100, sha256=SHA)])
            r = self.fixture(Path(tmp), lines=['STAGING_SUCCESS host=192.168.1.20 producer_phase=17 linkage=retained_collection_archive', 'PHASE_COMPLETE staged=1'], state=state)
            a = r['phases'][0]['artifacts'][0]
            self.assertEqual(a['action'], 'retained for staging')
            self.assertIsNone(a['timestamp'])
            self.assertEqual(r['phases'][0]['artifact_metrics']['artifacts_created'], 0)
            self.assertNotIn('five synthetic', a['purpose'])
        with tempfile.TemporaryDirectory() as tmp:
            line = f'STAGING_SUCCESS host=192.168.1.20 platform=linux file={LINUX} size=1177 sha256={SHA}'
            r = self.fixture(Path(tmp), [line, line, 'PHASE_COMPLETE staged=1'])
            self.assertEqual(len(r['phases'][0]['artifacts']), 1)
            self.assertEqual(r['phases'][0]['artifact_metrics']['total_bytes_staged'], 1177)
            r['warnings'] += ['Unavailable inventory: incident ID mismatch']
            self.assertNotIn('Unavailable inventory: incident ID mismatch', add_analysis(r)['warnings'])

    def test_multiple_artifacts_and_latest_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = [f'STAGING_SUCCESS host=192.168.1.20 platform=linux file={LINUX} size=1177 sha256={SHA}',
                     f'STAGING_SUCCESS host=192.168.1.20 platform=linux file={LINUX} size=1180 sha256=',
                     f'STAGING_SUCCESS host=192.168.1.20 platform=linux file={LINUX}.second size=20 sha256={SHA}',
                     'PHASE_COMPLETE staged=1 failed=0 skipped=0']
            r = self.fixture(Path(tmp), lines)
            phase = r['phases'][0]
            self.assertEqual(len(phase['artifacts']), 2)
            self.assertEqual(phase['artifact_metrics']['hosts_staged'], 1)
            self.assertEqual(phase['artifact_metrics']['total_bytes_staged'], 1200)
            self.assertIsNone(phase['artifacts'][0]['sha256'])
            self.assertEqual(len(phase['artifacts'][0]['references']), 2)

    def test_safe_commands_rendering_and_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.fixture(Path(tmp))
            for view in ('investigation', 'ground-truth'):
                html = export_html(r, view)
                for value in [LINUX, WINDOWS, SHA, '1177', 'sha256sum', 'Get-FileHash', 'Data Staging Findings', 'NordicERP', 'STAGING_FAILED', 'authenticated staging source']:
                    self.assertIn(value, html)
                pdf = export_pdf(r, view)
                pages = PdfReader(io.BytesIO(pdf)).pages
                text = ''.join(p.extract_text() for p in pages)
                compact = ''.join(text.split())
                for value in [LINUX, WINDOWS, SHA, '1177', 'Get-FileHash', 'sha256sum']:
                    self.assertIn(''.join(value.split()), compact)
            evil = "/tmp/a';$(touch nope)<script>.txt"
            p = r['phases'][0]
            p['events'] = [dict(event='STAGING_SUCCESS', timestamp=TIME, fields=dict(host='192.168.1.20', platform='linux', file=evil, size='bad', sha256='<script>'))]
            add_analysis(r)
            a = p['artifacts'][0]
            self.assertIsNone(a['sha256'])
            self.assertIsNone(a['size_bytes'])
            self.assertIn("'\"'\"'", a['inspection'][0])
            self.assertNotIn('<script>', export_html(r))
            self.assertIn('&lt;script&gt;', export_html(r))
            p['events'][0]['fields'].update(platform='windows', file="C:\\Staging\\a'b.txt")
            add_analysis(r)
            self.assertIn("a''b.txt", p['artifacts'][0]['inspection'][0])

    def test_reusable_model_and_p17_adapter(self):
        a = artifact_evidence('192.168.1.20', 'demo.service', 'service created', kind='systemd unit', verification='reported', cleanup='not attempted', inspection=['systemctl status demo.service'])
        self.assertEqual(a['kind'], 'systemd unit')
        self.assertTrue(a['display'])
        self.assertEqual(a['inspection'], ['systemctl status demo.service'])
        r = dict(phases=[dict(id='17', name='Collection', status='success', events=[dict(event='COLLECTION_ACTION_SUCCESS', outcome='success', message='archive created', target='192.168.1.20', timestamp=TIME, fields=dict(archive_path='/tmp/demo.tar.gz', files_selected='orders.csv', size='100', sha256=SHA, cleanup='retained_for_staging'))])])
        add_analysis(r)
        self.assertEqual(r['phases'][0]['artifacts'][0]['name'], '/tmp/demo.tar.gz')
        self.assertIn('archive created', export_html(r))
        r['phases'][0]['events'][0]['event'] = 'COLLECTION_ACTION_FAILED'
        add_analysis(r)
        self.assertEqual(r['phases'][0]['artifacts'], [])

if __name__ == '__main__':
    unittest.main()
