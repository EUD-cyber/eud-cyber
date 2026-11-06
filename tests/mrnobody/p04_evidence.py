"""Offline P04 capture, immutable report, failure and exporter regressions."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
# This test has the same basename as the production module; import it explicitly.
spec = importlib.util.spec_from_file_location('p04_evidence', PLATFORM / 'web/p04_evidence.py')
capture = importlib.util.module_from_spec(spec)
sys.modules['p04_evidence'] = capture
spec.loader.exec_module(capture)
from reports import build_report, p04_summary, save_report, load_report, run_phase, outcome
from report_exports import export_html, export_pdf

SOURCE, TARGET = '192.168.1.20', '192.168.1.1'
PORTS = [22, 80, 443, 445, 3389, 5985, 5986]
OUTPUT = '[DISCOVERY] target=' + TARGET + '\n[PING] target=' + TARGET + ' status=reachable\n' + ''.join(
    f'[TCP] target={TARGET} port={p} status={"open" if p in PORTS[:3] else "closed"}\n' for p in PORTS)


class P04(unittest.TestCase):
    def test_strict_capture(self):
        records = list(capture.parse_output(io.StringIO(OUTPUT), [TARGET], PORTS))
        self.assertEqual(len(records), 9)
        self.assertEqual([f['port'] for n, f in records if n.endswith('TCP')], list(map(str, PORTS)))
        bad = ('[PING] target=192.168.1.1 status=reachable\n'
               'INCIDENT=MRN-other PHASE=03 ACCESS_SUCCESS ip=192.168.1.1\n'
               '[DISCOVERY] target=192.168.1.99\n'
               '[DISCOVERY] target=192.168.1.1 trailing\n'
               '[DISCOVERY] target=192.168.1.1\n'
               '[TCP] target=192.168.1.1 port=65536 status=open\n'
               '[TCP] target=192.168.1.1 port=23 status=open\n'
               '[TCP] target=192.168.1.1 port=22 status=open PHASE=03\n'
               '\x1b[31m[TCP] target=192.168.1.1 port=22 status=open\n')
        self.assertEqual(len(list(capture.parse_output(io.StringIO(bad), [TARGET], PORTS))), 1)
        self.assertEqual(len(list(capture.parse_output(io.StringIO(OUTPUT + OUTPUT), [TARGET], PORTS))), 9)
        statuses = '[DISCOVERY] target=' + TARGET + '\n[PING] target=' + TARGET + ' status=no-reply\n[TCP] target=' + TARGET + ' port=22 status=error\n'
        self.assertEqual(list(capture.parse_output(io.StringIO(statuses), [TARGET], PORTS))[-1][1]['status'], 'error')
        old = capture.MAX_BYTES
        try:
            capture.MAX_BYTES = 20
            self.assertEqual(list(capture.parse_output(io.StringIO(OUTPUT), [TARGET], PORTS))[0][0], 'INTERNAL_DISCOVERY_TRUNCATED')
        finally:
            capture.MAX_BYTES = old

    def fixture(self, base, result=0, output=OUTPUT, platform='linux'):
        for d in ['state', 'logs', 'scripts', 'web', 'bin', 'config']:
            (base / d).mkdir(exist_ok=True)
        for name in ['p04_evidence.py', 'reports.py', 'report_exports.py']:
            shutil.copy(PLATFORM / 'web' / name, base / 'web' / name)
        script = (PLATFORM / 'scripts/04-lateral.sh').read_text().replace('/opt/nordic-attack', str(base))
        (base / 'scripts/04-lateral.sh').write_text(script)
        state = {'incident_id': 'MRN-other', 'hosts': [{'ip': '10.0.0.99'}]}
        (base / 'state/discovered-hosts.json').write_text(json.dumps(state))
        (base / 'state/compromised-hosts.json').write_text(json.dumps(state))
        config = f'''NORDIC_LOG_DIR="{base}/logs"
NORDIC_STATE_DIR="{base}/state"
NORDIC_DISCOVERED_STATE="{base}/state/discovered-hosts.json"
NORDIC_COMPROMISED_STATE="{base}/state/compromised-hosts.json"
NORDIC_GROUND_TRUTH_LOG="{base}/logs/incident-ground-truth.log"
NORDIC_DEFAULT_SSH_PASSWORD=fixture
NORDIC_SSH_TIMEOUT=1
NORDIC_CONNECT_TIMEOUT=1
'''
        (base / 'config/defaults.conf').write_text(config)
        mock = '#!/bin/bash\ncat >/dev/null\nprintf "%s" "$FIXTURE_OUTPUT"\nexit "$FIXTURE_RESULT"\n'
        (base / 'bin/sshpass').write_text(mock)
        (base / 'bin/sshpass').chmod(0o755)
        # WinRM worker substitution, including availability check; never connects.
        (base / 'venv/bin').mkdir(parents=True)
        worker = base / 'venv/bin/python'
        worker.write_text('#!/bin/bash\n[[ "$1" == "-c" ]] && exit 0\n' + mock.split('\n', 1)[1])
        worker.chmod(0o755)
        timeout = base / 'bin/timeout'
        timeout.write_text('#!/bin/bash\nexit 0\n')
        timeout.chmod(0o755)
        env = dict(os.environ, PATH=str(base / 'bin') + os.pathsep + os.environ['PATH'],
            NORDIC_INCIDENT_ID='MRN-20261106-143740-2af9dfa55ec3', MRNOBODY_RUN_MODE='standalone',
            MRNOBODY_SOURCE=SOURCE, MRNOBODY_TARGET=TARGET, MRNOBODY_USERNAME='student',
            MRNOBODY_PASSWORD='fixture', MRNOBODY_PROTOCOL='ssh' if platform == 'linux' else 'winrm',
            FIXTURE_OUTPUT=output, FIXTURE_RESULT=str(result))
        return env

    @unittest.skipUnless(os.name != 'nt' and shutil.which('bash'), 'requires Bash')
    def test_real_script_and_reports_offline(self):
        for platform, result, output in [('linux', 0, OUTPUT), ('windows', 0, OUTPUT), ('linux', 1, OUTPUT),
                                         ('linux', 1, ''), ('windows', 1, ''), ('linux', 0, '[DISCOVERY] target=' + TARGET + '\n')]:
            with self.subTest(platform=platform, result=result, missing=not output), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                env = self.fixture(base, result, output, platform)
                process = subprocess.run(['bash', str(base / 'scripts/04-lateral.sh')], env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(process.returncode, result, process.stderr + process.stdout)
                self.check_report(base, env, result, output, platform)

    @unittest.skipUnless(os.name != 'nt' and shutil.which('bash'), 'requires Bash')
    def test_auto_campaign_and_standalone_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env = self.fixture(base)
            incident = env['NORDIC_INCIDENT_ID']
            (base / 'state/discovered-hosts.json').write_text(json.dumps({'incident_id': incident, 'hosts': [{'ip': TARGET}, {'ip': SOURCE}]}))
            (base / 'state/compromised-hosts.json').write_text(json.dumps({'incident_id': incident, 'hosts': [{'ip': SOURCE, 'platform': 'linux', 'ssh_password': 'fixture'}]}))
            env['MRNOBODY_RUN_MODE'] = 'campaign'
            result = subprocess.run(['bash', str(base / 'scripts/04-lateral.sh')], env=env, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            (base / 'state/campaign.json').write_text(json.dumps({'incident_id': incident, 'status': 'complete', 'phases': {'04': 'complete'}}))
            report = build_report(base, incident, environ=env)
            phase = next(p for p in report['phases'] if p['id'] == '04')
            self.assertEqual(phase['discovery']['counts']['open_ports'], 3)
            self.assertEqual(report['summary']['compromised'], 1)
            self.assertEqual(phase['discovery']['counts']['targets'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env = self.fixture(base)
            env['MRN_OVERVIEW'] = '1'
            script = base / 'scripts/04-lateral.sh'
            script.chmod(0o755)
            self.assertEqual(run_phase(base, '04', script, env), 0)
            report = load_report(base / 'reports', env['NORDIC_INCIDENT_ID'])
            self.assertEqual(report['phases'][0]['discovery']['counts']['open_ports'], 3)
            self.assertEqual(report['summary']['compromised'], 0)

    def check_report(self, base, env, result, output, platform):
        incident = env['NORDIC_INCIDENT_ID']
        state = {'incident_id': incident, 'phase_id': '04', 'status': 'failed' if result else 'complete',
                 'phases': {'04': 'failed' if result else 'complete'}}
        with (base / 'logs/incident-ground-truth.log').open('a') as log:
            log.write('2026-11-06T14:37:46+00:00 INCIDENT=MRN-other PHASE=04 INTERNAL_DISCOVERY_TCP source=10.0.0.99 target=10.0.0.98 port=22 status=open\n')
        report = build_report(base, incident, result, env, standalone=state)
        phase = report['phases'][0]
        discovery = phase['discovery']
        self.assertEqual(report['summary']['compromised'], 0)
        self.assertEqual(report['summary']['involved_hosts'], 2)
        self.assertFalse(report['warnings'])
        self.assertNotIn('10.0.0.99', json.dumps(report))
        self.assertEqual(discovery['sources'][0]['execution'], 'failure' if result else 'success')
        self.assertEqual(discovery['counts']['open_ports'], 3 if output == OUTPUT else 0)
        pair = discovery['targets'][0]
        self.assertEqual(pair['ping'], 'reachable' if output == OUTPUT else 'unknown')
        self.assertEqual(pair['transport'], 'ssh' if platform == 'linux' else 'winrm')
        self.assertEqual(pair['tcp'], {str(p): ('open' if p in PORTS[:3] else 'closed') if output == OUTPUT else 'unknown' for p in PORTS})
        before = save_report(base, report).read_bytes()
        self.assertEqual(load_report(base / 'reports', incident), report)
        self.assertEqual(save_report(base, report).read_bytes(), before)
        html = export_html(report, 'ground-truth')
        for expected in [SOURCE, TARGET, 'remote execution source', 'scanned target', 'not applicable', 'ping=']:
            self.assertIn(expected, html)
        if output == OUTPUT:
            for p in PORTS:
                self.assertIn(f'{p}={pair["tcp"][str(p)]}', html)
            self.assertIn('incident-ground-truth.log:', html)
        self.assertNotIn('ping=reachable', export_html(report, 'investigation'))
        report['phases'][0]['discovery_findings'].append('<img src=x onerror=alert(1)>')
        html = export_html(report, 'ground-truth')
        self.assertNotIn('<img ', html)
        self.assertIn('&lt;img', html)
        pdf = export_pdf(report, 'ground-truth')
        self.assertTrue(pdf.startswith(b'%PDF'))
        content = '\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
        for token in [SOURCE, TARGET, 'remote execution source', 'scanned target', 'ping=']:
            self.assertIn(token, content)
        if output == OUTPUT:
            for port in PORTS:
                self.assertIn(f'{port}={pair["tcp"][str(port)]}', content)

    def test_multiple_sources_targets_historical(self):
        events = []
        for source in [SOURCE, '192.168.1.21']:
            for target in [TARGET, '192.168.1.2']:
                for name, fields in capture.parse_output(io.StringIO(OUTPUT.replace(TARGET, target)), [target], PORTS):
                    events.append({'event': name, 'fields': dict(fields, source=source, platform='linux', protocol='ssh')})
        summary = p04_summary(events)
        self.assertEqual(summary['counts']['sources'], 2)
        self.assertEqual(summary['counts']['targets'], 2)
        self.assertEqual(summary['counts']['relationships'], 4)
        self.assertEqual(summary['counts']['open_ports'], 12)
        legacy = p04_summary([{'event': 'INTERNAL_DISCOVERY', 'fields': {'source': SOURCE, 'target': TARGET}}])
        self.assertEqual(outcome("INTERNAL_DISCOVERY"), "observed")
        self.assertEqual(legacy['probes'], [])
        self.assertEqual(legacy['targets'][0]['ping'], 'unknown')


if __name__ == '__main__':
    unittest.main()
