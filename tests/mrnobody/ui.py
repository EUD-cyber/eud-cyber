"""Read-only UI/API contracts using the real installed registry; never launch attacks."""
import importlib.util
import json
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(BASE / 'web'))
import app as module
from reports import read_metadata
from scenario_model import catalogue, technique_metadata


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.ids, self.errors = [], set(), []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            assert attrs['id'] not in self.ids, attrs['id']
            self.ids.add(attrs['id'])
        if tag not in {'input', 'meta', 'link', 'br', 'hr', 'img', 'source', 'wbr'}:
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append((tag, self.stack[-4:]))
        else:
            self.stack.pop()


def verify():
    with tempfile.TemporaryDirectory(dir=ROOT) as temp:
        module.BASE_DIR = Path(temp)
        module.SCRIPT_DIR = BASE / 'scripts'
        module.SCENARIO_DIR = BASE / 'scenarios'
        module.STATE_DIR = Path(temp) / 'state'
        module.CAMPAIGN_STATE = module.STATE_DIR / 'campaign.json'
        module.INVENTORY_STATE = module.STATE_DIR / 'discovered-hosts.json'
        module.LOG_DIR = Path(temp) / 'logs'
        module.CAMPAIGN_LOG = module.LOG_DIR / 'campaign.log'
        module.CONFIG_FILE = BASE / 'config/defaults.conf'
        client = module.app.test_client()
        with patch.object(module, 'launch', side_effect=AssertionError('Execution forbidden')), patch.object(module.subprocess, 'Popen', side_effect=AssertionError('Process launch forbidden')):
            data = client.get('/api/phases').get_json()
            capabilities = catalogue(BASE / 'scripts', read_metadata)
            assert data['count'] == len(capabilities)
            for item in data['phases']:
                meta = read_metadata(BASE / 'scripts' / item['script'])
                edu = item['education']
                assert item['id'] == meta['ATTACK_ID']
                assert edu['description'] == meta['ATTACK_DESCRIPTION']
                assert edu['dependencies'] == capabilities[item['id']]['dependencies']
                assert edu['configuration'] == capabilities[item['id']]['fields']
                assert edu['required_fields'] == capabilities[item['id']]['required_fields']
                assert all(edu[k] for k in ['description', 'detection_focus', 'teaching_purpose', 'platforms', 'prerequisites', 'cleanup', 'target_type'])
                assert set(edu['supported_modes']) == {'Standalone', 'Custom Scenario', 'Full Incident', 'Scheduler'}
                assert all(t['url'].startswith('https://attack.mitre.org/techniques/') for t in edu['technique_details'])
                assert edu['readiness'] == 'Installed'
                assert item['mitre']['techniques'] == [t['id'] for t in edu['technique_details']]
            indexed = {p['id']: p for p in data['phases']}
            assert indexed['09']['education']['tactics'] == ['Persistence', 'Privilege Escalation']
            assert indexed['13']['education']['tactics'] == ['Execution', 'Stealth', 'Persistence']
            assert indexed['18']['mitre']['techniques'] == ['T1071.004']
            assert indexed['10']['education']['platforms'] == ['Windows', 'Linux']
            # Unknown/future metadata is not silently assigned a platform or a mode.
            future = technique_metadata({'ATTACK_ID': '99', 'MITRE_TECHNIQUES': 'javascript:bad,T1234.001'}, {})
            assert future['platforms'] == [] and future['supported_modes'] == []
            assert len(future['technique_details']) == 1
            for endpoint in ['/', '/api/health', '/api/config', '/api/scenarios', '/api/planning/capabilities', '/api/schedules', '/api/reports', '/api/execution-status', '/api/inventory']:
                response = client.get(endpoint)
                assert response.status_code == 200, (endpoint, response.status_code)
            html = client.get('/').get_data(as_text=True)
            parser = Structure(); parser.feed(html)
            assert not parser.errors, parser.errors
            assert not parser.stack, parser.stack
            assert {f'page-{page}' for page in ['dashboard', 'phases', 'scenarios', 'builder', 'schedules', 'reports', 'mitre', 'system', 'inventory', 'campaigns']} <= parser.ids
            settings = html.split('id="page-system"')[1].split('id="page-mitre"')[0]
            assert 'id="updateButton"' in settings and 'id="settingsRuntime"' in settings
            assert 'type="checkbox"' not in settings
            assert 'Nginx, TLS and target reachability are not independently monitored' in settings
            assert 'P01 through P14' not in html
            assert 'Attack Phases' not in html
            # Report lists include recorded names, without rewriting historical JSON.
            fixture = {'incident': {'id':'MRN-ui-test','started':'2026-11-01'}, 'phases':[{'id':'99','name':'Historical custom technique','status':'success'}]}
            from reports import list_reports
            with patch('reports.load_report', return_value=fixture):
                report_dir = Path(temp) / 'reports'; report_dir.mkdir(); (report_dir/'MRN-ui-test.json').write_text('{}')
                listed = list_reports(report_dir)
            assert listed[0]['techniques'][0]['id'] == '99'
            return data


if __name__ == '__main__':
    result = verify()
    if '--json' in sys.argv:
        print(json.dumps(result))
    else:
        print('UI/API contracts passed: real registry metadata, mappings, supported modes, historical lists, settings and semantic HTML; no execution.')
