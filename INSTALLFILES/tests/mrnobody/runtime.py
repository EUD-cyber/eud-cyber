"""Inspect fixtures and evaluate only ID/path assignments; never source a campaign."""
import ast
import hashlib
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = []
        self.panels = {}
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        identifier = attrs.get('id')
        if identifier:
            assert identifier not in self.ids, identifier
            self.ids.add(identifier)
        if tag == 'section':
            self.sections.append(identifier)
        if tag == 'pre' and 'data-live-log' in attrs:
            page = next(x for x in reversed(self.sections) if x and x.startswith('page-'))
            self.panels[page] = identifier

    def handle_endtag(self, tag):
        if tag == 'section':
            self.sections.pop()


parser = PageParser()
parser.feed((PLATFORM / 'web/templates/index.html').read_text(encoding='utf8'))
assert not parser.sections
for page in ['dashboard', 'campaigns', 'scenarios', 'phases', 'system']:
    assert 'page-' + page in parser.panels

# Inspect the active report ID validator and generator. The retired INCIDENTVM
# mirror is no longer distributed. Evaluate only assignments, never run_phase.
reports = ast.parse((PLATFORM / 'web/reports.py').read_text(encoding='utf8'))
validator = next(n for n in reports.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'INCIDENT_ID' for t in n.targets))
handler = next(n for n in reports.body if isinstance(n, ast.FunctionDef) and n.name == 'run_phase')
generator = next(n for n in handler.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'incident_id' for t in n.targets))
namespace = {'datetime': datetime, 'uuid': uuid, 're': re, 'requested_id': ''}
exec(compile(ast.Module(body=[validator, generator], type_ignores=[]), '<id assignments>', 'exec'), namespace)
assert re.fullmatch(r'MRN-\d{8}-\d{6}-[a-f0-9]{12}', namespace['incident_id'])
for prefix in ['MRN', 'H3']:
    historical = prefix + '-20261031-072933'
    assert namespace['INCIDENT_ID'].fullmatch(historical)
    namespace['requested_id'] = historical
    exec(compile(ast.Module(body=[generator], type_ignores=[]), '<id assignment>', 'exec'), namespace)
    assert namespace['incident_id'] == historical
for unsafe in ['../H3-20261031-072933', 'MRN-test/escape', '']:
    assert not namespace['INCIDENT_ID'].fullmatch(unsafe)

scripts = list((PLATFORM / 'scripts').glob('[0-9]*.sh')) + list((PLATFORM / 'scenarios').glob('*.sh'))
assert len(scripts) == 12
for script in scripts:
    text = script.read_text(encoding='utf8')
    assignment = next(line for line in text.splitlines() if line.startswith('INCIDENT_ID='))
    assert 'NORDIC_INCIDENT_ID:-MRN-' in assignment
    if '--bash' in sys.argv:
        for supplied in ['', 'H3-20261031-072933', 'MRN-20261031-072933']:
            # Only this single variable assignment is evaluated. No campaign body runs.
            result = subprocess.check_output(['bash', '-c',
                assignment + '\nprintf "%s" "$INCIDENT_ID"', 'id-fixture'],
                env={**__import__('os').environ, 'NORDIC_INCIDENT_ID': supplied}, text=True)
            assert result == supplied if supplied else re.fullmatch(r'MRN-\d{8}-\d{6}', result)

impact = (PLATFORM / 'scripts/07-impact.sh').read_text(encoding='utf8')
assert 'IMPACT_DIR="/tmp/nordic-impact-${INCIDENT_ID}"' in impact
assert '$root="C:\\NordicIncident\\$id\\impact"' in impact
assert '"$INCIDENT_ID" <<\'PY\'' in impact
assert 'LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-07-impact.log"' in impact
scenario = (PLATFORM / 'scenarios/full-incident.sh').read_text(encoding='utf8')
assert 'export NORDIC_INCIDENT_ID="$INCIDENT_ID"' in scenario
assert 'MASTER_LOG="$LOG_DIR/${INCIDENT_ID}-campaign.log"' in scenario
assert '"incident_id": incident_id' in scenario
assert '"campaign": "MrNobody Incident Platform"' in scenario

# Validate the exact bytes distributed by the updater, including CRLF where present.
for line in (PLATFORM / 'update-manifest.txt').read_text().splitlines():
    if not line or line.startswith('#'):
        continue
    digest, relative = line.split('|', 1)
    assert hashlib.sha256((PLATFORM / relative).read_bytes()).hexdigest() == digest, relative

# Check the JavaScript shipped by the active frontend.
for script in ['app.js', 'planning.js']:
    subprocess.run(['node', '--check', str(PLATFORM / 'web/static' / script)], check=True)

print('Page placement, MRN IDs, legacy H3 validation and propagated runtime paths passed.'
      + (' Bash ID assignments evaluated safely.' if '--bash' in sys.argv else ' Bash evaluation reserved for CI.'))
