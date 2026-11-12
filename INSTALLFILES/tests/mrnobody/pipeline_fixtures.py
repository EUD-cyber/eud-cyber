"""Offline shared fixtures for the three-stage contract."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'TESTFILES/ATTACKER-V2'
sys.path.insert(0, str(PLATFORM / 'web'))
import access_pipeline as pipeline
import windows_actions as actions

AUTH = dict(reachable=True, authenticated=True, auth='authenticated', warning='none', hostname='DC01', domain='lab.example')
DENIED = dict(reachable=True, authenticated=False, auth='denied', warning='credentials_denied')
ELIGIBLE = dict(result='eligible', warning='none', domain='lab.example', dc='dc.lab.example', probe='reachable', auth='authenticated')
NON_DC = dict(result='rejected', warning='target_must_be_domain_controller', domain='unknown', dc='unknown', probe='reachable', auth='authenticated')
GENERATION = 'a' * 32


def fact(port, state='open'):
    return dict(port=port, transport='tcp', state=state, observed=pipeline.now(), evidence={'tool':'fixture'})


def method(**changes):
    return dict(authenticated=True, protocol='winrm-http', port=5985, verification='read_only_windows_identity', **changes)


def child(data):
    return data if isinstance(data, (Exception, Mock)) else Mock(returncode=0, stdout=json.dumps(data))


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = dict(NORDIC_BASE_DIR=str(self.base), NORDIC_INCIDENT_ID='MRN-pipeline-test',
                        MRNOBODY_RUN_MODE='campaign', NORDIC_RDP_USERNAME='LAB\\operator',
                        NORDIC_RDP_PASSWORD='NEVER_PERSIST_WIN', NORDIC_SSH_PASSWORD='NEVER_PERSIST_SSH')
        self.write('networks.json', networks=[{'network':'192.168.1.0/24'}, {'network':'192.168.2.0/24'}])
        self.p01([('192.168.1.120', {22:'open',3389:'open',5985:'closed'}),
                  ('192.168.2.200', {22:'closed',3389:'closed',5985:'open'})])

    def write(self, name, **fields):
        pipeline.write(self.base / 'state' / name, dict(incident_id=self.env['NORDIC_INCIDENT_ID'], **fields))

    def read(self, name):
        return json.loads((self.base / 'state' / name).read_text())

    def p01(self, rows):
        self.write('discovered-hosts.json', schema_version=2, producer='P01', complete=True,
                   inventory_id=GENERATION, hosts=[dict(ip=ip, tcp_ports={str(p):fact(p,state) for p,state in ports.items()}) for ip,ports in rows])

    def p03(self, hosts=(), results=(), **changes):
        fields = dict(schema_version=2, producer='P03', run_mode='campaign', complete=True,
                      source_inventory_id=GENERATION, hosts=list(hosts), results=list(results))
        fields.update(changes)
        self.write('compromised-hosts.json', **fields)

    def access(self, rows):
        invoke = Mock(side_effect=[child(row) for row in rows])
        with contextlib.redirect_stdout(io.StringIO()):
            code = pipeline.run_access(self.env, invoke)
        return code, self.log(), invoke

    def campaign(self, rows):
        invoke = Mock(side_effect=[child(row) for row in rows])
        with contextlib.redirect_stdout(io.StringIO()):
            code = actions.run('09', self.env, invoke)
        return code, self.log(), invoke

    def log(self):
        log = (self.base / 'logs/incident-ground-truth.log').read_text()
        self.assertNotIn('NEVER_PERSIST', log)
        return log
