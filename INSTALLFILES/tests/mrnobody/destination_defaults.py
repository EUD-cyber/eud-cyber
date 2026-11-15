"""Deployment file -> public config -> receiver hints, without execution."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
import app as module
from deployment_config import DeploymentConfig, load_deployment_config


class DestinationDefaults(unittest.TestCase):
    def test_roles_and_field_types_via_config_api(self):
        for role in ('standalone', 'master', 'agent'):
            for url in ('', 'https://10.20.30.40:8443/api/', 'https://master.test:9443/base',
                        'http://10.20.30.40:8080/'):
                with self.subTest(role=role, url=url), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / 'deployment.conf'
                    path.write_text(f'MRNOBODY_ROLE={role}\nMRNOBODY_MASTER_URL={url}\nMRNOBODY_LAB_HTTP=1\n')
                    config = load_deployment_config(path)
                    expected_url = url if role == 'agent' else ''
                    expected_ip = '10.20.30.40' if expected_url and '10.20.30.40' in url else ''
                    with patch.object(module, 'DEPLOYMENT_CONFIG', config), \
                         patch.object(module, 'determine_incident_ip', side_effect=AssertionError('no local fallback')), \
                         patch.object(module, 'launch', side_effect=AssertionError('no execution')):
                        response = module.app.test_client().get('/api/config')
                    self.assertEqual(response.status_code, 200)
                    data = response.get_json()
                    self.assertEqual(data['incident_ip'], expected_ip)
                    self.assertEqual(data['receiver_suggestions']['ipv4'], expected_ip)
                    self.assertEqual(data['receiver_suggestions']['url'], expected_url)
                    self.assertEqual(data['receiver_suggestions']['host'],
                                     ('10.20.30.40' if expected_ip else 'master.test') if expected_url else '')
                    self.assertNotIn('token', str(data).lower())

    def test_missing_invalid_and_inactive_config(self):
        for config in (DeploymentConfig(), DeploymentConfig('agent', '', 'loaded'),
                       DeploymentConfig('agent', 'https://10.0.0.1', 'invalid')):
            self.assertEqual(config.destination_suggestions(), dict(host='', ipv4='', url=''))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'deployment.conf'
            self.assertEqual(load_deployment_config(path).destination_suggestions()['url'], '')
            path.write_text('MRNOBODY_ROLE=agent\nMRNOBODY_MASTER_URL=https://user:secret@master.test')
            self.assertEqual(load_deployment_config(path).destination_suggestions()['url'], '')


if __name__ == '__main__':
    unittest.main()
