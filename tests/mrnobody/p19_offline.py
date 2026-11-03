"""Run from repository root: python -m unittest discover -s tests/mrnobody -p p19_offline.py"""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('p19_validation', ROOT / 'docs/examples/p19_validation.py')
p19 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = p19
SPEC.loader.exec_module(p19)


def observation(**changes):
    result = dict(target='192.168.1.10', port=8080, protocol='http',
                  fingerprint='mrnobody-offline-fixture-v1', proof='benign-proof-v1')
    result.update(changes)
    return result


class OfflineValidationTests(unittest.TestCase):
    def test_success_never_grants_access(self):
        result = p19.evaluate({}, [observation()])
        self.assertEqual(result['outcome'], 'SUCCESS')
        self.assertEqual(result['access'], dict(verified_real_access=False, compromise_state_changed=False))
        self.assertTrue(result['simulation'])
        self.assertEqual(result['mitre'], [])
        self.assertLessEqual(result['started_at'], result['completed_at'])

    def test_mismatch_and_empty_are_not_applicable(self):
        for items in ([], [observation(fingerprint='other')], [observation(port=80)], [observation(protocol='https')]):
            self.assertEqual(p19.evaluate({}, items)['outcome'], 'NOT_APPLICABLE')

    def test_matching_bad_proof_fails(self):
        self.assertEqual(p19.evaluate({}, [observation(proof='bad')])['outcome'], 'FAILURE')

    def test_candidate_fallback(self):
        result = p19.evaluate({}, [observation(fingerprint='other'), observation(proof='bad'), observation()])
        self.assertEqual(result['outcome'], 'SUCCESS')
        self.assertEqual(len(result['attempts']), 3)

    def test_failure_survives_later_mismatch(self):
        self.assertEqual(p19.evaluate({}, [observation(proof='bad'), observation(port=80)])['outcome'], 'FAILURE')

    def test_fixed_filters_candidates(self):
        result = p19.evaluate(dict(mode='fixed', target='10.0.0.2'), [observation()])
        self.assertEqual(result['outcome'], 'NOT_APPLICABLE')
        self.assertEqual(result['attempts'], [])

    def test_private_boundaries(self):
        for target in ('10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.255.254'):
            self.assertEqual(p19.private_target(target), target)
        for target in ('8.8.8.8', '127.0.0.1', '169.254.1.1', '172.32.0.1', '::1', 'localhost', 'http://10.0.0.1', None):
            with self.subTest(target=target), self.assertRaises(ValueError):
                p19.evaluate({}, [observation(target=target)])

    def test_config_fails_closed(self):
        for config in ({'profile': 'unknown'}, {'profile': []}, {'mode': 'fixed'}, {'mode': 'custom'},
                       {'target': '10.0.0.1'}, {'command': 'anything'}, {'mode': 'fixed', 'target': '8.8.8.8'}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                p19.validate_config(config)

    def test_allowlist_redacts_all_untrusted_evidence(self):
        result = p19.evaluate({}, [observation(proof='password=secret', token='secret', body='secret', username='secret')])
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('password', json.dumps(result))

    def test_bounded_input(self):
        for items in ([observation()] * 65, {}, [None]):
            with self.assertRaises(ValueError):
                p19.evaluate({}, items)

    def test_registry_validates_identity(self):
        profile = p19.PROFILES['offline-marker-v1']
        with self.assertRaises(ValueError):
            p19.registry([profile, profile])
        with self.assertRaises(TypeError):
            p19.PROFILES['other'] = profile
        with self.assertRaises(ValueError):
            p19.Profile('id', 'name', 'service', 0, 'http', 'fp', 'proof')

    def test_profile_does_not_claim_attack(self):
        with self.assertRaises(ValueError):
            p19.Profile('id', 'name', 'service', 80, 'http', 'fp', 'proof', mitre=('T1190',))


if __name__ == '__main__':
    unittest.main()
