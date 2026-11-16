"""Offline imported-evidence contracts and the real administrator boundary."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from flask import Flask

WEB=Path(__file__).resolve().parents[2]/'TESTFILES/ATTACKER-V2/web'
sys.path.insert(0,str(WEB))
from master_registry import Registry, Unavailable
from master_api import install_master_api
from master_admin import install_admin_auth, PREFIX
from p06_synthetic import fixture
from detection_validation import correlate, ValidationError

NOW=1700000000
STAMP=datetime.fromtimestamp(NOW,timezone.utc).isoformat()
CAMP='MRN-validation-fixture'


class Validation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'master/registry.sqlite3'
        self.store=Registry(self.path,clock=lambda:NOW)
        self.token=self.store.issue('agent-1');self.store.register('agent-1',self.token,'Slave')
        raw=fixture(CAMP);self.digest=hashlib.sha256(raw).hexdigest()
        import base64
        self.p06=self.store.receive_p06(dict(agent_id='agent-1',protocol_version=1,campaign_id=CAMP,
            phase='P06',synthetic=True,size=len(raw),sha256=self.digest,content=base64.b64encode(raw).decode()),self.token)
        self.p11=self.store.receive_p11(dict(agent_id='agent-1',protocol_version=1,campaign_id=CAMP,
            phase='P11',synthetic=True,timestamp=STAMP,sequence=1,marker='MRN-EXERCISE-ONLY'),self.token)

    def request(self, records=None, kind='wazuh', **changes):
        body=dict(agent_id='agent-1',campaign_id=CAMP,window_seconds=120,
            wazuh_agent_id='001' if kind=='wazuh' else '',
            observed_source_ip='10.0.0.2' if kind=='suricata' else '',
            observed_destination_ip='10.0.0.1' if kind=='suricata' else '',
            sources=[dict(kind=kind,content='\n'.join(json.dumps(row) for row in (records or [])))])
        body.update(changes);return body

    def wazuh(self, **changes):
        row=dict(timestamp=STAMP,agent={'id':'001'},rule={'id':'100001','level':5,'description':'SECRET <img src=x>',
            'mitre':{'id':['T1071.001']}},full_log='password=SECRET Bearer PRIVATE-CREDENTIAL',
            data={'mrnobody':{'campaign_id':CAMP,'phase':'P11','receiver_event_id':self.p11['event_id']}})
        row.update(changes);return row

    def eve(self, **changes):
        row=dict(timestamp=STAMP,event_type='alert',src_ip='10.0.0.2',dest_ip='10.0.0.1',
            flow_id=2**63+123,alert={'signature_id':123,'signature':'SECRET'},
            payload_printable=json.dumps(dict(campaign_id=CAMP,phase='P11',sequence=1,marker='MRN-EXERCISE-ONLY')))
        row.update(changes);return row

    def snapshot(self):
        item=dict(id=CAMP,status='complete',report_type='campaign',phase_id=None,started=STAMP,completed=STAMP)
        report=dict(schema_version=1,incident=dict(id=CAMP,status='complete',started=STAMP,ended=STAMP),
            phases=[{'id':'11','mitre':{'techniques':[{'id':'T1543.003'}]}}],
            events=[dict(phase='11',event='P11_BEACON_ACK',timestamp=STAMP,
                fields=dict(event_id=str(self.p11['event_id']),sequence='1',verified='true'))],
            evidence={'exfiltration':{'live_lab':self.p06}})
        self.store.sync_reports('agent-1',self.token,[item]);self.store.transfer_report('agent-1',self.token,CAMP,report)

    def test_receipts_metadata_and_empty_exports_are_never_detection(self):
        self.snapshot()
        result=correlate(self.store,self.request())
        self.assertEqual(result['coverage'],'unknown')
        self.assertEqual(result['verdict'],'no_correlated_alert_in_supplied_slice')
        self.assertEqual(result['counts']['correlated_alert'],0)
        self.assertTrue(all(row['ground_truth_linked'] for row in result['receipts']))
        p11=next(row for row in result['receipts'] if row['phase']=='P11')
        self.assertEqual(p11['reference_techniques'],['T1071.001'])
        self.assertEqual(p11['phase_metadata_techniques'],['T1543.003'])

    def test_correlated_wazuh_alert_returns_only_sanitized_metadata(self):
        result=correlate(self.store,self.request([self.wazuh()]))
        self.assertEqual(result['counts']['correlated_alert'],1)
        self.assertEqual(result['rows'][0]['receiver_event_ids'],[self.p11['event_id']])
        self.assertEqual(result['rows'][0]['rule_techniques'],['T1071.001'])
        raw=json.dumps(result)
        for secret in ('SECRET','PRIVATE-CREDENTIAL','full_log','payload_printable','description',self.token):
            self.assertNotIn(secret,raw)

    def test_fixture_fim_hash_correlates_artifact_not_exfil_detection(self):
        row=self.wazuh(data={},full_log='',syscheck={'sha256_after':self.digest.upper()})
        result=correlate(self.store,self.request([row]))
        self.assertEqual(result['rows'][0]['basis'],['exact_fixture_hash'])
        self.assertEqual(result['rows'][0]['receiver_event_ids'],[self.p06['event_id']])
        self.assertEqual(result['counts']['correlated_alert'],1)
        self.assertEqual(result['coverage'],'unknown')

    def test_suricata_payload_marker_needs_exact_sequence_campaign_and_direction(self):
        result=correlate(self.store,self.request([self.eve()],kind='suricata'))
        self.assertEqual(result['counts']['correlated_alert'],1)
        self.assertEqual(result['rows'][0]['flow_id'],str(2**63+123))
        for change in ({'src_ip':'10.0.0.3'}, {'src_ip':'10.0.0.1','dest_ip':'10.0.0.2'}):
            result=correlate(self.store,self.request([self.eve(**change)],kind='suricata'))
            self.assertEqual(result['counts']['unmatched'],1)
        row=self.eve(payload_printable=json.dumps(dict(campaign_id=CAMP,phase='P11',sequence=2,marker='MRN-EXERCISE-ONLY')))
        result=correlate(self.store,self.request([row],kind='suricata'))
        self.assertEqual(result['counts']['correlated_alert'],0)
        self.assertEqual(result['counts']['candidate_alert'],1)

    def test_time_or_mitre_or_phase_alone_only_gives_candidates(self):
        for row in (self.wazuh(data={},full_log=''), self.wazuh(data={'mrnobody':{'campaign_id':CAMP,'phase':'P11'}},full_log='')):
            result=correlate(self.store,self.request([row]))
            self.assertEqual(result['counts']['candidate_alert'],1)
            self.assertEqual(result['counts']['correlated_alert'],0)
        result=correlate(self.store,self.request([self.eve(payload_printable='')],kind='suricata'))
        self.assertEqual(result['counts']['candidate_alert'],1)

    def test_flow_and_forwarded_ground_truth_are_not_independent_detection(self):
        row=self.eve(event_type='flow')
        result=correlate(self.store,self.request([row],kind='suricata'))
        self.assertEqual(result['counts']['correlated_telemetry'],1)
        self.assertEqual(result['counts']['correlated_alert'],0)
        row=self.wazuh(rule={},data={},full_log=f'INCIDENT={CAMP} PHASE=11 P11_BEACON_ACK event_id={self.p11["event_id"]}')
        result=correlate(self.store,self.request([row]))
        self.assertEqual(result['counts']['correlated_telemetry'],1)
        self.assertIn('independent observation',str(result['limitations']))

    def test_wrong_observer_campaign_prefix_or_conflicting_phase_never_matches(self):
        changes=({'agent':{'id':'002'}}, {'data':{'mrnobody':{'campaign_id':CAMP+'-other','phase':'P11'}}},
            {'full_log':f'INCIDENT={CAMP}-other PHASE=11'}, {'full_log':'PHASE=06'})
        for change in changes:
            result=correlate(self.store,self.request([self.wazuh(**change)]))
            self.assertEqual(result['counts']['unmatched'],1)

    def test_timezones_and_bounds_and_naive_timestamps(self):
        result=correlate(self.store,self.request([self.wazuh(timestamp='2023-11-14T23:13:20+0100')],window_seconds=0))
        self.assertEqual(result['counts']['correlated_alert'],1)
        result=correlate(self.store,self.request([self.wazuh(timestamp='2023-11-14T22:20:00Z')]))
        self.assertEqual(result['counts']['unmatched'],1)
        for stamp in ('2023-11-14T22:13:20','invalid','2023-99-14T22:13:20Z'):
            with self.assertRaises(ValidationError):correlate(self.store,self.request([self.wazuh(timestamp=stamp)]))

    def test_duplicates_are_deduplicated_without_silent_truncation(self):
        result=correlate(self.store,self.request([self.wazuh(),self.wazuh()]))
        self.assertEqual(result['counts']['parsed'],2);self.assertEqual(result['counts']['duplicates'],1)
        self.assertEqual(result['counts']['correlated_alert'],1)
        data=self.request();data['sources'][0]['content']='\n'.join('{}' for _ in range(2001))
        with self.assertRaises(ValidationError):correlate(self.store,data)
        data=self.request();data['sources'][0]['content']='x'*(512*1024+1)
        with self.assertRaises(ValidationError):correlate(self.store,data)

    def test_bad_json_duplicate_keys_and_bad_alert_schema_fail_whole_slice(self):
        for text in ('{','[]','{"timestamp":"x","timestamp":"y"}',json.dumps(self.wazuh(rule={'id':'1','level':True}))):
            data=self.request([self.wazuh()]);data['sources'][0]['content']+='\n'+text
            with self.assertRaises(ValidationError):correlate(self.store,data)

    def test_missing_reports_no_receipts_and_offline_agents_are_not_failed_detections(self):
        result=correlate(self.store,self.request([self.wazuh()]))
        self.assertEqual(result['reference']['report_status'],'not_synchronized')
        result=correlate(self.store,self.request([self.wazuh()],campaign_id='MRN-empty'))
        self.assertEqual(result['receipts'],[]);self.assertEqual(result['counts']['correlated_alert'],0)
        self.store.clock=lambda:NOW+1000
        self.assertEqual(correlate(self.store,self.request())['coverage'],'unknown')

    def test_ambiguous_repeated_receipt_is_candidate_not_many_detections(self):
        raw=fixture(CAMP)
        import base64
        self.store.receive_p06(dict(agent_id='agent-1',protocol_version=1,campaign_id=CAMP,phase='P06',
            synthetic=True,size=len(raw),sha256=self.digest,content=base64.b64encode(raw).decode()),self.token)
        row=self.wazuh(data={},full_log='',syscheck={'sha256_after':self.digest})
        result=correlate(self.store,self.request([row]))
        self.assertEqual(result['counts']['correlated_alert'],0)
        self.assertEqual(result['counts']['candidate_alert'],1)

    def test_report_corruption_is_unavailable_not_missing_sensor_evidence(self):
        self.snapshot()
        db=sqlite3.connect(self.path)
        try:
            with db:db.execute("UPDATE report_content SET content='{}'")
        finally:db.close()
        with self.assertRaises(Unavailable):correlate(self.store,self.request())

    def test_passive_preview_does_not_change_registry_or_report_bytes(self):
        self.snapshot();before=self.path.read_bytes()
        correlate(self.store,self.request([self.wazuh()]))
        self.assertEqual(self.path.read_bytes(),before)

    def test_scope_rejects_unknown_fields_or_unregistered_identity(self):
        for change in ({'command':'id'},{'url':'https://evil.test'},{'window_seconds':True},{'window_seconds':301},
                {'agent_id':'unknown'},{'campaign_id':'../etc'},{'wazuh_agent_id':''}):
            with self.assertRaises(ValueError):correlate(self.store,self.request(**change))

    def test_mixed_sources_are_separate_and_display_truncation_is_explicit(self):
        data=self.request([self.wazuh()])
        data.update(observed_source_ip='10.0.0.2',observed_destination_ip='10.0.0.1')
        data['sources'].append(dict(kind='suricata',content=json.dumps(self.eve())))
        result=correlate(self.store,data)
        self.assertEqual(result['counts']['correlated_alert'],2)
        self.assertEqual(len(result['sources']),2)
        records=[self.wazuh(unique=i) for i in range(201)]
        result=correlate(self.store,self.request(records))
        self.assertEqual(result['counts']['correlated_alert'],201)
        self.assertEqual(len(result['rows']),200);self.assertTrue(result['rows_truncated'])
        self.assertEqual(result['coverage'],'unknown')

    def test_record_and_line_limits_and_ignored_types(self):
        small=dict(timestamp=STAMP,event_type='stats')
        data=self.request([small]*2001,kind='suricata')
        with self.assertRaisesRegex(ValidationError,'2000 records'):correlate(self.store,data)
        result=correlate(self.store,self.request([small],kind='suricata'))
        self.assertEqual(result['counts']['ignored'],1)
        data=self.request([self.wazuh(full_log='x'*65536)])
        with self.assertRaisesRegex(ValidationError,'64 KiB line'):correlate(self.store,data)

    def test_unsupported_or_invalid_explicit_phase_cannot_supply_strong_anchor(self):
        for phase in ('P01','P09','unexpected',None):
            row=self.wazuh(data={'mrnobody':{'campaign_id':CAMP,'phase':phase,
                'receiver_event_id':self.p06['event_id']}},syscheck={'sha256_after':self.digest})
            result=correlate(self.store,self.request([row]))
            self.assertEqual(result['counts']['unmatched'],1)
        row=self.wazuh(data={},full_log='INCIDENT='+CAMP+'.evil PHASE=P06',syscheck={'sha256_after':self.digest})
        self.assertEqual(correlate(self.store,self.request([row]))['counts']['unmatched'],1)


class API(unittest.TestCase):
    request = Validation.request
    wazuh = Validation.wazuh
    def setUp(self):
        Validation.setUp(self)
        self.secret='a'*43
        self.config=SimpleNamespace(role='master',config_status='loaded',lab_http=True)
        self.app=Flask('validation',template_folder=str(WEB/'templates'))
        install_master_api(self.app,lambda:self.config,self.path)
        install_admin_auth(self.app,lambda:self.config,registry_path=self.path)
        self.loader=patch('master_admin.load_credential',return_value={'version':1,'origin':'https://master.lab',
            'sha256':hashlib.sha256(self.secret.encode()).hexdigest()})
        self.loader.start();self.addCleanup(self.loader.stop)
        self.client=self.app.test_client()

    def login(self):
        return self.client.post(PREFIX+'/session',base_url='https://master.lab',
            headers={'Origin':'https://master.lab'},json={'credential':self.secret}).json['csrf']

    def post(self, csrf='', **options):
        return self.client.post(PREFIX+'/validation',base_url='https://master.lab',
            headers={'Origin':'https://master.lab','X-CSRF-Token':csrf},json=self.request([self.wazuh()]),**options)

    def test_api_requires_admin_not_agent_and_csrf_and_lab_boundary(self):
        self.assertEqual(self.post().status_code,401)
        self.assertEqual(self.client.post(PREFIX+'/validation',base_url='https://master.lab',
            headers={'Authorization':'Bearer '+self.token},json=self.request()).status_code,401)
        csrf=self.login()
        self.assertEqual(self.post().status_code,403)
        self.assertEqual(self.post(csrf,environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code,403)
        result=self.post(csrf);self.assertEqual(result.status_code,200)
        self.assertEqual(result.headers['Cache-Control'],'no-store')
        self.assertEqual(result.json['coverage'],'unknown')

    def test_api_limits_and_role_and_authenticated_page(self):
        csrf=self.login()
        self.assertEqual(self.client.get('/master/validation',base_url='https://master.lab').status_code,200)
        for _ in range(3):self.assertEqual(self.post(csrf).status_code,200)
        result=self.post(csrf);self.assertEqual(result.status_code,429)
        self.assertEqual(result.headers['Retry-After'],'60')
        self.config.role='agent'
        self.assertEqual(self.post(csrf).status_code,404)
        self.assertEqual(self.client.get('/master/validation',base_url='https://master.lab').status_code,404)

    def test_api_https_origin_request_and_reference_fail_closed(self):
        csrf=self.login()
        for base,origin in (('http://master.lab','http://master.lab'),('https://master.lab','https://evil.test')):
            result=self.client.post(PREFIX+'/validation',base_url=base,
                headers={'Origin':origin,'X-CSRF-Token':csrf},json=self.request())
            self.assertEqual(result.status_code,403)
        headers={'Origin':'https://master.lab','X-CSRF-Token':csrf}
        for data,ctype,status in (('x','text/plain',415),('x'*(1024*1024+1),'application/json',413),('{','application/json',400)):
            result=self.client.post(PREFIX+'/validation',base_url='https://master.lab',headers=headers,data=data,content_type=ctype)
            self.assertEqual(result.status_code,status)
        with patch('detection_validation.correlate',side_effect=Unavailable('SECRET')):
            result=self.post(csrf)
        self.assertEqual(result.status_code,503);self.assertNotIn('SECRET',result.get_data(as_text=True))


if __name__=='__main__':unittest.main()
