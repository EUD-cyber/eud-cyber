"""Offline real payload/Flask/SQLite/transport integration; no lab hosts contacted."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import urllib.error

from flask import Flask
BASE=Path(__file__).resolve().parents[2]/'TESTFILES/ATTACKER-V2'
sys.path.insert(0,str(BASE/'web'))
from agent_client import AgentConfig, AgentTransport, FatalAgentError, RetryableAgentError
from master_api import install_master_api
from master_registry import Registry
from p06_synthetic import fixture
from p06_live_lab import MAX_FILE, read_verified, send, validate_selection

URL='/api/master/agents/p06-file'
IID='MRN-live-lab-test'


class LiveLab(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.path=self.root/'master'/'registry.sqlite3'
        self.store=Registry(self.path)
        self.token=self.store.issue('agent-1')
        self.store.register('agent-1',self.token,'Slave')
        self.config=types.SimpleNamespace(role='master',config_status='loaded',lab_http=False)
        self.app=Flask(__name__)
        install_master_api(self.app,lambda:self.config,self.path)
        self.client=self.app.test_client()
        self.raw=fixture(IID)
        self.payload=dict(campaign_id=IID,phase='P06',synthetic=True,size=len(self.raw),
                          sha256=hashlib.sha256(self.raw).hexdigest(),
                          content=base64.b64encode(self.raw).decode())
        self.data=dict(self.payload,agent_id='agent-1',protocol_version=1)

    def post(self,data=None,**kwargs):
        return self.client.post(URL,json=self.data if data is None else data,
            base_url='https://master.lab',headers={'Authorization':'Bearer '+self.token},
            environ_overrides={'REMOTE_ADDR':'10.0.0.2'},**kwargs)

    def test_receipt_is_committed_content_and_dashboard_evidence(self):
        before=self.store.list_agents()
        response=self.post()
        self.assertEqual(response.status_code,200)
        ack=response.get_json()
        with sqlite3.connect(self.path) as db:
            row=db.execute('SELECT event_id,phase,sha256,content FROM p06_receipts').fetchone()
        self.assertEqual(row,(ack['event_id'],'P06',self.payload['sha256'],self.raw))
        self.assertTrue(ack['verified'])
        self.assertEqual(self.store.list_agents(),before)
        event,=self.store.list_receiver_events()['events']
        self.assertEqual(event['agent_id'],'agent-1')
        self.assertEqual(event['campaign_id'],IID)
        self.assertEqual(event['received_size'],len(self.raw))
        self.assertEqual(event['sha256'],self.payload['sha256'])
        self.assertEqual(event['phase'],'P06')
        self.assertNotIn('content',event)
        self.assertNotIn(self.token,response.text)

    def test_hash_size_content_and_schema_errors_leave_no_receipt(self):
        mutations=[dict(sha256='0'*64),dict(size=0),dict(size=True),dict(size=MAX_FILE+1),
                   dict(size=len(self.raw)+1),dict(content='!bad base64'),dict(content='a'*6000),
                   dict(synthetic=False),dict(phase='P11'),dict(campaign_id='../etc'),
                   dict(campaign_id=None),dict(command='id'),dict(protocol_version=True)]
        altered=b'not a synthetic P06 file'
        mutations.append(dict(size=len(altered),sha256=hashlib.sha256(altered).hexdigest(),
                              content=base64.b64encode(altered).decode()))
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertEqual(self.post(dict(self.data,**mutation)).status_code,400)
        self.assertEqual(self.store.list_receiver_events()['events'],[])
        response=self.client.post(URL,data=b' '*8193,content_type='application/json',
            base_url='https://master.lab',headers={'Authorization':'Bearer '+self.token})
        self.assertEqual(response.status_code,413)

    def test_role_auth_lab_http_and_revoke(self):
        self.assertEqual(self.post(dict(self.data,agent_id='other')).status_code,401)
        self.config.role='agent'
        self.assertEqual(self.post().status_code,404)
        self.config.role='master'
        for lab,expected in ((False,403),(True,200)):
            self.config.lab_http=lab
            response=self.client.post(URL,json=self.data,base_url='http://master.lab',
                headers={'Authorization':'Bearer '+self.token},environ_overrides={'REMOTE_ADDR':'10.0.0.2'})
            self.assertEqual(response.status_code,expected)
        self.store.revoke('agent-1')
        self.assertEqual(self.post().status_code,401)

    def test_storage_failure_never_acknowledges_or_leaves_event(self):
        self.post()
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER reject_p06 BEFORE INSERT ON p06_receipts BEGIN SELECT RAISE(ABORT,'disk failure'); END")
        self.assertEqual(self.post().status_code,503)
        self.assertEqual(len(self.store.list_receiver_events()['events']),1)

    def artifact(self):
        self.upload=self.root/'uploads'
        self.upload.mkdir()
        self.file=self.upload/f'{IID}-linux-10.0.0.5.bin'
        self.file.write_bytes(self.raw)
        self.state=self.root/'exfiltration.json'
        self.state.write_text(json.dumps(dict(incident_id=IID,transfers=[dict(
            source='10.0.0.5',platform='linux',source_kind='synthetic-default',synthetic=True,
            verified=True,successful=True,sha256=self.payload['sha256'])])))

    def test_sender_posts_actual_verified_file_and_checks_master_ack(self):
        self.artifact()
        parent=self
        class Opener:
            def open(self,request,timeout):
                parent.assertEqual(timeout,10)
                parent.assertEqual(request.full_url,'https://master.lab'+URL)
                response=parent.client.post(URL,data=request.data,headers=dict(request.header_items()),
                    base_url='https://master.lab',environ_overrides={'REMOTE_ADDR':'10.0.0.2'})
                parent.assertEqual(response.status_code,200)
                result=io.BytesIO(response.data)
                result.status=200
                return result
        sender=AgentTransport(AgentConfig('https://master.lab','agent-1','Slave',self.token),opener=Opener())
        result=send(self.state,self.upload,IID,sender)
        self.assertTrue(result['verified'])
        self.assertEqual(json.loads(self.state.read_text())['live_lab']['event_id'],result['event_id'])
        for mutation in ({'sha256':'0'*64},{'campaign_id':'other'},{'accepted':False},{'verified':False},
                         {'phase':'P11'},{'size':999},{'agent_id':'other'},{'command':'id'}):
            body=io.BytesIO(json.dumps(dict(result,**mutation)).encode());body.status=200
            with patch.object(sender.opener,'open',return_value=body),self.assertRaises(FatalAgentError):
                sender.post('p06-file',p06=self.payload)
        for failure,kind in ((TimeoutError(),RetryableAgentError),
                             (urllib.error.HTTPError('url',400,'bad',{},io.BytesIO()),FatalAgentError)):
            with patch.object(sender.opener,'open',side_effect=failure),self.assertRaises(kind):
                sender.post('p06-file',p06=self.payload)

    def test_local_file_tamper_size_symlink_and_unverified_rejected(self):
        self.artifact()
        self.assertEqual(read_verified(self.state,self.upload,IID),self.raw)
        for raw in (b'local secret',b'x'*(MAX_FILE+1)):
            self.file.write_bytes(raw)
            with self.assertRaises(ValueError):read_verified(self.state,self.upload,IID)
        self.file.unlink()
        self.file.symlink_to(self.state)
        with self.assertRaises(ValueError):read_verified(self.state,self.upload,IID)
        self.file.unlink();self.file.write_bytes(self.raw)
        state=json.loads(self.state.read_text());state['transfers'][0]['verified']=False
        self.state.write_text(json.dumps(state))
        with self.assertRaises(ValueError):read_verified(self.state,self.upload,IID)

    def test_selection_is_explicit_and_never_reuses_user_paths(self):
        self.assertFalse(validate_selection({}))
        for data in ({'live_lab':'1'},{'live_lab':True,'file':'/etc/shadow'},
                     {'live_lab':True,'staging_incident':IID}):
            with self.assertRaises(ValueError):validate_selection(data)
        with patch('agent_client.load_agent_config',return_value=object()):
            self.assertTrue(validate_selection({'live_lab':True}))

    def test_standalone_api_opt_in_profile_and_default_dispatch(self):
        import app as web
        attrs=dict(BASE_DIR=self.root,SCRIPT_DIR=BASE/'scripts',STATE_DIR=self.root/'state',
                   PHASE_RUNNER=BASE/'scripts/run-phase.sh',LOG_DIR=self.root/'logs',
                   CAMPAIGN_LOG=self.root/'logs/campaign.log',campaign_process=None)
        data=dict(target='10.0.0.5',protocol='ssh',username='student',password='training-only')
        with patch.multiple(web,**attrs),patch.object(web,'launch') as launch,patch('agent_client.load_agent_config',return_value=object()):
            launch.return_value.pid=123
            for extra,expected in (({},'0'),({'live_lab':False},'0'),({'live_lab':True},'1'),
                ({'live_lab':True,'profile':{'mode':'normal','duration':0}},'1')):
                reply=web.app.test_client().post('/api/phase/06/run',json=dict(data,**extra))
                self.assertEqual(reply.status_code,200,reply.json)
                self.assertEqual(launch.call_args.kwargs['env']['MRNOBODY_P06_LIVE_LAB'],expected)
            launch.reset_mock()
            reply=web.app.test_client().post('/api/phase/06/run',json=dict(data,live_lab=True,file='/etc/shadow'))
            self.assertEqual(reply.status_code,400)
            launch.assert_not_called()


if __name__=='__main__':unittest.main()
