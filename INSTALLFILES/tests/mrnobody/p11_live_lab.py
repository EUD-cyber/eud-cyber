"""Isolated P11 beacon protocol, Receiver, limits, interruption and dispatch tests."""
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from flask import Flask
from werkzeug.serving import make_server

BASE=Path(__file__).resolve().parents[2]/'TESTFILES/ATTACKER-V2'
sys.path.insert(0,str(BASE/'web'))
from agent_client import AgentConfig, AgentTransport, FatalAgentError, RetryableAgentError
from master_api import install_master_api
from master_registry import Registry
from p11_live_lab import settings, run_loop, bounded_post, MARKER

URL='/api/master/agents/p11-beacon'


class LiveLab(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.path=self.root/'master'/'registry.sqlite3'
        self.store=Registry(self.path); self.token=self.store.issue('agent-1')
        self.store.register('agent-1',self.token,'Slave')
        self.config=types.SimpleNamespace(role='master',config_status='loaded',lab_http=True)
        self.app=Flask(__name__); install_master_api(self.app,lambda:self.config,self.path)
        self.client=self.app.test_client()
        self.payload=dict(campaign_id='MRN-p11-test',phase='P11',synthetic=True,
                          timestamp='2026-11-15T12:00:00+00:00',sequence=1,marker=MARKER)
        self.data=dict(self.payload,agent_id='agent-1',protocol_version=1)

    def post(self,data=None,**kw):
        return self.client.post(URL,json=self.data if data is None else data,
            headers={'Authorization':'Bearer '+self.token},**kw)

    def test_real_http_agent_transport_committed_receipt_and_filters(self):
        server=make_server('127.0.0.1',0,self.app)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            sender=AgentTransport(AgentConfig(f'http://localhost:{server.server_port}',
                'agent-1','Slave',self.token,lab_http=True))
            ack=sender.post('p11-beacon',p11=self.payload)
        finally:
            server.shutdown();thread.join();server.server_close()
        self.assertEqual(ack['ack'],'MRN-EXERCISE-ACK'); self.assertTrue(ack['verified'])
        event,=self.store.list_receiver_events(agent_id='agent-1',campaign_id='MRN-p11-test')['events']
        self.assertEqual(event['event_type'],'beacon'); self.assertEqual(event['phase'],'P11')
        self.assertEqual(event['sequence'],1); self.assertEqual(event['timestamp'],self.payload['timestamp'])
        self.assertTrue(event['verified']); self.assertEqual(event['bytes'],len(MARKER))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT event_id,phase,sequence FROM p11_receipts').fetchone(),(ack['event_id'],'P11',1))

    def test_fixed_schema_auth_role_http_and_size(self):
        for change in ({'command':'id'},{'phase':'P06'},{'marker':'other'}, {'sequence':True},
                       {'sequence':61},{'synthetic':False},{'timestamp':'today'},
                       {'timestamp':'2026-02-30T12:00:00+00:00'},{'campaign_id':'../etc'}):
            self.assertEqual(self.post(dict(self.data,**change)).status_code,400,change)
        self.assertEqual(self.post(dict(self.data,agent_id='other')).status_code,401)
        self.assertEqual(self.post(environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code,403)
        self.config.role='agent';self.assertEqual(self.post().status_code,404)
        self.config.role='master';self.config.lab_http=False
        self.assertEqual(self.post().status_code,403)
        self.assertEqual(self.post(base_url='https://master.lab').status_code,200)
        self.config.lab_http=True
        self.assertEqual(self.client.post(URL,data=b' '*4097,content_type='application/json',
            headers={'Authorization':'Bearer '+self.token}).status_code,413)
        self.store.revoke('agent-1');self.assertEqual(self.post().status_code,401)

    def test_storage_failure_rolls_back_and_never_acknowledges(self):
        self.post()
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER reject_p11 BEFORE INSERT ON p11_receipts BEGIN SELECT RAISE(ABORT,'failure'); END")
        self.assertEqual(self.post().status_code,503)
        self.assertEqual(len(self.store.list_receiver_events()['events']),1)

    def test_client_rejects_commands_mismatched_and_missing_ack(self):
        ack=self.post().json
        sender=AgentTransport(AgentConfig('https://master.lab','agent-1','Slave',self.token))
        for change in ({'command':'id'},{'ack':'run'},{'sequence':2},{'sequence':True},
                       {'verified':False},{'agent_id':'other'},{'accepted':False}):
            body=io.BytesIO(json.dumps(dict(ack,**change)).encode()); body.status=200
            with patch.object(sender.opener,'open',return_value=body),self.assertRaises(FatalAgentError):
                sender.post('p11-beacon',p11=self.payload)

    def test_explicit_opt_in_bounds_and_create_only(self):
        self.assertIsNone(settings({}));self.assertIsNone(settings({'p11_live_lab':False}))
        self.assertEqual(settings({'p11_live_lab':True}),dict(beacon_interval=30,beacon_duration=180,beacon_count=6))
        for change in ({'p11_live_lab':'true'},{'beacon_interval':9},{'beacon_interval':301},
                       {'beacon_interval':True},{'beacon_count':0},{'beacon_count':61},
                       {'beacon_duration':1801},{'beacon_duration':59},{'action':'cleanup'},
                       {'beacon_interval':300,'beacon_duration':60}):
            with self.assertRaises(ValueError): settings({'p11_live_lab':True,**change})

    def exercise(self,options,failures=(),cancel_after=None):
        timer=types.SimpleNamespace(now=0)
        class Stop:
            def is_set(self):return cancel_after is not None and timer.now>=cancel_after
            def wait(self,delay):timer.now+=delay;return self.is_set()
        sent=[];events=[]
        def post(data,timeout,stop):
            sent.append((timer.now,data['sequence'],timeout))
            if data['sequence'] in failures:raise RetryableAgentError('blocked')
            return {'event_id':data['sequence'],'received_at':123}
        code=run_loop(types.SimpleNamespace(agent_id='agent-1'),'MRN-test',options,
            post=post,stop=Stop(),clock=lambda:timer.now,record=lambda event,**fields:events.append((event,fields)))
        return code,sent,events

    def test_default_cadence_count_and_retry_after_network_unblock(self):
        code,sent,events=self.exercise(settings({'p11_live_lab':True}),failures=(2,3))
        self.assertEqual([s[0] for s in sent],[0,30,60,90,120,150])
        self.assertEqual([s[1] for s in sent],list(range(1,7)))
        self.assertEqual(events[-1][1]['acknowledged'],4);self.assertEqual(code,0)
        self.assertEqual(sum(e[0]=='P11_BEACON_RETRY' for e in events),2)

    def test_deadline_even_if_network_fails_and_stop_interrupts_wait(self):
        options=dict(beacon_interval=30,beacon_duration=60,beacon_count=60)
        code,sent,events=self.exercise(options,failures=range(1,61))
        self.assertEqual(len(sent),2);self.assertEqual(code,1)
        self.assertEqual(events[-1][1]['reason'],'duration_limit')
        code,sent,events=self.exercise(options,cancel_after=30)
        self.assertEqual(len(sent),1);self.assertEqual(events[-1][1]['reason'],'stopped')

    def test_fatal_ack_stops_without_retry(self):
        def fatal(*args):raise FatalAgentError('invalid ack')
        events=[]
        code=run_loop(types.SimpleNamespace(agent_id='agent-1'),'MRN-test',settings({'p11_live_lab':True}),
            post=fatal,record=lambda event,**fields:events.append((event,fields)))
        self.assertEqual(code,1);self.assertEqual(events[-1][1]['attempts'],1)
        self.assertEqual(events[-1][1]['reason'],'fatal_protocol_auth_or_tls_error')

    def test_hung_dns_or_http_worker_is_killed_at_deadline_or_stop(self):
        original=subprocess.Popen
        children=[]
        def hung(*args,**kw):
            child=original([sys.executable,'-c','import time; time.sleep(10)'],**kw)
            children.append(child);return child
        for cancel in (False,True):
            stop=threading.Event()
            timer=threading.Timer(.1,stop.set) if cancel else None
            if timer:timer.start()
            started=time.monotonic()
            with patch('p11_live_lab.subprocess.Popen',side_effect=hung),self.assertRaises(RetryableAgentError):
                bounded_post(self.payload,.2 if not cancel else 5,stop)
            self.assertLess(time.monotonic()-started,2)
            self.assertIsNotNone(children[-1].poll())
            if timer:timer.join()

    def test_api_opt_in_is_runtime_only_and_invalid_selection_never_launches(self):
        import app as web
        attrs=dict(BASE_DIR=self.root,SCRIPT_DIR=BASE/'scripts',STATE_DIR=self.root/'state',
            PHASE_RUNNER=BASE/'scripts/run-phase.sh',LOG_DIR=self.root/'logs',
            CAMPAIGN_LOG=self.root/'logs/campaign.log',campaign_process=None)
        data=dict(target='10.0.0.5',protocol='ssh',username='student',password='training-only',
                  method='process',action='create',persistence_duration=300)
        with patch.multiple(web,**attrs),patch.object(web,'launch') as launch,patch('agent_client.load_agent_config',return_value=object()):
            launch.return_value.pid=123
            for extra,live in (({},False),({'p11_live_lab':False},False),({'p11_live_lab':True},True)):
                reply=web.app.test_client().post('/api/phase/11/run',json=dict(data,**extra))
                self.assertEqual(reply.status_code,200,reply.json)
                env=launch.call_args.kwargs['env']
                self.assertEqual('MRNOBODY_P11_LIVE_CONFIG' in env,live)
                if live:self.assertNotIn('password',env['MRNOBODY_P11_LIVE_CONFIG'])
            launch.reset_mock()
            for extra in ({'action':'cleanup'},{'beacon_count':99}):
                reply=web.app.test_client().post('/api/phase/11/run',json=dict(data,**dict(p11_live_lab=True,**extra)))
                self.assertEqual(reply.status_code,400)
            launch.assert_not_called()

    def test_persistence_and_dns_dispatch_preserved_live_runs_only_after_success(self):
        import remote_actions as remote
        env=dict(NORDIC_BASE_DIR=str(self.root),NORDIC_INCIDENT_ID='MRN-test',
            MRNOBODY_RUN_MODE='standalone',MRNOBODY_METHOD='process-dns',
            MRNOBODY_PERSISTENCE_DURATION='300',MRNOBODY_PERSISTENCE_DNS='enabled',
            MRNOBODY_PERSISTENCE_DOMAIN='evilcorp.test',MRNOBODY_PERSISTENCE_RESOLVER='10.0.0.53',
            MRNOBODY_PROTOCOL='ssh',MRNOBODY_TARGET='10.0.0.5',MRNOBODY_USERNAME='student',
            MRNOBODY_PASSWORD='training-only',MRNOBODY_ACTION='create')
        def invoke(args,**kw):
            self.assertEqual(kw['env']['MRNOBODY_PERSISTENCE_DNS'],'enabled')
            return types.SimpleNamespace(returncode=0,stdout=b'{"result":"success"}')
        with patch('p11_live_lab.run',return_value=0) as live:
            self.assertEqual(remote.run('11',env,invoke),0);live.assert_not_called()
            env['MRNOBODY_P11_LIVE_CONFIG']=json.dumps({'p11_live_lab':True})
            self.assertEqual(remote.run('11',env,invoke),0);live.assert_called_once_with(env)
            live.reset_mock()
            self.assertEqual(remote.run('11',env,lambda *a,**k:types.SimpleNamespace(returncode=1)),1)
            live.assert_not_called()
            with patch('p11_campaign.run',return_value=0) as campaign:
                self.assertEqual(remote.run('11',dict(env,MRNOBODY_RUN_MODE='campaign'),invoke),0)
                campaign.assert_called_once();live.assert_not_called()


if __name__=='__main__':unittest.main()
