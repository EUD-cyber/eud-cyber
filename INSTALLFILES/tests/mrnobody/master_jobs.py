"""Fixed synthetic job state machine, HTTP boundary and worker failure tests."""
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import patch
from flask import Flask

WEB=Path(__file__).resolve().parents[2]/'TESTFILES/ATTACKER-V2/web'
sys.path.insert(0,str(WEB))
from master_jobs import Jobs, OPERATION
import master_jobs
from master_registry import Unauthorized, Conflict
from master_api import install_master_api
from agent_client import AgentConfig, AgentTransport, FatalAgentError, RetryableAgentError
from agent_jobs import Worker
from p11_live_lab import run_loop


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.now=1000
        self.jobs=Jobs(self.root/'master/registry.sqlite3',clock=lambda:self.now)
        self.token=self.jobs.issue('agent-1')
        self.jobs.register('agent-1',self.token,'Slave')
        self.config=AgentConfig('https://master.lab','agent-1','Slave',self.token)
        self.deployment=types.SimpleNamespace(role='master',config_status='loaded',lab_http=True)
        self.app=Flask(__name__)
        install_master_api(self.app,lambda:self.deployment,self.jobs.path)
        self.client=self.app.test_client()

    def start(self,key='request-1'):
        return self.jobs.enqueue('agent-1',key)

    def exchange(self,report=None):
        return self.jobs.exchange('agent-1',self.token,report)['job']

    def report(self,job,state):
        return self.exchange(dict(job_id=job['job_id'],status=state))

    def worker(self,run):
        sender=types.SimpleNamespace(post=lambda kind,job_report:dict(job=self.exchange(job_report)))
        return Worker(self.config,self.root/'slave/journal.sqlite3',sender=sender,run=run)

    def test_lifecycle_and_lost_response_idempotence(self):
        job=self.start()
        self.assertEqual(self.start(),job)
        self.assertEqual(self.exchange()['status'],'delivered')
        self.assertEqual(self.exchange()['job_id'],job['job_id'])
        self.assertEqual(self.report(job,'running')['status'],'running')
        self.assertEqual(self.report(job,'succeeded')['status'],'succeeded')
        self.assertEqual(self.report(job,'failed')['status'],'succeeded')
        self.assertEqual(self.start()['job_id'],job['job_id'])
        self.assertIsNone(self.exchange())
        self.assertNotIn(self.token,json.dumps(self.jobs.inspect(job['job_id'])))

    def test_allowlist_and_strict_schema(self):
        for operation in ('shell','P11','full-incident','p06-live-lab'):
            with self.assertRaises(ValueError): self.jobs.enqueue('agent-1','req',operation)
        for report in ({'job_id':'bad','status':'running'}, {'command':'id'}, {'job_id':[],'status':'running'}):
            with self.assertRaises(ValueError): self.exchange(report)
        with self.assertRaises(ValueError): self.jobs.enqueue('agent-1','../bad')

    def test_binding_and_revocation(self):
        job=self.start()
        token2=self.jobs.issue('agent-2'); self.jobs.register('agent-2',token2,'Other')
        with self.assertRaises(Unauthorized): self.jobs.exchange('agent-2',self.token,None)
        with self.assertRaises(Unauthorized): self.jobs.exchange('agent-2',token2,dict(job_id=job['job_id'],status='running'))
        with self.assertRaises(Conflict): self.jobs.enqueue('agent-2','request-1')
        self.jobs.revoke('agent-1')
        with self.assertRaises(Unauthorized): self.exchange()
        self.assertEqual(self.jobs.inspect(job['job_id'])['reason'],'identity_revoked_or_changed')

    def test_registration_online_and_global_single_job(self):
        self.jobs.issue('pending')
        with self.assertRaises(Conflict): self.jobs.enqueue('pending','pending-key')
        self.now+=91
        with self.assertRaises(Conflict): self.start()
        self.jobs.heartbeat('agent-1',self.token)
        self.start()
        with self.assertRaises(Conflict): self.start('other-key')

    def test_concurrent_enqueue_is_single_and_idempotent(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids=list(pool.map(lambda _:self.start()['job_id'],range(8)))
        self.assertEqual(len(set(ids)),1)

    def test_stop_queued_delivered_running_and_late_success(self):
        for number in range(3):
            job=self.start('stop-'+str(number))
            if number: self.exchange()
            if number==2: self.report(job,'running')
            stopped=self.jobs.inspect(job['job_id'],True)
            self.assertTrue(stopped['stop_requested'])
            if number: self.assertEqual(self.report(job,'stopped')['status'],'stopped')
            else: self.assertEqual(stopped['status'],'stopped')
        job=self.start('late'); self.exchange(); self.report(job,'running')
        self.jobs.inspect(job['job_id'],True)
        self.assertEqual(self.report(job,'succeeded')['status'],'stopped')

    def test_timeout_never_redelivers_or_accepts_late_success(self):
        job=self.start(); self.exchange(); self.report(job,'running')
        self.now+=180
        self.assertIsNone(self.exchange())
        self.assertEqual(self.report(job,'succeeded')['status'],'failed')
        self.assertEqual(self.jobs.inspect(job['job_id'])['reason'],'deadline_exceeded')

    def test_cannot_report_success_before_acceptance(self):
        job=self.start()
        with self.assertRaises(ValueError): self.report(job,'succeeded')
        self.exchange()
        with self.assertRaises(ValueError): self.report(job,'succeeded')

    def test_real_route_tls_auth_size_role_duplicate_fields(self):
        # Use a current timestamp for the real route's default clock.
        self.jobs.clock=__import__('time').time
        self.jobs.heartbeat('agent-1',self.token); self.start()
        payload=dict(agent_id='agent-1',protocol_version=1,report=None)
        def post(**kwargs):
            return self.client.post('/api/master/agents/job-poll',headers={'Authorization':'Bearer '+self.token},**kwargs)
        self.assertEqual(post(json=payload).status_code,403) # Lab HTTP is insufficient.
        self.assertEqual(post(json=payload,base_url='https://master.lab').status_code,200)
        self.assertEqual(post(json=dict(payload,agent_id='agent-2'),base_url='https://master.lab').status_code,401)
        self.assertEqual(post(json=dict(payload,command='id'),base_url='https://master.lab').status_code,400)
        self.assertEqual(post(data='{"agent_id":"a","agent_id":"b"}',content_type='application/json',base_url='https://master.lab').status_code,400)
        self.assertEqual(post(data=' '*4097,content_type='application/json',base_url='https://master.lab').status_code,413)
        self.deployment.role='agent'
        self.assertEqual(post(json=payload,base_url='https://master.lab').status_code,404)

    def test_worker_success_durable_no_replay(self):
        calls=[]
        def run(config,ident,options,stop,record):
            calls.append(ident)
            self.assertEqual(options,dict(beacon_interval=30,beacon_duration=90,beacon_count=3))
            record('P11_BEACON_STOP',acknowledged=3,failed=0)
            return 0
        job=self.start(); worker=self.worker(run); worker.step(); worker.step()
        self.assertEqual(calls,[job['job_id']])
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'succeeded')

    def test_restart_uncertain_job_fails_without_execution(self):
        job=self.start(); self.exchange()
        worker=self.worker(lambda *a,**kw:self.fail('must never execute'))
        worker.remember(job['job_id'],'running')
        worker.step()
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'failed')

    def test_lost_terminal_ack_does_not_execute_twice(self):
        job=self.start(); self.exchange(); self.report(job,'running')
        worker=self.worker(lambda *a,**kw:self.fail('must never execute'))
        worker.remember(job['job_id'],'succeeded')
        worker.step()
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'succeeded')

    def test_worker_partial_receipt_and_exception_fail(self):
        def partial(*args,**kw):
            kw['record']('P11_BEACON_STOP',acknowledged=1,failed=2)
            return 0
        job=self.start(); self.worker(partial).step()
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'failed')
        def broken(*args,**kw): raise RuntimeError('private error')
        job=self.start('broken'); self.worker(broken).step()
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'failed')

    def test_worker_stop_and_network_failure_cancel_active_beacon(self):
        for failure in (False,True):
            job=self.start('network' if failure else 'stop')
            cancelled=threading.Event()
            def run(*args,**kwargs):
                if not failure: self.jobs.inspect(job['job_id'],True)
                kwargs['stop'].wait(5)
                if kwargs['stop'].is_set(): cancelled.set()
                return 1
            worker=self.worker(run)
            original=worker.exchange; count=[0]
            def exchange(report=None):
                count[0]+=1
                if failure and count[0]==3: raise RetryableAgentError('unavailable')
                return original(report)
            worker.exchange=exchange
            if failure:
                with self.assertRaises(RetryableAgentError): worker.step()
                worker.exchange=original; worker.step()
            else: worker.step()
            self.assertTrue(cancelled.is_set())
            self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'failed' if failure else 'stopped')

    def test_http_worker_rejected_and_bad_master_operation(self):
        config=AgentConfig('http://master.lab','agent-1','Slave',self.token,lab_http=True)
        with self.assertRaises(FatalAgentError): Worker(config,self.root/'slave/journal.sqlite3')
        with self.assertRaises(FatalAgentError): AgentTransport(config).post('job-poll')
        sender=types.SimpleNamespace(post=lambda *a,**kw:dict(job=dict(self.start(),operation='shell')))
        worker=Worker(self.config,self.root/'slave/journal.sqlite3',sender=sender)
        with self.assertRaises(ValueError): worker.step()

    def test_transport_actual_routes_existing_beacons_and_committed_receipts(self):
        self.jobs.clock=__import__('time').time
        self.jobs.heartbeat('agent-1',self.token); job=self.start()
        class Response(io.BytesIO):
            status=200
        def open_request(request,timeout):
            response=self.client.post(request.full_url.split('master.lab',1)[1],
                data=request.data,content_type='application/json',
                headers={'Authorization':request.get_header('Authorization')},base_url='https://master.lab')
            self.assertEqual(response.status_code,200,response.data)
            return Response(response.data)
        sender=AgentTransport(self.config,types.SimpleNamespace(open=open_request))
        def accelerated(config,ident,options,stop,record):
            clock=[0]
            class Cadence:
                def is_set(inner): return stop.is_set()
                def wait(inner,seconds): clock[0]+=seconds; return stop.is_set()
            return run_loop(config,ident,options,stop=Cadence(),clock=lambda:clock[0],record=record,
                post=lambda payload,timeout,cancel:sender.post('p11-beacon',p11=payload))
        Worker(self.config,self.root/'slave/journal.sqlite3',sender=sender,run=accelerated).step()
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'succeeded')
        events=self.jobs.list_receiver_events(agent_id='agent-1',campaign_id=job['job_id'])['events']
        self.assertEqual(len(events),3)
        self.assertEqual({event['sequence'] for event in events},{1,2,3})
        self.assertTrue(all(event['verified'] and event['phase']=='P11' for event in events))

    def test_transport_rejects_forged_job_and_report_ack(self):
        job=self.start()
        def sender(value):
            class Response(io.BytesIO): status=200
            return AgentTransport(self.config,types.SimpleNamespace(open=lambda *a,**k:Response(json.dumps(value).encode())))
        valid=dict(agent_id='agent-1',protocol_version=1,job=dict(job,status='delivered'))
        for change in (dict(valid,agent_id='other'),dict(valid,protocol_version=True),
                       dict(valid,job=dict(job,operation='shell')),dict(valid,job=dict(job,target='10.0.0.1'))):
            with self.assertRaises(FatalAgentError): sender(change).post('job-poll')
        with self.assertRaises(FatalAgentError): sender(dict(valid,job=None)).post('job-poll',job_report=dict(job_id=job['job_id'],status='running'))

    def test_storage_failure_never_acknowledges_transition(self):
        job=self.start()
        with closing(sqlite3.connect(self.jobs.path)) as db, db:
            db.execute("CREATE TRIGGER reject_job BEFORE UPDATE ON execution_jobs BEGIN SELECT RAISE(ABORT,'failure'); END")
        payload=dict(agent_id='agent-1',protocol_version=1,report=None)
        response=self.client.post('/api/master/agents/job-poll',json=payload,
            headers={'Authorization':'Bearer '+self.token},base_url='https://master.lab')
        self.assertEqual(response.status_code,503)
        with closing(sqlite3.connect(self.jobs.path)) as db, db:
            self.assertEqual(db.execute('SELECT status FROM execution_jobs').fetchone()[0],'queued')

    def test_local_master_cli_and_role_boundary(self):
        self.jobs.clock=__import__('time').time
        self.jobs.heartbeat('agent-1',self.token)
        argv=['master_jobs.py','--database',str(self.jobs.path),'start','agent-1','cli-key']
        with patch('deployment_config.load_deployment_config',return_value=self.deployment), patch.object(sys,'argv',argv), patch('sys.stdout',new_callable=io.StringIO) as output:
            master_jobs.main()
        job=json.loads(output.getvalue())
        self.assertEqual(job['status'],'queued')
        with patch('deployment_config.load_deployment_config',return_value=self.deployment), patch.object(sys,'argv',argv), patch('sys.stdout',new_callable=io.StringIO) as output:
            master_jobs.main()
        self.assertEqual(json.loads(output.getvalue())['job_id'],job['job_id'])
        self.deployment.role='standalone'
        with patch('deployment_config.load_deployment_config',return_value=self.deployment), patch.object(sys,'argv',argv), patch('sys.stderr',new_callable=io.StringIO), self.assertRaises(SystemExit) as exc:
            master_jobs.main()
        self.assertEqual(exc.exception.code,2)

    def test_missing_storage_and_symlink_journal_fail_closed(self):
        with patch('deployment_config.load_deployment_config',return_value=self.deployment), patch.object(sys,'argv',['master_jobs.py','--database',str(self.root/'missing.sqlite3'),'start','agent-1','key']), patch('sys.stderr',new_callable=io.StringIO), self.assertRaises(SystemExit) as exc:
            master_jobs.main()
        self.assertEqual(exc.exception.code,2)
        self.assertFalse((self.root/'missing.sqlite3').exists())
        target=self.root/'target'; target.mkdir()
        link=self.root/'linked'; link.symlink_to(target,target_is_directory=True)
        with self.assertRaises(FatalAgentError): Worker(self.config,link/'journal.sqlite3')

    def test_local_deadline_is_failure_and_cancels_activity(self):
        job=self.start(); cancelled=threading.Event()
        def run(*args,**kwargs):
            kwargs['stop'].wait(5)
            if kwargs['stop'].is_set(): cancelled.set()
            return 1
        with patch('agent_jobs.time.monotonic',side_effect=[0,101]):
            self.worker(run).step()
        self.assertTrue(cancelled.is_set())
        self.assertEqual(self.jobs.inspect(job['job_id'])['status'],'failed')


if __name__=='__main__': unittest.main()
