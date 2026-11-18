"""Isolated private Lab Mode, CSRF, transport and zero-touch contracts."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from flask import Flask

ROOT=Path(__file__).resolve().parents[2]
WEB=ROOT/'TESTFILES/ATTACKER-V2/web'
sys.path.insert(0,str(WEB))
sys.path.insert(1,str(ROOT))
from deployment_config import DeploymentConfig, _parse, load_deployment_config
from lab_mode import contains, configure, nginx_content
from master_admin import install_admin_auth
from master_api import install_master_api
from master_jobs import Jobs
from agent_client import AgentConfig, AgentTransport, FatalAgentError, bootstrap_agent
from agent_jobs import Worker
from p11_live_lab import run_loop

BASE='http://192.168.50.3'
NETWORKS=('192.168.50.0/24',)


class Configuration(unittest.TestCase):
    def test_old_lab_http_never_implies_lab_mode(self):
        config=_parse('MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\n')
        self.assertFalse(config.lab_mode)
        self.assertEqual(config.lab_networks,())

    def test_explicit_private_cidrs_and_fail_closed_inputs(self):
        base='MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE=1\n'
        self.assertTrue(_parse(base+'MRNOBODY_LAB_NETWORKS=192.168.50.0/24').lab_mode)
        for net in ('','0.0.0.0/0','8.8.8.0/24','127.0.0.0/8','100.64.0.0/10','::/0','192.168.50.1/24'):
            with self.assertRaises(ValueError):_parse(base+'MRNOBODY_LAB_NETWORKS='+net)
        for bad in (base.replace('master','standalone'),base.replace('LAB_HTTP=1','LAB_HTTP=0'),base.replace('LAB_MODE=1','LAB_MODE=true')):
            with self.assertRaises(ValueError):_parse(bad+'MRNOBODY_LAB_NETWORKS=192.168.50.0/24')

    def test_control_origins_are_separate_explicit_exact_origins(self):
        base='MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE=1\nMRNOBODY_LAB_NETWORKS=192.168.50.0/24\n'
        self.assertEqual(_parse(base).lab_control_origins, ())
        self.assertEqual(_parse(base+'MRNOBODY_LAB_CONTROL_ORIGINS=http://master.lab,https://slave.lab:8443').lab_control_origins,
                         ('http://master.lab','https://slave.lab:8443'))
        for bad in ('*','http://*.lab','http://master.lab/','http://user@master.lab','http://master.lab:0',
                    'http://master.lab:65536','http://master.lab?x=1','https://master.lab#x',','.join(['http://a.lab']*17)):
            with self.assertRaises(ValueError):_parse(base+'MRNOBODY_LAB_CONTROL_ORIGINS='+bad)

    def test_nginx_switches_only_explicit_mode_and_keeps_tls_agent_routes(self):
        text=(WEB.parent/'nginx/nordic-incident.conf').read_text()
        old=DeploymentConfig('master','', 'loaded',True)
        self.assertEqual(nginx_content(text,old),text)
        active=nginx_content(text,replace(old,lab_mode=True,lab_networks=NETWORKS))
        self.assertNotIn('location / { return 301',active)
        self.assertIn('proxy_set_header Host $http_host;',active)
        self.assertEqual(active.split('# HTTPS\n')[1],text.split('# HTTPS\n')[1])
        with self.assertRaises(ValueError):nginx_content('wrong template',replace(old,lab_mode=True,lab_networks=NETWORKS))

    def test_private_single_vm_rendering_and_protected_standalone_defaults(self):
        import yaml
        from MRNOBODY.single_vm_create import render_userdata
        template=(ROOT/'MRNOBODY/mrnobody_userdata.yaml').read_text()
        for role in ('master','agent','standalone'):
            plan=dict(role=role,master_url=BASE if role=='agent' else '',ipv4='192.168.1.254/24',lab_http=role!='standalone')
            rendered=yaml.safe_load(render_userdata(template,plan))
            content=next(item['content'] for item in rendered['write_files'] if item['path']=='/etc/mrnobody/deployment.conf')
            config=_parse(content)
            self.assertEqual(config.lab_mode,role!='standalone')
            if role=='agent':self.assertTrue(contains(config,'192.168.50.3'))
            if role=='master':self.assertEqual(config.lab_networks,('192.168.1.0/24',))
        self.assertNotIn('MRNOBODY_LAB_MODE=',template)

    def test_shared_big_mini_custom_renderer_keeps_template_and_scopes_numeric_master(self):
        import subprocess
        import yaml
        source=(ROOT/'MRNOBODY/mrnobody_installer.sh').read_text()
        code=source.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        template=ROOT/'MRNOBODY/mrnobody_userdata.yaml';before=template.read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            for url,expected in ((BASE,True),('http://master.test',False)):
                result=subprocess.run([sys.executable,'-c',code,str(template),tmp,'3','agent',url],check=True,capture_output=True,text=True)
                data=yaml.safe_load((Path(tmp)/result.stdout.strip()).read_text())
                config=_parse(next(item['content'] for item in data['write_files'] if item['path']=='/etc/mrnobody/deployment.conf'))
                self.assertEqual(config.lab_mode,expected)
                if expected:self.assertEqual(set(config.lab_networks),{'192.168.1.0/24','192.168.2.0/24','172.20.0.0/24','192.168.50.3/32'})
        self.assertEqual(template.read_bytes(),before)

    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Root-owned isolated shell lifecycle on Linux')
    def test_worker_unit_activation_gate_and_failure_restore(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);web=root/'web';web.mkdir();(root/'systemd').mkdir();(root/'backup').mkdir()
            config=root/'deployment.conf';identity=root/'agent.json';identity.write_bytes(b'unchanged identity')
            parser=(WEB/'deployment_config.py').read_text().replace('Path("/etc/mrnobody/deployment.conf")','Path('+repr(str(config))+')')
            (web/'deployment_config.py').write_text(parser)
            (root/'systemd/mrnobody-agent-jobs.service').write_text('new worker unit\n')
            target=root/'active.service'
            source=(WEB.parent/'scripts/update.sh').read_text()
            helper=source[source.index('restore_jobs_unit() {'):source.index('repair_nginx_config() {')]
            helper=helper.replace('/etc/systemd/system/mrnobody-agent-jobs.service',str(target)).replace('/etc/mrnobody/agent.json',str(identity))
            for role,mode,fail in (('master',True,False),('standalone',False,False),('agent',False,False),('agent',True,False),('agent',True,True)):
                config.write_text('MRNOBODY_ROLE='+role+'\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE='+str(int(mode))+'\nMRNOBODY_LAB_NETWORKS=192.168.50.0/24\n')
                target.write_text('previous unit\n')
                script='''set -eu
JOBS_UNIT_INSTALLED=0; JOBS_WAS_ACTIVE=0; JOBS_WAS_ENABLED=0
log() { :; }
systemctl() {
 echo "CALL:$*"
 case "$1" in is-active|is-enabled) return 1;; esac
 if [[ "$1 $2" == "enable --now" && "$TEST_FAIL" == 1 ]]; then return 1; fi
 return 0
}
'''+helper+'\nif install_jobs_unit; then echo RESULT:0; else echo RESULT:1; fi\n'
                # $2 may be unset for daemon-reload under set -u.
                script=script.replace('$1 $2','$1 ${2:-}')
                result=subprocess.run(['bash'],input=script,text=True,capture_output=True,timeout=10,
                    env=dict(os.environ,INSTALL_DIR=str(root),BACKUP_DIR=str(root/'backup'),TEST_FAIL=str(int(fail))))
                self.assertEqual(result.returncode,0,result.stderr)
                selected=role=='agent' and mode
                self.assertEqual('CALL:enable --now mrnobody-agent-jobs.service' in result.stdout,selected)
                self.assertEqual(target.read_text(),'new worker unit\n' if selected and not fail else 'previous unit\n')
                self.assertIn('RESULT:1' if fail else 'RESULT:0',result.stdout)
                self.assertEqual(identity.read_bytes(),b'unchanged identity')

    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Root-owned migration fixture on Linux')
    def test_explicit_migration_discovers_only_local_private_networks_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'deployment.conf';identity=Path(tmp)/'agent.json'
            identity.write_bytes(b'private identity sentinel')
            path.write_text('MRNOBODY_ROLE=agent\nMRNOBODY_MASTER_URL='+BASE+'\nMRNOBODY_LAB_HTTP=1\n')
            discovery=lambda:[{'addr_info':[{'local':'192.168.1.254','prefixlen':24},{'local':'8.8.8.8','prefixlen':24}]}]
            configure(path,[],discover=discovery);config=load_deployment_config(path)
            self.assertTrue(config.lab_mode);self.assertTrue(contains(config,'192.168.50.3'))
            self.assertFalse(contains(config,'8.8.8.8'))
            first=path.read_bytes();configure(path,[],discover=discovery)
            self.assertEqual(path.read_bytes(),first);self.assertEqual(identity.read_bytes(),b'private identity sentinel')
            path.chmod(0o666)
            with self.assertRaises(ValueError):configure(path,NETWORKS)


class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.path=self.root/'master/registry.sqlite3'
        self.config=DeploymentConfig('master','', 'loaded',True,True,NETWORKS)
        self.now=1000
        self.app=Flask('lab-mode',template_folder=str(WEB/'templates'))
        self.app.add_url_rule('/',view_func=lambda:'dashboard')
        install_master_api(self.app,lambda:self.config,self.path)
        install_admin_auth(self.app,lambda:self.config,clock=lambda:self.now,registry_path=self.path)
        self.client=self.app.test_client();self.peer={'REMOTE_ADDR':'192.168.50.2'}

    def get(self,path,**options):
        return self.client.get(path,base_url=BASE,environ_overrides=self.peer,**options)

    def session(self):
        result=self.get('/api/master/admin/session')
        self.assertEqual(result.status_code,200,result.data)
        return result.json['csrf']

    def post(self,path,body,csrf='',headers=None,**options):
        return self.client.post(path,base_url=BASE,environ_overrides=options.pop('environ_overrides',self.peer),
            headers={'Origin':BASE,'X-CSRF-Token':csrf,**(headers or {})},json=body,**options)

    def seed(self):
        jobs=Jobs(self.path);token=jobs.issue('agent-1');jobs.register('agent-1',token,'Slave')
        return jobs,token

    def test_dashboard_and_controls_need_no_credential_but_session_is_opaque(self):
        with patch('master_admin.load_credential',side_effect=AssertionError('No provisioning in Lab Mode')):
            self.assertEqual(self.get('/').status_code,200)
            self.assertEqual(self.get('/master/admin').status_code,200)
            self.assertEqual(self.get('/master/validation').status_code,200)
            result=self.get('/api/master/admin/session')
        self.assertTrue(result.json['lab_mode']);self.assertEqual(len(result.json['csrf']),43)
        cookie=result.headers['Set-Cookie'];self.assertIn('HttpOnly',cookie);self.assertIn('SameSite=Strict',cookie)
        self.assertNotIn('Secure;',cookie);self.assertEqual(result.headers['Cache-Control'],'no-store')
        self.assertEqual(self.session(),result.json['csrf'])

    def test_all_networks_ip_dns_and_ipv6_can_read_without_control_authority(self):
        for role in ('master','agent'):
            self.config=replace(self.config,role=role)
            for peer,host in (('8.8.8.8',BASE),('192.168.51.2',BASE),('2001:db8::2','http://master.lab'),
                              ('192.168.50.2','http://unapproved.test'),('8.8.8.8','http://203.0.113.3:8080')):
                with self.subTest(role=role,peer=peer,host=host):
                    result=self.client.get('/',base_url=host,environ_overrides={'REMOTE_ADDR':peer})
                    self.assertEqual(result.status_code,200)
                    result=self.client.get('/api/master/admin/session',base_url=host,environ_overrides={'REMOTE_ADDR':peer},headers={'Origin':host})
                    self.assertEqual(result.status_code,200)
                    self.assertFalse(result.json['web_job_control'])
                    csrf=result.json['csrf']
                    for path in ('/api/master/admin/jobs','/api/execute','/api/update','/api/config','/api/scenarios'):
                        for method in ('POST','PUT','PATCH','DELETE'):
                            result=self.client.open(path,method=method,base_url=host,json={},environ_overrides={'REMOTE_ADDR':peer},
                                headers={'Origin':host,'X-CSRF-Token':csrf,'X-Real-IP':'192.168.50.2','X-Forwarded-Proto':'https'})
                            self.assertEqual(result.status_code,403)
        self.assertEqual(self.get('/api/master/admin/session',headers={'Origin':'https://evil.test'}).status_code,403)
        self.assertEqual(self.get('/',headers={'Sec-Fetch-Site':'cross-site'}).status_code,403)

    def test_only_loopback_proxy_is_trusted_and_https_cookie_remains_secure(self):
        result=self.client.get('/api/master/admin/session',base_url='http://192.168.50.3',
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'192.168.50.2','X-Forwarded-Proto':'https'})
        self.assertEqual(result.status_code,200);self.assertIn('Secure;',result.headers['Set-Cookie'])
        result=self.client.get('/api/master/admin/session',base_url=BASE,environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(result.status_code,200);self.assertFalse(result.json['web_job_control'])

    def test_dns_control_requires_root_approved_origin_trusted_peer_and_csrf(self):
        self.seed();host='http://master.lab:8080';body=dict(agent_id='agent-1',request_key='dns-start')
        def get_session():
            return self.client.get('/api/master/admin/session',base_url=host,environ_overrides=self.peer).json
        def post(csrf,peer=None,origin=host):
            return self.client.post('/api/master/admin/jobs',base_url=host,json=body,environ_overrides=peer or self.peer,
                headers={'Origin':origin,'X-CSRF-Token':csrf,'X-Real-IP':'192.168.50.2'})
        first=get_session();self.assertFalse(first['web_job_control'])
        self.assertEqual(post(first['csrf']).status_code,403)
        self.config=replace(self.config,lab_control_origins=(host,))
        session=get_session();self.assertTrue(session['web_job_control'])
        self.assertEqual(post(first['csrf']).status_code,403)  # Configuration revokes prior sessions.
        self.assertEqual(post(session['csrf'],origin='http://evil.test').status_code,403)
        self.assertEqual(post(session['csrf'],peer={'REMOTE_ADDR':'8.8.8.8'}).status_code,403)
        self.assertEqual(post(session['csrf']).status_code,200)
        self.assertEqual(self.client.post('/api/master/agents/job-poll',base_url=host,json={},environ_overrides=self.peer).status_code,403)

    def test_public_session_and_stolen_trusted_session_cannot_start_or_stop_jobs(self):
        jobs,_=self.seed();csrf=self.session()
        first=self.post('/api/master/admin/jobs',dict(agent_id='agent-1',request_key='trusted-start'),csrf)
        ident=first.json['job']['job_id'];stop='/api/master/admin/jobs/'+ident+'/stop'
        for peer in ('8.8.8.8','192.168.51.2'):
            self.peer={'REMOTE_ADDR':peer}
            public_csrf=self.session()
            self.assertFalse(self.get('/api/master/admin/session').json['web_job_control'])
            self.assertFalse(self.get('/api/master/agents').json['control_capabilities']['web_job_control'])
            for token in (public_csrf,csrf):
                self.assertEqual(self.post('/api/master/admin/jobs',dict(agent_id='agent-1',request_key='public-start'),token).status_code,403)
                self.assertEqual(self.post(stop,{'confirm_job_id':ident},token).status_code,403)
        self.assertEqual(len(jobs.history()),1)
        self.assertEqual(jobs.inspect(ident)['status'],'queued')

    def test_public_master_reads_and_local_nginx_preserve_real_peer_boundary(self):
        self.seed()
        for path in ('/master/admin','/master/validation','/api/master/agents',
                     '/api/master/admin/jobs','/api/master/receiver/events'):
            result=self.client.get(path,base_url='http://master.lab',environ_overrides={'REMOTE_ADDR':'8.8.8.8'})
            self.assertEqual(result.status_code,200,(path,result.data))
        result=self.client.get('/api/master/admin/session',base_url=BASE,environ_overrides={'REMOTE_ADDR':'127.0.0.1'},
            headers={'X-Real-IP':'8.8.8.8','X-Forwarded-Proto':'http'})
        self.assertFalse(result.json['web_job_control'])
        result=self.client.post('/api/master/admin/jobs',base_url=BASE,json=dict(agent_id='agent-1',request_key='proxy'),
            environ_overrides={'REMOTE_ADDR':'127.0.0.1'},headers={'X-Real-IP':'8.8.8.8','Origin':BASE,'X-CSRF-Token':result.json['csrf']})
        self.assertEqual(result.status_code,403)

    def test_csrf_origin_session_expiry_and_idempotent_start_stop(self):
        jobs,_=self.seed();body=dict(agent_id='agent-1',request_key='lab-start')
        self.assertEqual(self.post('/api/master/admin/jobs',body).status_code,403)
        csrf=self.session()
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf,headers={'Origin':'https://evil.test'}).status_code,403)
        first=self.post('/api/master/admin/jobs',body,csrf);self.assertEqual(first.status_code,200,first.data)
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf).json,first.json)
        ident=first.json['job']['job_id'];stop='/api/master/admin/jobs/'+ident+'/stop'
        self.assertEqual(self.post(stop,{'confirm_job_id':'wrong'},csrf).status_code,400)
        result=self.post(stop,{'confirm_job_id':ident},csrf);self.assertEqual(result.json['job']['status'],'stopped')
        self.now+=901
        self.assertEqual(self.post(stop,{'confirm_job_id':ident},csrf).status_code,403)
        self.assertNotEqual(self.session(),csrf)
        self.assertEqual(jobs.inspect(ident)['status'],'stopped')

    def test_agent_tokens_still_required_and_bound_http_jobs_are_not_anonymous(self):
        _,token=self.seed();body=dict(agent_id='agent-1',protocol_version=1,report=None)
        self.assertEqual(self.post('/api/master/agents/job-poll',body).status_code,401)
        self.assertEqual(self.post('/api/master/agents/job-poll',body,headers={'Authorization':'Bearer '+token}).status_code,200)
        self.assertEqual(self.post('/api/master/agents/job-poll',dict(body,agent_id='other'),headers={'Authorization':'Bearer '+token}).status_code,401)
        self.assertEqual(self.post('/api/master/agents/job-poll',body,headers={'Authorization':'Bearer '+token},environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code,403)

    def test_protected_mode_never_gets_automatic_authority(self):
        self.config=replace(self.config,lab_mode=False)
        self.assertEqual(self.get('/').status_code,403)  # HTTP remains rejected.
        with patch('master_admin.load_credential',side_effect=OSError()):
            result=self.client.get('/',base_url='https://192.168.50.3',environ_overrides=self.peer)
            self.assertEqual(result.status_code,503)

    def test_agent_lab_ui_is_scoped_but_never_exposes_master_controls(self):
        self.config=replace(self.config,role='agent')
        self.assertEqual(self.get('/').status_code,200)
        self.assertEqual(self.get('/master/admin').status_code,404)
        self.assertEqual(self.get('/api/master/agents').status_code,404)
        self.assertEqual(self.client.get('/',base_url=BASE,environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code,200)
        self.assertEqual(len(self.session()),43)
        self.config=DeploymentConfig(config_status='invalid')
        self.assertEqual(self.get('/').status_code,503)

    def test_actual_transport_worker_receipts_and_restart_do_not_replay(self):
        jobs,token=self.seed();csrf=self.session()
        job=self.post('/api/master/admin/jobs',dict(agent_id='agent-1',request_key='roundtrip'),csrf).json['job']
        cfg=AgentConfig(BASE,'agent-1','Slave',token,lab_http=True,lab_mode=True,lab_networks=NETWORKS)
        class Response(io.BytesIO):status=200
        def open_request(req,timeout):
            with self.app.test_client() as client:
                result=client.post(urlsplit(req.full_url).path,base_url=BASE,data=req.data,
                    content_type='application/json',headers={'Authorization':req.get_header('Authorization')},environ_overrides=self.peer)
            self.assertEqual(result.status_code,200,result.data)
            return Response(result.data)
        sender=AgentTransport(cfg,SimpleNamespace(open=open_request));calls=[]
        def run(config,ident,options,stop,record):
            calls.append(ident)
            class Fast:
                now=0
                def is_set(self):return stop.is_set()
                def wait(self,seconds):self.now+=seconds;return stop.is_set()
            fast=Fast()
            return run_loop(config,ident,options,stop=fast,clock=lambda:fast.now,record=record,
                post=lambda payload,timeout,stop:sender.post('p11-beacon',p11=payload))
        worker=Worker(cfg,self.root/'journal.sqlite3',sender=sender,run=run);worker.step()
        self.assertEqual(jobs.inspect(job['job_id'])['status'],'succeeded')
        self.assertEqual(len(jobs.list_receiver_events(campaign_id=job['job_id'])['events']),3)
        Worker(cfg,self.root/'journal.sqlite3',sender=sender,run=run).step()
        self.assertEqual(calls,[job['job_id']])

    def test_plaintext_worker_requires_both_mode_and_declared_numeric_private_master(self):
        cfg=AgentConfig(BASE,'agent-1','Slave','a'*43,lab_http=True,lab_mode=True,lab_networks=NETWORKS)
        for change in ({'lab_mode':False},{'lab_http':False},{'master_url':'http://evil.test'},
                {'master_url':'http://8.8.8.8'},{'lab_networks':('192.168.51.0/24',)}):
            with self.assertRaises(FatalAgentError):Worker(replace(cfg,**change),self.root/'rejected.sqlite3')
        self.assertFalse((self.root/'rejected.sqlite3').exists())


if __name__=='__main__':unittest.main()
