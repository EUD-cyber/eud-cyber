"""Open Lab Mode controls, automatic binding, CSRF and transport contracts."""
from dataclasses import replace
import io
import hashlib
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
from lab_mode import contains, configure, nginx_content, access_status
from master_admin import install_admin_auth
from master_api import install_master_api
from master_jobs import Jobs
from agent_client import AgentConfig, AgentTransport, FatalAgentError, bootstrap_agent
from agent_jobs import Worker
from p11_live_lab import run_loop

BASE='http://192.168.50.3'
NETWORKS=('192.168.50.0/24',)


class Configuration(unittest.TestCase):
    def test_status_command_exits_blocked_and_exports_no_credentials(self):
        import subprocess
        result=subprocess.run([sys.executable,str(WEB/'lab_mode.py'),'status'],
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,2,result.stderr)
        data=json.loads(result.stdout)
        self.assertEqual(set(data),{'lab_mode','role','zero_interaction_ready',
                                   'operator_authorized','pairing','blocker','access_model'})
        self.assertFalse(data['zero_interaction_ready'])
        self.assertFalse(data['operator_authorized'])
        self.assertEqual(data['pairing'],'automatic-first-binding')

    def test_old_lab_http_never_implies_lab_mode(self):
        config=_parse('MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\n')
        self.assertFalse(config.lab_mode)
        self.assertEqual(config.lab_networks,())

    def test_explicit_private_cidrs_and_fail_closed_inputs(self):
        base='MRNOBODY_ROLE=master\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE=1\n'
        self.assertTrue(_parse(base+'MRNOBODY_LAB_NETWORKS=192.168.50.0/24').lab_mode)
        for net in ('0.0.0.0/0','8.8.8.0/24','127.0.0.0/8','100.64.0.0/10','::/0','192.168.50.1/24'):
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
            if role=='agent':self.assertTrue(config.lab_mode)
            if role=='master':self.assertEqual(config.lab_networks,())
        self.assertNotIn('MRNOBODY_LAB_MODE=',template)
        for url in ('http://master.lab:8080','http://203.0.113.3'):
            rendered=yaml.safe_load(render_userdata(template,dict(role='agent',master_url=url,lab_http=True)))
            config=_parse(next(item['content'] for item in rendered['write_files'] if item['path']=='/etc/mrnobody/deployment.conf'))
            self.assertTrue(config.lab_mode);self.assertEqual(config.master_url,url)

    def test_shared_big_mini_custom_renderer_keeps_template_and_supports_ip_dns(self):
        import subprocess
        import yaml
        source=(ROOT/'MRNOBODY/mrnobody_installer.sh').read_text()
        code=source.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        template=ROOT/'MRNOBODY/mrnobody_userdata.yaml';before=template.read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            for url,expected in ((BASE,True),('http://master.test',True)):
                result=subprocess.run([sys.executable,'-c',code,str(template),tmp,'3','agent',url],check=True,capture_output=True,text=True)
                data=yaml.safe_load((Path(tmp)/result.stdout.strip()).read_text())
                config=_parse(next(item['content'] for item in data['write_files'] if item['path']=='/etc/mrnobody/deployment.conf'))
                self.assertEqual(config.lab_mode,expected)
                if expected:self.assertEqual(config.lab_networks,())
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
            self.assertTrue(config.lab_mode);self.assertEqual(config.master_url,BASE)
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
        self.app=Flask('lab-mode',template_folder=str(WEB/'templates'),static_folder=str(WEB/'static'))
        self.app.add_url_rule('/',view_func=lambda:'dashboard')
        self.app.add_url_rule('/api/config',endpoint='save_config',view_func=lambda:{'saved':True},methods=['POST'])
        install_master_api(self.app,lambda:self.config,self.path)
        install_admin_auth(self.app,lambda:self.config,clock=lambda:self.now,registry_path=self.path)
        self.client=self.app.test_client();self.peer={'REMOTE_ADDR':'192.168.50.2'}

    def get(self,path,**options):
        return self.client.get(path,base_url=BASE,environ_overrides=self.peer,**options)

    def session(self):
        result=self.get('/api/master/admin/session')
        self.assertEqual(result.status_code,200,result.data)
        self.assertTrue(result.json['web_job_control'])
        return result.json['csrf']

    authorized=session  # No separate authorization step exists in Lab Mode.

    def post(self,path,body,csrf='',headers=None,**options):
        return self.client.post(path,base_url=BASE,environ_overrides=options.pop('environ_overrides',self.peer),
            headers={'Origin':BASE,'X-CSRF-Token':csrf,**(headers or {})},json=body,**options)

    def seed(self):
        jobs=Jobs(self.path);token=jobs.issue('agent-1');jobs.register('agent-1',token,'Slave')
        return jobs,token

    def test_every_visitor_controls_master_from_ip_dns_nat_and_ipv6_without_login(self):
        jobs,_=self.seed()
        for index,(host,peer) in enumerate(((BASE,'192.168.99.2'),('http://master.lab:8080','198.51.100.2'),
                                          ('https://master.lab','2001:db8::7'))):
            client=self.app.test_client()
            access=client.get('/api/master/admin/session',base_url=host,environ_overrides={'REMOTE_ADDR':peer})
            self.assertTrue(access.json['web_job_control'])
            self.assertTrue(access.json['lab_access']['zero_interaction_ready'])
            self.assertEqual(access.json['lab_access']['access_model'],'open-lab')
            self.assertNotIn('Max-Age=',access.headers['Set-Cookie'])
            headers={'Origin':host,'X-CSRF-Token':access.json['csrf']}
            body=dict(agent_id='agent-1',request_key='network-'+str(index))
            first=client.post('/api/master/admin/jobs',base_url=host,json=body,headers=headers)
            self.assertEqual(first.status_code,200,first.data)
            ident=first.json['job']['job_id']
            self.assertEqual(client.post('/api/master/admin/jobs',base_url=host,json=body,headers=headers).json,first.json)
            self.assertEqual(client.post('/api/master/admin/jobs/'+ident+'/stop',base_url=host,
                json={'confirm_job_id':ident},headers=headers).json['job']['status'],'stopped')
        self.assertEqual(len(jobs.history()),3)

    def test_automatic_csrf_survives_clock_advance_and_service_restart(self):
        csrf=self.session()
        self.now+=365*86400
        self.assertEqual(self.post('/api/config',{},csrf).status_code,200)
        # A separate app has no login/session state. The browser's CSRF cookie
        # remains sufficient; no key or server-side session is read.
        from lab_mode import COOKIE
        other=Flask('restarted')
        other.add_url_rule('/api/config',view_func=lambda:{'saved':True},methods=['POST'])
        install_admin_auth(other,lambda:self.config,clock=lambda:self.now)
        client=other.test_client();client.set_cookie(COOKIE,csrf,domain=urlsplit(BASE).hostname)
        self.assertEqual(client.post('/api/config',base_url=BASE,json={},
            headers={'Origin':BASE,'X-CSRF-Token':csrf}).status_code,200)
        # A new browser always receives state automatically.
        self.client=self.app.test_client()
        self.assertNotEqual(self.session(),csrf)

    def test_old_activation_login_is_gone_and_bookmark_redirects(self):
        result=self.get('/lab/control')
        self.assertEqual(result.status_code,302)
        self.assertEqual(result.headers['Location'],'/')
        for body in ({'handoff':'x'*43},{'credential':'x'*43},{}):
            self.assertEqual(self.post('/api/master/admin/session',body).status_code,410)

    def test_slave_controls_are_automatic_but_master_role_endpoints_remain_absent(self):
        self.config=replace(self.config,role='agent')
        self.assertEqual(self.post('/api/config',{},self.session()).status_code,200)
        self.assertEqual(self.post('/api/master/admin/jobs',{},self.session()).status_code,404)
        self.assertEqual(self.get('/master/admin').status_code,404)

    def test_missing_wrong_cookie_header_origin_and_fetch_metadata_cannot_trigger_browser_writes(self):
        csrf=self.session()
        self.assertEqual(self.post('/api/config',{}).status_code,403)
        self.assertEqual(self.post('/api/config',{},'x'*43).status_code,403)
        for extra in ({'Origin':'http://evil.test'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.post('/api/config',{},csrf,headers=extra).status_code,403)
        self.assertEqual(self.post('/api/config',{},csrf).status_code,200)

    def test_automatic_first_binding_retries_reject_mismatch_and_revocation(self):
        body=dict(agent_id='nat-slave',protocol_version=1,name='Slave')
        self.peer={'REMOTE_ADDR':'198.51.100.4'}
        def register(token):
            return self.post('/api/master/agents/register',body,headers={'Authorization':'Bearer '+token})
        self.assertEqual(register('a'*43).status_code,200)
        self.assertEqual(register('a'*43).status_code,200)
        self.assertEqual(register('b'*43).status_code,401)
        jobs=Jobs(self.path);jobs.revoke('nat-slave')
        self.assertEqual(register('a'*43).status_code,401)
        self.assertEqual(register('b'*43).status_code,401)

    def test_sixteen_master_registries_keep_agent_tokens_and_jobs_separate(self):
        tokens=[];fixtures=[]
        for number in range(16):
            app=Flask('lab-'+str(number));database=self.root/str(number)/'registry.sqlite3'
            install_master_api(app,lambda:self.config,database)
            install_admin_auth(app,lambda:self.config,registry_path=database)
            client=app.test_client();token=__import__('secrets').token_urlsafe(32)
            response=client.post('/api/master/agents/register',base_url=BASE,
                json=dict(agent_id='slave',protocol_version=1,name='Slave'),
                headers={'Authorization':'Bearer '+token})
            self.assertEqual(response.status_code,200)
            fixtures.append((client,Jobs(database)));tokens.append(token)
        self.assertEqual(len(set(tokens)),16)
        for number,(client,jobs) in enumerate(fixtures):
            body=dict(agent_id='slave',protocol_version=1)
            self.assertEqual(client.post('/api/master/agents/heartbeat',base_url=BASE,json=body,
                headers={'Authorization':'Bearer '+tokens[(number+1)%16]}).status_code,401)
            self.assertEqual(client.post('/api/master/agents/heartbeat',base_url=BASE,json=body,
                headers={'Authorization':'Bearer '+tokens[number]}).status_code,200)
            csrf=client.get('/api/master/admin/session',base_url=BASE).json['csrf']
            self.assertEqual(client.post('/api/master/admin/jobs',base_url=BASE,
                json=dict(agent_id='slave',request_key='local-'+str(number)),
                headers={'Origin':BASE,'X-CSRF-Token':csrf}).status_code,200)
            self.assertEqual(len(jobs.history()),1)

    def test_bound_agent_protocol_across_nat_ip_dns_and_different_subnets(self):
        import base64
        from p06_synthetic import fixture
        jobs,token=self.seed()
        other=jobs.issue('other');jobs.register('other',other,'Other-Slave')
        for index,(host,peer) in enumerate(((BASE,'192.168.99.2'),('http://master.lab:8080','198.51.100.2'),
                                          ('https://master.lab','2001:db8::7'))):
            common=dict(agent_id='agent-1',protocol_version=1)
            campaign='MRN-network-protocol-'+str(index);raw=fixture(campaign)
            payloads={
                'agents/register':dict(common,name='Slave'),
                'agents/heartbeat':common,
                'agents/reports':dict(common,reports=[]),
                'agents/report-transfer':dict(common,report_id=None,content=None),
                'agents/job-poll':dict(common,report=None),
                'agents/p06-file':dict(common,campaign_id=campaign,phase='P06',synthetic=True,size=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),content=base64.b64encode(raw).decode()),
                'agents/p11-beacon':dict(common,campaign_id=campaign,phase='P11',synthetic=True,
                    timestamp='2026-11-18T10:00:00+00:00',sequence=1,marker='MRN-EXERCISE-ONLY'),
                'receiver/events':dict(common,campaign_id=campaign,event_type='http_test',synthetic=True,
                    timestamp='2026-11-18T10:00:00Z',bytes=32)}
            def post(suffix,body,credential=token):
                return self.client.post('/api/master/'+suffix,base_url=host,environ_overrides={'REMOTE_ADDR':peer},
                    json=body,headers={'Authorization':'Bearer '+credential})
            for suffix,body in payloads.items():
                with self.subTest(host=host,peer=peer,endpoint=suffix):
                    self.assertEqual(post(suffix,body,'x'*43).status_code,401)
                    self.assertEqual(post(suffix,dict(body,agent_id='other')).status_code,401)
                    result=post(suffix,body)
                    self.assertEqual(result.status_code,200,result.data)
                    if suffix in {'agents/p06-file','agents/p11-beacon'}:
                        self.assertTrue(result.json['verified'])
                        self.assertEqual(post(suffix,dict(body,synthetic=False)).status_code,400)
        self.assertEqual(len(jobs.list_receiver_events()['events']),9)


    def test_cross_site_links_and_redirects_can_enter_master_and_slave_ui(self):
        for role in ('master','agent'):
            self.config=replace(self.config,role=role)
            for host in (BASE,'http://slave.lab'):
                for site in ('cross-site','same-site'):
                    for method in ('GET','HEAD'):
                        headers={'Sec-Fetch-Site':site,'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'}
                        result=self.client.open('/',method=method,base_url=host,headers=headers,
                            environ_overrides={'REMOTE_ADDR':'8.8.8.8'})
                        self.assertEqual(result.status_code,200,(role,host,headers,result.data))
                        self.assertIn("frame-ancestors 'none'",result.headers['Content-Security-Policy'])
            self.assertEqual(self.get('/api/master/admin/session',headers={
                'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty'}).status_code,200)


    def test_navigation_exception_never_allows_cross_site_fetch_iframe_or_writes(self):
        jobs,_=self.seed();csrf=self.session()
        for role in ('master','agent'):
            self.config=replace(self.config,role=role)
            for mode,dest in (('cors','empty'),('no-cors','image'),('navigate','iframe'),('navigate','frame'),('navigate',None),(None,'document')):
                headers={'Sec-Fetch-Site':'cross-site'}
                if mode:headers['Sec-Fetch-Mode']=mode
                if dest:headers['Sec-Fetch-Dest']=dest
                for path in ('/','/api/master/admin/session'):
                    self.assertEqual(self.get(path,headers=headers).status_code,403,(role,headers))
            for method in ('POST','PUT','PATCH','DELETE'):
                # Even forged navigation metadata, a trusted source and a valid
                # same-Origin CSRF session cannot bypass cross-site write denial.
                result=self.client.open('/api/master/admin/jobs',method=method,base_url=BASE,
                    environ_overrides=self.peer,json=dict(agent_id='agent-1',request_key='cross-site'),
                    headers={'Origin':BASE,'X-CSRF-Token':csrf,'Sec-Fetch-Site':'cross-site',
                             'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'})
                self.assertEqual(result.status_code,403)
            self.assertEqual(self.get('/',headers={'Origin':'http://portal.lab','Sec-Fetch-Site':'cross-site',
                'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'}).status_code,403)
        self.assertEqual(jobs.history(),[])


    def test_agent_tokens_still_required_and_bound_http_jobs_are_not_anonymous(self):
        _,token=self.seed();body=dict(agent_id='agent-1',protocol_version=1,report=None)
        self.assertEqual(self.post('/api/master/agents/job-poll',body).status_code,401)
        self.assertEqual(self.post('/api/master/agents/job-poll',body,headers={'Authorization':'Bearer '+token}).status_code,200)
        self.assertEqual(self.post('/api/master/agents/job-poll',dict(body,agent_id='other'),headers={'Authorization':'Bearer '+token}).status_code,401)
        self.assertEqual(self.post('/api/master/agents/job-poll',body,headers={'Authorization':'Bearer '+token},environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code,200)


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
        token=__import__('secrets').token_urlsafe(32)
        self.assertEqual(self.post('/api/master/agents/register',
            dict(agent_id='agent-1',name='Slave',protocol_version=1),
            headers={'Authorization':'Bearer '+token}).status_code,200)
        jobs=Jobs(self.path);csrf=self.session()
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


    def test_plaintext_worker_requires_explicit_mode_but_not_subnet_or_numeric_host(self):
        cfg=AgentConfig(BASE,'agent-1','Slave','a'*43,lab_http=True,lab_mode=True,lab_networks=NETWORKS)
        for change in ({'lab_mode':False},{'lab_http':False}):
            with self.assertRaises(FatalAgentError):Worker(replace(cfg,**change),self.root/'rejected.sqlite3')
        for index,url in enumerate(('http://master.lab','http://203.0.113.3:8080')):
            Worker(replace(cfg,master_url=url,lab_networks=()),self.root/('accepted-'+str(index)+'.sqlite3'))


if __name__=='__main__':
    if sys.argv[1:] == ['--navigation-server']:
        import threading
        from werkzeug.serving import make_server
        fixtures=[];servers=[]
        try:
            for role in ('master','agent'):
                fixture=Boundary();fixture.setUp();fixtures.append(fixture)
                fixture.config=replace(fixture.config,role=role)
                server=make_server('127.0.0.1',0,fixture.app);servers.append(server)
                threading.Thread(target=server.serve_forever,daemon=True).start()
            print(json.dumps({'ports':[server.server_port for server in servers]}),flush=True)
            for line in sys.stdin:
                pass  # No issuance command or manual browser activation exists.
        finally:
            for server in servers:server.shutdown();server.server_close()
            for fixture in fixtures:fixture.doCleanups()
    else:
        unittest.main()
