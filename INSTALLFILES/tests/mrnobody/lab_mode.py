"""Isolated private Lab Mode, CSRF, transport and zero-touch contracts."""
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
from lab_access import issue, consume, SESSION_TTL
from lab_mode import contains, configure, nginx_content, ensure_control, control_digest
from master_admin import install_admin_auth
from master_api import install_master_api
from master_jobs import Jobs
from agent_client import AgentConfig, AgentTransport, FatalAgentError, bootstrap_agent
from agent_jobs import Worker
from p11_live_lab import run_loop

BASE='http://192.168.50.3'
NETWORKS=('192.168.50.0/24',)


class Configuration(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Root-owned key fixture on Linux')
    def test_control_key_install_update_preserve_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'control.key'
            config=DeploymentConfig('master','', 'loaded',True,True)
            ensure_control(config,key);first=key.read_bytes()
            self.assertEqual(key.stat().st_mode & 0o777,0o600)
            self.assertEqual(len(first),44)
            self.assertEqual(control_digest(key),hashlib.sha256(first.strip()).hexdigest())
            ensure_control(config,key);self.assertEqual(key.read_bytes(),first)
            key.chmod(0o644)
            with self.assertRaises(OSError):ensure_control(config,key)
            key.unlink();key.symlink_to(Path(tmp)/'missing')
            with self.assertRaises(OSError):ensure_control(config,key)
            key.unlink()
            ensure_control(replace(config,role='standalone',lab_mode=False),key)
            self.assertFalse(key.exists())
            ensure_control(replace(config,role='agent'),key)
            self.assertEqual(len(key.read_bytes()),44)

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


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0, 'Local handoff requires Linux root-owned fixtures')
class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.path=self.root/'master/registry.sqlite3'
        self.config=DeploymentConfig('master','', 'loaded',True,True,NETWORKS)
        self.secret='s'*43
        self.digest=hashlib.sha256(self.secret.encode()).hexdigest()
        self.key_patch=patch('lab_mode.control_digest', side_effect=lambda: self.digest)
        self.key_patch.start();self.addCleanup(self.key_patch.stop)
        self.now=1000
        self.access=self.root/'access'
        real_consume=consume
        self.access_patch=patch('lab_access.consume', side_effect=lambda token,config,origin,digest:
            real_consume(token,config,origin,digest,directory=self.access,clock=lambda:self.now))
        self.access_patch.start();self.addCleanup(self.access_patch.stop)
        self.app=Flask('lab-mode',template_folder=str(WEB/'templates'),static_folder=str(WEB/'static'))
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

    def test_zero_touch_first_binding_works_through_public_nat_but_never_controls_jobs(self):
        self.peer={'REMOTE_ADDR':'198.51.100.20'}
        body=dict(agent_id='nat-agent',protocol_version=1,name='NAT-Slave')
        for token,expected in (('t'*43,200),('t'*43,200),('u'*43,401)):
            result=self.post('/api/master/agents/register',body,headers={'Authorization':'Bearer '+token})
            self.assertEqual(result.status_code,expected,result.data)
        self.assertEqual(self.login(secret='t'*43).status_code,401)
        self.assertEqual(self.post('/api/master/admin/jobs',dict(agent_id='nat-agent',request_key='unauthorized'),
            self.session(),headers={'Authorization':'Bearer '+'t'*43}).status_code,403)

    def test_dashboard_reads_need_no_credential_but_session_is_opaque(self):
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
                    self.now+=61  # Keep each negative-case group below the global write limit.
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

    def login(self, host=BASE, peer=None, secret=None):
        if secret is None:
            secret=issue(self.config,host,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        return self.client.post('/api/master/admin/session', base_url=host,
            environ_overrides=peer or self.peer, json={'handoff': secret}, headers={'Origin':host})

    def authorized(self):
        result=self.login()
        self.assertEqual(result.status_code,200,result.data)
        return result.json['csrf']

    def test_handoff_single_use_expiry_origin_role_key_and_sixteen_labs(self):
        from concurrent.futures import ThreadPoolExecutor
        ticket=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        check=lambda token=ticket,config=self.config,origin=BASE,digest=self.digest: consume(
            token,config,origin,digest,directory=self.access,clock=lambda:self.now)
        self.assertFalse(check(config=replace(self.config,role='agent')))
        self.assertFalse(check(origin='http://other.lab'))
        self.assertFalse(check(digest='0'*64))
        with ThreadPoolExecutor(8) as pool:
            self.assertEqual(sum(pool.map(lambda _:check(),range(8))),1)
        self.assertFalse(check())
        # Separate worker processes must also share one-use state.
        import subprocess
        token=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        code = ("import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                "from lab_access import consume; from deployment_config import DeploymentConfig; "
                "c=DeploymentConfig(role='master',config_status='loaded',lab_http=True,lab_mode=True); "
                "print(int(consume(sys.argv[2],c,sys.argv[3],sys.argv[4],directory=Path(sys.argv[5]),clock=lambda:float(sys.argv[6]))))")
        processes=[subprocess.Popen([sys.executable,'-c',code,str(WEB),token,BASE,self.digest,
                                     str(self.access),str(self.now)],stdout=subprocess.PIPE,text=True) for _ in range(4)]
        self.assertEqual(sum(int(process.communicate(timeout=10)[0]) for process in processes),1)
        ticket=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        self.now+=121
        self.assertFalse(check(token=ticket))
        # Unique root-provisioned identities even where all labs use the same IP/origin.
        for index in range(16):
            directory=self.root/('lab-'+str(index))
            digest=hashlib.sha256(str(index).encode()).hexdigest()
            with patch('lab_mode.control_digest',return_value=digest):
                token=issue(replace(self.config,role='agent'),BASE,directory=directory,clock=lambda:self.now).split('#handoff=')[1]
            self.assertFalse(consume(token,self.config,BASE,digest,directory=directory,clock=lambda:self.now))
            self.assertFalse(consume(token,replace(self.config,role='agent'),BASE,self.digest,directory=directory,clock=lambda:self.now))
            self.assertFalse(consume(token,self.config,BASE,self.digest,directory=self.access,clock=lambda:self.now))
            self.assertTrue(consume(token,replace(self.config,role='agent'),BASE,digest,directory=directory,clock=lambda:self.now))

    def test_manual_key_login_removed_and_role_change_revokes_session(self):
        self.assertEqual(self.login(secret=self.secret).status_code,401)
        self.assertEqual(self.post('/api/master/admin/session',{'credential':self.secret}).status_code,401)
        csrf=self.authorized()
        self.now+=901
        self.assertTrue(self.get('/api/master/admin/session').json['web_job_control'])
        self.config=replace(self.config,role='agent')
        self.assertEqual(self.post('/api/config',{},csrf).status_code,403)

    def test_handoff_permissions_reissue_and_no_portal_header_identity(self):
        first=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        second=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        self.assertEqual(self.login(secret=first).status_code,401)
        self.assertEqual(self.login(secret=second).status_code,200)
        self.assertEqual(self.login(secret=second).status_code,401)
        self.access.chmod(0o755)
        with self.assertRaises(OSError):issue(self.config,BASE,directory=self.access)
        self.access.chmod(0o700)
        self.client=self.app.test_client()
        self.assertFalse(self.get('/api/master/admin/session',headers={
            'X-Remote-User':'guacadmin','X-Lab-ID':'1','X-Role':'master'}).json['web_job_control'])

    def test_cross_lab_http_ticket_and_cookie_rejected_even_at_same_private_origin(self):
        other=Flask('other-lab')
        other.add_url_rule('/api/config',view_func=lambda:{'saved':True},methods=['POST'])
        install_admin_auth(other,lambda:self.config,clock=lambda:self.now,registry_path=self.root/'other.sqlite3')
        client=other.test_client()
        ticket=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        # A different installation binding cannot redeem A's outstanding ticket.
        with patch('lab_mode.control_digest',return_value='0'*64):
            self.assertEqual(client.post('/api/master/admin/session',base_url=BASE,
                json={'handoff':ticket},headers={'Origin':BASE}).status_code,401)
        result=self.login(secret=ticket);self.assertEqual(result.status_code,200)
        from lab_mode import COOKIE
        client.set_cookie(COOKIE,self.client.get_cookie(COOKIE,domain=urlsplit(BASE).hostname).value,
                          domain=urlsplit(BASE).hostname)
        self.assertEqual(client.post('/api/config',base_url=BASE,json={},
            headers={'Origin':BASE,'X-CSRF-Token':result.json['csrf']}).status_code,403)

    def test_handoff_private_files_and_unprivileged_issuance(self):
        with patch('os.geteuid',return_value=1000):
            with self.assertRaises(OSError):issue(self.config,BASE,directory=self.access)
        with self.assertRaises(ValueError):issue(replace(self.config,lab_mode=False),BASE,directory=self.access)
        for value in ('http://master.lab/','http://user@master.lab','http://master.lab:65536','http://master.lab#x'):
            with self.assertRaises(ValueError):issue(self.config,value,directory=self.access)
        token=issue(self.config,BASE,directory=self.access,clock=lambda:self.now).split('#handoff=')[1]
        target=self.access/'ticket'
        target.chmod(0o644)
        self.assertFalse(consume(token,self.config,BASE,self.digest,directory=self.access,clock=lambda:self.now))
        target.unlink();target.symlink_to(self.root/'missing')
        with self.assertRaises(OSError):issue(self.config,BASE,directory=self.access)

    def test_control_across_subnets_nat_ip_dns_and_ipv6(self):
        jobs,token=self.seed()
        for index,(host,peer) in enumerate(((BASE,'192.168.51.2'),('http://master.lab:8080','198.51.100.2'),
                                          ('https://203.0.113.8','2001:db8::2'))):
            self.now+=61
            self.peer={'REMOTE_ADDR':peer}
            anonymous=self.client.get('/api/master/admin/session',base_url=host,environ_overrides=self.peer)
            self.assertFalse(anonymous.json['web_job_control'])
            result=self.login(host)
            self.assertTrue(result.json['web_job_control'])
            self.assertNotEqual(result.json['csrf'],anonymous.json['csrf'])
            csrf=result.json['csrf']; headers={'Origin':host,'X-CSRF-Token':csrf}
            body=dict(agent_id='agent-1',request_key='network-'+str(index))
            def start(data=body):
                return self.client.post('/api/master/admin/jobs',base_url=host,environ_overrides=self.peer,json=data,headers=headers)
            first=start();self.assertEqual(first.status_code,200,first.data)
            ident=first.json['job']['job_id']
            self.assertEqual(start().json['job']['job_id'],ident)
            self.assertEqual(start(dict(body,command='id')).status_code,400)
            stopped=self.client.post('/api/master/admin/jobs/'+ident+'/stop',base_url=host,environ_overrides=self.peer,
                json={'confirm_job_id':ident},headers=headers)
            self.assertEqual(stopped.status_code,200)
            self.assertEqual(stopped.json['job']['status'],'stopped')
            self.assertTrue(self.client.get('/api/master/agents',base_url=host,environ_overrides=self.peer).json['control_capabilities']['web_job_control'])
            result=self.client.delete('/api/master/admin/session',base_url=host,environ_overrides=self.peer,json={},headers=headers)
            self.assertEqual(result.status_code,200)
            self.assertEqual(start().status_code,403)
        self.assertEqual(len(jobs.history()),3)

    def test_key_csrf_origin_expiry_rotation_and_agent_tokens(self):
        jobs,token=self.seed();body=dict(agent_id='agent-1',request_key='denied')
        anonymous=self.session()
        self.assertEqual(self.post('/api/master/admin/jobs',body,anonymous).status_code,403)
        self.assertEqual(self.login(secret=token).status_code,401)
        self.assertEqual(self.login(secret='x'*43).status_code,401)
        self.assertEqual(self.client.post('/api/master/admin/session',base_url=BASE,json={'credential':self.secret},
            headers={'Origin':'http://evil.test'}).status_code,403)
        csrf=self.authorized()
        self.peer={'REMOTE_ADDR':'198.51.100.99'}
        self.assertTrue(self.get('/api/master/agents').json['control_capabilities']['web_job_control'])
        self.assertEqual(self.post('/api/master/admin/jobs',body).status_code,403)
        self.assertEqual(self.post('/api/master/admin/jobs',body,anonymous).status_code,403)
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf,headers={'Origin':'http://evil.test'}).status_code,403)
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf,headers={'Sec-Fetch-Site':'cross-site'}).status_code,403)
        # A changed IP is valid; a changed browser origin is not.
        self.assertEqual(self.client.post('/api/master/admin/jobs',base_url='http://192.168.50.3:8080',json=body,
            headers={'Origin':'http://192.168.50.3:8080','X-CSRF-Token':csrf}).status_code,403)
        self.digest='0'*64
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf).status_code,403)
        self.digest=hashlib.sha256(self.secret.encode()).hexdigest()
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf).status_code,403)
        self.now+=SESSION_TTL+1
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf).status_code,403)
        self.digest=''
        self.assertEqual(self.login().status_code,401)
        self.assertEqual(jobs.history(),[])

    def test_slave_control_uses_its_own_key_and_cannot_expose_master_jobs(self):
        self.config=replace(self.config,role='agent')
        self.app.add_url_rule('/api/config',endpoint='save_config',view_func=lambda:{'saved':True},methods=['POST'])
        self.peer={'REMOTE_ADDR':'198.51.100.7'}
        self.assertEqual(self.get('/lab/control').status_code,200)
        self.assertEqual(self.post('/api/config',{},self.session()).status_code,403)
        csrf=self.authorized()
        self.assertEqual(self.post('/api/config',{},csrf).status_code,200)
        self.assertEqual(self.post('/api/master/admin/jobs',{},csrf).status_code,404)

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
        csrf=self.authorized()
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf,headers={'Origin':'https://evil.test'}).status_code,403)
        first=self.post('/api/master/admin/jobs',body,csrf);self.assertEqual(first.status_code,200,first.data)
        self.assertEqual(self.post('/api/master/admin/jobs',body,csrf).json,first.json)
        ident=first.json['job']['job_id'];stop='/api/master/admin/jobs/'+ident+'/stop'
        self.assertEqual(self.post(stop,{'confirm_job_id':'wrong'},csrf).status_code,400)
        result=self.post(stop,{'confirm_job_id':ident},csrf);self.assertEqual(result.json['job']['status'],'stopped')
        self.now+=SESSION_TTL+1
        self.assertEqual(self.post(stop,{'confirm_job_id':ident},csrf).status_code,403)
        self.assertNotEqual(self.session(),csrf)
        self.assertEqual(jobs.inspect(ident)['status'],'stopped')

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
        jobs,token=self.seed();csrf=self.authorized()
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
        # Real browser/middleware fixture; no campaign runtime or processes.
        import threading
        from werkzeug.serving import make_server
        fixtures=[];servers=[]
        try:
            for role in ('master','agent'):
                fixture=Boundary();fixture.setUp();fixtures.append(fixture)
                fixture.config=replace(fixture.config,role=role)
                server=make_server('127.0.0.1',0,fixture.app);servers.append(server)
                threading.Thread(target=server.serve_forever,daemon=True).start()
            print(json.dumps({'ports':[server.server_port for server in servers],
                              'handoff':os.name=='posix' and os.geteuid()==0}),flush=True)
            # Test-only stdin channel models the authorized local terminal.
            # No HTTP issuance endpoint is added, even in the fixture.
            for line in sys.stdin:
                command=json.loads(line)
                fixture=fixtures[command['index']]
                link=issue(fixture.config,command['origin'],directory=fixtures[-1].access,
                           clock=lambda:fixtures[-1].now)
                print(json.dumps({'link':link}),flush=True)
        finally:
            for server in servers:server.shutdown();server.server_close()
            for fixture in fixtures:fixture.doCleanups()
    else:
        unittest.main()
