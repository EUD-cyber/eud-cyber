"""P01 production and end-to-end data contract; fixed local transport doubles."""
import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch
from pipeline_fixtures import *
from ad_prerequisite import DC


class Contract(Fixture):
    def test_nmap_per_port_states_and_evidence(self):
        xml=b'''<nmaprun><host><address addr="192.168.2.200"/><ports>
        <port protocol="tcp" portid="22"><state state="closed" reason="conn-refused"/></port>
        <port protocol="tcp" portid="3389"><state state="filtered" reason="no-response"/></port>
        <port protocol="tcp" portid="5985"><state state="open" reason="syn-ack"/></port>
        </ports></host></nmaprun>'''
        rows=pipeline.tcp_facts('192.168.2.200',[22,3389,5985,443],self.env,Mock(return_value=Mock(returncode=0,stdout=xml)))
        self.assertEqual([rows[str(p)]['state'] for p in (22,3389,5985,443)],['closed','filtered','open','timeout'])
        self.assertTrue(all(row['observed'] and row['started'] and row['evidence'] for row in rows.values()))

    def test_nmap_compressed_closed_or_filtered_results(self):
        for state in ('closed','filtered'):
            xml=f'<nmaprun><host><address addr="192.168.2.200"/><ports><extraports state="{state}" count="2"/></ports></host></nmaprun>'.encode()
            rows=pipeline.tcp_facts('192.168.2.200',[22,3389],self.env,Mock(return_value=Mock(returncode=0,stdout=xml)))
            self.assertEqual({r['state'] for r in rows.values()},{state})

    def test_timeouts_errors_and_foreign_nmap_host_never_mean_open(self):
        for child in (subprocess.TimeoutExpired('nmap',20),OSError('SECRET'),Mock(returncode=1,stdout=b''),
                      Mock(returncode=0,stdout=b'not XML'),Mock(returncode=0,stdout=b'<nmaprun><host><address addr="10.0.0.1"/></host></nmaprun>')):
            invoke=Mock(side_effect=child) if isinstance(child,Exception) else Mock(return_value=child)
            rows=pipeline.tcp_facts('192.168.2.200',[5985],self.env,invoke)
            self.assertEqual(rows['5985']['state'],'timeout')
            self.assertNotIn('SECRET',json.dumps(rows))

    def test_ports_are_configurable_bounded_and_include_existing_services(self):
        self.assertTrue({22,3389,5985,80,443} <= set(pipeline.scan_ports(self.env)))
        self.assertIn(2222,pipeline.scan_ports(dict(self.env,NORDIC_SSH_PORT='2222',NORDIC_DISCOVERY_TCP_PORTS='445')))
        for ports in ('0','65536','22-100','abc',','.join(map(str,range(1,70)))):
            with self.assertRaises(pipeline.ContractError): pipeline.scan_ports(dict(self.env,NORDIC_DISCOVERY_TCP_PORTS=ports))

    def test_out_of_scope_excluded_and_network_addresses_cannot_reach_p03(self):
        self.p01([(ip,{5985:'open'}) for ip in ('192.168.2.200','192.168.1.120','192.168.2.0','192.168.2.255','10.20.30.40')])
        self.env['NORDIC_DISCOVERY_EXCLUDE_NETWORKS']='192.168.1.0/25'
        self.assertEqual([t['target'] for t in pipeline.open_targets(self.env,'winrm')],['192.168.2.200'])

    def test_wrong_port_number_or_transport_cannot_cross_boundary(self):
        for change in ({'port':22},{'transport':'udp'},{'state':'authenticated'}):
            self.p01([('192.168.2.200',{5985:'open'})])
            data=self.read('discovered-hosts.json'); data['hosts'][0]['tcp_ports']['5985'].update(change)
            pipeline.write(self.base/'state/discovered-hosts.json',data)
            with self.assertRaises(pipeline.ContractError): pipeline.open_targets(self.env,'winrm')

    def test_producer_to_validator_to_consumer_ten_hosts(self):
        addresses=['192.168.1.1','192.168.1.20','192.168.1.100','192.168.1.120','192.168.1.150',
                   '192.168.2.1','192.168.2.20','192.168.2.21','192.168.2.25','192.168.2.200']
        self.write('discovered-hosts.json',hosts=[{'ip':ip} for ip in addresses])
        def nmap(argv,**kwargs):
            ip=argv[-1]
            ports=pipeline.scan_ports(self.env)
            records=''.join(f'<port protocol="tcp" portid="{p}"><state state="{("open" if ip==addresses[-1] and p==5985 else "closed")}" reason="fixture"/></port>' for p in ports)
            return Mock(returncode=0,stdout=f'<nmaprun><host><address addr="{ip}"/><ports>{records}</ports></host></nmaprun>'.encode())
        with contextlib.redirect_stdout(io.StringIO()): produced=pipeline.produce(self.env,nmap)
        self.assertEqual(len(produced['hosts']),10)
        self.assertFalse(any(h.get('authenticated') for h in produced['hosts']))
        self.assertEqual(self.access([AUTH])[2].call_count,1)
        code,log,invoke=self.campaign([ELIGIBLE,DC])
        self.assertEqual(code,0); self.assertEqual(invoke.call_count,2)
        self.assertIn('P09_DC_SELECTED target=192.168.2.200',log)
        self.assertEqual(produced,self.read('discovered-hosts.json'))

    def test_standalone_p03_needs_no_p01_and_does_not_change_it(self):
        self.env.update(MRNOBODY_RUN_MODE='standalone',MRNOBODY_PROTOCOL='winrm-http',MRNOBODY_TARGET='10.20.30.40',MRNOBODY_USERNAME='manual',MRNOBODY_PASSWORD='SECRET')
        before=(self.base/'state/discovered-hosts.json').read_bytes()
        self.assertEqual(self.access([AUTH])[0],0)
        self.assertEqual(before,(self.base/'state/discovered-hosts.json').read_bytes())


if __name__=='__main__': unittest.main()
