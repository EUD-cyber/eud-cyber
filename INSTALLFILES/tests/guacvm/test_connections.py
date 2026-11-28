"""Integration tests against a disposable PostgreSQL database, never a lab DB.

GUACVM_TEST_DSN must point to a database whose public schema may be destroyed.
Imports the shipped Guacamole backup, including real schema/constraints/IDs.
"""
import concurrent.futures
import gzip
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "GUACVM/topology-api"))
import psycopg
from psycopg.rows import dict_row
import connections as service
from app import app

DSN = os.environ.get("GUACVM_TEST_DSN")


def connect():
    return psycopg.connect(DSN, row_factory=dict_row, connect_timeout=10)


def restore_fixture():
    sql = gzip.decompress((ROOT / 'GUACVM/backups/guacamole-db.sql.gz').read_bytes()).decode()
    # Owner is irrelevant in a disposable fixture; the production backup is untouched.
    sql = re.sub(r'^ALTER .* OWNER TO guacamole_user;\n', '', sql, flags=re.M)
    parts = re.split(r'(^COPY [^\n]+ FROM stdin;\n[\s\S]*?^\\\.\n)', sql, flags=re.M)
    with connect() as db:
        db.execute('DROP SCHEMA public CASCADE; CREATE SCHEMA public')
        for part in parts:
            if part.startswith('COPY '):
                command, data = part.split('\n', 1)
                with db.cursor().copy(command[:-1]) as copy:
                    copy.write(data[:-3].encode())
            elif part.strip():
                db.execute(part, prepare=False)
        db.execute("SET search_path TO public")


@unittest.skipUnless(DSN, 'Set GUACVM_TEST_DSN to a disposable PostgreSQL database')
class ConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ['CONNECTIONS_KEY_FILE'] = str(Path(cls.temp.name)/'key')
        app.config['TESTING'] = True

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        restore_fixture()
        self.patch = patch.object(service, 'database', connect)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.env = patch.dict(os.environ, {'GUACVM_LAB_ID':'1'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = app.test_client()

    def put(self, key='slave', body=None, op='create-1', **headers):
        return self.client.put('/api/vm-connections/'+key,
            json=body if body is not None else self.body(),
            headers={'Idempotency-Key':op, **headers})

    def body(self, **extra):
        body = dict(name='MrNobody Slave', label='Slave SSH', protocol='ssh',
                    host='192.168.1.50', port=22, password='secret-fixture')
        body.update(extra)
        return body

    def rows(self):
        response = self.client.get('/api/vm-connections')
        self.assertEqual(response.status_code,200,response.get_json())
        return response.get_json()['connections']

    def test_legacy_migration_preserves_ids_and_no_passwords(self):
        rows = self.rows()
        self.assertGreaterEqual(len(rows),23)
        self.assertEqual(next(r for r in rows if r['key']=='legacy-0-0')['connectionId'],6)
        self.assertFalse(any(r['owned'] for r in rows))
        self.assertNotIn('password', json.dumps(rows).lower().replace('haspassword',''))
        self.assertEqual(rows,self.rows())

    def test_create_edit_delete_all_protocols_and_permissions(self):
        for i, protocol in enumerate(['rdp','ssh','vnc']):
            body = self.body(); body.update(protocol=protocol, port=service.PROTOCOLS[protocol])
            result = self.put(key=protocol,body=body,op='create-'+protocol)
            self.assertEqual(result.status_code,200,result.get_json())
            cid = result.get_json()['connectionId']
            with connect() as db:
                self.assertEqual(db.execute('SELECT protocol FROM guacamole_connection WHERE connection_id=%s',(cid,)).fetchone()['protocol'],protocol)
                self.assertTrue(db.execute("SELECT 1 FROM guacamole_connection_permission WHERE connection_id=%s AND permission='READ'",(cid,)).fetchone())
            sessions = self.client.get('/api/sessions').get_json()['sessions']
            self.assertTrue(any(s['name']=='MrNobody Slave' for s in sessions))
            body.pop('password');body.update(version=1,host='slave.example.test')
            self.assertEqual(self.put(key=protocol,body=body,op='edit-'+protocol).status_code,200)
            with connect() as db:
                self.assertEqual(db.execute("SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id=%s AND parameter_name='password'",(cid,)).fetchone()['parameter_value'],'secret-fixture')
            body.update(version=2,password='')
            self.assertEqual(self.put(key=protocol,body=body,op='clear-'+protocol).status_code,200)
            row = next(r for r in self.rows() if r['key']==protocol)
            self.assertFalse(row['hasPassword'])
            removed = self.client.delete('/api/vm-connections/'+protocol,json={'version':3},headers={'Idempotency-Key':'delete-'+protocol})
            self.assertTrue(removed.get_json()['databaseDeleted'])
            with connect() as db:
                self.assertIsNone(db.execute('SELECT 1 FROM guacamole_connection WHERE connection_id=%s',(cid,)).fetchone())

    def test_retries_conflicts_and_versions(self):
        first = self.put()
        self.assertEqual(first.status_code,200)
        self.assertEqual(first.get_json(),self.put().get_json())
        self.assertEqual(self.put(body=self.body(label='Other')).status_code,409)
        self.assertEqual(self.put(op='another-key').status_code,409)
        self.assertEqual(self.put(body=self.body(version=9),op='stale').status_code,409)
        with connect() as db:
            self.assertEqual(db.execute("SELECT count(*) AS n FROM guacamole_connection WHERE connection_name='Slave SSH'").fetchone()['n'],1)

    @unittest.skipIf(os.environ.get('GUACVM_TEST_PGLITE'), 'PGlite has one backend; native PostgreSQL CI tests concurrency')
    def test_concurrent_idempotency(self):
        def create(_):
            with app.test_client() as client:
                r = client.put('/api/vm-connections/slave',json=self.body(),headers={'Idempotency-Key':'concurrent'})
                return r.status_code,r.get_json()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(create,range(3)))
        self.assertTrue(all(code==200 for code,_ in results),results)
        self.assertEqual(len({r['connectionId'] for _,r in results}),1)

    def test_transaction_rollback_after_database_write(self):
        self.rows()
        with connect() as db:
            db.execute("""CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected failure'; END $$;
                CREATE TRIGGER injected BEFORE INSERT ON cyberlab_connection_audit
                FOR EACH ROW EXECUTE FUNCTION fail_audit()""")
        response = self.put()
        self.assertEqual(response.status_code,503)
        with connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM guacamole_connection WHERE connection_name='Slave SSH'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM cyberlab_connection WHERE key='slave'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM cyberlab_connection_operation WHERE operation='create-1'").fetchone())

    def test_legacy_remove_preserves_guacamole_and_tombstone(self):
        row = self.rows()[0]
        result = self.client.delete('/api/vm-connections/'+row['key'],json={'version':1},headers={'Idempotency-Key':'remove-legacy'})
        self.assertEqual(result.status_code,200,result.get_json())
        self.assertFalse(result.get_json()['databaseDeleted'])
        with connect() as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM guacamole_connection WHERE connection_id=%s',(row['connectionId'],)).fetchone())
        self.assertNotIn(row['key'],[r['key'] for r in self.rows()])

    def test_lab_scope_and_shared_connection_conflict(self):
        self.put()
        with patch.dict(os.environ,{'GUACVM_LAB_ID':'16'}):
            self.assertNotIn('slave',[r['key'] for r in self.rows()])
            self.assertEqual(self.put(body=self.body(lab=1),op='wrong-lab').status_code,400)
        row = next(r for r in self.rows() if r['key']=='legacy-0-0')
        body = {k:row[k] for k in service.FIELDS if k in row}
        self.assertEqual(self.put(key=row['key'],body=body,op='shared').status_code,409)

    def test_validation_and_cross_origin_no_login(self):
        for change in [{'protocol':'https'},{'host':'http://bad/'},{'host':'a;DROP TABLE x'},
                       {'port':True},{'port':0},{'visible':'yes'},{'password':None},{'lab':2},{'unknown':1}]:
            body=self.body();body.update(change)
            self.assertEqual(self.put(body=body).status_code,400,change)
        self.assertEqual(self.put(Origin='https://other.example').status_code,403)
        self.assertEqual(self.put(**{'Sec-Fetch-Site':'cross-site'}).status_code,403)
        self.assertEqual(self.client.put('/api/vm-connections/a',data='{}').status_code,415)
        self.assertEqual(self.put(body=self.body(description='x'*17000)).status_code,413)
        self.assertEqual(self.put(Origin='http://localhost').status_code,200)

    def test_http_preserved_but_cannot_be_added_or_changed(self):
        row = next(r for r in self.rows() if r['protocol']=='https')
        body = {k:row[k] for k in service.FIELDS if k in row}
        body.update(label='Existing web',port=443)
        self.assertEqual(self.put(key=row['key'],body=body,op='web-edit').status_code,200)
        sessions=self.client.get('/api/sessions').get_json()['sessions']
        self.assertTrue(any(c['label']=='Existing web' for s in sessions for c in s['connections']))
        body.pop('version');self.assertEqual(self.put(key='new-web',body=body,op='web-new').status_code,400)

    def test_hide_does_not_delete_and_does_not_return_credentials(self):
        self.put()
        body=self.body(version=1,visible=False)
        self.assertEqual(self.put(body=body,op='hide').status_code,200)
        self.assertNotIn('secret-fixture',self.client.get('/api/vm-connections').text)
        self.assertNotIn('MrNobody Slave',self.client.get('/api/sessions').text)
        self.assertTrue(next(r for r in self.rows() if r['key']=='slave')['hasPassword'])


if __name__ == '__main__':
    if not DSN:
        raise SystemExit('GUACVM_TEST_DSN is required; tests destroy the public schema of that database')
    unittest.main(verbosity=2)
