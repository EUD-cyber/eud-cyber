"""Read-only dashboard API, isolated SQLite; no listeners or VM access."""
import master_receiver as receiver
URL=receiver.URL
import sqlite3
from unittest.mock import patch
import unittest


class DashboardTests(unittest.TestCase):
    setUp=receiver.ReceiverTests.setUp
    post=receiver.ReceiverTests.post
    def get(self, query="", base="https://master.test", peer="10.1.2.3", headers=None):
        return self.client.get(URL+query,base_url=base,headers=headers or {},
                               environ_overrides={"REMOTE_ADDR":peer})

    def test_empty_legacy_and_missing_database_do_not_write(self):
        before=self.path.read_bytes()
        self.assertEqual(self.get().get_json(),dict(events=[],next_before=None))
        self.assertEqual(self.path.read_bytes(),before)
        self.path.unlink()
        self.assertEqual(self.get().get_json(),dict(events=[],next_before=None))
        self.assertFalse(self.path.exists())

    def test_pagination_filters_persistence_no_duplicates_or_side_effects(self):
        agents=self.store.list_agents()
        for i in range(6):
            self.assertEqual(self.post(dict(self.data,campaign_id="MRN-"+str(i%2))).status_code,200)
        response=self.get("?limit=2")
        self.assertEqual(response.headers["Cache-Control"],"no-store")
        page=response.get_json()
        self.assertEqual([e["id"] for e in page["events"]],[6,5])
        self.assertEqual(page["next_before"],5)
        self.post()  # A concurrent new receipt must not shift the older page.
        self.assertEqual([e["id"] for e in self.get("?limit=2&before=5").get_json()["events"]],[4,3])
        self.assertEqual(self.get("?limit=2&before=3").get_json()["next_before"],None)
        self.assertEqual([e["id"] for e in self.get("?agent_id=agent-1&campaign_id=MRN-1").get_json()["events"]],[6,4,2])
        self.assertEqual(self.get("?agent_id=other").get_json()["events"],[])
        self.assertEqual(self.store.list_agents(),agents)
        snapshot=self.path.read_bytes()
        self.get()
        self.assertEqual(self.path.read_bytes(),snapshot)
        self.assertNotIn(self.token,self.get().get_data(as_text=True))
        self.assertEqual(set(page["events"][0]),{"id","agent_id","campaign_id","event_type","timestamp","bytes","received_at","status"})
        self.assertEqual(page["events"][0]["bytes"],128)

    def test_strict_bounded_queries(self):
        for query in ("limit=0","limit=101","limit=-1","limit=1.5","limit=true","limit=",
                      "limit=1&limit=2","before=0","before=-1","before=9223372036854775808",
                      "before=1&before=2","agent_id=","agent_id=../x","campaign_id=",
                      "campaign_id=x%27%20OR%201=1","unknown=1","campaign_id="+"x"*102):
            self.assertEqual(self.get("?"+query).status_code,400,query)
        self.assertEqual(self.get("?limit=100").status_code,200)
        for i in range(102):
            self.post()
        self.assertEqual(len(self.get().get_json()["events"]),50)
        self.assertEqual(len(self.get("?limit=100").get_json()["events"]),100)

    def test_dashboard_access_boundary_independent_of_post_lab_http(self):
        for role,status in (("agent","loaded"),("standalone","loaded"),("master","invalid"),("master","default")):
            self.config.role,self.config.config_status=role,status
            self.assertEqual(self.get().status_code,404)
        self.config.role,self.config.config_status="master","loaded"
        self.config.lab_http=True
        self.assertEqual(self.get(base="http://master.test").status_code,403)
        for peer,headers in (("8.8.8.8",{}),("8.8.8.8",{"X-Real-IP":"10.0.0.1"}),
                             ("127.0.0.1",{"X-Real-IP":"8.8.8.8"})):
            self.assertEqual(self.get(peer=peer,headers=headers).status_code,403)
        self.assertEqual(self.get(base="http://master.test",peer="127.0.0.1",
            headers={"X-Forwarded-Proto":"https","X-Real-IP":"10.0.0.1"}).status_code,200)
        self.assertEqual(self.client.delete(URL).status_code,405)

    def test_storage_errors_are_not_empty_success(self):
        with patch("master_registry.sqlite3.connect",side_effect=sqlite3.OperationalError("private path")):
            response=self.get()
        self.assertEqual(response.status_code,503)
        self.assertNotIn("private path",response.get_data(as_text=True))


if __name__=="__main__":
    unittest.main()
