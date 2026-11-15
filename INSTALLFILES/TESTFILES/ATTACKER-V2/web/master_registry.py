"""Persistent agent identities, heartbeat and bounded report snapshots; no execution."""
import argparse
from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time


DATABASE = Path("/var/lib/mrnobody/master/registry.sqlite3")
HEARTBEAT_INTERVAL = 30
OFFLINE_AFTER = 90
AGENT_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class Unauthorized(Exception):
    pass


class Conflict(Exception):
    pass


class Unavailable(Exception):
    pass


def validate_id(agent_id):
    if not isinstance(agent_id,str) or not AGENT_ID.fullmatch(agent_id):
        raise ValueError("Invalid agent ID.")
    return agent_id


MAX_REPORTS = 50
REPORT_ID = re.compile(r"(?:MRN|H3)-[A-Za-z0-9][A-Za-z0-9_-]{0,100}")
MAX_REPORT_BYTES = 2*1024*1024


def validate_snapshot(report_id, content):
    if not isinstance(report_id,str) or not REPORT_ID.fullmatch(report_id):
        raise ValueError("Invalid report ID.")
    if not isinstance(content,dict) or content.get("schema_version")!=1:
        raise ValueError("Invalid report snapshot.")
    incident=content.get("incident")
    if not isinstance(incident,dict) or incident.get("id")!=report_id:
        raise ValueError("Report identity mismatch.")
    raw=json.dumps(content,ensure_ascii=True,allow_nan=False)
    if len(raw.encode("utf-8"))>MAX_REPORT_BYTES:
        raise ValueError("Report too large.")
    return raw


def validate_reports(reports):
    """Allow only bounded inventory fields, never paths, output or credentials."""
    from datetime import datetime
    if not isinstance(reports,list) or len(reports)>MAX_REPORTS:
        raise ValueError("Invalid report inventory.")
    ids=set()
    for item in reports:
        if not isinstance(item,dict) or set(item)!={"id","status","report_type","phase_id","started","completed"}:
            raise ValueError("Invalid metadata fields.")
        ident=item["id"]
        if not isinstance(ident,str) or not REPORT_ID.fullmatch(ident) or ident in ids:
            raise ValueError("Invalid report ID.")
        ids.add(ident)
        if item["status"] not in ("complete","failed","partial","interrupted","running","unknown") or item["report_type"] not in ("campaign","standalone_phase"):
            raise ValueError("Invalid report state.")
        phase=item["phase_id"]
        if phase is not None and (not isinstance(phase,str) or not re.fullmatch(r"[0-9]{2}",phase)):
            raise ValueError("Invalid phase.")
        for key in ("started","completed"):
            value=item[key]
            if value is not None:
                if not isinstance(value,str) or len(value)>40 or datetime.fromisoformat(value.replace("Z","+00:00")).tzinfo is None:
                    raise ValueError("Invalid timestamp.")
    return reports


class Registry:
    def __init__(self,path=DATABASE,clock=None):
        self.path=Path(path)
        self.clock=time.time if clock is None else clock

    @contextmanager
    def _db(self, *, create=False, write=False):
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise Unavailable("Registry path must not be a symlink.")
        if create:
            self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            self.path.parent.chmod(0o700)
        elif not self.path.is_file():
            raise Unavailable("Registry is not initialized.")
        connection=sqlite3.connect(self.path,timeout=5)
        connection.row_factory=sqlite3.Row
        try:
            if create:
                self.path.chmod(0o600)
            with connection:
                if write:
                    connection.execute("BEGIN IMMEDIATE")
                if create:
                    connection.execute("""CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,
                        name TEXT NOT NULL, created_at INTEGER NOT NULL,
                        registered_at INTEGER, last_seen_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0
                    )""")
                yield connection
        finally:
            connection.close()

    def issue(self,agent_id):
        validate_id(agent_id)
        token=secrets.token_urlsafe(32)
        digest=hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._db(create=True,write=True) as db:
            try:
                db.execute("INSERT INTO agents(agent_id,token_hash,name,created_at) VALUES(?,?,?,?)",
                           (agent_id,digest,agent_id,int(self.clock())))
            except sqlite3.IntegrityError as exc:
                raise Conflict("Agent ID already issued; it was not overwritten.") from exc
        return token

    def _authenticate(self,db,agent_id,token):
        validate_id(agent_id)
        if not isinstance(token,str) or not TOKEN.fullmatch(token):
            raise Unauthorized()
        row=db.execute("SELECT * FROM agents WHERE agent_id=?",(agent_id,)).fetchone()
        supplied=hashlib.sha256(token.encode("ascii")).hexdigest()
        expected=row["token_hash"] if row is not None else "0"*64
        valid=hmac.compare_digest(supplied,expected)
        if not valid or row is None or row["revoked"]:
            raise Unauthorized()
        return row

    def register(self,agent_id,token,name, *, enroll=False):
        validate_id(agent_id)
        if not isinstance(token,str) or not TOKEN.fullmatch(token):
            raise Unauthorized()
        if not isinstance(name,str) or not NAME.fullmatch(name):
            raise ValueError("Invalid agent name.")
        with self._db(create=enroll,write=True) as db:
            if enroll:
                # A private per-VM credential is persisted before first contact.
                # Retrying after a lost response must never rotate credentials,
                # replace an existing identity, or undo revocation.
                db.execute("""INSERT OR IGNORE INTO agents
                              (agent_id,token_hash,name,created_at) VALUES(?,?,?,?)""",
                           (agent_id,hashlib.sha256(token.encode("ascii")).hexdigest(),
                            name,int(self.clock())))
            row=self._authenticate(db,agent_id,token)
            now=max(int(self.clock()),row["last_seen_at"] or 0)
            db.execute("""UPDATE agents SET name=?, registered_at=COALESCE(registered_at,?),
                          last_seen_at=? WHERE agent_id=?""",(name,now,now,agent_id))
        return dict(agent_id=agent_id,registered=True,protocol_version=1,
                    heartbeat_interval=HEARTBEAT_INTERVAL,server_time=now)

    def heartbeat(self,agent_id,token):
        with self._db(write=True) as db:
            row=self._authenticate(db,agent_id,token)
            if row["registered_at"] is None:
                raise Conflict("Agent must register first.")
            now=max(int(self.clock()),row["last_seen_at"] or 0)
            db.execute("UPDATE agents SET last_seen_at=? WHERE agent_id=?",(now,agent_id))
        return dict(agent_id=agent_id,accepted=True,protocol_version=1,server_time=now)

    def sync_reports(self,agent_id,token,reports):
        validate_reports(reports)
        with self._db(write=True) as db:
            row=self._authenticate(db,agent_id,token)
            if row["registered_at"] is None:
                raise Conflict("Agent must register first.")
            # Lazy additive migration supports existing registries and old agents.
            db.execute("CREATE TABLE IF NOT EXISTS report_inventory (agent_id TEXT PRIMARY KEY, reports TEXT NOT NULL, synced_at INTEGER NOT NULL)")
            now=int(self.clock())
            db.execute("INSERT OR REPLACE INTO report_inventory VALUES(?,?,?)",
                       (agent_id,json.dumps(reports),now))
            self._report_table(db)
            # Remove old snapshots, including changed metadata, within the same transaction.
            versions={r["id"]:json.dumps(r,sort_keys=True) for r in reports if r["status"]!="running"}
            for cached in db.execute("SELECT report_id,version FROM report_content WHERE agent_id=?",(agent_id,)).fetchall():
                if versions.get(cached["report_id"])!=cached["version"]:
                    db.execute("DELETE FROM report_content WHERE agent_id=? AND report_id=?",(agent_id,cached["report_id"]))
        return dict(agent_id=agent_id,accepted=True,protocol_version=1,server_time=now)

    def receive_p06(self,data,token):
        from p06_live_lab import validate_payload
        raw=validate_payload(data)
        event=dict(protocol_version=1,agent_id=data['agent_id'],campaign_id=data['campaign_id'],
                   event_type='exfil',timestamp=datetime.now(timezone.utc).isoformat(),
                   bytes=len(raw),synthetic=True)
        result=self.receive_event(event,token,p06=raw)
        result.update(agent_id=data['agent_id'],campaign_id=data['campaign_id'],phase='P06',
                      size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),verified=True)
        return result

    def receive_event(self,data,token, *, p06=None):
        """Append synthetic evidence; optionally commit a validated P06 fixture atomically."""
        fields={"protocol_version","agent_id","campaign_id","event_type","timestamp","bytes","synthetic"}
        if (not isinstance(data,dict) or set(data)!=fields
                or type(data["protocol_version"]) is not int or data["protocol_version"]!=1
                or data["synthetic"] is not True):
            raise ValueError("Invalid synthetic event.")
        validate_id(data["agent_id"])
        campaign=data["campaign_id"]
        if not isinstance(campaign,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}",campaign):
            raise ValueError("Invalid campaign ID.")
        if data["event_type"] not in ("http_test","beacon","exfil"):
            raise ValueError("Invalid event type.")
        if type(data["bytes"]) is not int or not 0<=data["bytes"]<=2**31-1:
            raise ValueError("Invalid synthetic byte count.")
        stamp=data["timestamp"]
        if not isinstance(stamp,str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",stamp):
            raise ValueError("Invalid event timestamp.")
        # Strict RFC3339 subset, normalized to UTC; keep receipt time separate.
        if stamp[-6:-5] in ("+","-") and (int(stamp[-5:-3])>23 or int(stamp[-2:])>59):
            raise ValueError("Invalid timestamp offset.")
        try:
            stamp=datetime.fromisoformat(stamp.replace("Z","+00:00")).astimezone(timezone.utc).isoformat()
        except OverflowError as exc:
            raise ValueError("Timestamp outside UTC range.") from exc
        with self._db(write=True) as db:
            row=self._authenticate(db,data["agent_id"],token)
            if row["registered_at"] is None:
                raise Conflict("Registration required.")
            # Additive, lazy migration: existing identities and reports are untouched.
            db.execute("""CREATE TABLE IF NOT EXISTS receiver_events (
                id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL, campaign_id TEXT NOT NULL,
                event_type TEXT NOT NULL, timestamp TEXT NOT NULL, bytes INTEGER NOT NULL,
                received_at INTEGER NOT NULL, status TEXT NOT NULL CHECK(status='received')
            )""")
            now=int(self.clock())
            cursor=db.execute("""INSERT INTO receiver_events
                (agent_id,campaign_id,event_type,timestamp,bytes,received_at,status)
                VALUES(?,?,?,?,?,?,'received')""",
                (data["agent_id"],campaign,data["event_type"],stamp,data["bytes"],now))
            event_id=cursor.lastrowid
            if p06 is not None:
                db.execute("""CREATE TABLE IF NOT EXISTS p06_receipts (
                    event_id INTEGER PRIMARY KEY, phase TEXT NOT NULL, sha256 TEXT NOT NULL, content BLOB NOT NULL)""")
                db.execute("INSERT INTO p06_receipts VALUES(?,?,?,?)",
                           (event_id,'P06',hashlib.sha256(p06).hexdigest(),p06))
        # Success is returned only after the transaction committed.
        return dict(protocol_version=1,accepted=True,event_id=event_id,status="received",received_at=now)

    def list_receiver_events(self, *, limit=50, before=None, agent_id=None, campaign_id=None):
        """Bounded keyset page; never initialize, migrate or write the registry."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid limit.")
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63-1):
            raise ValueError("Invalid cursor.")
        if agent_id is not None:
            validate_id(agent_id)
        if campaign_id is not None and (not isinstance(campaign_id,str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}",campaign_id)):
            raise ValueError("Invalid campaign ID.")
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise Unavailable("Registry path must not be a symlink.")
        if not self.path.exists():
            return dict(events=[],next_before=None)
        db=sqlite3.connect(self.path.resolve().as_uri()+"?mode=ro",uri=True,timeout=5)
        db.row_factory=sqlite3.Row
        try:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='receiver_events'").fetchone():
                return dict(events=[],next_before=None)
            clauses,values=[],[]
            for column,value in (("id",before),("agent_id",agent_id),("campaign_id",campaign_id)):
                if value is not None:
                    clauses.append(column+(" < ?" if column=="id" else " = ?"))
                    values.append(value)
            where=" WHERE "+" AND ".join(clauses) if clauses else ""
            rows=db.execute("SELECT id,agent_id,campaign_id,event_type,timestamp,bytes,received_at,status "
                            "FROM receiver_events"+where+" ORDER BY id DESC LIMIT ?",values+[limit+1]).fetchall()
            events=[dict(row) for row in rows[:limit]]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='p06_receipts'").fetchone():
                for event in events:
                    receipt=db.execute("SELECT phase,sha256,length(content) AS received_size FROM p06_receipts WHERE event_id=?",(event['id'],)).fetchone()
                    if receipt:
                        event.update(dict(receipt),verified=True)
            return dict(events=events,
                        next_before=rows[limit-1]["id"] if len(rows)>limit else None)
        finally:
            db.close()

    @staticmethod
    def _report_table(db):
        db.execute("""CREATE TABLE IF NOT EXISTS report_content (
            agent_id TEXT NOT NULL, report_id TEXT NOT NULL, version TEXT NOT NULL,
            content TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(agent_id,report_id))""")

    def transfer_report(self,agent_id,token,report_id=None,content=None):
        """Agent polls for one missing finalized inventory snapshot, then uploads it."""
        with self._db(write=True) as db:
            row=self._authenticate(db,agent_id,token)
            if row["registered_at"] is None:
                raise Conflict("Registration required.")
            self._report_table(db)
            inventory=db.execute("SELECT reports FROM report_inventory WHERE agent_id=?",(agent_id,)).fetchone()
            reports=json.loads(inventory[0]) if inventory else []
            if report_id is not None:
                from report_exports import safe_report
                content=safe_report(content)
                raw=validate_snapshot(report_id,content)
                item=next((r for r in reports if r["id"]==report_id and r["status"]!="running"),None)
                incident=content["incident"]
                if (item is None or any(item[k]!=incident.get(v) for k,v in
                        (("status","status"),("started","started"),("completed","ended")))
                        or item["report_type"]!=content.get("report_type","campaign")
                        or item["phase_id"]!=content.get("phase_id")):
                    raise ValueError("Snapshot is outside the current inventory.")
                db.execute("INSERT OR REPLACE INTO report_content VALUES(?,?,?,?,?)",
                           (agent_id,report_id,json.dumps(item,sort_keys=True),raw,hashlib.sha256(raw.encode()).hexdigest()))
            elif content is not None:
                raise ValueError("Unexpected content.")
            cached={r[0] for r in db.execute("SELECT report_id FROM report_content WHERE agent_id=?",(agent_id,))}
            missing=next((r["id"] for r in reports if r["status"]!="running" and r["id"] not in cached),None)
        return dict(agent_id=agent_id,protocol_version=1,server_time=int(self.clock()),accepted=True,report_id=missing)

    def read_report(self,agent_id,report_id):
        validate_id(agent_id)
        if not isinstance(report_id,str) or not REPORT_ID.fullmatch(report_id):
            raise ValueError("Invalid report ID.")
        with self._db() as db:
            row=db.execute("SELECT revoked FROM agents WHERE agent_id=?",(agent_id,)).fetchone()
            if row is None or row[0]:
                return None
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='report_content'").fetchone():
                return None
            cached=db.execute("SELECT content,sha256 FROM report_content WHERE agent_id=? AND report_id=?",(agent_id,report_id)).fetchone()
            return dict(cached) if cached else None

    def revoke(self,agent_id):
        validate_id(agent_id)
        with self._db(write=True) as db:
            result=db.execute("UPDATE agents SET revoked=1 WHERE agent_id=?",(agent_id,))
            if result.rowcount != 1:
                raise ValueError("Unknown agent ID.")

    def list_agents(self):
        now=int(self.clock())
        with self._db() as db:
            rows=db.execute("""SELECT agent_id,name,created_at,registered_at,last_seen_at,revoked
                               FROM agents ORDER BY agent_id""").fetchall()
            inventory={}
            available={}
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='report_content'").fetchone():
                for cached in db.execute("SELECT agent_id,report_id FROM report_content"):
                    available.setdefault(cached["agent_id"],[]).append(cached["report_id"])
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_inventory'").fetchone():
                inventory={r["agent_id"]:dict(reports=json.loads(r["reports"]),reports_synced_at=r["synced_at"])
                           for r in db.execute("SELECT * FROM report_inventory")}
        result=[]
        for row in rows:
            item=dict(row)
            item["available_reports"]=[] if row["revoked"] else available.get(row["agent_id"],[])
            item.update(inventory.get(row["agent_id"],dict(reports=[],reports_synced_at=None)))
            item["status"]=("revoked" if row["revoked"] else "pending" if row["registered_at"] is None
                            else "online" if now-row["last_seen_at"] <= OFFLINE_AFTER else "offline")
            item["revoked"]=bool(item["revoked"])
            result.append(item)
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database",type=Path,default=DATABASE)
    sub=parser.add_subparsers(dest="command",required=True)
    for command in ("issue","revoke"):
        sub.add_parser(command).add_argument("agent_id")
    sub.add_parser("list")
    args=parser.parse_args()
    if not hasattr(os,"geteuid") or os.geteuid()!=0:
        parser.error("Run as root on the Master VM.")
    from deployment_config import load_deployment_config
    config=load_deployment_config()
    if config.role!="master" or config.config_status!="loaded":
        parser.error("A valid Master deployment is required.")
    store=Registry(args.database)
    try:
        if args.command=="issue":
            # Printed once for operator transfer; never stored or logged by API.
            print(json.dumps(dict(agent_id=args.agent_id,token=store.issue(args.agent_id),
                                  protocol_version=1,heartbeat_interval=HEARTBEAT_INTERVAL)))
        elif args.command=="revoke":
            store.revoke(args.agent_id)
            print(json.dumps(dict(agent_id=args.agent_id,revoked=True)))
        else:
            print(json.dumps(dict(agents=store.list_agents()),indent=2))
    except (ValueError,Conflict,Unavailable,OSError,sqlite3.Error) as exc:
        print(f"Registry operation failed: {exc}")
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
