"""Persistent agent identities and heartbeat state; no execution or file transfer."""
import argparse
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
        return dict(agent_id=agent_id,accepted=True,protocol_version=1,server_time=now)

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
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_inventory'").fetchone():
                inventory={r["agent_id"]:dict(reports=json.loads(r["reports"]),reports_synced_at=r["synced_at"])
                           for r in db.execute("SELECT * FROM report_inventory")}
        result=[]
        for row in rows:
            item=dict(row)
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
