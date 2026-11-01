"""SQLite-backed local scheduler. One service thread, durable atomic claims.

    Execution is delegated to the application's existing endpoints. Credentials
    are provided at run time; the database contains no passwords or uploads.
"""
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar

current_schedule = ContextVar("mrn_schedule", default=None)
from datetime import datetime, timezone


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('An ISO date/time with timezone is required')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except ValueError:
        raise ValueError('An ISO date/time with timezone is required') from None


class Store:
    def __init__(self, directory):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / 'execution.sqlite3'
        with self.connect() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise ValueError('Unsupported planning database version')
            db.execute('CREATE TABLE IF NOT EXISTS scenarios (id TEXT PRIMARY KEY, definition TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, definition TEXT NOT NULL, next_run REAL NOT NULL, enabled INTEGER NOT NULL, last_status TEXT NOT NULL DEFAULT \'never\')')
            db.execute('PRAGMA user_version=1')
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def scenarios(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT definition FROM scenarios ORDER BY id')]

    def save_scenario(self, definition):
        definition = dict(definition)
        definition.setdefault('id', 'custom-' + uuid.uuid4().hex)
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO scenarios VALUES (?, ?)', (definition['id'], json.dumps(definition)))
        return definition

    def delete_scenario(self, sid):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute('SELECT definition FROM schedules'):
                if json.loads(row[0])['execution']['id'] == sid:
                    raise ValueError('Delete schedules referencing this scenario first')
            if db.execute('DELETE FROM scenarios WHERE id=?', (sid,)).rowcount != 1:
                raise ValueError('Custom scenario not found; built-ins cannot be deleted')

    def schedules(self):
        with self.connect() as db:
            return [dict(json.loads(r['definition']), id=r['id'], next_run=datetime.fromtimestamp(r['next_run'], timezone.utc).isoformat(),
                         enabled=bool(r['enabled']), last_status=r['last_status']) for r in db.execute('SELECT * FROM schedules ORDER BY next_run')]

    def save_schedule(self, value, sid=None):
        sid = sid or 'schedule-' + uuid.uuid4().hex
        next_run = timestamp(value['at'])
        with self.connect() as db:
            db.execute('INSERT INTO schedules (id,definition,next_run,enabled) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition,next_run=excluded.next_run,enabled=excluded.enabled',
                       (sid, json.dumps(value), next_run, int(value.get('enabled', True))))
        return sid

    def update(self, sid, enabled=None, delete=False):
        with self.connect() as db:
            if delete:
                db.execute('DELETE FROM schedules WHERE id=?', (sid,))
            else:
                db.execute('UPDATE schedules SET enabled=? WHERE id=?', (int(enabled), sid))

    def finish(self, sid, status):
        with self.connect() as db:
            db.execute('UPDATE schedules SET last_status=? WHERE id=?', (status, sid))

    def claim(self, now):
        """Advance before launch: at-most-once dispatch, no replay storm after reboot.

        Missed recurrences coalesce into one run; a crash after claim is reported
        as interrupted on restart, never retried with potentially destructive work.
        """
        result = []
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute('SELECT * FROM schedules WHERE enabled=1 AND next_run<=?', (now,)).fetchall():
                definition = json.loads(row['definition'])
                interval = definition.get('interval', 0)
                next_run = row['next_run'] + (int((now - row['next_run']) // interval) + 1) * interval if interval else row['next_run']
                db.execute('UPDATE schedules SET next_run=?,enabled=?,last_status=\'dispatching\' WHERE id=?',
                           (next_run, int(bool(interval)), row['id']))
                result.append((row['id'], definition))
        return result


class Scheduler:
    def __init__(self, store, dispatch, log, clock=time.time, observe=None):
        self.store, self.dispatch, self.log, self.clock = store, dispatch, log, clock
        self.credentials = {}  # Deliberately process-local; never written to SQLite.
        self.stop_event = threading.Event()
        self.observe = observe

    def run(self, sid, definition, credentials=None):
        self.log(sid, 'start requested')
        token = current_schedule.set(sid)
        try:
            status = self.dispatch(definition['execution'], credentials or self.credentials.get(sid, {}))
        except Exception:
            status = 'failed: execution could not be dispatched'
        finally:
            current_schedule.reset(token)
        self.store.finish(sid, status)
        self.log(sid, status)
        if status == 'started' and self.observe is not None:
            process = self.observe()
            def complete():
                try:
                    code = process.wait()
                    outcome = 'complete' if code == 0 else 'failed: runner exited' if code not in {130, 137, 143, -15, -9} else 'interrupted'
                    self.store.finish(sid, outcome)
                    self.log(sid, outcome)
                except Exception:
                    self.log(sid, 'failed: could not observe runner exit')
            threading.Thread(target=complete, name='mrn-scheduled-result', daemon=True).start()
        return status

    def tick(self):
        for sid, definition in self.store.claim(self.clock()):
            self.run(sid, definition)

    def start(self):
        with self.store.connect() as db:
            db.execute("UPDATE schedules SET last_status='interrupted by service restart' WHERE last_status IN ('dispatching', 'started')")
        def loop():
            while not self.stop_event.wait(5):
                try:
                    self.tick()
                except Exception:
                    self.log('scheduler', 'failed: scheduler tick; retrying')
        threading.Thread(target=loop, name='mrn-scheduler', daemon=True).start()
