"""Local Master administration and one fixed synthetic P11 operation.

No target parameters, scripts or generic execution adapter.
Delivery is at-most-once: an expired delivery is failed, never requeued.
"""
import argparse
import json
import re
import secrets
import sqlite3
from master_registry import Registry, DATABASE, Conflict, Unauthorized, Unavailable, OFFLINE_AFTER, validate_id

OPERATION = 'p11-live-lab'
OPTIONS = dict(beacon_interval=30, beacon_duration=90, beacon_count=3)
TERMINAL = frozenset({'succeeded', 'failed', 'stopped'})
STATES = TERMINAL | {'queued', 'delivered', 'running'}
KEY = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}')
JOB_ID = re.compile(r'MRN-job-[0-9a-f]{32}')


def validate_job(job, agent_id):
    if (not isinstance(job, dict) or set(job) != {'job_id', 'agent_id', 'operation', 'status', 'stop_requested'}
            or not isinstance(job['job_id'], str) or not JOB_ID.fullmatch(job['job_id'])
            or job['agent_id'] != agent_id or job['operation'] != OPERATION
            or not isinstance(job['status'], str) or job['status'] not in STATES
            or type(job['stop_requested']) is not bool):
        raise ValueError('Invalid fixed-operation job.')
    return job


class Jobs(Registry):
    def _table(self, db):
        db.execute('''CREATE TABLE IF NOT EXISTS execution_jobs (
            job_id TEXT PRIMARY KEY, request_key TEXT UNIQUE NOT NULL,
            agent_id TEXT NOT NULL, credential_hash TEXT NOT NULL,
            status TEXT NOT NULL, stop_requested INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL, deadline INTEGER NOT NULL,
            reason TEXT NOT NULL DEFAULT '')''')
        now = int(self.clock())
        db.execute("""UPDATE execution_jobs SET status='failed', reason='deadline_exceeded'
                      WHERE status NOT IN ('succeeded','failed','stopped') AND deadline<=?""", (now,))
        db.execute("""UPDATE execution_jobs SET status='failed', reason='identity_revoked_or_changed'
                      WHERE status NOT IN ('succeeded','failed','stopped') AND NOT EXISTS
                      (SELECT 1 FROM agents a WHERE a.agent_id=execution_jobs.agent_id
                       AND a.revoked=0 AND a.token_hash=execution_jobs.credential_hash)""")

    @staticmethod
    def _public(row):
        return dict(job_id=row['job_id'], agent_id=row['agent_id'], operation=OPERATION,
                    status=row['status'], stop_requested=bool(row['stop_requested']))

    def enqueue(self, agent_id, request_key, operation=OPERATION):
        validate_id(agent_id)
        if operation != OPERATION or not isinstance(request_key, str) or not KEY.fullmatch(request_key):
            raise ValueError('Only the fixed P11 Live Lab operation and a bounded request key are supported.')
        with self._db(write=True) as db:
            self._table(db)
            old = db.execute('SELECT * FROM execution_jobs WHERE request_key=?', (request_key,)).fetchone()
            if old:
                if old['agent_id'] != agent_id:
                    raise Conflict('Request key already bound to another agent.')
                return self._public(old)
            agent = db.execute('SELECT * FROM agents WHERE agent_id=?', (agent_id,)).fetchone()
            if (not agent or agent['revoked'] or agent['registered_at'] is None
                    or agent['last_seen_at'] is None or int(self.clock())-agent['last_seen_at'] > OFFLINE_AFTER):
                raise Conflict('A registered, online, non-revoked agent is required.')
            if db.execute("SELECT 1 FROM execution_jobs WHERE status NOT IN ('succeeded','failed','stopped')").fetchone():
                raise Conflict('Sprint 1 permits one active job globally.')
            if db.execute('SELECT count(*) FROM execution_jobs').fetchone()[0] >= 10000:
                raise Conflict('Job retention limit reached; archive the database administratively.')
            ident = 'MRN-job-'+secrets.token_hex(16)
            now = int(self.clock())
            db.execute('''INSERT INTO execution_jobs
                          (job_id,request_key,agent_id,credential_hash,status,created_at,deadline)
                          VALUES(?,?,?,?,?,?,?)''',
                       (ident, request_key, agent_id, agent['token_hash'], 'queued', now, now+180))
            return self._public(db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (ident,)).fetchone())

    def inspect(self, job_id, stop=False):
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ValueError('Invalid job ID.')
        with self._db(write=True) as db:
            self._table(db)
            row = db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (job_id,)).fetchone()
            if row is None:
                raise ValueError('Unknown job.')
            if stop and row['status'] not in TERMINAL:
                db.execute("""UPDATE execution_jobs SET stop_requested=1,
                              status=CASE WHEN status='queued' THEN 'stopped' ELSE status END
                              WHERE job_id=?""", (job_id,))
                row = db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (job_id,)).fetchone()
            return dict(self._public(row), reason=row['reason'], deadline=row['deadline'])

    def history(self):
        """Newest 50 fixed jobs only; never expose request keys or token hashes."""
        if not self.path.exists() and not self.path.is_symlink():
            return []
        with self._db(write=True) as db:
            self._table(db)
            rows = db.execute('SELECT * FROM execution_jobs ORDER BY created_at DESC, rowid DESC LIMIT 50').fetchall()
            return [dict(self._public(row), reason=row['reason'], deadline=row['deadline'],
                         created_at=row['created_at']) for row in rows]

    def exchange(self, agent_id, token, report):
        if report is not None and (not isinstance(report, dict) or set(report) != {'job_id', 'status'}
                or not isinstance(report['job_id'], str) or not JOB_ID.fullmatch(report['job_id'])
                or not isinstance(report['status'], str) or report['status'] not in TERMINAL | {'running'}):
            raise ValueError('Invalid job report.')
        with self._db(write=True) as db:
            agent = self._authenticate(db, agent_id, token)
            if agent['registered_at'] is None:
                raise Conflict('Registration required.')
            self._table(db)
            if report is not None:
                row = db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (report['job_id'],)).fetchone()
                if not row or row['agent_id'] != agent_id or row['credential_hash'] != agent['token_hash']:
                    raise Unauthorized()
                state = report['status']
                if row['status'] not in TERMINAL:
                    if row['status'] == 'queued' or (row['status'] == 'delivered' and state == 'succeeded'):
                        raise ValueError('Job must be delivered and accepted first.')
                    if row['stop_requested'] and state == 'succeeded':
                        state = 'stopped'
                    reason={'failed':'agent_reported_failure','stopped':'agent_stopped'}.get(state,'')
                    db.execute('UPDATE execution_jobs SET status=?, reason=? WHERE job_id=?', (state, reason, row['job_id']))
                row = db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (row['job_id'],)).fetchone()
            else:
                row = db.execute("""SELECT * FROM execution_jobs WHERE agent_id=? AND credential_hash=?
                                    AND status NOT IN ('succeeded','failed','stopped')""",
                                 (agent_id, agent['token_hash'])).fetchone()
                if row and row['status'] == 'queued':
                    db.execute("UPDATE execution_jobs SET status='delivered' WHERE job_id=?", (row['job_id'],))
                    row = db.execute('SELECT * FROM execution_jobs WHERE job_id=?', (row['job_id'],)).fetchone()
            return dict(agent_id=agent_id, protocol_version=1, job=self._public(row) if row else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', default=str(DATABASE))
    sub = parser.add_subparsers(dest='action', required=True)
    start = sub.add_parser('start')
    start.add_argument('agent_id'); start.add_argument('request_key')
    for action in ('status', 'stop'):
        sub.add_parser(action).add_argument('job_id')
    args = parser.parse_args()
    try:
        from deployment_config import load_deployment_config
        deployment=load_deployment_config()
        if deployment.role!='master' or deployment.config_status!='loaded':
            raise ValueError('A configured Master is required for local job administration.')
        jobs = Jobs(args.database)
        result = jobs.enqueue(args.agent_id, args.request_key) if args.action == 'start' else jobs.inspect(args.job_id, args.action == 'stop')
        print(json.dumps(result))
    except (ValueError, Conflict) as exc:
        parser.exit(2, str(exc)+'\n')
    except (Unavailable,OSError,sqlite3.Error):
        parser.exit(2,'Job storage unavailable.\n')


if __name__ == '__main__':
    main()
