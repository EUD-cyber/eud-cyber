"""Explicitly enabled, fixed synthetic P11 worker; no general phase execution."""
from contextlib import closing
from pathlib import Path
import signal
import sqlite3
import threading
import time

from agent_client import AgentTransport, load_agent_config, FatalAgentError, RetryableAgentError
from master_jobs import OPERATION, OPTIONS, TERMINAL, validate_job
from p11_live_lab import run_loop

STATE = Path('/var/lib/mrnobody/agent-jobs/journal.sqlite3')


class Worker:
    def __init__(self, config, path=STATE, *, sender=None, run=run_loop, stop=None):
        from lab_mode import http_master_allowed
        if not (config.master_url.startswith('https://') or http_master_allowed(config)):
            raise FatalAgentError('Remote jobs require verified HTTPS.')
        self.config=config
        self.sender=sender if sender is not None else AgentTransport(config)
        self.path=Path(path)
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise FatalAgentError('Journal must not be a symlink.')
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path.parent.chmod(0o700)
        self.run=run
        self.stop=stop if stop is not None else threading.Event()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS journal (job_id TEXT PRIMARY KEY, status TEXT NOT NULL)')
        self.path.chmod(0o600)

    def remember(self, ident, status):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT OR REPLACE INTO journal VALUES(?,?)',(ident,status))

    def exchange(self, report=None):
        result=self.sender.post('job-poll',job_report=report)
        job=result['job']
        if job is not None:
            validate_job(job,self.config.agent_id)
        return job

    def step(self):
        job=self.exchange()
        if job is None or job['status'] in TERMINAL:
            return
        ident=job['job_id']
        with closing(sqlite3.connect(self.path)) as db, db:
            previous=db.execute('SELECT status FROM journal WHERE job_id=?',(ident,)).fetchone()
        # A prior running entry is uncertain after restart: fail, never rerun.
        if previous:
            state=previous[0] if previous[0] in TERMINAL else 'failed'
            self.remember(ident,state)
            self.exchange(dict(job_id=ident,status=state))
            return
        if job['status']!='delivered' or job['operation']!=OPERATION:
            self.remember(ident,'failed')
            self.exchange(dict(job_id=ident,status='failed'))
            return
        self.remember(ident,'running')  # Durable before acknowledgement or any effect.
        accepted=self.exchange(dict(job_id=ident,status='running'))
        if accepted['status']!='running' or accepted['stop_requested'] or self.stop.is_set():
            self.remember(ident,'stopped')
            self.exchange(dict(job_id=ident,status='stopped'))
            return
        cancel=threading.Event()
        outcome={'status':'failed'}

        def execute():
            receipt={}
            try:
                rc=self.run(self.config,ident,dict(OPTIONS),stop=cancel,
                            record=lambda event,**fields: receipt.update(fields) if event=='P11_BEACON_STOP' else None)
                if rc==0 and receipt.get('acknowledged')==OPTIONS['beacon_count'] and receipt.get('failed')==0:
                    outcome['status']='succeeded'
            except Exception:
                # Never serialize exception text or local data to the Master.
                outcome['status']='failed'

        thread=threading.Thread(target=execute,daemon=True)
        thread.start()
        deadline=time.monotonic()+100
        state='failed'
        try:
            while thread.is_alive():
                if self.stop.wait(2):
                    state='stopped'
                    cancel.set()
                    break
                if time.monotonic()>=deadline:
                    cancel.set()
                    break
                current=self.exchange(dict(job_id=ident,status='running'))
                if current['stop_requested'] or current['status'] in TERMINAL:
                    state='stopped' if current['stop_requested'] else 'failed'
                    cancel.set()
                    break
            thread.join(12)
            if not cancel.is_set():
                state=outcome['status']
        finally:
            cancel.set()
            thread.join(12)
            self.remember(ident,state)
        if thread.is_alive():
            raise FatalAgentError('Synthetic worker did not stop within its bound.')
        self.exchange(dict(job_id=ident,status=state))


def main():
    # Linux service-wide lock: concurrent processes cannot execute the same journal.
    import fcntl
    config=load_agent_config()
    stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,lambda *_: stop.set())
    STATE.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if STATE.parent.is_symlink():
        raise FatalAgentError('Unsafe journal directory.')
    with open(STATE.parent/'worker.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker=Worker(config,stop=stop)
        while not stop.is_set():
            try:
                worker.step()
            except RetryableAgentError:
                pass  # Any active operation has already been cancelled in finally.
            if stop.wait(2):
                break


if __name__=='__main__':
    try:
        main()
    except (FatalAgentError,ValueError,OSError,sqlite3.Error):
        print('Remote job worker stopped: configuration, authentication, protocol or storage failure.')
        raise SystemExit(2)
