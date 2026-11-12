"""Existing OpenSSH/sshpass transport, with runtime-only secrets and bounded pipes.

Uses the same clients and host-key policy as P03/P05; no additional SSH library.
Command text travels on stdin, passwords through sshpass's environment input.
"""
import os
import re
import subprocess
import threading

from scenario_model import private


def execute(target, source, env, timeout):
    password = env.get('MRNOBODY_PASSWORD') or env.get('NORDIC_SSH_PASSWORD')
    if not password:
        raise ValueError('Missing runtime SSH password')
    username = target['username']
    if not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,128}', username):
        raise ValueError('Invalid SSH username')
    argv = ['sshpass', '-e', 'ssh', '-T', '-p', str(target['port']),
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
            '-o', 'NumberOfPasswordPrompts=1', '-l', username,
            private(target['target']), 'bash', '-s']
    # Drain both streams concurrently, but retain at most 64 KiB each. Oversized
    # streams are withheld by the preview scrubber, rather than partly redacted.
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=dict(env, SSHPASS=password))
    streams = {}
    def drain(key, pipe):
        retained = bytearray()
        count = 0
        tail = b''
        with pipe:
            while block := pipe.read(8192):
                count += len(block)
                tail = (tail + block)[-256:]
                retained.extend(block[:max(0, 65537 - len(retained))])
        streams[key] = (bytes(retained) if count <= 65536 else bytes(retained[:65281]) + tail, count)
    readers = [threading.Thread(target=drain, args=(k, p), daemon=True)
               for k, p in (('stdout', child.stdout), ('stderr', child.stderr))]
    for reader in readers:
        reader.start()
    def write():
        try:
            with child.stdin:
                child.stdin.write(source.encode('utf-8'))
        except (BrokenPipeError, OSError):
            pass
    writer = threading.Thread(target=write, daemon=True)
    writer.start()
    try:
        code = child.wait(timeout=timeout)
    except BaseException:
        child.kill()
        child.wait()
        raise
    finally:
        for reader in readers:
            reader.join()
        writer.join()
    return code, streams['stdout'], streams['stderr']
