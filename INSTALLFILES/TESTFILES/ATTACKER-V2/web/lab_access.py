"""Local root-authorized, single-use browser handoff. No portal trust implied."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import time
from urllib.parse import urlsplit

DIRECTORY = Path('/etc/mrnobody/lab-access')
SESSION_TTL = 8 * 60 * 60


def exact_origin(value):
    url = urlsplit(value)
    if (url.scheme not in {'http', 'https'} or not url.hostname or url.username
            or url.password or url.path or url.query or url.fragment
            or url.port == 0 or value != url.scheme + '://' + url.netloc
            or any(c.isspace() for c in value)):
        raise ValueError('Exact HTTP/HTTPS origin required, without trailing slash')
    return value


def private_file(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise OSError('Private root-owned file required')
    return fd


def locked(directory):
    """Serialize issuance/consumption across processes, including CLI and web."""
    import contextlib
    import fcntl

    @contextlib.contextmanager
    def acquire():
        if os.geteuid() != 0:
            raise OSError('Run locally as root on this VM')
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise OSError('Private root-owned access directory required')
        with os.fdopen(private_file(directory / 'lock', os.O_RDWR | os.O_CREAT), 'r+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield
    return acquire()


def issue(config, value, directory=DIRECTORY, clock=time.time):
    from lab_mode import enabled, control_digest
    if not enabled(config):
        raise ValueError('Explicit Lab Mode Master/Slave required')
    exact_origin(value)
    if os.geteuid() != 0:
        raise OSError('Run locally as root on this VM')
    directory.mkdir(mode=0o700, exist_ok=True)
    token = secrets.token_urlsafe(32)
    data = dict(origin=value, role=config.role, binding=control_digest(),
                expires=clock() + 120, sha256=hashlib.sha256(token.encode()).hexdigest())
    with locked(directory):
        # One outstanding ticket; reissuing revokes the previous unused link.
        with os.fdopen(private_file(directory / 'ticket', os.O_WRONLY | os.O_CREAT), 'w') as handle:
            handle.truncate(0)
            json.dump(data, handle)
            handle.flush(); os.fsync(handle.fileno())
    return value + '/lab/control#handoff=' + token


def consume(token, config, origin, digest, directory=DIRECTORY, clock=time.time):
    from master_admin import TOKEN
    if not isinstance(token, str) or not TOKEN.fullmatch(token) or not digest:
        return False
    try:
        with locked(directory):
            with os.fdopen(private_file(directory / 'ticket', os.O_RDONLY), 'r') as handle:
                data = json.loads(handle.read(2049))
            valid = (data['origin'] == origin and data['role'] == config.role
                     and data['binding'] == digest and clock() < data['expires'] <= clock() + 120
                     and hmac.compare_digest(data['sha256'], hashlib.sha256(token.encode()).hexdigest()))
            if valid:
                (directory / 'ticket').unlink()
            return valid
    except (OSError, ValueError, TypeError, KeyError):
        return False
