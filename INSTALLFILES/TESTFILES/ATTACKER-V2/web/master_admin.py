"""Opt-in administrator authentication prerequisite. Grants no job authority yet.

Root provisions a separate high-entropy credential; Agent/enrollment tokens are
never accepted. No default credential, request-supplied origin or proxy identity.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit

from flask import jsonify, request, render_template

CREDENTIAL = Path('/etc/mrnobody/web-admin/credential.json')
COOKIE = '__Secure-mrn-admin'
PREFIX = '/api/master/admin'
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
TTL = 900


def origin(value):
    if not isinstance(value, str):
        raise ValueError('Invalid HTTPS origin.')
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path or url.query or url.fragment or url.port == 0
            or value != 'https://' + url.netloc or any(c.isspace() for c in value)):
        raise ValueError('An exact HTTPS origin without a trailing slash is required.')
    return value


def load_credential(path=CREDENTIAL):
    """Fail closed on missing, replaced, linked, shared or malformed credentials."""
    if os.name != 'posix':
        raise OSError('Linux ownership verification required.')
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise OSError('Private root-owned credential directory required.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise OSError('Private root-owned credential required.')
        raw = stream.read(2049)
    if len(raw) > 2048:
        raise ValueError('Invalid credential.')
    data = json.loads(raw)
    if (not isinstance(data, dict) or set(data) != {'version', 'origin', 'sha256'}
            or type(data['version']) is not int or data['version'] != 1
            or not isinstance(data['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', data['sha256'])):
        raise ValueError('Invalid credential.')
    origin(data['origin'])
    return data


def provision(value, path=CREDENTIAL):
    if os.name != 'posix' or os.geteuid() != 0:
        raise OSError('Run locally as root.')
    origin(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise OSError('Private root-owned directory required.')
    secret = secrets.token_urlsafe(32)
    data = dict(version=1, origin=value, sha256=hashlib.sha256(secret.encode()).hexdigest())
    # Refuse replacement: rotation explicitly revokes the old file first.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return secret


def install_admin_auth(app, deployment, credential_path=CREDENTIAL, clock=time.monotonic):
    sessions = {}
    # One global limit is deliberately independent of spoofable client IPs.
    buckets = {}
    lock = threading.Lock()

    def limited(key, maximum):
        now = clock()
        with lock:
            start, count = buckets.get(key, (now, 0))
            if now - start >= 60:
                start, count = now, 0
            buckets[key] = start, count + 1
            return count >= maximum

    def response(data, status=200):
        result = jsonify(data)
        result.status_code = status
        result.headers['Cache-Control'] = 'no-store'
        result.headers['Pragma'] = 'no-cache'
        result.headers['X-Content-Type-Options'] = 'nosniff'
        result.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        return result

    @app.route('/master/admin', methods=['GET'])
    def admin_page():
        config = deployment()
        if config.role != 'master' or config.config_status != 'loaded':
            return response({'message': 'Not found.'}, 404)
        if not (request.is_secure or (request.remote_addr in {'127.0.0.1', '::1'}
                and request.headers.get('X-Forwarded-Proto') == 'https')):
            return response({'message': 'HTTPS required.'}, 403)
        page = app.make_response(render_template('master_admin.html'))
        page.headers['Cache-Control'] = 'no-store'
        page.headers['Referrer-Policy'] = 'no-referrer'
        page.headers['X-Content-Type-Options'] = 'nosniff'
        page.headers['Content-Security-Policy'] = ("default-src 'none'; script-src 'self'; "
                "style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
        return page

    @app.route(PREFIX + '/session', methods=['GET', 'POST', 'DELETE'])
    def admin_session():
        config = deployment()
        if config.role != 'master' or config.config_status != 'loaded':
            return response({'message': 'Not found.'}, 404)
        # Match the existing deployment's local-nginx TLS trust boundary only.
        secure = request.is_secure or (request.remote_addr in {'127.0.0.1', '::1'}
                and request.headers.get('X-Forwarded-Proto') == 'https')
        if not secure:
            return response({'message': 'HTTPS required.'}, 403)
        if limited('all', 120):
            result = response({'message': 'Try later.'}, 429)
            result.headers['Retry-After'] = '60'
            return result
        try:
            credential = load_credential(credential_path)
        except (OSError, ValueError, TypeError, KeyError):
            with lock:
                sessions.clear()
            return response({'message': 'Administrator authentication is not configured.'}, 503)
        if 'https://' + request.host != credential['origin']:
            return response({'message': 'Origin rejected.'}, 403)
        if request.args:
            return response({'message': 'Query parameters are not accepted.'}, 400)
        if request.method != 'GET':
            if request.headers.get('Origin') != credential['origin']:
                return response({'message': 'Origin rejected.'}, 403)
            if request.mimetype != 'application/json':
                return response({'message': 'JSON required.'}, 415)
            if request.content_length is None or request.content_length > 1024:
                return response({'message': 'Bounded request required.'}, 413)
            raw = request.stream.read(1025)
            if len(raw) > 1024:
                return response({'message': 'Request too large.'}, 413)
            try:
                from master_api import _object
                body = json.loads(raw, object_pairs_hook=_object)
                if not isinstance(body, dict):
                    raise ValueError()
            except (ValueError, UnicodeError, RecursionError):
                return response({'message': 'Invalid request.'}, 400)
        if request.method == 'POST':
            if limited('login', 5):
                result = response({'message': 'Try later.'}, 429)
                result.headers['Retry-After'] = '60'
                return result
            token = body.get('credential')
            if set(body) != {'credential'} or not isinstance(token, str) or not TOKEN.fullmatch(token):
                return response({'message': 'Unauthorized.'}, 401)
            if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), credential['sha256']):
                return response({'message': 'Unauthorized.'}, 401)
            ident, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            now = clock()
            with lock:
                for key in list(sessions):
                    if sessions[key][0] <= now or sessions[key][2] != credential['sha256']:
                        del sessions[key]
                sessions.pop(request.cookies.get(COOKIE), None)
                if len(sessions) >= 16:
                    return response({'message': 'Session capacity reached.'}, 503)
                sessions[ident] = now + TTL, csrf, credential['sha256']
            result = response({'authenticated': True, 'csrf': csrf, 'web_job_control': False})
            result.set_cookie(COOKIE, ident, secure=True, httponly=True, samesite='Strict',
                              path=PREFIX, max_age=TTL)
            return result
        ident = request.cookies.get(COOKIE)
        with lock:
            session = sessions.get(ident)
            if not session or session[0] <= clock() or session[2] != credential['sha256']:
                sessions.pop(ident, None)
                return response({'message': 'Unauthorized.'}, 401)
            if request.method == 'DELETE':
                csrf = request.headers.get('X-CSRF-Token', '')
                if body or not TOKEN.fullmatch(csrf) or not hmac.compare_digest(csrf, session[1]):
                    return response({'message': 'CSRF rejected.'}, 403)
                del sessions[ident]
        if request.method == 'DELETE':
            result = response({'authenticated': False, 'web_job_control': False})
            result.delete_cookie(COOKIE, path=PREFIX, secure=True, httponly=True, samesite='Strict')
            return result
        return response({'authenticated': True, 'csrf': session[1], 'web_job_control': False})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Provision separate web administrator authentication; no web job authority.')
    parser.add_argument('command', choices=['provision'])
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    try:
        print(provision(args.origin))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')
