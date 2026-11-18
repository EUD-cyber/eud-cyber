"""Explicit Lab Mode: unrestricted UI reads, separately network-trusted writes."""
import hashlib
import hmac
import ipaddress
import json
import secrets
from urllib.parse import urlsplit

from flask import request

COOKIE = 'mrn-lab-session'
TTL = 900
PRIVATE = tuple(ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def enabled(config):
    return (getattr(config, 'lab_mode', False) is True and config.config_status == 'loaded'
            and config.role in {'master', 'agent'} and config.lab_http is True
            and bool(getattr(config, 'lab_networks', ())))


def contains(config, value):
    try:
        address = ipaddress.IPv4Address(value)
        return (enabled(config) and any(address in net for net in PRIVATE)
                and any(address in ipaddress.IPv4Network(net) for net in config.lab_networks))
    except (ValueError, TypeError):
        return False


def peer_allowed(config):
    peer = request.remote_addr
    if peer in {'127.0.0.1', '::1'}:
        peer = request.headers.get('X-Real-IP', peer)
    return contains(config, peer)


def request_origin():
    scheme = request.scheme
    if request.remote_addr in {'127.0.0.1', '::1'}:
        scheme = request.headers.get('X-Forwarded-Proto', scheme)
    if scheme not in {'http', 'https'}:
        raise ValueError('Invalid scheme')
    return scheme + '://' + request.host


def lab_request(config):
    """UI access is independent of client subnet and numeric versus DNS Host."""
    if not enabled(config):
        return False
    try:
        url = urlsplit(request_origin())
        return bool(url.hostname) and not (url.username or url.password) and url.port != 0
    except (ValueError, TypeError):
        return False


def transport_request(config):
    """Numeric private Host prevents DNS rebinding. Only local nginx may forward IPs."""
    if not enabled(config):
        return False
    try:
        url = urlsplit(request_origin())
        return peer_allowed(config) and contains(config, url.hostname) and 1 <= (url.port or 80) <= 65535
    except (ValueError, TypeError):
        return False


def control_request(config):
    """Separate mutation authority; never infer authority from a public UI session.

    Preserve numeric private lab control. DNS control requires an exact origin
    explicitly provisioned by root, as well as a trusted private source network.
    Forwarded client identity is accepted only from local, header-overwriting nginx.
    """
    return lab_request(config) and peer_allowed(config) and (
        transport_request(config) or request_origin() in getattr(config, 'lab_control_origins', ()))


def http_master_allowed(config):
    try:
        url = urlsplit(config.master_url)
        return url.scheme == 'http' and contains(config, url.hostname)
    except (ValueError, TypeError):
        return False


def boundary(config, sessions, lock, clock, limited, response, agent_posts):
    """All-network reads, automatic opaque session, separately authorized CSRF writes."""
    if request.endpoint == 'static' or (request.path == '/api/health' and request.method == 'GET'):
        return None
    if not lab_request(config):
        return response({'message': 'Valid Lab Mode web origin required.'}, 403)
    if request.path in agent_posts and request.method == 'POST':
        if not transport_request(config):
            return response({'message': 'Configured private lab transport network and numeric Host required.'}, 403)
        return None  # Individual bearer token and strict schema remain mandatory.
    can_control = control_request(config)
    if request.method not in {'GET', 'HEAD', 'OPTIONS'} and not can_control:
        return response({'message': 'Lab UI is read-only here. Mutations require a trusted lab/VPN source and numeric lab Host or root-configured control origin.'}, 403)
    if limited('operator_requests', 600):
        result = response({'message': 'Try later.'}, 429); result.headers['Retry-After'] = '60'
        return result
    origin = request_origin()
    # A link from another site is a normal entry into the UI. Exempt only
    # top-level read navigation, never iframe loads, API fetches or mutations.
    navigation = (request.method in {'GET', 'HEAD'}
                  and request.headers.get('Sec-Fetch-Mode') == 'navigate'
                  and request.headers.get('Sec-Fetch-Dest') == 'document')
    if not navigation and request.headers.get('Sec-Fetch-Site') not in {None, 'same-origin', 'none'}:
        return response({'message': 'Cross-site request rejected.'}, 403)
    if request.headers.get('Origin') not in {None, origin}:
        return response({'message': 'Origin rejected.'}, 403)
    if request.method not in {'GET', 'HEAD', 'OPTIONS'} and limited('operator_writes', 30):
        result = response({'message': 'Try later.'}, 429); result.headers['Retry-After'] = '60'
        return result
    fingerprint = hashlib.sha256(json.dumps([config.lab_networks, getattr(config, 'lab_control_origins', ()), origin]).encode()).hexdigest()
    now = clock(); ident = request.cookies.get(COOKIE)
    with lock:
        for key in list(sessions):
            if sessions[key][0] <= now:
                del sessions[key]
        session = sessions.get(ident)
        if session and session[2] != fingerprint:
            session = None
        if request.path == '/api/master/admin/session' and request.method == 'GET':
            if not session:
                if len(sessions) >= 64:
                    return response({'message': 'Session capacity reached.'}, 503)
                ident, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                session = (now + TTL, csrf, fingerprint); sessions[ident] = session
            result = response({'authenticated': True, 'csrf': session[1], 'lab_mode': True, 'web_job_control': can_control})
            result.set_cookie(COOKIE, ident, secure=origin.startswith('https://'), httponly=True,
                              samesite='Strict', path='/', max_age=max(1, int(session[0]-now)))
            return result
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            csrf = request.headers.get('X-CSRF-Token', '')
            if (request.headers.get('Origin') != origin or not session or len(csrf) != 43
                    or not hmac.compare_digest(csrf, session[1])):
                return response({'message': 'Lab session and same-origin CSRF token required.'}, 403)
            if request.content_length is None or request.content_length > 8 * 1024 * 1024:
                return response({'message': 'Bounded request required (maximum 8 MiB).'}, 413)
    if request.path == '/api/master/admin/session':
        return response({'message': 'Lab Mode has no administrator login; mutation access is separately network-controlled.'}, 405)
    return None


def nginx_content(text, config):
    if not enabled(config):
        return text
    anchor = '    location / { return 301 https://$host$request_uri; }'
    if text.count(anchor) != 1:
        raise ValueError('Missing unique HTTP redirect in nginx template')
    return text.replace(anchor, '''    # Explicit Lab Mode: all-network UI; backend separately authorizes mutations/transport.
    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto http;
        proxy_buffering off;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }''')


def configure(path, networks, *, discover=None):
    """Root-only explicit migration; preserve existing role, URL and identity files."""
    import os
    from pathlib import Path
    import stat
    import subprocess
    import tempfile
    from deployment_config import load_deployment_config, _parse
    path = Path(path)
    if os.geteuid() != 0:
        raise ValueError('Run locally as root')
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError('Root-owned unlinked deployment file required')
    config = load_deployment_config(path)
    if config.config_status != 'loaded' or config.role not in {'master', 'agent'}:
        raise ValueError('A valid Master or Agent deployment is required')
    if not networks:
        discover = discover or (lambda: json.loads(subprocess.run(
            ['ip', '-j', '-4', 'address', 'show', 'scope', 'global'], check=True,
            capture_output=True, text=True, timeout=5).stdout))
        networks = []
        private = tuple(ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        for interface in discover():
            for item in interface.get('addr_info', []):
                net = ipaddress.ip_interface(str(item['local']) + '/' + str(item['prefixlen'])).network
                if any(net.subnet_of(parent) for parent in private):
                    networks.append(str(net))
    if config.role == 'agent' and config.master_url:
        # Only a literal private address is allowed for plaintext job transport.
        host = urlsplit(config.master_url).hostname
        try:
            ip = ipaddress.IPv4Address(host)
            if ip.is_private and not ip.is_loopback:
                networks = list(networks) + [str(ip) + '/32']
        except ValueError:
            if config.master_url.startswith('http://'):
                raise ValueError('Lab HTTP jobs require a numeric private Master URL') from None
    lines = [line for line in path.read_text().splitlines() if line.strip().partition('=')[0].strip()
             not in {'MRNOBODY_LAB_MODE','MRNOBODY_LAB_HTTP','MRNOBODY_LAB_NETWORKS'}]
    text = '\n'.join(lines) + '\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE=1\nMRNOBODY_LAB_NETWORKS=' + ','.join(sorted(set(networks))) + '\n'
    candidate = _parse(text)  # Validate all networks before any write.
    if candidate.role == 'agent' and candidate.master_url.startswith('http://') and not http_master_allowed(candidate):
        raise ValueError('Configured Master must be in the private lab scope')
    fd, temporary = tempfile.mkstemp(prefix='.lab-mode-', dir=path.parent)
    try:
        with os.fdopen(fd,'w') as handle:
            handle.write(text);handle.flush();os.fsync(handle.fileno())
        os.chmod(temporary, 0o600);os.replace(temporary,path)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    from deployment_config import load_deployment_config, DEPLOYMENT_FILE
    parser = argparse.ArgumentParser(description='Explicit local Lab Mode setup and nginx rendering')
    sub = parser.add_subparsers(dest='command', required=True)
    render = sub.add_parser('nginx');render.add_argument('source');render.add_argument('destination')
    enable = sub.add_parser('enable');enable.add_argument('--network', action='append', default=[])
    args = parser.parse_args()
    try:
        if args.command == 'nginx':
            Path(args.destination).write_text(nginx_content(Path(args.source).read_text(),load_deployment_config()))
        else:
            configure(DEPLOYMENT_FILE,args.network)
            print('Explicit private Lab Mode configured. Run sudo mrnobody update to repair services/nginx, then restart the web service.')
    except (OSError, ValueError) as error:
        parser.exit(1,str(error)+'\n')
