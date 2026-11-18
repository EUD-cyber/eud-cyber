"""Subnet-independent Lab UI, open operator control and bound Agent transport."""
import hmac
import ipaddress
import json
import secrets
from urllib.parse import urlsplit

from flask import request

COOKIE = 'mrn-lab-csrf'  # Automatic CSRF state only; never a login credential.
PRIVATE = tuple(ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def enabled(config):
    return (getattr(config, 'lab_mode', False) is True and config.config_status == 'loaded'
            and config.role in {'master', 'agent'} and config.lab_http is True)


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
    """Transport eligibility only. Every endpoint still authenticates Agent ID/token."""
    return lab_request(config)


def control_request(config):
    """Explicit Lab Mode grants every visitor control of this installation."""
    return lab_request(config)


def access_status(config):
    active = enabled(config)
    return dict(lab_mode=active, role=config.role, zero_interaction_ready=active,
                operator_authorized=active, pairing='automatic-first-binding',
                access_model='open-lab' if active else 'protected',
                blocker=None if active else 'explicit-lab-mode-required')


def http_master_allowed(config):
    # URL is root-provisioned configuration, never a request-selected destination.
    try:
        url = urlsplit(config.master_url)
        return (getattr(config, 'lab_mode', False) is True and config.lab_http is True
                and url.scheme == 'http' and bool(url.hostname)
                and not (url.username or url.password or url.query or url.fragment)
                and 1 <= (url.port or 80) <= 65535)
    except (ValueError, TypeError):
        return False


def boundary(config, sessions, lock, clock, limited, response, agent_posts):
    """Open Lab UI with automatic CSRF; Agent transport keeps ID/token checks.

    No operator credentials, tickets, server-side login sessions or expiry.
    Protected/non-Lab deployments retain their separate authentication.
    """
    if request.endpoint == 'static' or (request.path == '/api/health' and request.method == 'GET'):
        return None
    if not lab_request(config):
        return response({'message': 'Valid Lab Mode web origin required.'}, 403)
    if request.path in agent_posts and request.method == 'POST':
        return None  # Registration binds ID/token; all other transport authenticates it.
    if limited('operator_requests', 6000):
        result = response({'message': 'Try later.'}, 429)
        result.headers['Retry-After'] = '60'
        return result
    origin = request_origin()
    navigation = (request.method in {'GET', 'HEAD'}
                  and request.headers.get('Sec-Fetch-Mode') == 'navigate'
                  and request.headers.get('Sec-Fetch-Dest') == 'document')
    if not navigation and request.headers.get('Sec-Fetch-Site') not in {None, 'same-origin', 'none'}:
        return response({'message': 'Cross-site request rejected.'}, 403)
    if request.headers.get('Origin') not in {None, origin}:
        return response({'message': 'Origin rejected.'}, 403)
    from master_admin import TOKEN
    csrf = request.cookies.get(COOKIE, '')
    if request.path == '/api/master/admin/session':
        if request.method == 'POST':
            return response({'message': 'Lab Mode has no login or browser activation. Open the dashboard.'}, 410)
        if request.method == 'GET':
            if not TOKEN.fullmatch(csrf):
                csrf = secrets.token_urlsafe(32)
            result = response({'authenticated': True, 'csrf': csrf, 'lab_mode': True,
                               'web_job_control': True, 'lab_access': access_status(config)})
            # Browser-session CSRF cookie. It is recreated automatically, including
            # after browser/service restart. No authorization or absolute TTL.
            result.set_cookie(COOKIE, csrf, secure=origin.startswith('https://'),
                              httponly=True, samesite='Strict', path='/')
            return result
    if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
        supplied = request.headers.get('X-CSRF-Token', '')
        if (request.headers.get('Origin') != origin or not TOKEN.fullmatch(csrf)
                or not TOKEN.fullmatch(supplied) or not hmac.compare_digest(csrf, supplied)):
            return response({'message': 'Same-origin CSRF token required; refresh the page to retry.'}, 403)
        if request.content_length is None or request.content_length > 8 * 1024 * 1024:
            return response({'message': 'Bounded request required (maximum 8 MiB).'}, 413)
        if limited('operator_writes', 600):
            result = response({'message': 'Try later.'}, 429)
            result.headers['Retry-After'] = '60'
            return result
    if request.path == '/api/master/admin/session' and request.method == 'DELETE':
        result = response({'authenticated': True, 'lab_mode': True, 'web_job_control': True})
        result.delete_cookie(COOKIE, path='/', secure=origin.startswith('https://'),
                             httponly=True, samesite='Strict')
        return result  # Compatibility only: Lab Mode cannot be logged out.
    return None


def nginx_content(text, config):
    if not enabled(config):
        return text
    anchor = '    location / { return 301 https://$host$request_uri; }'
    if text.count(anchor) != 1:
        raise ValueError('Missing unique HTTP redirect in nginx template')
    return text.replace(anchor, '''    # Explicit Lab Mode: open all-network UI; Agent transport retains ID/token checks.
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
    lines = [line for line in path.read_text().splitlines() if line.strip().partition('=')[0].strip()
             not in {'MRNOBODY_LAB_MODE','MRNOBODY_LAB_HTTP','MRNOBODY_LAB_NETWORKS'}]
    text = '\n'.join(lines) + '\nMRNOBODY_LAB_HTTP=1\nMRNOBODY_LAB_MODE=1\nMRNOBODY_LAB_NETWORKS=' + ','.join(sorted(set(networks))) + '\n'
    candidate = _parse(text)  # Validate all networks before any write.
    if candidate.role == 'agent' and candidate.master_url.startswith('http://') and not http_master_allowed(candidate):
        raise ValueError('Configured Lab HTTP Master URL required')
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
    sub.add_parser('provision-control')
    sub.add_parser('status')
    enable = sub.add_parser('enable');enable.add_argument('--network', action='append', default=[])
    args = parser.parse_args()
    try:
        if args.command == 'nginx':
            Path(args.destination).write_text(nginx_content(Path(args.source).read_text(),load_deployment_config()))
        elif args.command == 'provision-control':
            pass  # Compatibility with old updaters; Lab Mode needs no control key.
        elif args.command == 'status':
            config = load_deployment_config()
            print(json.dumps(access_status(config), sort_keys=True))
            raise SystemExit(0 if enabled(config) else 2)
        else:
            configure(DEPLOYMENT_FILE,args.network)
            print('Lab Mode configured. Run sudo mrnobody update to repair services/nginx.')
    except (OSError, ValueError) as error:
        parser.exit(1,str(error)+'\n')
