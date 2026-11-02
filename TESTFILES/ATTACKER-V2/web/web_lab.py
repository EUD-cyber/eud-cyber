"""Optional isolated P15 teaching endpoint; no shell, filesystem reads or real data.

Run manually on an isolated private lab host: python3 web_lab.py --bind 192.168.1.20
Do not expose this deliberately vulnerable example outside the lab.
"""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        result, status = {}, 404
        if url.path == '/mrn-lab/fingerprint':
            result, status = {'app': 'MrNobody Web Lab v1', 'synthetic': True}, 200
        elif url.path == '/mrn-lab/search':
            # Ephemeral database, single SELECT, fixed synthetic rows only.
            with sqlite3.connect(':memory:') as db:
                db.execute('create table items (name text)')
                db.execute("insert into items values ('MRN_SYNTHETIC_SQLI')")
                try:
                    rows = db.execute("select name from items where name = '" + query.get('q', [''])[0][:80] + "'").fetchall()
                    if rows == [('MRN_SYNTHETIC_SQLI',)]:
                        result, status = {'evidence': 'MRN_SYNTHETIC_SQLI', 'synthetic': True}, 200
                except sqlite3.Error: status = 400
        elif url.path == '/mrn-lab/file' and query.get('name') == ['../synthetic-marker.txt']:
            # Virtual traversal analogue: never resolves/reads an OS path.
            result, status = {'evidence': 'MRN_SYNTHETIC_TRAVERSAL', 'synthetic': True}, 200
        body = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    from scenario_model import private
    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', required=True)
    parser.add_argument('--port', type=int, default=8088)
    args = parser.parse_args()
    HTTPServer((private(args.bind), args.port), Handler).serve_forever()
