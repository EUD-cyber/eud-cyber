"""Disposable browser fixture server. Never use with a production DSN."""
from pathlib import Path
import os
import sys

sys.path.insert(0,str(Path(__file__).parent))
from test_connections import app, service, connect, restore_fixture, ROOT
from flask import send_from_directory

restore_fixture()
service.database = connect
os.environ['GUACVM_LAB_ID'] = '1'
os.environ['CONNECTIONS_KEY_FILE'] = '/tmp/guacvm-browser.key'


@app.get('/')
def index():
    return send_from_directory(ROOT/'GUACVM/nginx/web','index.html')


@app.get('/<path:filename>')
def web(filename):
    return send_from_directory(ROOT/'GUACVM/nginx/web',filename)


app.run(host='127.0.0.1',port=5055,debug=False)
