"""Isolated read-only UI server for browser tests. No scheduler or subprocesses."""
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'TESTFILES/ATTACKER-V2'
sys.path.insert(0,str(BASE/'web'))
import app as module
from flask import request, jsonify
from werkzeug.serving import make_server

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
        module.BASE_DIR=Path(temporary)
        module.SCRIPT_DIR=BASE/'scripts';module.SCENARIO_DIR=BASE/'scenarios'
        module.STATE_DIR=Path(temporary)/'state';module.LOG_DIR=Path(temporary)/'logs'
        module.CAMPAIGN_STATE=module.STATE_DIR/'campaign.json';module.INVENTORY_STATE=module.STATE_DIR/'discovered-hosts.json'
        module.CAMPAIGN_LOG=module.LOG_DIR/'campaign.log';module.CONFIG_FILE=BASE/'config/defaults.conf'
        module.launch=Mock(side_effect=AssertionError('Execution forbidden in browser tests'))
        module.subprocess.Popen=Mock(side_effect=AssertionError('Subprocess forbidden in browser tests'))
        @module.app.before_request
        def read_only():
            if request.method != 'GET':
                return jsonify({'message':'Read-only UI test server'}),403
        server=make_server('127.0.0.1',0,module.app,threaded=True)
        print(f'UI_TEST_URL=http://127.0.0.1:{server.server_port}',flush=True)
        server.serve_forever()
