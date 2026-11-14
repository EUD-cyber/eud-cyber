"""Exercise the real updater with temporary nginx copies and fake services only."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
PLATFORM=ROOT/"TESTFILES/ATTACKER-V2"
SOURCE=(PLATFORM/"scripts/update.sh").read_text()
BASH=shutil.which("bash") if os.name!="nt" else None


@unittest.skipUnless(BASH,"Isolated shell lifecycle requires Linux")
class NginxUpdate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.runtime=self.root/"runtime"
        (self.runtime/"nginx").mkdir(parents=True)
        self.nginx_source=self.runtime/"nginx/nordic-incident.conf"
        self.payload=(PLATFORM/"nginx/nordic-incident.conf").read_bytes()
        self.nginx_source.write_bytes(self.payload)
        self.target=self.root/"active.conf"
        self.target.write_text("old active config\n")
        self.backups=self.root/"backups"
        self.backups.mkdir()
        self.bin=self.root/"bin"
        self.bin.mkdir()
        self.remote=self.root/"remote"
        self.remote.mkdir()
        (self.remote/"nordic-incident.conf").write_bytes(self.payload)
        (self.remote/"update-manifest.txt").write_text(hashlib.sha256(self.payload).hexdigest()+"|nginx/nordic-incident.conf\n")
        self.calls=self.root/"calls"
        self.calls.write_text("")
        for name,body in {
            "nginx": 'echo "nginx $*" >> "$TEST_CALLS"\nif [ "$TEST_FAIL" = validate ] && grep -q "location = /api/master/agents/reports" "$TEST_TARGET"; then exit 1; fi\n',
            "systemctl": 'echo "systemctl $*" >> "$TEST_CALLS"\nif [ "$TEST_FAIL" = reload ] && grep -q "location = /api/master/agents/reports" "$TEST_TARGET"; then exit 1; fi\n',
            "curl": 'case "$*" in *api/health*) exit 0;; esac\nwhile [ "$#" -gt 0 ]; do case "$1" in -o) dest="$2"; shift;; https://*) url="$1";; esac; shift; done\ncp "$TEST_REMOTE/${url##*/}" "$dest"\n',
        }.items():
            p=self.bin/name
            p.write_text("#!/bin/sh\nset -eu\n"+body)
            p.chmod(0o755)
        self.script=self.root/"update.sh"
        self.script.write_text(SOURCE.replace("/var/backups",str(self.backups)).replace(
            "/etc/nginx/sites-available/nordic-incident.conf",str(self.target)))
        self.env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ["PATH"],
                      NORDIC_BASE_DIR=str(self.runtime),TEST_REMOTE=str(self.remote),
                      TEST_TARGET=str(self.target),TEST_CALLS=str(self.calls),TEST_FAIL="")
        self.sentinels={self.runtime/"agent.json":b"private identity",self.runtime/"registry.sqlite3":b"report state"}
        for path,content in self.sentinels.items():
            path.write_bytes(content)

    def run_update(self,success=True):
        result=subprocess.run([BASH,str(self.script)],env=self.env,text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode==0,success,result.stdout+result.stderr)
        for path,content in self.sentinels.items():
            self.assertEqual(path.read_bytes(),content)
        return result

    def test_matching_download_hash_repairs_stale_active_config_and_keeps_backup(self):
        result=self.run_update()
        self.assertIn("already up to date",result.stdout)
        self.assertEqual(self.target.read_bytes(),self.payload)
        saved=list(self.backups.glob("*/system/nginx/nordic-incident.conf.repair"))
        self.assertEqual(len(saved),1)
        self.assertEqual(saved[0].read_text(),"old active config\n")
        self.assertIn("systemctl reload nginx",self.calls.read_text())

    def test_matching_active_file_still_validates_and_reloads(self):
        self.target.write_bytes(self.payload)
        self.run_update()
        self.assertEqual(self.calls.read_text().splitlines(),["nginx -t","systemctl reload nginx"])

    def test_validation_failure_restores_old_file_and_returns_failure(self):
        self.env["TEST_FAIL"]="validate"
        self.run_update(False)
        self.assertEqual(self.target.read_text(),"old active config\n")
        self.assertEqual(self.calls.read_text().splitlines(),["nginx -t","nginx -t","systemctl reload nginx"])

    def test_reload_failure_restores_old_file_and_returns_failure(self):
        self.env["TEST_FAIL"]="reload"
        self.run_update(False)
        self.assertEqual(self.target.read_text(),"old active config\n")

    def test_missing_active_file_is_installed(self):
        self.target.unlink()
        self.run_update()
        self.assertEqual(self.target.read_bytes(),self.payload)

    def test_downloaded_nginx_update_uses_normal_activation(self):
        self.nginx_source.write_text("old runtime copy\n")
        self.run_update()
        self.assertEqual(self.target.read_bytes(),self.payload)
        self.assertEqual(self.calls.read_text().count("systemctl reload nginx"),1)

    def test_unrelated_update_also_repairs_cached_nginx_copy(self):
        (self.runtime/"release").write_text("old release\n")
        payload=b"new release\n"
        (self.remote/"release").write_bytes(payload)
        manifest=self.remote/"update-manifest.txt"
        manifest.write_text(manifest.read_text()+hashlib.sha256(payload).hexdigest()+"|release\n")
        self.run_update()
        self.assertEqual(self.target.read_bytes(),self.payload)
        self.assertEqual(self.calls.read_text().count("systemctl reload nginx"),1)


class FreshInstall(unittest.TestCase):
    def test_cloud_init_installs_and_enables_the_same_complete_nginx_config(self):
        import yaml
        data=yaml.safe_load((ROOT/"MRNOBODY/mrnobody_userdata.yaml").read_text())
        script=next(item["content"] for item in data["write_files"] if item["path"]=="/usr/local/sbin/install-mrnobody")
        self.assertIn('"$INSTALL_DIR/nginx/nordic-incident.conf"',script)
        self.assertIn('/etc/nginx/sites-enabled/nordic-incident.conf',script)
        source=(PLATFORM/"nginx/nordic-incident.conf").read_text()
        for route in ("register","heartbeat","reports","report-transfer"):
            self.assertIn("location = /api/master/agents/"+route+" {",source)
        self.assertIn('location / { return 301 https://$host$request_uri; }',source)


if __name__=="__main__":
    unittest.main()
