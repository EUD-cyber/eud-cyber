#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify
import subprocess
import os
import uuid
from datetime import datetime

app = Flask(__name__)

BASE_DIR = "/opt/nordic-attack"
SCRIPT_DIR = os.path.join(BASE_DIR, "scripts")
LOG_DIR = os.path.join(BASE_DIR, "logs")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

SCRIPTS = {
    "recon": "01-recon.sh",
    "web": "02-web.sh",
    "auth": "03-auth.sh",
    "lateral": "04-lateral.sh",
    "staging": "05-staging.sh",
    "exfil": "06-exfil.sh",
    "ransomware": "07-ransomware-sim.sh",
}


def incident_id():
    return datetime.now().strftime("WEB-%Y%m%d-%H%M%S")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/run/<phase>", methods=["POST"])
def run_phase(phase):

    if phase not in SCRIPTS:
        return jsonify({
            "success": False,
            "message": "Unknown phase"
        }), 400

    data = request.get_json(silent=True) or {}

    compromised_host = data.get("compromised_host", "").strip()
    web_target = data.get("web_target", "").strip()
    web_port = str(data.get("web_port", "80")).strip()
    internal_target = data.get("internal_target", "").strip()
    incident_ip = data.get("incident_ip", "").strip()
    ssh_user = data.get("ssh_user", "").strip()
    ssh_password = data.get("ssh_password", "")

    iid = incident_id()

    env = os.environ.copy()

    env["NORDIC_AUTO"] = "1"
    env["NORDIC_INCIDENT_ID"] = iid

    if compromised_host:
        env["NORDIC_COMPROMISED_HOST"] = compromised_host

    if web_target:
        env["NORDIC_WEB_TARGET"] = web_target

    if web_port:
        env["NORDIC_WEB_PORT"] = web_port

    if internal_target:
        env["NORDIC_INTERNAL_TARGET"] = internal_target

    if incident_ip:
        env["NORDIC_INCIDENT_IP"] = incident_ip

    if ssh_user:
        env["NORDIC_SSH_USER"] = ssh_user

    if ssh_password:
        env["NORDIC_SSH_PASSWORD"] = ssh_password

    script = os.path.join(SCRIPT_DIR, SCRIPTS[phase])

    if not os.path.isfile(script):
        return jsonify({
            "success": False,
            "message": f"Script not found: {script}"
        }), 404

    run_id = str(uuid.uuid4())[:8]

    web_log = os.path.join(
        LOG_DIR,
        f"{iid}-{phase}-{run_id}-web.log"
    )

    try:

        logfile = open(web_log, "w")

        process = subprocess.Popen(
            [script],
            stdout=logfile,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=BASE_DIR,
            start_new_session=True
        )

        return jsonify({
            "success": True,
            "incident_id": iid,
            "phase": phase,
            "pid": process.pid,
            "log": web_log
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/api/logs")
def logs():

    files = []

    if os.path.isdir(LOG_DIR):

        for name in os.listdir(LOG_DIR):

            if name.endswith(".log"):

                path = os.path.join(LOG_DIR, name)

                files.append({
                    "name": name,
                    "size": os.path.getsize(path),
                    "mtime": os.path.getmtime(path)
                })

    files.sort(
        key=lambda x: x["mtime"],
        reverse=True
    )

    return jsonify(files[:50])


@app.route("/api/uploads")
def uploads():

    files = []

    if os.path.isdir(UPLOAD_DIR):

        for name in os.listdir(UPLOAD_DIR):

            path = os.path.join(UPLOAD_DIR, name)

            if os.path.isfile(path):

                files.append({
                    "name": name,
                    "size": os.path.getsize(path)
                })

    return jsonify(files)


@app.route("/api/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Nordic Incident Control"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )