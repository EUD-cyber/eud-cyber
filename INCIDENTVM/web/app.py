#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify
import subprocess
import os
import uuid
import re
from datetime import datetime

app = Flask(__name__)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = "/opt/nordic-attack"
SCRIPT_DIR = os.path.join(BASE_DIR, "scripts")
SCENARIO_DIR = os.path.join(BASE_DIR, "scenarios")
LOG_DIR = os.path.join(BASE_DIR, "logs")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

CAMPAIGN_SCRIPT = os.path.join(
    SCENARIO_DIR,
    "full-incident-h3.sh"
)

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# INDIVIDUAL ATTACK SCRIPTS
# ============================================================

SCRIPTS = {
    "recon": "01-recon.sh",
    "web": "02-web.sh",
    "auth": "03-auth.sh",
    "lateral": "04-lateral.sh",
    "staging": "05-staging.sh",
    "exfil": "06-exfil.sh",
    "ransomware": "07-ransomware-sim.sh",
}


# ============================================================
# RUNNING CAMPAIGNS
#
# Enough for our current single IncidentVM.
# If Flask restarts, historical logs remain, but this runtime
# status dictionary is reset.
# ============================================================

campaigns = {}


# ============================================================
# HELPERS
# ============================================================

def create_incident_id(prefix="H3"):
    return datetime.now().strftime(
        f"{prefix}-%Y%m%d-%H%M%S"
    )


def valid_ip(value):
    """
    Basic IPv4 validation for lab configuration.
    """

    if not value:
        return False

    parts = value.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        return False


def valid_port(value):

    try:
        port = int(value)

        return 1 <= port <= 65535

    except (ValueError, TypeError):
        return False


def get_configuration(data):

    return {
        "compromised_host":
            str(
                data.get(
                    "compromised_host",
                    ""
                )
            ).strip(),

        "web_target":
            str(
                data.get(
                    "web_target",
                    ""
                )
            ).strip(),

        "web_port":
            str(
                data.get(
                    "web_port",
                    "80"
                )
            ).strip(),

        "internal_target":
            str(
                data.get(
                    "internal_target",
                    ""
                )
            ).strip(),

        "incident_ip":
            str(
                data.get(
                    "incident_ip",
                    ""
                )
            ).strip(),

        "ssh_user":
            str(
                data.get(
                    "ssh_user",
                    ""
                )
            ).strip(),

        "ssh_password":
            str(
                data.get(
                    "ssh_password",
                    ""
                )
            )
    }


def validate_configuration(config):

    required_ips = [
        ("Compromised Linux Host",
         config["compromised_host"]),

        ("Web Server",
         config["web_target"]),

        ("Internal Target",
         config["internal_target"]),

        ("IncidentVM IP",
         config["incident_ip"])
    ]

    for name, value in required_ips:

        if not valid_ip(value):

            return (
                False,
                f"{name} is not a valid IPv4 address."
            )

    if not valid_port(
        config["web_port"]
    ):

        return (
            False,
            "Web Port must be between 1 and 65535."
        )

    if not config["ssh_user"]:

        return (
            False,
            "SSH Username is required."
        )

    if not config["ssh_password"]:

        return (
            False,
            "SSH Password is required."
        )

    return True, None


def build_environment(config, incident_id):

    env = os.environ.copy()

    env["NORDIC_AUTO"] = "1"

    env["NORDIC_INCIDENT_ID"] = (
        incident_id
    )

    env["NORDIC_COMPROMISED_HOST"] = (
        config["compromised_host"]
    )

    env["NORDIC_WEB_TARGET"] = (
        config["web_target"]
    )

    env["NORDIC_WEB_PORT"] = (
        config["web_port"]
    )

    env["NORDIC_INTERNAL_TARGET"] = (
        config["internal_target"]
    )

    env["NORDIC_INCIDENT_IP"] = (
        config["incident_ip"]
    )

    env["NORDIC_SSH_USER"] = (
        config["ssh_user"]
    )

    env["NORDIC_SSH_PASSWORD"] = (
        config["ssh_password"]
    )

    return env


def process_running(pid):

    try:

        os.kill(pid, 0)

        return True

    except OSError:

        return False


# ============================================================
# MAIN GUI
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/api/health")
def health():

    return jsonify({
        "status": "ok",
        "service":
            "Nordic Incident Control"
    })


# ============================================================
# RUN INDIVIDUAL PHASE
# ============================================================

@app.route(
    "/api/run/<phase>",
    methods=["POST"]
)
def run_phase(phase):

    if phase not in SCRIPTS:

        return jsonify({
            "success": False,
            "message":
                "Unknown attack phase."
        }), 400


    data = (
        request.get_json(
            silent=True
        ) or {}
    )

    config = get_configuration(data)


    # Individual phases don't necessarily need
    # every configuration field, so we do not
    # perform full campaign validation here.

    iid = create_incident_id(
        phase.upper()
    )


    env = build_environment(
        config,
        iid
    )


    script = os.path.join(
        SCRIPT_DIR,
        SCRIPTS[phase]
    )


    if not os.path.isfile(script):

        return jsonify({
            "success": False,
            "message":
                f"Script not found: {script}"
        }), 404


    if not os.access(
        script,
        os.X_OK
    ):

        return jsonify({
            "success": False,
            "message":
                f"Script is not executable: {script}"
        }), 500


    run_id = str(
        uuid.uuid4()
    )[:8]


    log_path = os.path.join(
        LOG_DIR,
        f"{iid}-{run_id}-web.log"
    )


    try:

        logfile = open(
            log_path,
            "w"
        )


        process = subprocess.Popen(
            [script],
            stdout=logfile,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=BASE_DIR,
            start_new_session=True
        )


        logfile.close()


        return jsonify({
            "success": True,
            "incident_id": iid,
            "phase": phase,
            "pid": process.pid,
            "log": log_path
        })


    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ============================================================
# START FULL H3 CAMPAIGN
# ============================================================

@app.route(
    "/api/campaign/h3",
    methods=["POST"]
)
def start_h3_campaign():

    data = (
        request.get_json(
            silent=True
        ) or {}
    )


    config = get_configuration(data)


    valid, error = (
        validate_configuration(
            config
        )
    )


    if not valid:

        return jsonify({
            "success": False,
            "message": error
        }), 400


    if not os.path.isfile(
        CAMPAIGN_SCRIPT
    ):

        return jsonify({
            "success": False,
            "message":
                "H3 campaign script not found.",
            "script":
                CAMPAIGN_SCRIPT
        }), 404


    if not os.access(
        CAMPAIGN_SCRIPT,
        os.X_OK
    ):

        return jsonify({
            "success": False,
            "message":
                "H3 campaign script is not executable.",
            "script":
                CAMPAIGN_SCRIPT
        }), 500


    # --------------------------------------------------------
    # Prevent two H3 campaigns running simultaneously
    # --------------------------------------------------------

    for existing_id, campaign in campaigns.items():

        if (
            campaign["status"] == "running"
            and process_running(
                campaign["pid"]
            )
        ):

            return jsonify({
                "success": False,
                "message":
                    "An H3 campaign is already running.",
                "incident_id":
                    existing_id,
                "pid":
                    campaign["pid"]
            }), 409


    # --------------------------------------------------------
    # Incident ID
    # --------------------------------------------------------

    iid = create_incident_id(
        "H3"
    )


    # --------------------------------------------------------
    # Environment
    # --------------------------------------------------------

    env = build_environment(
        config,
        iid
    )


    # --------------------------------------------------------
    # Campaign log
    # --------------------------------------------------------

    log_path = os.path.join(
        LOG_DIR,
        f"{iid}-CAMPAIGN.log"
    )


    try:

        logfile = open(
            log_path,
            "w"
        )


        process = subprocess.Popen(
            [CAMPAIGN_SCRIPT],
            stdout=logfile,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=BASE_DIR,
            start_new_session=True
        )


        logfile.close()


        campaigns[iid] = {
            "pid": process.pid,
            "status": "running",
            "log": log_path,
            "started":
                datetime.now().isoformat(),
            "config": {
                "compromised_host":
                    config[
                        "compromised_host"
                    ],

                "web_target":
                    config[
                        "web_target"
                    ],

                "web_port":
                    config[
                        "web_port"
                    ],

                "internal_target":
                    config[
                        "internal_target"
                    ],

                "incident_ip":
                    config[
                        "incident_ip"
                    ],

                "ssh_user":
                    config[
                        "ssh_user"
                    ]

                # Password intentionally NOT stored.
            }
        }


        return jsonify({
            "success": True,
            "incident_id": iid,
            "pid": process.pid,
            "status": "running",
            "log": log_path
        })


    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ============================================================
# CAMPAIGN STATUS
# ============================================================

@app.route(
    "/api/campaign/status/<incident_id>"
)
def campaign_status(incident_id):

    # Only permit our generated incident IDs.

    if not re.fullmatch(
        r"H3-[0-9]{8}-[0-9]{6}",
        incident_id
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid incident ID."
        }), 400


    if incident_id not in campaigns:

        return jsonify({
            "success": False,
            "message":
                "Campaign not found."
        }), 404


    campaign = campaigns[
        incident_id
    ]


    pid = campaign["pid"]


    if campaign["status"] == "running":

        if not process_running(pid):

            # ------------------------------------------------
            # Determine completion from campaign log.
            # The campaign script should print a completion
            # marker when all phases succeed.
            # ------------------------------------------------

            status = "failed"

            try:

                with open(
                    campaign["log"],
                    "r",
                    errors="replace"
                ) as logfile:

                    content = logfile.read()


                if (
                    "FULL INCIDENT COMPLETED"
                    in content.upper()
                ):

                    status = "completed"

            except OSError:

                pass


            campaign["status"] = status


    return jsonify({
        "success": True,
        "incident_id":
            incident_id,
        "pid":
            campaign["pid"],
        "status":
            campaign["status"],
        "log":
            campaign["log"],
        "started":
            campaign["started"]
    })


# ============================================================
# LOG LIST
# ============================================================

@app.route("/api/logs")
def logs():

    files = []


    if os.path.isdir(
        LOG_DIR
    ):

        for name in os.listdir(
            LOG_DIR
        ):

            if not name.endswith(
                ".log"
            ):
                continue


            path = os.path.join(
                LOG_DIR,
                name
            )


            if not os.path.isfile(
                path
            ):
                continue


            files.append({
                "name": name,
                "size":
                    os.path.getsize(
                        path
                    ),
                "mtime":
                    os.path.getmtime(
                        path
                    )
            })


    files.sort(
        key=lambda item:
            item["mtime"],
        reverse=True
    )


    return jsonify(
        files[:50]
    )


# ============================================================
# UPLOAD LIST
# ============================================================

@app.route("/api/uploads")
def uploads():

    files = []


    if os.path.isdir(
        UPLOAD_DIR
    ):

        for name in os.listdir(
            UPLOAD_DIR
        ):

            path = os.path.join(
                UPLOAD_DIR,
                name
            )


            if not os.path.isfile(
                path
            ):
                continue


            files.append({
                "name": name,
                "size":
                    os.path.getsize(
                        path
                    )
            })


    return jsonify(files)


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )