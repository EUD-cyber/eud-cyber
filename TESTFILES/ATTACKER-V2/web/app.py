#!/usr/bin/env python3

import ipaddress
import sys
import time
import uuid
from planning_api import install, launch, BusyError
from execution import snapshot
from scheduler import current_schedule
from scenario_model import needs_password
import json
import os
import signal
import subprocess
import threading
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from reports import list_reports, load_report, read_metadata
from report_exports import VIEWS, export_html, export_pdf


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(os.environ.get("NORDIC_BASE_DIR", "/opt/nordic-attack"))
CONFIG_FILE = BASE_DIR / "config" / "defaults.conf"
STATE_DIR = BASE_DIR / "state"
LOG_DIR = BASE_DIR / "logs"
SCRIPT_DIR = BASE_DIR / "scripts"
PHASE_RUNNER = SCRIPT_DIR / "run-phase.sh"
UPDATE_SCRIPT = SCRIPT_DIR / "update.sh"
UPLOAD_DIR = BASE_DIR / "runtime" / "uploads"

SCENARIO_DIR = BASE_DIR / "scenarios"

CAMPAIGN_STATE = STATE_DIR / "campaign.json"
INVENTORY_STATE = STATE_DIR / "discovered-hosts.json"

CAMPAIGN_LOG = LOG_DIR / "campaign.log"

# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)
app.url_map.redirect_defaults = False
campaign_process = None
campaign_lock = threading.Lock()


# ============================================================
# HELPERS
# ============================================================

def read_defaults():
    """
    Read simple KEY=VALUE entries from defaults.conf.
    """

    config = {}

    if not CONFIG_FILE.exists():
        return config

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip()

                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in ("'", '"')
                ):
                    value = value[1:-1]

                config[key] = value

    except Exception:
        return {}

    return config


def read_json(path, default):
    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    except Exception:
        return default

def read_attack_metadata(path):
    """
    Read ATTACK_* and MITRE_* metadata from a phase script.
    """

    return read_metadata(path)


def read_scenario_metadata(path):
    """
    Read SCENARIO_* metadata from a scenario script.
    """

    metadata_keys = {
        "SCENARIO_ID",
        "SCENARIO_NAME",
        "SCENARIO_DESCRIPTION",
        "SCENARIO_PHASES",
    }

    result = {}

    try:

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for raw_line in handle:

                line = raw_line.strip()

                if not line.startswith("#"):
                    continue

                line = line.lstrip("#").strip()

                if "=" not in line:
                    continue

                key, value = line.split(
                    "=",
                    1,
                )

                key = key.strip()

                if key not in metadata_keys:
                    continue

                value = value.strip()

                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in ("'", '"')
                ):
                    value = value[1:-1]

                result[key] = value

    except Exception:

        return {}

    return result

def find_scenario(
    scenario_id,
):
    """
    Find an installed scenario by SCENARIO_ID.
    """

    custom = planning.custom(scenario_id)
    if custom is not None:
        return {"path": SCENARIO_DIR / "full-incident.sh", "metadata": {"SCENARIO_ID": custom["id"], "SCENARIO_NAME": custom["name"]}}

    if not SCENARIO_DIR.exists():
        return None


    for path in SCENARIO_DIR.glob(
        "*.sh"
    ):

        metadata = read_scenario_metadata(path)


        current_id = metadata.get(
            "SCENARIO_ID",
            path.stem,
        )


        if current_id == scenario_id:

            return {
                "path": path,
                "metadata": metadata,
            }


    return None

def tail_file(path, lines=300):
    if not path.exists():
        return ""

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:
            content = handle.readlines()

        return "".join(content[-lines:])

    except Exception as exc:
        return f"Unable to read log: {exc}\n"


def valid_port(value):
    try:
        port = int(value)
        return 1 <= port <= 65535
    except (TypeError, ValueError):
        return False


def normalize_ports(value):
    """
    Validate and normalize comma-separated TCP ports.
    """

    if isinstance(value, list):
        raw_ports = value
    else:
        raw_ports = str(value).split(",")

    result = []

    for raw_port in raw_ports:
        raw_port = str(raw_port).strip()

        if not raw_port:
            continue

        if not valid_port(raw_port):
            raise ValueError(
                f"Invalid TCP port: {raw_port}"
            )

        port = str(int(raw_port))

        if port not in result:
            result.append(port)

    if not result:
        raise ValueError(
            "At least one web port is required."
        )

    return ",".join(result)


def determine_incident_ip():
    """
    Determine a private IPv4 address on IncidentVM.

    The GUI can override this value.
    """

    try:
        output = subprocess.check_output(
            [
                "ip",
                "-o",
                "-4",
                "addr",
                "show",
                "scope",
                "global",
            ],
            text=True,
            timeout=5,
        )

        candidates = []

        for line in output.splitlines():
            parts = line.split()

            if len(parts) < 4:
                continue

            address = parts[3].split("/", 1)[0]

            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue

            if ip.is_private:
                candidates.append(address)

        # Prefer production/lab networks over OOBM.

        for address in candidates:
            if not address.startswith("172.20."):
                return address

        if candidates:
            return candidates[0]

    except Exception:
        pass

    return "192.168.1.254"


def process_running():
    global campaign_process

    with campaign_lock:
        if campaign_process is None:
            return False

        return campaign_process.poll() is None


def default_configuration():
    defaults = read_defaults()

    return {
        "incident_ip": determine_incident_ip(),

        "web_ports": defaults.get(
            "NORDIC_DEFAULT_WEB_PORTS",
            "80,443,3010,8080,8443",
        ),

        # ----------------------------------------------------
        # Linux / SSH
        # ----------------------------------------------------

        "ssh_port": defaults.get(
            "NORDIC_DEFAULT_SSH_PORT",
            "22",
        ),

        "ssh_username": defaults.get(
            "NORDIC_DEFAULT_SSH_USER",
            "ubuntu",
        ),

        # Password is deliberately never returned.

        "ssh_password": "",

        # ----------------------------------------------------
        # Windows / RDP
        # ----------------------------------------------------

        "rdp_port": defaults.get(
            "NORDIC_DEFAULT_RDP_PORT",
            "3389",
        ),

        "rdp_username": defaults.get(
            "NORDIC_DEFAULT_RDP_USER",
            "Administrator",
        ),

        # Password is deliberately never returned.

        "rdp_password": "",

        # ----------------------------------------------------
        # Exfiltration
        # ----------------------------------------------------

        "exfil_port": defaults.get(
            "NORDIC_DEFAULT_EXFIL_PORT",
            "9090",
        ),

        "excluded_networks": defaults.get(
            "NORDIC_DISCOVERY_EXCLUDE_NETWORKS",
            "172.20.0.0/24",
        ),
    }


# ============================================================
# ROUTES - GUI
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# ROUTES - HEALTH
# ============================================================

@app.route("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "MrNobody Incident Platform",
            "version": "2.1",
        }
    )


# ============================================================
# ROUTES - CONFIG
# ============================================================

@app.route("/api/config")
def api_config():
    return jsonify(default_configuration())

# ============================================================
# ROUTES - PHASES
# ============================================================

@app.route("/api/phases")
def api_phases():

    phases = []

    if not SCRIPT_DIR.exists():
        return jsonify(
            {
                "count": 0,
                "phases": [],
            }
        )

    for path in sorted(
        SCRIPT_DIR.glob("[0-9][0-9]-*.sh")
    ):

        metadata = read_attack_metadata(path)

        if not metadata:
            continue

        phase_id = metadata.get(
            "ATTACK_ID",
            path.name.split("-", 1)[0],
        )

        name = metadata.get(
            "ATTACK_NAME",
            path.stem,
        )

        alias = metadata.get(
            "ATTACK_ALIAS",
            path.stem.split("-", 1)[-1],
        )

        standalone_raw = metadata.get(
            "ATTACK_STANDALONE",
            "false",
        ).strip().lower()

        standalone = standalone_raw in (
            "1",
            "true",
            "yes",
            "on",
        )

        parameters = [
            value.strip()
            for value in metadata.get(
                "ATTACK_PARAMETERS",
                "",
            ).split(",")
            if value.strip()
        ]

        campaign_state = [
            value.strip()
            for value in metadata.get(
                "ATTACK_CAMPAIGN_STATE",
                "",
            ).split(",")
            if value.strip()
        ]

        techniques = [
            value.strip()
            for value in metadata.get(
                "MITRE_TECHNIQUES",
                "",
            ).split(",")
            if value.strip()
        ]

        phases.append(
            {
                "id": phase_id,
                "name": name,
                "alias": alias,
                "script": path.name,
                "standalone": standalone,
                "parameters": parameters,
                "campaign_state": campaign_state,
                "mitre": {
                    "tactic": metadata.get(
                        "MITRE_TACTIC",
                        "",
                    ),
                    "techniques": techniques,
                },
            }
        )

    phases.sort(
        key=lambda item: int(item["id"])
    )

    return jsonify(
        {
            "count": len(phases),
            "phases": phases,
        }
    )

# ============================================================
# ROUTES - RUN PHASE
# ============================================================

@app.route(
    "/api/phase/<phase_id>/run",
    methods=["POST"],
)
def api_run_phase(phase_id):

    # --------------------------------------------------------
    # Validate phase ID
    # --------------------------------------------------------

    if (
        len(phase_id) != 2
        or not phase_id.isdigit()
    ):
        return jsonify(
            {
                "status": "error",
                "message": "Invalid phase ID.",
            }
        ), 400

    # --------------------------------------------------------
    # Locate phase script
    # --------------------------------------------------------

    matches = list(
        SCRIPT_DIR.glob(
            f"{phase_id}-*.sh"
        )
    )

    if len(matches) != 1:
        return jsonify(
            {
                "status": "error",
                "message": (
                    f"Phase {phase_id} was not found."
                ),
            }
        ), 404

    phase_script = matches[0]

    metadata = read_attack_metadata(
        phase_script
    )

    if not metadata:
        return jsonify(
            {
                "status": "error",
                "message": (
                    f"Phase {phase_id} has no valid metadata."
                ),
            }
        ), 400


    # --------------------------------------------------------
    # Only standalone phases can be executed here
    # --------------------------------------------------------

    standalone = (
        metadata
        .get(
            "ATTACK_STANDALONE",
            "false",
        )
        .strip()
        .lower()
        in (
            "1",
            "true",
            "yes",
            "on",
        )
    )

    if not standalone:
        return jsonify(
            {
                "status": "error",
                "message": (
                    f"Phase {phase_id} does not support "
                    "standalone execution."
                ),
            }
        ), 400


    # --------------------------------------------------------
    # Request data
    # --------------------------------------------------------

    if request.is_json:

        data = request.get_json(
            silent=True
        ) or {}

    else:

        data = request.form.to_dict()


    # --------------------------------------------------------
    # Dry run
    # --------------------------------------------------------

    phase_env = os.environ.copy()
    phase_env["NORDIC_INCIDENT_ID"] = "MRN-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]
    phase_env['MRNOBODY_PASSWORD'] = str(data.get('password', ''))
    if phase_id in {'09', '10'}:
        try:
            from windows_actions import runtime_command
            # Validate even legacy standalone callers without a profile.
            data.setdefault('profile', {'mode': 'normal', 'duration': 0})
            if phase_id == '10':
                phase_env['MRN_POWERSHELL_SECRET'] = runtime_command(data.get('powershell') or phase_env.get('MRN_POWERSHELL_SECRET', ''))
        except ValueError as exc:
            return jsonify({'status': 'error', 'message': str(exc)}), 400
    if "profile" in data:
        try:
            from scenario_model import keys
            keys(data, set(allowed_phase_fields(phase_id)) | {"profile", "timing", "target_mode", "password", "dry_run", "auto", "powershell"}, "phase execution")
            spec = {"type": "phase", "id": phase_id, "profile": data["profile"],
                    "parameters": {k: v for k, v in data.items() if k in allowed_phase_fields(phase_id)},
                    "timing": data.get("timing", {}), "target_mode": data.get("target_mode", "fixed")}
            planning.execution(spec)
            from scenario_model import plan
            from scenario_model import profile
            definition = plan({"target_mode": spec["target_mode"], "profile": profile(spec["profile"]),
                               "phases": [{"id": phase_id, "parameters": spec["parameters"], "timing": spec["timing"]}]})
            phase_env["MRN_EXECUTION"] = json.dumps(definition)
            phase_env["MRN_STARTED"] = str(time.time())
            phase_env["NORDIC_SSH_PASSWORD"] = str(data.get("password", ""))
            phase_env["NORDIC_RDP_PASSWORD"] = str(data.get("password", ""))
        except (ValueError, TypeError, KeyError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    dry_run_raw = str(
        data.get(
            "dry_run",
            "0",
        )
    ).strip().lower()

    dry_run = dry_run_raw in (
        "1",
        "true",
        "yes",
        "on",
    )


    # --------------------------------------------------------
    # Allowed parameters come directly from metadata
    # --------------------------------------------------------

    allowed_parameters = [
        value.strip()
        for value in metadata.get(
            "ATTACK_PARAMETERS",
            "",
        ).split(",")
        if value.strip()
    ]


    # --------------------------------------------------------
    # Build runner command
    # --------------------------------------------------------

    if not PHASE_RUNNER.exists():
        return jsonify(
            {
                "status": "error",
                "message": "Phase runner is missing.",
            }
        ), 500


    command = [
        "/usr/bin/env",
        "bash",
        str(PHASE_RUNNER),
        phase_id,
    ]


    parameter_flags = {
        "source": "--source",
        "target": "--target",
        "subnet": "--subnet",
        "port": "--port",
        "protocol": "--protocol",
        "username": "--user",
        "file": "--file",
        "timeout": "--timeout",
    }


    # --------------------------------------------------------
    # Boolean --auto
    # --------------------------------------------------------

    if "auto" in allowed_parameters:

        auto_raw = str(
            data.get(
                "auto",
                "0",
            )
        ).strip().lower()

        if auto_raw in (
            "1",
            "true",
            "yes",
            "on",
        ):
            command.append(
                "--auto"
            )


    # --------------------------------------------------------
    # Normal parameters
    # --------------------------------------------------------

    for parameter in allowed_parameters:

        if parameter == "auto":
            continue

        flag = parameter_flags.get(
            parameter
        )

        if not flag:
            continue

        value = str(
            data.get(
                parameter,
                "",
            )
        ).strip()

        if not value:
            continue

        command.extend(
            [
                flag,
                value,
            ]
        )


    # --------------------------------------------------------
    # Dry run flag
    # --------------------------------------------------------

    if dry_run:
        command.append(
            "--dry-run"
        )


    # --------------------------------------------------------
    # Prepare log directory
    # --------------------------------------------------------

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    # --------------------------------------------------------
    # Start phase
    # --------------------------------------------------------

    try:

        log_handle = CAMPAIGN_LOG.open(
            "a",
            encoding="utf-8",
        )

        log_handle.write(
            "\n"
            "================================================\n"
            f"Phase {phase_id} requested from Web GUI\n"
            f"Name: {metadata.get('ATTACK_NAME', phase_script.name)}\n"
            f"Dry run: {'YES' if dry_run else 'NO'}\n"
            "================================================\n"
        )

        # Never log command arguments because they may
        # contain passwords.

        log_handle.flush()

        phase_env['MRN_OVERVIEW'] = json.dumps(dict(
            json.loads(phase_env.get('MRN_EXECUTION', '{}')),
            type='phase', id=phase_id, name=metadata.get('ATTACK_NAME', phase_id),
            phases=json.loads(phase_env.get('MRN_EXECUTION', '{}')).get('phases', [{'id': phase_id}]),
            trigger='scheduler' if current_schedule.get() else 'manual', schedule_id=current_schedule.get()))
        global campaign_process
        process = launch(BASE_DIR,
            command,
            env=phase_env,
            cwd=str(BASE_DIR),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        campaign_process = process
        log_handle.close()

    except BusyError:
        log_handle.close()
        return jsonify({"status": "error", "message": "An execution is already running."}), 409
    except Exception as exc:

        return jsonify(
            {
                "status": "error",
                "message": (
                    f"Unable to start phase {phase_id}: "
                    f"{exc}"
                ),
            }
        ), 500


    return jsonify(
        {
            "status": "started",
            "phase": phase_id,
            "name": metadata.get(
                "ATTACK_NAME",
                phase_script.name,
            ),
            "dry_run": dry_run,
            "pid": process.pid,
            "message": (
                f"Phase {phase_id} started."
            ),
        }
    )

# ============================================================
# ROUTES - STATUS
# ============================================================

@app.route("/api/execution-status")
def api_execution_status():
    return jsonify(snapshot(BASE_DIR, planning.capabilities(), campaign_process))


@app.route("/api/status")
def api_status():
    state = read_json(
        CAMPAIGN_STATE,
        {
            "status": "idle",
            "phase": None,
            "message": "Campaign has not been started.",
        },
    )

    state["process_running"] = process_running()

    return jsonify(state)


# ============================================================
# ROUTES - INVENTORY
# ============================================================

@app.route("/api/reports")
def api_reports():
    reports = list_reports(BASE_DIR / "reports")
    return jsonify({"count": len(reports), "reports": reports})


@app.route("/api/reports/<incident_id>")
def api_report(incident_id):
    try:
        return jsonify(load_report(BASE_DIR / "reports", incident_id, enrich=request.args.get("raw") != "1"))
    except FileNotFoundError:
        return jsonify({"error": "Report not found"}), 404
    except (OSError, ValueError, TypeError, AttributeError):
        return jsonify({"error": "Invalid or unreadable report"}), 404


@app.route("/api/reports/<incident_id>/export/<format>")
def api_report_export(incident_id, format):
    view = request.args.get("view", "investigation")
    if format not in {"html", "pdf"} or view not in VIEWS:
        return jsonify({"error": "Unsupported export format or report view"}), 400
    try:
        report = load_report(BASE_DIR / "reports", incident_id)
    except (OSError, ValueError, TypeError, AttributeError):
        return jsonify({"error": "Report not found or unreadable"}), 404
    try:
        content = export_html(report, view) if format == "html" else export_pdf(report, view)
    except ImportError:
        return jsonify({"error": "PDF support unavailable. Install python3-reportlab on the server, then retry."}), 503
    response = Response(content, mimetype="text/html" if format == "html" else "application/pdf")
    response.headers["Content-Disposition"] = f'attachment; filename="{incident_id}-{view}.{format}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    return response


@app.route("/api/inventory")
def api_inventory():
    inventory = read_json(
        INVENTORY_STATE,
        {
            "hosts": []
        },
    )

    return jsonify(inventory)


# ============================================================
# ROUTES - LOG
# ============================================================

@app.route("/api/log")
def api_log():
    try:
        lines = int(
            request.args.get(
                "lines",
                "300",
            )
        )
    except ValueError:
        lines = 300

    lines = max(
        10,
        min(
            lines,
            2000,
        ),
    )

    return jsonify(
        {
            "log": tail_file(
                CAMPAIGN_LOG,
                lines,
            )
        }
    )

# ============================================================
# ROUTES - UPDATE
# ============================================================

@app.route(
    "/api/update",
    methods=["POST"],
)
def api_update():

    if not UPDATE_SCRIPT.exists():
        return jsonify(
            {
                "status": "error",
                "message": "Update script is missing.",
            }
        ), 500


    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    try:

        log_handle = CAMPAIGN_LOG.open(
            "a",
            encoding="utf-8",
        )

        log_handle.write(
            "\n"
            "================================================\n"
            "MrNobody update requested from Web GUI\n"
            "================================================\n"
        )

        log_handle.flush()


        process = subprocess.Popen(
            [
                "/usr/bin/env",
                "bash",
                str(UPDATE_SCRIPT),
            ],
            cwd=str(BASE_DIR),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    except Exception as exc:

        return jsonify(
            {
                "status": "error",
                "message": (
                    f"Unable to start update: {exc}"
                ),
            }
        ), 500


    return jsonify(
        {
            "status": "started",
            "pid": process.pid,
            "message": "MrNobody update started.",
        }
    )

# ============================================================
# ROUTES - SCENARIOS
# ============================================================

@app.route(
    "/api/scenarios",
    methods=["GET"],
)
def api_scenarios():

    scenarios = [dict(x, custom=True, phases=[p["id"] for p in x["phases"] if p.get("enabled", True)]) for x in planning.store.scenarios()]

    if not SCENARIO_DIR.exists():

        return jsonify(
            {
                "count": 0,
                "scenarios": [],
            }
        )


    for path in sorted(
        SCENARIO_DIR.glob("*.sh")
    ):

        metadata = read_scenario_metadata(
            path
        )


        scenario_id = metadata.get(
            "SCENARIO_ID",
            path.stem,
        )


        name = metadata.get(
            "SCENARIO_NAME",
            path.stem.replace(
                "-",
                " ",
            ).title(),
        )


        description = metadata.get(
            "SCENARIO_DESCRIPTION",
            "",
        )


        phases = [
            value.strip()
            for value in metadata.get(
                "SCENARIO_PHASES",
                "",
            ).split(",")
            if value.strip()
        ]


        scenarios.append(
            {
                "id": scenario_id,
                "name": name,
                "description": description,
                "script": path.name,
                "phases": phases,
            }
        )


    return jsonify(
        {
            "count": len(scenarios),
            "scenarios": scenarios,
        }
    )



# ============================================================
# ROUTES - START CAMPAIGN
# ============================================================

@app.route(
    "/api/start",
    defaults={"scenario_id": "full-incident"},
    methods=["POST"],
)
@app.route(
    "/api/scenario/<scenario_id>/start",
    methods=["POST"],
)
def api_start(scenario_id="full-incident"):
    global campaign_process

    with campaign_lock:

        if (
            campaign_process is not None
            and campaign_process.poll() is None
        ):
            return jsonify(
                {
                    "status": "error",
                    "message": "Campaign is already running.",
                }
            ), 409

        scenario = find_scenario(scenario_id)

        if scenario is None:
            return jsonify(
                {
                    "status": "error",
                    "message": f"Scenario '{scenario_id}' was not found.",
                }
            ), 404

        scenario_path = scenario["path"]
        scenario_name = scenario["metadata"].get(
            "SCENARIO_NAME",
            scenario_id,
        )

        # ----------------------------------------------------
        # Request data
        #
        # JSON is retained for backwards compatibility.
        # multipart/form-data is used by the GUI when a
        # wordlist file is uploaded.
        # ----------------------------------------------------

        if request.is_json:

            data = request.get_json(
                silent=True
            ) or {}

        else:

            data = request.form.to_dict()

        try:
            execution_plan = planning.definition(scenario_id, data)
        except (ValueError, TypeError, KeyError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400
        defaults = read_defaults()

        # ----------------------------------------------------
        # General
        # ----------------------------------------------------

        incident_ip = str(
            data.get(
                "incident_ip",
                determine_incident_ip(),
            )
        ).strip()

        web_ports = data.get(
            "web_ports",
            defaults.get(
                "NORDIC_DEFAULT_WEB_PORTS",
                "80,443,3010,8080,8443",
            ),
        )

        exfil_port = str(
            data.get(
                "exfil_port",
                defaults.get(
                    "NORDIC_DEFAULT_EXFIL_PORT",
                    "9090",
                ),
            )
        ).strip()

        # ----------------------------------------------------
        # Linux / SSH
        # ----------------------------------------------------

        ssh_port = str(
            data.get(
                "ssh_port",
                defaults.get(
                    "NORDIC_DEFAULT_SSH_PORT",
                    "22",
                ),
            )
        ).strip()

        ssh_username = str(
            data.get(
                "ssh_username",
                defaults.get(
                    "NORDIC_DEFAULT_SSH_USER",
                    "ubuntu",
                ),
            )
        ).strip()

        ssh_password = str(
            data.get(
                "ssh_password",
                "",
            )
        )

        # ----------------------------------------------------
        # Windows / RDP
        # ----------------------------------------------------

        rdp_port = str(
            data.get(
                "rdp_port",
                defaults.get(
                    "NORDIC_DEFAULT_RDP_PORT",
                    "3389",
                ),
            )
        ).strip()

        rdp_username = str(
            data.get(
                "rdp_username",
                defaults.get(
                    "NORDIC_DEFAULT_RDP_USER",
                    "Administrator",
                ),
            )
        ).strip()

        rdp_password = str(
            data.get(
                "rdp_password",
                "",
            )
        )


        # ----------------------------------------------------
        # Wordlist Authentication
        # ----------------------------------------------------

        wordlist_enabled_raw = str(
            data.get(
                "wordlist_enabled",
                "0",
            )
        ).strip().lower()

        wordlist_enabled = (
            wordlist_enabled_raw
            in (
                "1",
                "true",
                "yes",
                "on",
            )
        )

        if execution_plan is not None:
            wordlist_enabled = any(p["id"] == "08" for p in execution_plan["phases"])

        wordlist_users = str(
            data.get(
                "wordlist_users",
                "",
            )
        ).strip()

        wordlist_upload = (
            request.files.get("wordlist_file")
            if not request.is_json
            else None
        )

        # ====================================================
        # VALIDATION
        # ====================================================

        try:
            ipaddress.ip_address(
                incident_ip
            )
        except ValueError:
            return jsonify(
                {
                    "status": "error",
                    "message": "Invalid IncidentVM IP address.",
                }
            ), 400


        try:
            web_ports = normalize_ports(
                web_ports
            )
        except ValueError as exc:
            return jsonify(
                {
                    "status": "error",
                    "message": str(exc),
                }
            ), 400


        # ----------------------------------------------------
        # Linux validation
        # ----------------------------------------------------

        if not valid_port(
            ssh_port
        ):
            return jsonify(
                {
                    "status": "error",
                    "message": "Invalid SSH port.",
                }
            ), 400


        if not ssh_username:
            return jsonify(
                {
                    "status": "error",
                    "message": "Linux SSH username is required.",
                }
            ), 400


        if not ssh_password and needs_password(execution_plan):
            return jsonify(
                {
                    "status": "error",
                    "message": "Linux SSH password is required.",
                }
            ), 400


        # ----------------------------------------------------
        # Windows validation
        # ----------------------------------------------------

        if not valid_port(
            rdp_port
        ):
            return jsonify(
                {
                    "status": "error",
                    "message": "Invalid RDP port.",
                }
            ), 400


        if not rdp_username:
            return jsonify(
                {
                    "status": "error",
                    "message": "Windows RDP username is required.",
                }
            ), 400


        if not rdp_password and needs_password(execution_plan, windows=True):
            return jsonify(
                {
                    "status": "error",
                    "message": "Windows RDP password is required.",
                }
            ), 400

        # ----------------------------------------------------
        # Wordlist validation
        # ----------------------------------------------------

        server_wordlist = str(data.get("wordlist_path", "")).strip()
        has_upload = wordlist_upload is not None and bool(wordlist_upload.filename)
        if wordlist_enabled and server_wordlist and has_upload:
            return jsonify({"status": "error", "message": "Choose either an upload or a server wordlist path."}), 400
        if wordlist_enabled:

            if not wordlist_users:

                return jsonify(
                    {
                        "status": "error",
                        "message": (
                            "At least one wordlist username "
                            "is required."
                        ),
                    }
                ), 400

            if (
                wordlist_upload is None
                or not wordlist_upload.filename
            ) and not server_wordlist and not os.environ.get("NORDIC_WORDLIST_FILE"):

                return jsonify(
                    {
                        "status": "error",
                        "message": (
                            "A password wordlist file "
                            "is required."
                        ),
                    }
                ), 400

        # ----------------------------------------------------
        # Exfiltration validation
        # ----------------------------------------------------

        if not valid_port(
            exfil_port
        ):
            return jsonify(
                {
                    "status": "error",
                    "message": "Invalid exfiltration port.",
                }
            ), 400


        # ====================================================
        # WORDLIST UPLOAD
        # ====================================================

        wordlist_path = None
        existing_wordlist = server_wordlist or os.environ.get("NORDIC_WORDLIST_FILE", "")
        if wordlist_enabled and existing_wordlist and not has_upload:
            try:
                candidate = Path(existing_wordlist)
                if not candidate.is_absolute():
                    raise ValueError()
                candidate = candidate.resolve(strict=True)
                if not candidate.is_file() or candidate.stat().st_size == 0:
                    raise ValueError()
                with candidate.open('rb') as handle:
                    if not handle.read(1):
                        raise ValueError()
                wordlist_path = candidate
            except (OSError, ValueError):
                return jsonify({"status": "error", "message": "Server wordlist must be an absolute path to an existing, readable, non-empty regular file."}), 400

        if wordlist_enabled and has_upload:

            UPLOAD_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            wordlist_path = (
                UPLOAD_DIR /
                f"wordlist-{os.getpid()}-{threading.get_ident()}.txt"
            )

            try:

                wordlist_upload.save(
                    str(wordlist_path)
                )
                os.chmod(wordlist_path, 0o600)

            except Exception as exc:

                return jsonify(
                    {
                        "status": "error",
                        "message": (
                            "Unable to save wordlist: "
                            f"{exc}"
                        ),
                    }
                ), 500

            try:

                if (
                    not wordlist_path.exists()
                    or wordlist_path.stat().st_size == 0
                ):

                    wordlist_path.unlink(
                        missing_ok=True
                    )

                    return jsonify(
                        {
                            "status": "error",
                            "message": (
                                "Uploaded wordlist is empty."
                            ),
                        }
                    ), 400

            except OSError as exc:

                wordlist_path.unlink(
                    missing_ok=True
                )

                return jsonify(
                    {
                        "status": "error",
                        "message": (
                            "Unable to validate wordlist: "
                            f"{exc}"
                        ),
                    }
                ), 500


        # ====================================================
        # ENVIRONMENT
        # ====================================================

        env = os.environ.copy()
        powershell_enabled = str(data.get('powershell_enabled', '0')).lower() in {'1', 'true', 'yes', 'on'}
        env['MRN_POWERSHELL_ENABLED'] = '1' if powershell_enabled else '0'
        if (execution_plan and any(p['id'] == '10' for p in execution_plan['phases'])) or (execution_plan is None and powershell_enabled and '10' in scenario['metadata'].get('SCENARIO_PHASES', '').split(',')):
            try:
                from windows_actions import runtime_command
                env['MRN_POWERSHELL_SECRET'] = runtime_command(data.get('powershell') or env.get('MRN_POWERSHELL_SECRET', ''))
            except ValueError as exc:
                return jsonify({'status': 'error', 'message': str(exc)}), 400
        if execution_plan is not None:
            env["MRN_EXECUTION"] = json.dumps(execution_plan)
            env["MRN_STARTED"] = str(time.time())
            env["NORDIC_WORDLIST_ENABLED"] = "1" if any(p["id"] == "08" for p in execution_plan["phases"]) else "0"
        env["NORDIC_INCIDENT_ID"] = "MRN-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]

        env["NORDIC_INCIDENT_IP"] = incident_ip
        env["NORDIC_WEB_PORTS"] = web_ports

        # Linux / SSH

        env["NORDIC_SSH_PORT"] = ssh_port
        env["NORDIC_SSH_USERNAME"] = ssh_username

        # Legacy compatibility for older phase scripts.

        env["NORDIC_SSH_USER"] = ssh_username

        env["NORDIC_SSH_PASSWORD"] = ssh_password

        # Windows / RDP

        env["NORDIC_RDP_PORT"] = rdp_port
        env["NORDIC_RDP_USERNAME"] = rdp_username
        env["NORDIC_RDP_PASSWORD"] = rdp_password

        # Wordlist Authentication

        env["NORDIC_WORDLIST_ENABLED"] = (
            "1"
            if wordlist_enabled
            else "0"
        )

        env["NORDIC_WORDLIST_USERS"] = (
            wordlist_users
        )

        if wordlist_path is not None:

            env["NORDIC_WORDLIST_FILE"] = (
                str(wordlist_path)
            )

        else:

            env.pop(
                "NORDIC_WORDLIST_FILE",
                None,
            )

        # Exfiltration

        env["NORDIC_EXFIL_PORT"] = exfil_port


        # ====================================================
        # PREPARE DIRECTORIES
        # ====================================================

        STATE_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        LOG_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )


        # ====================================================
        # START CAMPAIGN
        # ====================================================

        try:
            log_handle = CAMPAIGN_LOG.open(
                "a",
                encoding="utf-8",
            )

            log_handle.write(
                "\n"
                "================================================\n"
                "Campaign requested from Web GUI\n"
                f"Scenario: {scenario_name} ({scenario_id})\n"
                "Linux + Windows credentials supplied\n"
                f"Wordlist authentication: "
                f"{'ENABLED' if wordlist_enabled else 'DISABLED'}\n"
                "================================================\n"
            )

            # IMPORTANT:
            # Never write credential values to this log.

            log_handle.flush()

            env['MRN_OVERVIEW'] = json.dumps(dict(
                execution_plan or {}, type='custom' if planning.custom(scenario_id) else 'campaign',
                id=scenario_id, name=scenario_name,
                phases=(execution_plan or {}).get('phases', [{'id': p.strip()} for p in scenario['metadata'].get('SCENARIO_PHASES', '').split(',') if p.strip() and (p.strip() != '08' or wordlist_enabled) and (p.strip() != '10' or powershell_enabled)]),
                trigger='scheduler' if current_schedule.get() else 'manual', schedule_id=current_schedule.get()))
            campaign_process = launch(BASE_DIR,
                [
                    "/usr/bin/env",
                    "bash",
                    str(scenario_path),
                ],
                cwd=str(BASE_DIR),
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

            log_handle.close()
        except BusyError:
            log_handle.close()
            return jsonify({"status": "error", "message": "An execution is already running."}), 409
        except Exception as exc:
            return jsonify(
                {
                    "status": "error",
                    "message": (
                        "Unable to start campaign: "
                        f"{exc}"
                    ),
                }
            ), 500


        return jsonify(
            {
                "status": "started",
                "pid": campaign_process.pid,
                "scenario_id": scenario_id,
                "scenario_name": scenario_name,
                "message": f"{scenario_name} started.",
            }
        )


# ============================================================
# ROUTES - STOP CAMPAIGN
# ============================================================

@app.route(
    "/api/stop",
    methods=["POST"],
)
def api_stop():
    global campaign_process

    with campaign_lock:

        if (
            campaign_process is None
            or campaign_process.poll() is not None
        ):
            return jsonify(
                {
                    "status": "idle",
                    "message": "No campaign is currently running.",
                }
            )

        try:
            os.killpg(
                os.getpgid(
                    campaign_process.pid
                ),
                signal.SIGTERM,
            )

            campaign_process.wait(
                timeout=10
            )

        except subprocess.TimeoutExpired:

            try:
                os.killpg(
                    os.getpgid(
                        campaign_process.pid
                    ),
                    signal.SIGKILL,
                )
            except Exception:
                pass

        except ProcessLookupError:
            pass

        except Exception as exc:
            return jsonify(
                {
                    "status": "error",
                    "message": (
                        "Unable to stop campaign: "
                        f"{exc}"
                    ),
                }
            ), 500

        campaign_process = None

        return jsonify(
            {
                "status": "stopped",
                "message": "Campaign stopped.",
            }
        )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(_error):
    return jsonify(
        {
            "status": "error",
            "message": "Not found.",
        }
    ), 404


@app.errorhandler(500)
def internal_error(_error):
    return jsonify(
        {
            "status": "error",
            "message": "Internal server error.",
        }
    ), 500


# ============================================================
# MAIN
# ============================================================

def allowed_phase_fields(phase_id):
    return planning.capabilities().get(phase_id, {}).get("fields", {})


planning = install(sys.modules[__name__] if __name__ in sys.modules else type("ModuleProxy", (), {"__getattr__": lambda self, key: globals()[key]})())

if __name__ == "__main__":
    planning.start()
    defaults = read_defaults()

    host = defaults.get(
        "NORDIC_WEB_HOST",
        "127.0.0.1",
    )

    try:
        port = int(
            defaults.get(
                "NORDIC_WEB_PORT",
                "8082",
            )
        )
    except ValueError:
        port = 8082

    app.run(
        host=host,
        port=port,
        debug=False,
        threaded=True,
    )

