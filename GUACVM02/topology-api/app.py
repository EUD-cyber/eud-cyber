#!/usr/bin/env python3

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)

DATA_DIR = Path("/data")
TOPOLOGY_FILE = DATA_DIR / "topology.json"
TEMP_FILE = DATA_DIR / "topology.json.tmp"

EMPTY_TOPOLOGY: dict[str, Any] = {
    "version": 1,
    "devices": [],
    "connections": [],
}

file_lock = threading.Lock()


def validate_topology(data: Any) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "Request body must be a JSON object."

    if not isinstance(data.get("devices"), list):
        return False, "'devices' must be a list."

    if not isinstance(data.get("connections"), list):
        return False, "'connections' must be a list."

    if len(data["devices"]) > 500:
        return False, "Too many devices."

    if len(data["connections"]) > 2000:
        return False, "Too many connections."

    return True, ""


@app.get("/api/topology")
def get_topology():
    if not TOPOLOGY_FILE.exists():
        return jsonify(EMPTY_TOPOLOGY)

    try:
        with file_lock:
            with TOPOLOGY_FILE.open("r", encoding="utf-8") as file:
                topology = json.load(file)

        valid, error = validate_topology(topology)

        if not valid:
            app.logger.error("Invalid saved topology: %s", error)
            return jsonify(EMPTY_TOPOLOGY), 500

        return jsonify(topology)

    except (OSError, json.JSONDecodeError) as error:
        app.logger.exception("Could not read topology: %s", error)
        return jsonify(EMPTY_TOPOLOGY), 500


@app.post("/api/topology")
def save_topology():
    topology = request.get_json(silent=True)

    valid, error = validate_topology(topology)

    if not valid:
        return jsonify({
            "saved": False,
            "error": error,
        }), 400

    topology["version"] = topology.get("version", 1)

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        with file_lock:
            with TEMP_FILE.open("w", encoding="utf-8") as file:
                json.dump(
                    topology,
                    file,
                    ensure_ascii=False,
                    indent=2,
                )

            TEMP_FILE.replace(TOPOLOGY_FILE)

        return jsonify({
            "saved": True,
            "devices": len(topology["devices"]),
            "connections": len(topology["connections"]),
        })

    except OSError as error:
        app.logger.exception("Could not save topology: %s", error)

        return jsonify({
            "saved": False,
            "error": "Topology could not be saved.",
        }), 500


@app.delete("/api/topology")
def reset_topology():
    try:
        with file_lock:
            TOPOLOGY_FILE.unlink(missing_ok=True)
            TEMP_FILE.unlink(missing_ok=True)

        return jsonify({
            "reset": True,
        })

    except OSError as error:
        app.logger.exception("Could not reset topology: %s", error)

        return jsonify({
            "reset": False,
            "error": "Topology could not be reset.",
        }), 500


@app.get("/api/topology/status")
def topology_status():
    return jsonify({
        "ready": True,
        "saved": TOPOLOGY_FILE.exists(),
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
