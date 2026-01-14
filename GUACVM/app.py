from flask import Flask, jsonify
import paramiko

app = Flask(__name__)

# =========================
# SSH CONFIG
# =========================
SSH_KEY = "/root/.ssh/shared_admin_ed25519"

# =========================
# LAB TARGETS
# =========================
TARGETS = {
    "juice-vuln1": {
        "host": "172.20.0.10",
        "user": "ubuntu",
        "compose_dir": "/opt/juiceshop"
    },
    "juice-vuln2": {
        "host": "172.20.0.21",
        "user": "ubuntu",
        "compose_dir": "/opt/juiceshop"
    }
}

# =========================
# SSH EXEC
# =========================
def run_ssh(target, cmd):
    if target not in TARGETS:
        return "INVALID_TARGET"

    t = TARGETS[target]

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=t["host"],
        username=t["user"],
        key_filename=SSH_KEY,
        timeout=10
    )

    stdin, stdout, stderr = ssh.exec_command(cmd)

    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()

    ssh.close()

    if err:
        return f"ERROR: {err}"

    return out


# =========================
# STATUS (REAL RUNNING STATE)
# =========================
@app.route("/api/<target>/status")
def status(target):
    if target not in TARGETS:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[target]

    cmd = (
        f"cd {t['compose_dir']} && "
        "for c in $(docker compose ps -q); do "
        "docker inspect -f '{{.State.Running}}' $c; "
        "done"
    )

    out = run_ssh(target, cmd)

    running = "true" in out.lower()

    return jsonify(
        lab=target,
        status="running" if running else "stopped"
    )


# =========================
# START LAB
# =========================
@app.route("/api/<target>/start")
def start(target):
    if target not in TARGETS:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[target]

    cmd = f"cd {t['compose_dir']} && docker compose up -d"
    out = run_ssh(target, cmd)

    return jsonify(
        lab=target,
        result="started",
        raw=out
    )


# =========================
# STOP LAB
# =========================
@app.route("/api/<target>/stop")
def stop(target):
    if target not in TARGETS:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[target]

    cmd = f"cd {t['compose_dir']} && docker compose down"
    out = run_ssh(target, cmd)

    return jsonify(
        lab=target,
        result="stopped",
        raw=out
    )


# =========================
# LIST ALL LABS
# =========================
@app.route("/api/labs")
def labs():
    return jsonify(TARGETS)


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
