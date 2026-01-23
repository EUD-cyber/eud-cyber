from flask import Flask, jsonify
import paramiko

app = Flask(__name__)

# =========================
# SSH CONFIG
# =========================
SSH_KEY = "/root/.ssh/shared_admin_ed25519"
SSH_TIMEOUT = 10

# =========================
# TARGETS
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
    },
    "proxmox": {
        "host": "172.20.0.100",
        "user": "root",
        "compose_dir": None
    }
}

# =========================
# MIRROR CONFIG
# =========================
MIRROR = {
    "bridge": "lan1",
    "src": "lan1",
    "dst": "tap100i0",
    "name": "lan1-mirror"
}

# =========================
# SSH HELPER
# =========================
def run_ssh(target, cmd):
    if target not in TARGETS:
        return {"error": "invalid target"}

    t = TARGETS[target]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=t["host"],
            username=t["user"],
            key_filename=SSH_KEY,
            timeout=SSH_TIMEOUT
        )

        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()

        if err:
            return {"error": err}

        return {"output": out}

    except Exception as e:
        return {"error": str(e)}

# =========================
# LAB STATUS
# =========================
@app.route("/api/<lab>/status")
def lab_status(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[lab]
    cmd = (
        f"cd {t['compose_dir']} && "
        "for c in $(docker compose ps -q); do "
        "docker inspect -f '{{.State.Running}}' $c; "
        "done"
    )

    r = run_ssh(lab, cmd)
    running = "true" in r.get("output", "").lower()

    return jsonify(
        lab=lab,
        status="running" if running else "stopped"
    )

# =========================
# START LAB
# =========================
@app.route("/api/<lab>/start")
def lab_start(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose up -d"
    r = run_ssh(lab, cmd)

    return jsonify(lab=lab, result="started", raw=r)

# =========================
# STOP LAB
# =========================
@app.route("/api/<lab>/stop")
def lab_stop(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose down"
    r = run_ssh(lab, cmd)

    return jsonify(lab=lab, result="stopped", raw=r)

# =========================
# MIRROR ENABLE
# =========================
@app.route("/api/mirror/enable", methods=["POST"])
def mirror_enable():
    m = MIRROR

    cmd = f"""
ovs-vsctl \
-- --id=@dst get Port {m['dst']} \
-- --id=@m create Mirror name={m['name']} \
select-all=true \
output-port=@dst \
-- set Bridge {m['bridge']} mirrors=@m
"""
    r = run_ssh("proxmox", cmd)
    return jsonify(enabled=True, raw=r)

# =========================
# MIRROR DISABLE
# =========================
@app.route("/api/mirror/disable", methods=["POST"])
def mirror_disable():
    m = MIRROR
    cmd = f"""
ovs-vsctl clear Bridge {m['bridge']} mirrors
ovs-vsctl -- --all destroy Mirror
"""
    r = run_ssh("proxmox", cmd)
    return jsonify(enabled=False, raw=r)

# =========================
# MIRROR STATUS
# =========================
@app.route("/api/mirror/status")
def mirror_status():
    r = run_ssh("proxmox", "ovs-vsctl list Mirror | grep name")
    enabled = MIRROR["name"] in r.get("output", "")
    return jsonify(enabled=enabled)

# =========================
# LIST LABS
# =========================
@app.route("/api/labs")
def list_labs():
    return jsonify(TARGETS)

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
