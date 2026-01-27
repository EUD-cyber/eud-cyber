from flask import Flask, jsonify
import paramiko
import re

app = Flask(__name__)

SSH_KEY = "/root/.ssh/shared_admin_ed25519"
SSH_TIMEOUT = 10

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
    "suricata-appsrv01": {
        "host": "172.20.0.25",
        "user": "ubuntu",
        "compose_dir": "/opt/suricata"
    },
    "proxmox": {
        "host": "172.20.0.100",
        "user": "root",
        "compose_dir": None
    }
}

MIRROR = {
    "bridge": "lan1",
    "mirror_name": "lan1-mirror"
}

# =========================
# SSH HELPER
# =========================
def run_ssh(target, cmd):
    t = TARGETS[target]

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=t["host"],
        username=t["user"],
        key_filename=SSH_KEY,
        timeout=SSH_TIMEOUT
    )

    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    ssh.close()

    if err.strip():
        return {"error": err.strip()}

    return {"output": out.strip()}


# =========================
# FIND KALI TAP INTERFACE
# =========================
def find_kali_tap():
    cmd = "qm list"
    r = run_ssh("proxmox", cmd)

    if "output" not in r:
        return None, "qm list failed"

    for line in r["output"].splitlines():
        if re.search(r"kali", line, re.IGNORECASE):
            parts = line.split()
            vmid = parts[0]
            tap = f"tap{vmid}i2"
            return tap, None

    return None, "No Kali VM found"


# =========================
# MIRROR ENABLE
# =========================
@app.route("/api/mirror/enable", methods=["POST"])
def mirror_enable():

    tap_iface, err = find_kali_tap()
    if err:
        return jsonify(error=err), 500

    m = MIRROR

    cmd = f"""
# Clean old mirrors
ovs-vsctl clear Bridge {m['bridge']} mirrors
ovs-vsctl -- --all destroy Mirror

# Create mirror to Kali TAP interface
ovs-vsctl \
-- --id=@dst get Port {tap_iface} \
-- --id=@m create Mirror name={m['mirror_name']} select-all=true output-port=@dst \
-- set Bridge {m['bridge']} mirrors=@m
"""

    r = run_ssh("proxmox", cmd)

    return jsonify(
        enabled=True,
        kali_interface=tap_iface,
        raw=r
    )


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
    r = run_ssh("proxmox", "ovs-vsctl list Mirror")
    enabled = MIRROR["mirror_name"] in r.get("output", "")
    return jsonify(enabled=enabled)


# =========================
# LAB CONTROL
# =========================
@app.route("/api/<lab>/status")
def lab_status(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[lab]
    cmd = (
        f"cd {t['compose_dir']} && "
        "docker compose ps -q | "
        "xargs -r docker inspect -f '{{.State.Running}}'"
    )

    r = run_ssh(lab, cmd)
    running = "true" in r.get("output", "").lower()

    return jsonify(lab=lab, status="running" if running else "stopped")


@app.route("/api/<lab>/start")
def lab_start(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose up -d"
    r = run_ssh(lab, cmd)
    return jsonify(lab=lab, result="started", raw=r)


@app.route("/api/<lab>/stop")
def lab_stop(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose down"
    r = run_ssh(lab, cmd)
    return jsonify(lab=lab, result="stopped", raw=r)


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
