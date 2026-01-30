from flask import Flask, jsonify
import paramiko
import re

app = Flask(__name__)

SSH_KEY = "/root/.ssh/shared_admin_ed25519"
SSH_TIMEOUT = 10

TARGETS = {
    "juice-vuln1": {"host": "172.20.0.10", "user": "ubuntu", "compose_dir": "/opt/juiceshop"},
    "juice-vuln2": {"host": "172.20.0.21", "user": "ubuntu", "compose_dir": "/opt/juiceshop"},
    "suricata-appsrv01": {"host": "172.20.0.25", "user": "ubuntu", "compose_dir": "/opt/suricata"},
    "radius-appsrv01": {"host": "172.20.0.25", "user": "ubuntu", "compose_dir": "/opt/radius"},
    "proxmox": {"host": "172.20.0.100", "user": "root", "compose_dir": None}
}

SNAPSHOT_NAME = "First_snapshot"

VM_RESET_MAP = {
    "opnsense": "opnsense",
    "vuln-srv01": "vuln",
    "vuln-srv02": "vuln",
    "appsrv01": "appsrv",
    "kali01": "kali",
    "client01": "client",
    "wazuh": "wazuh",
    "win2025": "win2025"
}

MIRROR_CONFIGS = {
    "kali": {
        "vm_prefix": "kali",
        "mirror_name": "mirror_kali",
        "bridge": "lan1",
        "nic_index": 2
    },
    "appsrv": {
        "vm_prefix": "appsrv",
        "mirror_name": "mirror_appsrv",
        "bridge": "lan1",
        "nic_index": 2
    }
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
    return out.strip(), err.strip()

# =========================
# PROXMOX HELPERS
# =========================
def get_vmid_by_prefix(prefix):
    out, _ = run_ssh("proxmox", "qm list")
    for line in out.splitlines():
        if re.search(prefix, line, re.IGNORECASE):
            return line.split()[0]
    return None


def get_tap_interface(vmid, nic_index):
    return f"tap{vmid}i{nic_index}"


def tap_exists(bridge, tap):
    out, _ = run_ssh("proxmox", f"ovs-vsctl list-ports {bridge}")
    return tap in out.splitlines()


def clear_all_mirrors():
    cmd = """
ovs-vsctl clear Bridge lan1 mirrors
ovs-vsctl -- --all destroy Mirror
"""
    return run_ssh("proxmox", cmd)

# =========================
# MIRROR ENABLE
# =========================
@app.route("/api/mirror/<target>/enable", methods=["POST"])
def mirror_enable(target):
    if target not in MIRROR_CONFIGS:
        return jsonify(error="Unknown mirror target"), 404

    m = MIRROR_CONFIGS[target]
    vmid = get_vmid_by_prefix(m["vm_prefix"])

    if not vmid:
        return jsonify(error="VM not found"), 404

    tap = get_tap_interface(vmid, m["nic_index"])

    if not tap_exists(m["bridge"], tap):
        return jsonify(error="Tap port not found", tap=tap), 409

    cmd = f"""
ovs-vsctl clear Bridge {m['bridge']} mirrors
ovs-vsctl -- --all destroy Mirror

ovs-vsctl \
-- --id=@dst get Port {tap} \
-- --id=@m create Mirror name={m['mirror_name']} select-all=true output-port=@dst \
-- set Bridge {m['bridge']} mirrors=@m
"""

    out, err = run_ssh("proxmox", cmd)

    return jsonify(
        enabled=True,
        mirror=m["mirror_name"],
        vmid=vmid,
        tap=tap,
        output=out,
        error=err
    )

# =========================
# MIRROR DISABLE
# =========================
@app.route("/api/mirror/disable", methods=["POST"])
def mirror_disable():
    out, err = clear_all_mirrors()
    return jsonify(enabled=False, output=out, error=err)

# =========================
# MIRROR STATUS
# =========================
@app.route("/api/mirror/status")
def mirror_status():
    out, _ = run_ssh("proxmox", "ovs-vsctl list Mirror")

    active = None
    for key, cfg in MIRROR_CONFIGS.items():
        if cfg["mirror_name"] in out:
            active = key

    return jsonify(active_mirror=active)

# =========================
# LAB CONTROL
# =========================
@app.route("/api/<lab>/status")
def lab_status(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    t = TARGETS[lab]
    cmd = f"cd {t['compose_dir']} && docker compose ps -q | xargs -r docker inspect -f '{{{{.State.Running}}}}'"
    out, _ = run_ssh(lab, cmd)
    running = "true" in out.lower()

    return jsonify(lab=lab, status="running" if running else "stopped")


@app.route("/api/<lab>/start")
def lab_start(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose up -d"
    out, err = run_ssh(lab, cmd)
    return jsonify(lab=lab, result="started", output=out, error=err)


@app.route("/api/<lab>/stop")
def lab_stop(lab):
    if lab not in TARGETS or not TARGETS[lab]["compose_dir"]:
        return jsonify(error="Unknown lab"), 404

    cmd = f"cd {TARGETS[lab]['compose_dir']} && docker compose down -v"
    out, err = run_ssh(lab, cmd)
    return jsonify(lab=lab, result="stopped", output=out, error=err)


# =========================
# RESET LABS
# =========================
@app.route("/api/resetvm/<vmname>", methods=["POST"])
def reset_vm(vmname):

    if vmname not in VM_RESET_MAP:
        return jsonify(status="error", message="Unknown VM"), 404

    prefix = VM_RESET_MAP[vmname]
    vmid = get_vmid_by_prefix(prefix)

    if not vmid:
        return jsonify(status="error", message="VM not found"), 404

    cmd = f"""
qm rollback {vmid} {SNAPSHOT_NAME}
sleep 2
qm start {vmid}
"""

    out, err = run_ssh("proxmox", cmd)

    if err:
        return jsonify(
            status="error",
            vm=vmname,
            vmid=vmid,
            snapshot=SNAPSHOT_NAME,
            error=err,
            output=out
        ), 500

    return jsonify(
        status="success",
        vm=vmname,
        vmid=vmid,
        snapshot=SNAPSHOT_NAME,
        message="Snapshot rolled back and VM started",
        output=out
    )

@app.route("/api/resetvm_all", methods=["POST"])
def reset_all_vms():

    results = {}

    for vmname, prefix in VM_RESET_MAP.items():
        vmid = get_vmid_by_prefix(prefix)

        if not vmid:
            results[vmname] = "VM not found"
            continue

        cmd = f"""
qm rollback {vmid} {SNAPSHOT_NAME}
sleep 2
qm start {vmid}
"""

        out, err = run_ssh("proxmox", cmd)

        if err:
            results[vmname] = f"error: {err}"
        else:
            results[vmname] = "reset started"

    return jsonify(
        status="success",
        snapshot=SNAPSHOT_NAME,
        results=results
    )

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
