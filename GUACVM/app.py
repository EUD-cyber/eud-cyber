from flask import Flask, jsonify
import paramiko

app = Flask(__name__)

# =====================
# SSH CONFIG
# =====================
SSH_KEY = "/root/.ssh/shared_admin_ed25519"

TARGETS = {
    "vuln1": {
        "host": "172.20.0.10",
        "user": "ubuntu",
        "compose_dir": "/opt/labs/apache"
    },
    "vuln2": {
        "host": "172.20.0.21",
        "user": "ubuntu",
        "compose_dir": "/opt/labs/apache"
    }
}

# =====================
# SSH EXEC
# =====================
def run_ssh(target, cmd):
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
        return f"ERROR:\n{err}"
    return out if out else "OK"

# =====================
# STATUS
# =====================
# =====================
# START
# =====================
@app.route("/api/<target>/start")
def start(target):
    t = TARGETS[target]

    cmd = f"cd {t['compose_dir']} && docker compose up -d"
    out = run_ssh(target, cmd)

    return jsonify(result=out)

# =====================
# STOP
# =====================
@app.route("/api/<target>/stop")
def stop(target):
    t = TARGETS[target]

    cmd = f"cd {t['compose_dir']} && docker compose down"
    out = run_ssh(target, cmd)

    return jsonify(result=out)

# =====================
# RUN
# =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
