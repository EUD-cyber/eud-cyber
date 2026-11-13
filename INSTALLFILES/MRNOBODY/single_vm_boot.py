"""Verify first boot and create a stopped baseline for an owned Single VM."""
import argparse
import inspect
import json
import os
import re
import ssl
import subprocess
import time
import urllib.request
from urllib.parse import unquote
from pathlib import Path


def guest_probe():
    """Runs inside the VM via QEMU Guest Agent; all checks are read-only."""
    try:
        status = subprocess.run(["cloud-init","status","--format","json"],capture_output=True,
                                text=True,encoding="utf-8",timeout=5)
        state = json.loads(status.stdout)
        if not isinstance(state,dict) or status.returncode != 0 or state.get("errors") or state.get("recoverable_errors"):
            return {"state":"error","reason":"cloud-init"}
        if state.get("status") != "done":
            return {"state":"waiting"}
        if state.get("extended_status", "done") != "done":
            return {"state":"error","reason":"cloud-init degraded"}
        marker = Path("/opt/nordic-attack/INSTALL_COMPLETE")
        if not marker.is_file() or not marker.stat().st_size:
            return {"state":"error","reason":"installation marker"}
        identity = json.loads(Path("/etc/mrnobody/single-vm.json").read_text(encoding="utf-8"))
        # The existing installer generates a self-signed certificate. This is
        # solely a loopback health check, not certificate policy for agents.
        with urllib.request.urlopen("https://127.0.0.1/api/health",
                                    context=ssl._create_unverified_context(),timeout=5) as response:
            health = json.load(response)
        return {"state":"ready","identity":identity,"health":health,"cloud_init":"done","marker":True}
    except (OSError,ValueError,subprocess.SubprocessError):
        return {"state":"error","reason":"guest verification"}


def verify_boot(vmid, instance_id, *, run=None, clock=None, sleep=None, timeout=1800, write=print):
    """Start only a matching stopped Single VM. Never force-stop or delete it."""
    if type(vmid) is not int or not 100 <= vmid <= 999_999_999 or not re.fullmatch(r"[0-9a-f]{16}",instance_id):
        raise ValueError("Angiv gyldigt VMID og instance-ID fra oprettelsen.")
    if type(timeout) is not int or not 1 <= timeout <= 7200:
        raise ValueError("Timeout skal være 1-7200 sekunder.")
    run = subprocess.run if run is None else run
    clock = time.monotonic if clock is None else clock
    sleep = time.sleep if sleep is None else sleep

    def command(argv, limit=15):
        return run(argv,check=True,capture_output=True,text=True,encoding="utf-8",
                   timeout=limit,env=dict(os.environ,LC_ALL="C",LANG="C")).stdout

    def owned_config():
        fields = {}
        for line in command(["qm","config",str(vmid)]).splitlines():
            key, separator, value = line.partition(": ")
            if separator:
                if key in fields:
                    raise ValueError("Tvetydig VM-konfiguration.")
                fields[key] = value
        marker = re.fullmatch(r"MRNOBODY_SINGLE_VM:([0-9a-f]{16}):(master|agent|standalone)",
                              unquote(fields.get("description","")))
        snippet = fields.get("cicustom","")
        expected = rf"user=[A-Za-z][A-Za-z0-9_.-]*[A-Za-z0-9]:snippets/mrnobody_single_{vmid}_{instance_id}\.yaml"
        if not marker or marker[1] != instance_id or not re.fullmatch(expected,snippet):
            raise ValueError("VM'en matcher ikke denne Single VM-oprettelse.")
        return dict(vmid=vmid,instance_id=instance_id,role=marker[2])

    def status():
        result = command(["qm","status",str(vmid)]).strip()
        if result not in {"status: running","status: stopped"}:
            raise ValueError("Ukendt VM-status.")
        return result.split(": ")[1]

    identity = owned_config()
    if status() != "stopped":
        raise ValueError("Første opstart kræver en slukket VM.")
    if re.search(r"(?<![A-Za-z0-9_])First_snapshot(?![A-Za-z0-9_])",command(["qm","listsnapshot",str(vmid)])):
        raise ValueError("First_snapshot findes allerede; intet overskrives.")
    probe = ("import json, subprocess, ssl, urllib.request\nfrom pathlib import Path\n"
             + inspect.getsource(guest_probe) + "\nprint(json.dumps(guest_probe()))")
    write(f"Starter Single VM {vmid}; venter på cloud-init og lokal HTTPS-health.")
    command(["qm","start",str(vmid)],120)
    deadline = clock() + timeout
    while clock() < deadline:
        if status() != "running":
            raise ValueError("VM'en slukkede før verificeret installation; intet snapshot.")
        try:
            result = json.loads(command(["qm","guest","exec",str(vmid),"--synchronous","1",
                                         "--timeout","15","--","python3","-c",probe],20))
        except subprocess.CalledProcessError:
            sleep(5)
            continue
        if not isinstance(result,dict):
            raise ValueError("Ugyldigt guest-agent-resultat.")
        exited = result.get("exited",False)
        if type(exited) not in (bool,int) or exited not in (False,True):
            raise ValueError("Ugyldig guest-agent-exitstatus.")
        if not exited:
            sleep(5)
            continue
        if type(result.get("exitcode")) is not int or result["exitcode"] != 0 or result.get("out-truncated"):
            raise ValueError("Guest-kontrollen fejlede.")
        report = json.loads(result.get("out-data",""))
        if not isinstance(report,dict):
            raise ValueError("Ugyldig guest-kontrol.")
        if report.get("state") == "waiting":
            sleep(5)
            continue
        health = report.get("health",{})
        deployment = health.get("deployment",{}) if isinstance(health,dict) else {}
        if (not isinstance(health,dict) or not isinstance(deployment,dict)
                or report.get("state") != "ready" or report.get("identity") != identity
                or report.get("cloud_init") != "done" or report.get("marker") is not True
                or health.get("status") != "ok" or health.get("service") != "MrNobody Incident Platform"
                or deployment.get("role") != identity["role"] or deployment.get("config_status") != "loaded"):
            raise ValueError("Cloud-init, instance eller health kunne ikke verificeres; intet snapshot.")
        break
    else:
        raise TimeoutError("Installationen blev ikke verificeret inden timeout; VM'en bevares.")
    if owned_config() != identity:
        raise ValueError("VM-identiteten blev ændret; ingen shutdown eller snapshot.")
    command(["qm","shutdown",str(vmid),"--timeout","120","--forceStop","0"],130)
    if status() != "stopped":
        raise ValueError("VM'en er ikke slukket; intet snapshot.")
    if owned_config() != identity:
        raise ValueError("VM-identiteten blev ændret; intet snapshot.")
    command(["qm","snapshot",str(vmid),"First_snapshot","--description",
             "Verified Single VM baseline: cloud-init and local HTTPS health"],300)
    return dict(vmid=vmid,instance_id=instance_id,role=identity["role"],
                cloud_init_verified=True,health_verified=True,baseline="First_snapshot",started=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vmid",type=int,required=True)
    parser.add_argument("--instance-id",required=True)
    parser.add_argument("--timeout",type=int,default=1800)
    args = parser.parse_args()
    if not hasattr(os,"geteuid") or os.geteuid() != 0:
        parser.error("Kør som root på Proxmox.")
    try:
        result = verify_boot(args.vmid,args.instance_id,timeout=args.timeout)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(f"Kontrol stoppet: {exc}. VM'en bevares; ingen automatisk rollback/sletning.")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError,KeyboardInterrupt):
        print("\nAfbrudt. Kontrollér VM-status før næste forsøg.")
        raise SystemExit(130)
