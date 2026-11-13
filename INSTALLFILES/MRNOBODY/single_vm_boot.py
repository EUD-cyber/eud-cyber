"""Wait for guest poweroff and snapshot an owned Single VM."""
import argparse
import json
import os
import re
import subprocess
import time
from urllib.parse import unquote



def verify_boot(vmid, instance_id, *, run=None, clock=None, sleep=None, timeout=1800, write=print):
    """Use guest poweroff as completion signal; no QGA or HTTP checks."""
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
    write(f"Starter Single VM {vmid}; venter på at VM'en selv slukker efter installation.")
    command(["qm","start",str(vmid)],120)
    deadline = clock() + timeout
    next_progress = clock() + 30
    while True:
        if status() == "stopped":
            break
        if clock() >= deadline:
            raise TimeoutError("VM'en slukkede ikke inden timeout; VM'en bevares, intet snapshot.")
        if clock() >= next_progress:
            write(f"VM {vmid} installerer stadig; venter på automatisk slukning.")
            next_progress = clock() + 30
        sleep(5)
    if owned_config() != identity:
        raise ValueError("VM-identiteten blev ændret; intet snapshot.")
    if status() != "stopped":
        raise ValueError("VM'en er startet igen; intet snapshot.")
    command(["qm","snapshot",str(vmid),"First_snapshot","--description",
             "Single VM baseline after guest poweroff"],300)
    return dict(vmid=vmid,instance_id=instance_id,role=identity["role"],
                completion_signal="guest_poweroff",cloud_init_verified=False,health_verified=False,
                baseline="First_snapshot",started=False)


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
