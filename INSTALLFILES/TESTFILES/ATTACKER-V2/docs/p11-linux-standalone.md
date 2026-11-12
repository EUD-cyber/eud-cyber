# P11 Linux Standalone acceptance plan

Scope: Ubuntu 192.168.1.20, SSH user ubuntu. No deployment is performed by this change.
Windows P11 and Linux cron payloads remain unchanged. Full Campaign orchestration is unchanged.

## Before testing

Use the P11 Standalone form with target 192.168.1.20, platform Linux, protocol SSH
(auto port 22, or the configured custom SSH port), user ubuntu and runtime credentials.
Use a different artifact suffix for each method. Save Ground Truth for every create,
inspect and cleanup. A campaign stop does not clean up remote artifacts.

Log in to Ubuntu as ubuntu, not root. Check:
```sh
id
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user show-environment
```
A missing user manager is reported as manager/user_manager_unavailable.
The tool does not enable linger, elevate privileges or create a root service.
An administrator must arrange a working user session/manager before service tests.
Logout survival depends on the host's logind policy; no reboot survival is claimed
for a user service without the required user-manager lifecycle.

## systemd

1. Select systemd, create, suffix linux-sd. Leave DNS disabled. Start once.
2. As ubuntu, inspect:
   `systemctl --user status mrnobody-p11-linux-sd.service`
   `systemctl --user is-enabled mrnobody-p11-linux-sd.service`
   `journalctl --user -u mrnobody-p11-linux-sd.service`
   The unit is in ~/.config/systemd/user, not the system manager.
3. Run create again with identical settings. The stored deadline must not extend.
4. Select inspect. Verify service and enabled state against Ground Truth.
5. Select cleanup twice. Unit, activity directory and active service must be absent.
6. Repeat with no user manager and with an unrelated same-name unit. Expect an
   explicit failure; never report a successful create or delete the unrelated unit.

## cron-systemd

1. Create suffix linux-pair. Inspect both the user unit and `crontab -l`.
2. Create again: exactly one matching maintenance entry and the original deadline.
3. Optional DNS: explicitly configure the dedicated INTERNAL resolver for .test;
   it must serve evilcorp.test authoritatively without forwarding.
4. Cleanup twice. Confirm unit, matching cron entry and files are gone while
   unrelated cron lines remain. Repeat a clean create/cleanup cycle.

## process

1. Select process, suffix linux-process, CPU low and lifetime 300 seconds.
   Allowed lifetimes are 300/900/1800/3600 seconds (5/15/30/60 minutes).
2. In Ubuntu use `top -u ubuntu`, htop and
   `ps -p PID -o pid,ppid,user,comm,%cpu,etime,lstart,args`.
   The command name is mrn-p11-worker; args contain the artifact worker path.
3. Inspect in Standalone. Correlate PID, UID/owner, command, kernel start ticks,
   UTC start, deadline, CPU seconds and running state with /proc and ps.
4. Repeat create: same PID and deadline. Changed CPU/settings require cleanup first.
5. Test idle, low (~2%) and medium (~10% of one core) separately.
   These are duty-cycle budgets, not a scheduler-enforced hard CPU quota.
6. Let a 5-minute process expire. Inspect must report running=false.
   Create must refuse renewing expired activity until cleanup.
7. Cleanup twice. Confirm PID has stopped and the artifact directory is gone.
   Cleanup refuses a changed PID/start-time/owner/command or foreign artifact.
   No cron or service should be created: this is execution, not reboot persistence.

## process-dns

1. Configure a dedicated internal RFC1918 resolver serving evilcorp.test locally
   without recursion/forwarding. The client sets RD=0; resolver-side configuration
   must independently prevent forwarding. There is no public/system resolver fallback.
2. Select process-dns, suffix linux-dns, low CPU, 300-second lifetime and interval 10.
   The domain is fixed to evilcorp.test and the query is always A IN.
3. Observe target/resolver traffic with, for example:
   `sudo tcpdump -ni any 'udp port 53 and host INTERNAL_RESOLVER_IP'`.
   Inspect after 20–30 seconds. Attempts and matching response counters should grow.
4. NOERROR/NXDOMAIN matching replies show DNS exchange, not sensor detection,
   successful A-record resolution, C2 or exfiltration. Compare actual packet,
   resolver and available SIEM evidence separately.
5. Stop via cleanup and verify traffic ceases. Repeat with resolver unavailable:
   attempt counters grow, responses stay zero, and no fallback destination is used.
6. Repeat inspect, rerun, expiry and cleanup checks from process.

Do not proceed to Full Campaign until all applicable Standalone checks pass.
GitHub CI uses isolated temporary processes and mocked DNS/service providers only;
it cannot establish the state of the user's Ubuntu user manager or lab DNS server.
