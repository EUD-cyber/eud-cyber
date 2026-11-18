"""Opt-in outbound identity/heartbeat client: HTTPS or explicit lab HTTP."""
import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import random
import secrets
import signal
import ssl
import stat
import tempfile
import threading
import urllib.error
import urllib.request
import uuid

from deployment_config import load_deployment_config, MASTER_URL, LAB_MASTER_URL
from master_registry import AGENT_ID, NAME, TOKEN, HEARTBEAT_INTERVAL, MAX_REPORTS, REPORT_ID, validate_reports, validate_snapshot, MAX_REPORT_BYTES


CREDENTIALS=Path("/etc/mrnobody/agent.json")
MAX_RESPONSE=4096


class FatalAgentError(Exception):
    pass


class RetryableAgentError(Exception):
    pass


class RegistrationRequired(Exception):
    pass


@dataclass(frozen=True)
class AgentConfig:
    master_url: str
    agent_id: str
    name: str
    token: str=field(repr=False)
    ca_file: str | None=None
    lab_http: bool=False
    lab_mode: bool=False
    lab_networks: tuple=()
    role: str='agent'
    config_status: str='loaded'


def _credential_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise FatalAgentError("Duplicate credential fields are not allowed.")
        result[key]=value
    return result


def load_agent_config(path=CREDENTIALS, deployment=None):
    deployment=load_deployment_config() if deployment is None else deployment
    if deployment.role!="agent" or deployment.config_status!="loaded" or not deployment.master_url:
        raise FatalAgentError("A valid agent deployment and Master URL are required.")
    path=Path(path)
    if path.is_symlink():
        raise FatalAgentError("Credential file must not be a symlink.")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>8192 or (os.name=="posix" and (info.st_mode&0o077 or info.st_uid!=os.geteuid())):
        raise FatalAgentError("Credential file must be private and owned by the service user.")
    with path.open("rb") as handle:
        raw=handle.read(8193)
    if len(raw)>8192:
        raise FatalAgentError("Credential file is too large.")
    data=json.loads(raw.decode("utf-8"),object_pairs_hook=_credential_object)
    allowed={"agent_id","token","name","ca_file","protocol_version","heartbeat_interval"}
    if not isinstance(data,dict) or not {"agent_id","token"}<=data.keys() or data.keys()-allowed:
        raise FatalAgentError("Invalid credential fields.")
    agent_id,token=data["agent_id"],data["token"]
    name=data.get("name",agent_id[:63] if isinstance(agent_id,str) else "")
    if (not isinstance(agent_id,str) or not AGENT_ID.fullmatch(agent_id)
            or not isinstance(token,str) or not TOKEN.fullmatch(token)
            or not isinstance(name,str) or not NAME.fullmatch(name)):
        raise FatalAgentError("Invalid agent identity or credential.")
    for key,expected in (("protocol_version",1),("heartbeat_interval",HEARTBEAT_INTERVAL)):
        if key in data and (type(data[key]) is not int or data[key]!=expected):
            raise FatalAgentError("Unsupported protocol settings.")
    ca_file=data.get("ca_file")
    if ca_file is not None and (not isinstance(ca_file,str) or not Path(ca_file).is_absolute() or not Path(ca_file).is_file()):
        raise FatalAgentError("CA file must be an existing absolute path.")
    return AgentConfig(deployment.master_url,agent_id,name,token,ca_file,deployment.lab_http,
                       getattr(deployment,'lab_mode',False),getattr(deployment,'lab_networks',()))


def pair_agent(source, *, destination=CREDENTIALS, ca_file=None, deployment=None, transport=None):
    """Import a Master-issued private file after authenticated registration succeeds.

    Never replace an existing identity. The caller explicitly enables the unit.
    """
    deployment=load_deployment_config() if deployment is None else deployment
    if not (deployment.master_url.startswith("https://") or
            (deployment.master_url.startswith("http://") and deployment.lab_http is True)):
        raise FatalAgentError("Pairing requires configured lab HTTP or verified HTTPS.")
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FatalAgentError("Agent identity already exists; it was not overwritten.")
    config=load_agent_config(source,deployment)
    if ca_file is not None:
        from dataclasses import replace
        config=replace(config,ca_file=str(Path(ca_file).resolve(strict=True)))
    sender=(AgentTransport if transport is None else transport)(config)
    sender.post("register")
    sender.post("heartbeat")
    if destination.parent.is_symlink():
        raise FatalAgentError("Credential directory must not be a symlink.")
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    data=dict(agent_id=config.agent_id,token=config.token,name=config.name,
              protocol_version=1,heartbeat_interval=HEARTBEAT_INTERVAL)
    if config.ca_file:
        data["ca_file"]=config.ca_file
    _publish_credentials(destination,data)


def _publish_credentials(destination,data):
    # Publish a complete mode-0600 file atomically, without overwriting a racer.
    fd,temporary=tempfile.mkstemp(prefix=".agent-",dir=destination.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(data,handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary,destination)
    finally:
        Path(temporary).unlink()


def bootstrap_agent(path=CREDENTIALS, deployment=None):
    """Create one durable per-VM lab identity, without contacting the Master."""
    deployment=load_deployment_config() if deployment is None else deployment
    if deployment.role!="agent" or deployment.config_status!="loaded" or not deployment.master_url:
        raise FatalAgentError("A valid agent deployment and Master URL are required.")
    path=Path(path)
    if path.exists() or path.is_symlink():
        return load_agent_config(path,deployment)
    if deployment.lab_http is not True:
        raise FatalAgentError("Automatic enrollment requires explicit lab mode.")
    if path.parent.is_symlink():
        raise FatalAgentError("Credential directory must not be a symlink.")
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    agent_id="agent-"+uuid.uuid4().hex
    data=dict(agent_id=agent_id,name=agent_id,token=secrets.token_urlsafe(32),
              protocol_version=1,heartbeat_interval=HEARTBEAT_INTERVAL)
    try:
        _publish_credentials(path,data)
    except FileExistsError:
        pass  # A concurrent bootstrap published the winning identity.
    return load_agent_config(path,deployment)


def collect_report_metadata(directory=Path("/opt/nordic-attack/reports")):
    """Inventory at most 50 recent named snapshots; skip invalid/oversize files."""
    import itertools
    import stat
    if directory.is_symlink():
        raise ValueError("Report directory must not be a symlink.")
    result=[]
    remaining=8*1024*1024
    paths=sorted(itertools.islice(directory.glob("*.json"),1000),reverse=True)
    for path in paths:
        if len(result)>=MAX_REPORTS:
            break
        if not REPORT_ID.fullmatch(path.stem):
            continue
        try:
            if path.is_symlink():
                continue
            descriptor=os.open(path,os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_NONBLOCK",0))
            with os.fdopen(descriptor,"rb") as handle:
                info=os.fstat(handle.fileno())
                if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size>2*1024*1024:
                    continue
                if info.st_size>remaining:
                    break
                raw=handle.read(2*1024*1024+1)
                remaining-=len(raw)
            if len(raw)>2*1024*1024:
                continue
            data=json.loads(raw)
            incident=data["incident"]
            if data.get("schema_version")!=1 or incident.get("id")!=path.stem:
                continue
            item={key:incident.get(key) for key in ("id","status","started","completed")}
            item["completed"]=incident.get("ended")
            item.update(report_type=data.get("report_type","campaign"),phase_id=data.get("phase_id"))
            validate_reports([item])
            result.append(item)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):
            continue
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise FatalAgentError("Master redirects are refused.")


def read_report_snapshot(report_id,directory=Path("/opt/nordic-attack/reports")):
    if not isinstance(report_id,str) or not REPORT_ID.fullmatch(report_id) or directory.is_symlink():
        raise ValueError("Invalid report location.")
    path=directory/(report_id+".json")
    if path.is_symlink():
        raise ValueError("Report must not be a symlink.")
    descriptor=os.open(path,os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_NONBLOCK",0))
    with os.fdopen(descriptor,"rb") as handle:
        info=os.fstat(handle.fileno())
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size>MAX_REPORT_BYTES:
            raise ValueError("Invalid report file.")
        raw=handle.read(MAX_REPORT_BYTES+1)
    if len(raw)>MAX_REPORT_BYTES:
        raise ValueError("Report too large.")
    data=json.loads(raw)
    validate_snapshot(report_id,data)
    from report_exports import safe_report
    return safe_report(data)


class AgentTransport:
    def __init__(self,config,opener=None):
        pattern=LAB_MASTER_URL if config.lab_http is True else MASTER_URL
        match=pattern.fullmatch(config.master_url) if isinstance(config.master_url,str) else None
        if not match or not 1<=int(match.group(3) or "443")<=65535:
            raise FatalAgentError("Use HTTPS, or explicitly enable lab HTTP on the agent.")
        self.config=config
        from lab_mode import http_master_allowed
        if config.lab_mode and config.master_url.startswith('http://') and not http_master_allowed(config):
            raise FatalAgentError('Lab HTTP requires explicit Lab Mode and a configured Master URL.')
        try:
            self.context=ssl.create_default_context(cafile=config.ca_file)
        except (OSError,ssl.SSLError) as exc:
            raise FatalAgentError("TLS trust configuration is invalid.") from exc
        # No environment proxies, redirects or automatic protocol fallback.
        # HTTPS certificate verification stays required even with lab_http=True.
        self.opener=opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=self.context),NoRedirect())

    def sync_reports(self):
        inventory=collect_report_metadata()
        self.post("reports",inventory)
        result=self.post("report-transfer")
        if result["report_id"] is not None:
            ident=result["report_id"]
            if not any(item["id"]==ident and item["status"]!="running" for item in inventory):
                raise FatalAgentError("Master requested a report outside the finalized inventory.")
            self.post("report-transfer",snapshot=(ident,read_report_snapshot(ident)))

    def post(self,kind, reports=None, *, snapshot=None, p06=None, p11=None, job_report=None):
        if kind not in {"register","heartbeat","reports","report-transfer","p06-file","p11-beacon","job-poll"}:
            raise FatalAgentError("Unsupported agent operation.")
        data=dict(agent_id=self.config.agent_id,protocol_version=1)
        if kind=="job-poll":
            from lab_mode import http_master_allowed
            if not (self.config.master_url.startswith('https://') or http_master_allowed(self.config)):
                raise FatalAgentError('Job polling requires verified HTTPS.')
            data['report']=job_report
        if kind=="register":
            data["name"]=self.config.name
        if kind=="reports":
            data["reports"]=validate_reports(reports)
        if kind=="report-transfer":
            ident,content=snapshot if snapshot is not None else (None,None)
            if ident is not None:
                validate_snapshot(ident,content)
            data.update(report_id=ident,content=content)
        if kind=="p06-file":
            from p06_live_lab import validate_payload
            data.update(p06 or {})
            validate_payload(data)
        if kind=="p11-beacon":
            from p11_live_lab import validate_payload
            data.update(p11 or {})
            validate_payload(data)
        url=self.config.master_url.rstrip("/")+"/api/master/agents/"+kind
        request=urllib.request.Request(url,data=json.dumps(data).encode("utf-8"),method="POST",
                                      headers={"Content-Type":"application/json","Authorization":"Bearer "+self.config.token})
        try:
            with self.opener.open(request,timeout=10) as response:
                if response.status!=200:
                    raise FatalAgentError("Unexpected Master response status.")
                body=response.read(MAX_RESPONSE+1)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code==409 and kind=="heartbeat":
                raise RegistrationRequired() from None
            if exc.code in {408,425,429} or 500<=exc.code<=599:
                raise RetryableAgentError("Master temporarily unavailable.") from None
            raise FatalAgentError(f"Master refused the request (HTTP {exc.code}).") from None
        except ssl.SSLCertVerificationError:
            raise FatalAgentError("Master certificate verification failed.") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason,ssl.SSLCertVerificationError):
                raise FatalAgentError("Master certificate verification failed.") from None
            raise RetryableAgentError("Master connection unavailable.") from None
        except (TimeoutError,ConnectionError,OSError):
            raise RetryableAgentError("Master connection unavailable.") from None
        if len(body)>MAX_RESPONSE:
            raise FatalAgentError("Master response is too large.")
        try:
            result=json.loads(body.decode("utf-8"))
        except (ValueError,UnicodeError,RecursionError):
            raise FatalAgentError("Invalid Master response.") from None
        if kind=="job-poll":
            from master_jobs import validate_job
            try:
                if (not isinstance(result,dict) or set(result)!={'agent_id','protocol_version','job'}
                        or result['agent_id']!=self.config.agent_id
                        or type(result['protocol_version']) is not int or result['protocol_version']!=1):
                    raise ValueError('Invalid job response.')
                if result['job'] is not None:
                    validate_job(result['job'],self.config.agent_id)
                if job_report is not None and (result['job'] is None or result['job']['job_id']!=job_report['job_id']):
                    raise ValueError('Job report acknowledgement mismatch.')
            except (ValueError,TypeError,KeyError):
                raise FatalAgentError('Master job response mismatch.') from None
            return result
        if kind=="p11-beacon":
            expected={'protocol_version','accepted','event_id','status','received_at',
                      'agent_id','campaign_id','phase','sequence','verified','ack'}
            if (not isinstance(result,dict) or set(result)!=expected
                    or result['accepted'] is not True or result['verified'] is not True
                    or result['ack']!='MRN-EXERCISE-ACK' or result['status']!='received'
                    or type(result['protocol_version']) is not int or result['protocol_version']!=1
                    or type(result['event_id']) is not int or result['event_id']<=0
                    or type(result['received_at']) is not int or result['received_at']<0
                    or type(result['sequence']) is not int
                    or any(result[key]!=data[key] for key in ('agent_id','campaign_id','phase','sequence'))):
                raise FatalAgentError('P11 Master receipt mismatch.')
            return result
        if kind=="p06-file":
            expected={'protocol_version','accepted','event_id','status','received_at',
                      'agent_id','campaign_id','phase','size','sha256','verified'}
            if (not isinstance(result,dict) or set(result)!=expected
                    or result['accepted'] is not True or result['verified'] is not True
                    or type(result['protocol_version']) is not int or result['protocol_version']!=1
                    or type(result['event_id']) is not int or result['event_id']<=0
                    or type(result['received_at']) is not int or result['received_at']<0
                    or result['status']!='received'
                    or any(result[key]!=data[key] for key in ('agent_id','campaign_id','phase','size','sha256'))):
                raise FatalAgentError('P06 Master receipt mismatch.')
            return result
        expected={"agent_id","protocol_version","server_time"}
        expected |= {"registered","heartbeat_interval"} if kind=="register" else {"accepted"}
        if kind=="report-transfer":
            expected.add("report_id")
        if (not isinstance(result,dict) or set(result)!=expected or result["agent_id"]!=self.config.agent_id
                or type(result["protocol_version"]) is not int or result["protocol_version"]!=1
                or type(result["server_time"]) is not int or result["server_time"]<0):
            raise FatalAgentError("Master protocol response mismatch.")
        if kind=="register":
            if (result["registered"] is not True or type(result["heartbeat_interval"]) is not int
                    or result["heartbeat_interval"]!=HEARTBEAT_INTERVAL):
                raise FatalAgentError("Master registration was not accepted.")
        elif result["accepted"] is not True:
            raise FatalAgentError("Master heartbeat was not accepted.")
        if kind=="report-transfer" and result["report_id"] is not None:
            if not isinstance(result["report_id"],str) or not REPORT_ID.fullmatch(result["report_id"]):
                raise FatalAgentError("Invalid report request.")
        return result


def run_loop(config, *, sender=None, stop=None, jitter=None, write=print):
    sender=AgentTransport(config) if sender is None else sender
    stop=threading.Event() if stop is None else stop
    jitter=random.uniform if jitter is None else jitter
    registered=False
    failures=0
    last_state=None
    while not stop.is_set():
        try:
            sender.post("heartbeat" if registered else "register")
            state="online" if registered else "registered"
            registered=True
            failures=0
            if state!=last_state:
                write("Master "+state+".")
                last_state=state
            # Metadata is optional: old Masters or broken snapshots must not stop heartbeat.
            if hasattr(sender,"sync_reports"):
                try:
                    sender.sync_reports()
                except (FatalAgentError,RetryableAgentError,RegistrationRequired,OSError,ValueError,RecursionError) as exc:
                    # Transport exceptions contain fixed messages/status codes, never tokens
                    # or response bodies. Other failures expose only their category.
                    detail=str(exc) if isinstance(exc,(FatalAgentError,RetryableAgentError)) else type(exc).__name__
                    write("Report sync unavailable: "+detail+" Heartbeat remains active.")
            if stop.wait(HEARTBEAT_INTERVAL):
                break
        except RegistrationRequired:
            registered=False
            failures=0
            last_state="registration-required"
            write("Master requires registration again.")
            if stop.wait(5):
                break
        except RetryableAgentError:
            registered=False
            failures=min(failures+1,6)
            last_state="unavailable"
            delay=min(60.0,max(1.0,min(60,5*2**(failures-1))*jitter(0.8,1.2)))
            write(f"Master unavailable; retry in {delay:.1f}s.")
            if stop.wait(delay):
                break


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials",type=Path,default=CREDENTIALS)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument("--check",action="store_true",help="Validate configuration/trust without network")
    mode.add_argument("--bootstrap",action="store_true",help="Create/reuse persistent lab identity without network")
    mode.add_argument("--once",action="store_true",help="Register and send one heartbeat")
    mode.add_argument("--pair",type=Path,metavar="PRIVATE_JSON",help="Import Master-issued credentials after authenticated registration")
    parser.add_argument("--ca-file",type=Path,help="Trusted CA/public certificate for --pair; never the Master private key")
    args=parser.parse_args()
    if args.ca_file and not args.pair:
        parser.error("--ca-file requires --pair")
    try:
        if args.pair:
            if not hasattr(os,"geteuid") or os.geteuid()!=0:
                raise FatalAgentError("Run pairing as root on the agent VM.")
            pair_agent(args.pair,destination=args.credentials,ca_file=args.ca_file)
            print("Pairing and heartbeat accepted; private agent identity installed.")
            print("Activate explicitly: systemctl enable --now mrnobody-agent.service")
            return 0
        if args.bootstrap:
            bootstrap_agent(args.credentials)
            print("Persistent agent identity ready.")
            return 0
        config=load_agent_config(args.credentials)
        sender=AgentTransport(config)
        if args.check:
            print(json.dumps(dict(agent_id=config.agent_id,name=config.name,master_url=config.master_url,tls_verify=config.master_url.startswith("https://"),lab_http=config.lab_http)))
            return 0
        print("Agent transport: "+("HTTPS (certificate verification required)." if config.master_url.startswith("https://") else "HTTP lab mode (plaintext)."))
        if args.once:
            sender.post("register")
            sender.post("heartbeat")
            print("Registration and heartbeat accepted.")
            return 0
        stop=threading.Event()
        signal.signal(signal.SIGTERM,lambda signum,frame:stop.set())
        signal.signal(signal.SIGINT,lambda signum,frame:stop.set())
        run_loop(config,sender=sender,stop=stop)
    except FatalAgentError as exc:
        print(str(exc))
        return 2
    except RetryableAgentError:
        print("Master temporarily unavailable.")
        return 1
    except RegistrationRequired:
        print("Master requires registration again.")
        return 1
    except FileNotFoundError:
        print("Agent identity or trust file is missing. Pair using --pair PRIVATE_JSON.")
        print("Guide: https://github.com/EUD-cyber/eud-cyber/blob/main/INSTALLFILES/docs/mrnobody-agent-client.md")
        return 2
    except (OSError,ValueError,RecursionError):
        print("Agent configuration could not be loaded.")
        return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
