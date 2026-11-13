"""Opt-in outbound identity/heartbeat client: HTTPS or explicit lab HTTP."""
import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import random
import signal
import ssl
import stat
import threading
import urllib.error
import urllib.request

from deployment_config import load_deployment_config, MASTER_URL, LAB_MASTER_URL
from master_registry import AGENT_ID, NAME, TOKEN, HEARTBEAT_INTERVAL


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
    data=json.loads(raw.decode("utf-8"))
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
    return AgentConfig(deployment.master_url,agent_id,name,token,ca_file,deployment.lab_http)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise FatalAgentError("Master redirects are refused.")


class AgentTransport:
    def __init__(self,config,opener=None):
        pattern=LAB_MASTER_URL if config.lab_http is True else MASTER_URL
        match=pattern.fullmatch(config.master_url) if isinstance(config.master_url,str) else None
        if not match or not 1<=int(match.group(3) or "443")<=65535:
            raise FatalAgentError("Use HTTPS, or explicitly enable lab HTTP on the agent.")
        self.config=config
        try:
            self.context=ssl.create_default_context(cafile=config.ca_file)
        except (OSError,ssl.SSLError) as exc:
            raise FatalAgentError("TLS trust configuration is invalid.") from exc
        # No environment proxies, redirects or automatic protocol fallback.
        # HTTPS certificate verification stays required even with lab_http=True.
        self.opener=opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=self.context),NoRedirect())

    def post(self,kind):
        if kind not in {"register","heartbeat"}:
            raise FatalAgentError("Unsupported agent operation.")
        data=dict(agent_id=self.config.agent_id,protocol_version=1)
        if kind=="register":
            data["name"]=self.config.name
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
        expected={"agent_id","protocol_version","server_time"}
        expected |= {"registered","heartbeat_interval"} if kind=="register" else {"accepted"}
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
    mode.add_argument("--once",action="store_true",help="Register and send one heartbeat")
    args=parser.parse_args()
    try:
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
    except (OSError,ValueError,RecursionError):
        print("Agent configuration could not be loaded.")
        return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
