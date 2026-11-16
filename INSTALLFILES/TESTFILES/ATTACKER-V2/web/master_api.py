"""Master-only authenticated endpoints; HTTPS by default, explicit lab HTTP."""
import json
import ipaddress
import re
import sqlite3
from pathlib import Path

from flask import jsonify, request
from master_registry import DATABASE, Registry, Unauthorized, Conflict, Unavailable, TOKEN, MAX_REPORT_BYTES

# Installed implementation capabilities, never inferred from heartbeat/online state.
# This is intentionally separate from the strict agent protocol v1 responses.
CONTROL_CAPABILITIES = {
    "web_job_control": True,
    "remote_phase_start": False,
    "remote_phase_stop": False,
    "remote_scenario_start": False,
    "remote_scenario_stop": False,
    "execution_job_polling": True,
    "fixed_p11_live_lab_job": True,
    "multi_agent_campaigns": False,
}

MAX_BODY = 4096
LAB_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"))


def lab_peer():
    # Only the local nginx may supply X-Real-IP; it overwrites client headers.
    peer=request.remote_addr
    if peer in {"127.0.0.1","::1"}:
        peer=request.headers.get("X-Real-IP",peer)
    try:
        address=ipaddress.ip_address(peer)
        if address.version==6 and address.ipv4_mapped:
            address=address.ipv4_mapped
        return any(address in network for network in LAB_NETWORKS)
    except ValueError:
        return False


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key]=value
    return result


def install_master_api(app,deployment,registry_path=DATABASE):
    def handle(register, reports=False, transfer=False, receiver=False, p06=False, p11=False, jobs=False):
        config=deployment()
        if config.role!="master" or config.config_status!="loaded":
            return jsonify({"message":"Not found."}),404
        secure=request.is_secure or (request.remote_addr in {"127.0.0.1","::1"}
                                      and request.headers.get("X-Forwarded-Proto")=="https")
        if not secure and getattr(config,"lab_http",False) is not True:
            return jsonify({"message":"HTTPS required; lab HTTP is not enabled."}),403
        if jobs and not secure:
            return jsonify({"message":"Job polling requires HTTPS."}),403
        if (transfer or receiver or p06 or p11) and not lab_peer():
            return jsonify({"message":"Lab access required."}),403
        authorization=request.headers.get("Authorization","")
        if not authorization.startswith("Bearer ") or len(authorization)!=50:
            return jsonify({"message":"Unauthorized."}),401
        token=authorization[7:]
        if not TOKEN.fullmatch(token):
            return jsonify({"message":"Unauthorized."}),401
        if not request.is_json:
            return jsonify({"message":"JSON required."}),415
        limit=8192 if p06 else MAX_REPORT_BYTES+4096 if transfer else 32768 if reports else MAX_BODY
        if request.content_length is not None and request.content_length>limit:
            return jsonify({"message":"Request too large."}),413
        body=request.stream.read(limit+1)
        if len(body)>limit:
            return jsonify({"message":"Request too large."}),413
        try:
            data=json.loads(body.decode("utf-8"),object_pairs_hook=_object)
            fields={"agent_id","protocol_version","name"} if register else {"agent_id","protocol_version"}
            if reports:
                fields.add("reports")
            if jobs:
                fields.add("report")
            if transfer:
                fields.update(("report_id","content"))
            if p06:
                fields.update(("campaign_id","phase","synthetic","size","sha256","content"))
            if p11:
                fields.update(('campaign_id','phase','synthetic','timestamp','sequence','marker'))
            if receiver:
                fields.update(("campaign_id","event_type","timestamp","bytes","synthetic"))
            if not isinstance(data,dict) or set(data)!=fields or type(data["protocol_version"]) is not int or data["protocol_version"]!=1:
                raise ValueError("Invalid protocol payload.")
            store=Registry(registry_path)
            if jobs:
                from master_jobs import Jobs
                response=jsonify(Jobs(registry_path).exchange(data['agent_id'],token,data['report']))
                response.headers['Cache-Control']='no-store'
                return response,200
            result=(store.register(data["agent_id"],token,data["name"],
                                   enroll=getattr(config,"lab_http",False) is True and lab_peer()) if register
                    else store.transfer_report(data["agent_id"],token,data["report_id"],data["content"]) if transfer
                    else store.receive_p11(data,token) if p11
                    else store.receive_p06(data,token) if p06
                    else store.receive_event(data,token) if receiver
                    else store.sync_reports(data["agent_id"],token,data["reports"]) if reports
                    else store.heartbeat(data["agent_id"],token))
            return jsonify(result),200
        except Unauthorized:
            return jsonify({"message":"Unauthorized."}),401
        except Conflict:
            return jsonify({"message":"Registration required."}),409
        except (ValueError,UnicodeError,RecursionError):
            return jsonify({"message":"Invalid request."}),400
        except (Unavailable,OSError,sqlite3.Error):
            return jsonify({"message":"Registry unavailable."}),503

    @app.route("/api/master/agents/register",methods=["POST"])
    def master_register():
        return handle(True)

    @app.route("/api/master/agents/job-poll",methods=["POST"])
    def master_job_poll():
        return handle(False,jobs=True)

    @app.route("/api/master/agents/p11-beacon",methods=["POST"])
    def master_receive_p11():
        return handle(False,p11=True)

    @app.route("/api/master/agents/p06-file",methods=["POST"])
    def master_receive_p06():
        return handle(False,p06=True)

    @app.route("/api/master/receiver/events",methods=["POST"])
    def master_receive_event():
        return handle(False,receiver=True)

    @app.route("/api/master/receiver/events",methods=["GET"])
    def master_receiver_events():
        config=deployment()
        if config.role!="master" or config.config_status!="loaded":
            return jsonify({"message":"Not found."}),404
        secure=request.is_secure or (request.remote_addr in {"127.0.0.1","::1"}
                                     and request.headers.get("X-Forwarded-Proto")=="https")
        if not secure or not lab_peer():
            return jsonify({"message":"Lab HTTPS access required."}),403
        try:
            allowed={"limit","before","agent_id","campaign_id"}
            if set(request.args)-allowed or any(len(request.args.getlist(key))!=1 for key in request.args):
                raise ValueError("Invalid query.")
            def number(key,default):
                value=request.args.get(key)
                if value is None:
                    return default
                if not re.fullmatch(r"[1-9][0-9]{0,18}",value):
                    raise ValueError("Invalid number.")
                return int(value)
            result=Registry(registry_path).list_receiver_events(
                limit=number("limit",50),before=number("before",None),
                agent_id=request.args.get("agent_id"),campaign_id=request.args.get("campaign_id"))
            response=jsonify(result)
            response.headers["Cache-Control"]="no-store"
            return response,200
        except ValueError:
            return jsonify({"message":"Invalid receiver query."}),400
        except (Unavailable,OSError,sqlite3.Error):
            return jsonify({"message":"Receiver storage unavailable."}),503

    @app.route("/api/master/agents/heartbeat",methods=["POST"])
    def master_heartbeat():
        return handle(False)

    @app.route("/api/master/agents/reports",methods=["POST"])
    def master_reports():
        return handle(False,reports=True)

    @app.route("/api/master/agents/report-transfer",methods=["POST"])
    def master_report_transfer():
        return handle(False,transfer=True)

    @app.route("/api/master/agents/<agent_id>/reports/<report_id>",methods=["GET"])
    def master_report_content(agent_id,report_id):
        config=deployment()
        if config.role!="master" or config.config_status!="loaded":
            return jsonify({"message":"Not found."}),404
        secure=request.is_secure or (request.remote_addr in {"127.0.0.1","::1"}
                                     and request.headers.get("X-Forwarded-Proto")=="https")
        if not secure or not lab_peer():
            return jsonify({"message":"Lab HTTPS access required."}),403
        try:
            cached=Registry(registry_path).read_report(agent_id,report_id)
            if cached is None:
                return jsonify({"message":"Report not synchronized or unavailable."}),404
            # Reuse the escaped, script-free report export for readable viewing.
            download=request.args.get("download")=="1"
            from report_exports import export_html
            body=cached["content"] if download else export_html(json.loads(cached["content"]))
            response=app.response_class(body,mimetype="application/json" if download else "text/html")
            response.headers["Content-Disposition"]=("attachment" if download else "inline")+'; filename="'+report_id+('.json"' if download else '.html"')
            response.headers["X-Content-Type-Options"]="nosniff"
            response.headers["Content-Security-Policy"]="default-src 'none'; style-src 'unsafe-inline'; sandbox"
            response.headers["Cache-Control"]="no-store"
            response.headers["X-Report-SHA256"]=cached["sha256"]
            return response
        except ValueError:
            return jsonify({"message":"Invalid report ID."}),400
        except (Unavailable,OSError,sqlite3.Error):
            return jsonify({"message":"Report storage unavailable."}),503

    @app.route("/api/master/agents",methods=["GET"])
    def master_agents():
        # Administration follows the existing UI's lab-network access boundary.
        # Lab HTTP opt-in applies only to registration and heartbeat.
        config=deployment()
        if config.role!="master" or config.config_status!="loaded":
            return jsonify({"message":"Not found."}),404
        secure=request.is_secure or (request.remote_addr in {"127.0.0.1","::1"}
                                      and request.headers.get("X-Forwarded-Proto")=="https")
        if not secure:
            return jsonify({"message":"HTTPS required."}),403
        try:
            path=Path(registry_path)
            if not path.exists() and not path.is_symlink():
                return jsonify({"agents":[],"initialized":False,"control_capabilities":dict(CONTROL_CAPABILITIES)}),200
            rows=Registry(registry_path).list_agents()
            fields=("agent_id","name","status","last_seen_at","registered_at","reports","reports_synced_at","available_reports")
            return jsonify({"agents":[{key:row[key] for key in fields} for row in rows],
                            "initialized":True,"control_capabilities":dict(CONTROL_CAPABILITIES)}),200
        except (Unavailable,OSError,sqlite3.Error,ValueError):
            return jsonify({"message":"Registry unavailable."}),503
