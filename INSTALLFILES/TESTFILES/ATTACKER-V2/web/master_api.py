"""Master-only authenticated endpoints; HTTPS by default, explicit lab HTTP."""
import json
import sqlite3

from flask import jsonify, request
from master_registry import DATABASE, Registry, Unauthorized, Conflict, Unavailable, TOKEN

MAX_BODY = 4096


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key]=value
    return result


def install_master_api(app,deployment,registry_path=DATABASE):
    def handle(register):
        config=deployment()
        if config.role!="master" or config.config_status!="loaded":
            return jsonify({"message":"Not found."}),404
        secure=request.is_secure or (request.remote_addr in {"127.0.0.1","::1"}
                                      and request.headers.get("X-Forwarded-Proto")=="https")
        if not secure and getattr(config,"lab_http",False) is not True:
            return jsonify({"message":"HTTPS required; lab HTTP is not enabled."}),403
        authorization=request.headers.get("Authorization","")
        if not authorization.startswith("Bearer ") or len(authorization)!=50:
            return jsonify({"message":"Unauthorized."}),401
        token=authorization[7:]
        if not TOKEN.fullmatch(token):
            return jsonify({"message":"Unauthorized."}),401
        if not request.is_json:
            return jsonify({"message":"JSON required."}),415
        if request.content_length is not None and request.content_length>MAX_BODY:
            return jsonify({"message":"Request too large."}),413
        body=request.stream.read(MAX_BODY+1)
        if len(body)>MAX_BODY:
            return jsonify({"message":"Request too large."}),413
        try:
            data=json.loads(body.decode("utf-8"),object_pairs_hook=_object)
            fields={"agent_id","protocol_version","name"} if register else {"agent_id","protocol_version"}
            if not isinstance(data,dict) or set(data)!=fields or type(data["protocol_version"]) is not int or data["protocol_version"]!=1:
                raise ValueError("Invalid protocol payload.")
            store=Registry(registry_path)
            result=(store.register(data["agent_id"],token,data["name"]) if register
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

    @app.route("/api/master/agents/heartbeat",methods=["POST"])
    def master_heartbeat():
        return handle(False)
