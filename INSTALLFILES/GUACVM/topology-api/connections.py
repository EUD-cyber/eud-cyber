"""Lab-only, login-free connection management. PostgreSQL is the source of truth.

Guacamole parameters, permissions and portal metadata commit/roll back together.
The HTTP API deliberately grants portal visitors administrative access (trusted lab).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from flask import Blueprint, current_app, jsonify, request

api = Blueprint("vm_connections", __name__)
KEY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\Z")
PROTOCOLS = {"rdp": 3389, "ssh": 22, "vnc": 5900}
FIELDS = {"name", "description", "category", "icon", "label", "host", "port",
          "protocol", "username", "password", "domain", "visible", "version", "lab"}


class Invalid(ValueError):
    pass


class Conflict(Exception):
    pass


def database():
    return psycopg.connect(host=os.environ.get("PGHOST", "postgres"),
        dbname=os.environ.get("PGDATABASE", "guacamole_db"),
        user=os.environ.get("PGUSER", "guacamole_user"),
        password=Path(os.environ["PGPASSWORD_FILE"]).read_text().strip(),
        connect_timeout=5, row_factory=dict_row)


def lab_id():
    value = int(os.environ.get("GUACVM_LAB_ID", "1"))
    if not 1 <= value <= 16:
        raise RuntimeError("GUACVM_LAB_ID must be 1..16")
    return value


def signing_key():
    path = Path(os.environ.get("CONNECTIONS_KEY_FILE", "/data/connections.key"))
    # Multiple gunicorn workers may start at once. Atomic publication avoids a
    # worker ever reading a partially written key.
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + secrets.token_hex(8))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secrets.token_bytes(32))
    try:
        os.link(tmp, path)
    except FileExistsError:
        pass
    finally:
        tmp.unlink()
    return path.read_bytes()


def initialize(db):
    # Cross-process lock also serializes first-run legacy import and mutations.
    db.execute("SELECT pg_advisory_xact_lock(67300421)")
    db.execute("""CREATE TABLE IF NOT EXISTS cyberlab_connection (
        lab integer NOT NULL CHECK(lab BETWEEN 1 AND 16), key text NOT NULL,
        connection_id integer REFERENCES guacamole_connection(connection_id) ON DELETE SET NULL,
        owned boolean NOT NULL DEFAULT false, metadata jsonb NOT NULL,
        version integer NOT NULL DEFAULT 1, removed boolean NOT NULL DEFAULT false,
        PRIMARY KEY(lab,key), UNIQUE(lab,connection_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS cyberlab_connection_operation (
        lab integer NOT NULL, operation text NOT NULL, fingerprint text NOT NULL,
        result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY(lab,operation))""")
    db.execute("""CREATE TABLE IF NOT EXISTS cyberlab_connection_audit (
        id bigserial PRIMARY KEY, lab integer NOT NULL, key text NOT NULL,
        action text NOT NULL, version integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now())""")
    db.execute("CREATE TABLE IF NOT EXISTS cyberlab_connection_seed (lab integer PRIMARY KEY)")
    lab = lab_id()
    if db.execute("SELECT 1 FROM cyberlab_connection_seed WHERE lab=%s", (lab,)).fetchone():
        return
    legacy = json.loads(Path(__file__).with_name("legacy-sessions.json").read_text())
    for si, session in enumerate(legacy):
        for ci, connection in enumerate(session["connections"]):
            metadata = {k: session.get(k, "") for k in ("name", "description", "category", "icon")}
            metadata.update(label=connection["label"], host=session.get("address", ""),
                            protocol=connection["type"].lower(), visible=True,
                            legacy=connection)
            cid = None
            if metadata["protocol"] in PROTOCOLS:
                encoded = connection["url"].rsplit("/", 1)[-1]
                parts = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode().split("\0")
                if len(parts) != 3 or parts[1:] != ["c", "postgresql"] or not parts[0].isdigit():
                    raise Invalid("Invalid legacy Guacamole URL")
                candidate = int(parts[0])
                exists = db.execute("SELECT 1 FROM guacamole_connection WHERE connection_id=%s",
                                    (candidate,)).fetchone()
                if exists:
                    cid = candidate
            db.execute("""INSERT INTO cyberlab_connection(lab,key,connection_id,metadata)
                VALUES (%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING""",
                (lab, f"legacy-{si}-{ci}", cid, json.dumps(metadata)))
    # Include database-only connections in Settings, hidden in the portal until
    # explicitly enabled. Existing Guacamole ownership/permissions stay intact.
    for row in db.execute("""SELECT c.* FROM guacamole_connection c
            WHERE c.protocol IN ('rdp','ssh','vnc') AND NOT EXISTS
            (SELECT 1 FROM cyberlab_connection p WHERE p.lab=%s AND p.connection_id=c.connection_id)
            ORDER BY c.connection_id""", (lab,)).fetchall():
        params = {p['parameter_name']:p['parameter_value'] for p in db.execute(
            'SELECT parameter_name,parameter_value FROM guacamole_connection_parameter WHERE connection_id=%s',
            (row['connection_id'],)).fetchall()}
        metadata = dict(name=row['connection_name'], label=row['connection_name'],
            host=params.get('hostname',''), protocol=row['protocol'], visible=False,
            description='', category='Guacamole', icon='GUAC')
        db.execute("""INSERT INTO cyberlab_connection(lab,key,connection_id,metadata)
            VALUES (%s,%s,%s,%s::jsonb)""", (lab,'guac-'+str(row['connection_id']),row['connection_id'],json.dumps(metadata)))
    db.execute("INSERT INTO cyberlab_connection_seed VALUES (%s)", (lab,))


def validate(body, existing=None):
    if not isinstance(body, dict) or set(body) - FIELDS:
        raise Invalid("Expected a JSON object with known connection fields")
    if "lab" in body and (type(body["lab"]) is not int or body["lab"] != lab_id()):
        raise Invalid("Connection belongs to another lab instance")
    protocol = body.get("protocol", "")
    old_protocol = existing["metadata"]["protocol"] if existing else None
    if protocol not in PROTOCOLS and protocol != old_protocol:
        raise Invalid("Only RDP, SSH and VNC can be added")
    if existing and protocol != old_protocol:
        raise Invalid("Protocol cannot be changed; add a new connection")
    result = {"protocol": protocol}
    for field, limit, required in [("name",128,True), ("label",128,True), ("host",253,True),
            ("description",512,False), ("category",64,False), ("icon",32,False)]:
        value = body.get(field, "")
        if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
            raise Invalid(f"Invalid {field}")
        value = value.strip()
        if required and not value:
            raise Invalid(f"{field} is required")
        result[field] = value
    host = result["host"]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p)
                                   for p in host.rstrip(".").split(".")):
            raise Invalid("Host must be an IP address or DNS hostname, without URL or port")
    port = body.get("port", PROTOCOLS.get(protocol, 443))
    if type(port) is not int or not 1 <= port <= 65535:
        raise Invalid("Port must be an integer from 1 to 65535")
    if type(body.get("visible", True)) is not bool:
        raise Invalid("visible must be boolean")
    result.update(port=port, visible=body.get("visible", True))
    if protocol not in PROTOCOLS and existing:
        if host != existing['metadata']['host'] or any(f in body for f in ('username','password','domain')):
            raise Invalid('HTTP/HTTPS supports portal labels and visibility only; NAT is unchanged')
    for field in ("username", "password", "domain"):
        if field in body and (not isinstance(body[field], str) or len(body[field]) > 4096 or "\0" in body[field]):
            raise Invalid(f"Invalid {field}")
    if existing and "legacy" in existing["metadata"]:
        result["legacy"] = existing["metadata"]["legacy"]
    return result


def public_row(db, row):
    result = dict(row["metadata"], key=row["key"], lab=row["lab"], version=row["version"],
                  connectionId=row["connection_id"], owned=row["owned"])
    result.pop("legacy", None)
    if row["connection_id"]:
        params = {p["parameter_name"]: p["parameter_value"] for p in db.execute(
            "SELECT parameter_name,parameter_value FROM guacamole_connection_parameter WHERE connection_id=%s",
            (row["connection_id"],)).fetchall()}
        raw_port = params.get('port','')
        port = int(raw_port) if raw_port.isdigit() and 1 <= int(raw_port) <= 65535 else PROTOCOLS.get(result['protocol'],443)
        result.update(host=params.get("hostname", result["host"]),
                      port=port,
                      username=params.get("username", ""), domain=params.get("domain", ""),
                      hasPassword=bool(params.get("password")))
    else:
        result.update(hasPassword=False, missing=result["protocol"] in PROTOCOLS)
    return result


@api.before_request
def guard():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # No login by design. Cross-origin writes are forbidden; scripts can use the
    # same JSON API without Origin. No CORS permission is emitted.
    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        return jsonify(error="Cross-origin changes are forbidden"), 403
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        return jsonify(error="Cross-site changes are forbidden"), 403
    if not request.is_json:
        return jsonify(error="application/json required"), 415
    if request.content_length is None or request.content_length > 16384:
        return jsonify(error="Request body must be at most 16 KiB"), 413


@api.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@api.errorhandler(Invalid)
def invalid(error):
    return jsonify(error=str(error)), 400


@api.errorhandler(Conflict)
def conflict(error):
    return jsonify(error=str(error)), 409


@api.errorhandler(psycopg.Error)
@api.errorhandler(OSError)
def db_error(error):
    # PostgreSQL errors can contain credential parameter values. Never log them.
    current_app.logger.error("VM connection database operation failed (%s)", type(error).__name__)
    return jsonify(error="Database operation failed; transaction rolled back"), 503


@api.get("/api/vm-connections")
def list_connections():
    with database() as db:
        initialize(db)
        rows = db.execute("SELECT * FROM cyberlab_connection WHERE lab=%s AND NOT removed ORDER BY key",
                          (lab_id(),)).fetchall()
        return jsonify(lab=lab_id(), connections=[public_row(db,r) for r in rows])


@api.get("/api/sessions")
def sessions():
    with database() as db:
        initialize(db)
        rows = db.execute("SELECT * FROM cyberlab_connection WHERE lab=%s AND NOT removed ORDER BY key",
                          (lab_id(),)).fetchall()
        groups = {}
        for row in rows:
            m = row["metadata"]
            if not m["visible"]:
                continue
            if m["protocol"] in PROTOCOLS:
                if not row["connection_id"]:
                    continue
                encoded = base64.b64encode(f'{row["connection_id"]}\0c\0postgresql'.encode()).decode().rstrip("=")
                connection = dict(type=m["protocol"].upper(), label=m["label"],
                    url="/guacamole/#/client/" + encoded, newTab=True)
            else:
                connection = dict(m["legacy"], label=m["label"])
            group = groups.setdefault((m["name"], m["host"]), dict(name=m["name"], address=m["host"],
                description=m["description"], category=m["category"], icon=m["icon"], connections=[]))
            group["connections"].append(connection)
        return jsonify(sessions=list(groups.values()), lab=lab_id())


def mutate(key, deleting=False):
    if not KEY.fullmatch(key):
        raise Invalid("Invalid stable connection key")
    operation = request.headers.get("Idempotency-Key", "")
    if not KEY.fullmatch(operation):
        raise Invalid("Idempotency-Key is required (1..80 letters, digits, dash or underscore)")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Invalid("Expected JSON object")
    fingerprint = hmac.new(signing_key(), json.dumps([request.method,key,body],sort_keys=True).encode(), hashlib.sha256).hexdigest()
    with database() as db:
        initialize(db)
        lab = lab_id()
        previous = db.execute("SELECT * FROM cyberlab_connection_operation WHERE lab=%s AND operation=%s",
                              (lab,operation)).fetchone()
        if previous:
            if not hmac.compare_digest(previous["fingerprint"],fingerprint):
                raise Conflict("Idempotency-Key already used with different input")
            return jsonify(previous["result"])
        row = db.execute("SELECT * FROM cyberlab_connection WHERE lab=%s AND key=%s FOR UPDATE", (lab,key)).fetchone()
        if row and (row["removed"] or type(body.get("version")) is not int or body["version"] != row["version"]):
            raise Conflict("Connection changed or removed; refresh before retrying")
        if not row and (deleting or body.get("version") is not None):
            raise Conflict("Connection does not exist")
        if deleting and set(body) != {"version"}:
            raise Invalid("Delete body must contain only version")
        metadata = row["metadata"] if deleting else validate(body,row)
        cid = row["connection_id"] if row else None
        owned = row["owned"] if row else True
        if row and cid and db.execute("SELECT 1 FROM cyberlab_connection WHERE connection_id=%s AND lab<>%s AND NOT removed", (cid,lab)).fetchone():
            raise Conflict("Shared connection belongs to another lab; manage it separately")
        version = row["version"] + 1 if row else 1
        if not deleting and metadata["protocol"] in PROTOCOLS:
            if row and not cid:
                raise Conflict("Legacy connection is missing in Guacamole; add a new connection")
            if not cid:
                cid = db.execute("INSERT INTO guacamole_connection(connection_name,protocol) VALUES (%s,%s) RETURNING connection_id",
                    (metadata["label"],metadata["protocol"])).fetchone()["connection_id"]
                # Match this instance's existing header-auth portal identity.
                principal = os.environ.get("GUACVM_PORTAL_USER", "guacadmin")
                entity = db.execute("SELECT entity_id FROM guacamole_entity WHERE name=%s AND type='USER'", (principal,)).fetchone()
                if not entity:
                    raise Conflict("Portal Guacamole user is missing; no connection was created")
                db.execute("INSERT INTO guacamole_connection_permission(entity_id,connection_id,permission) VALUES (%s,%s,'READ')", (entity["entity_id"],cid))
            else:
                db.execute("UPDATE guacamole_connection SET connection_name=%s WHERE connection_id=%s", (metadata["label"],cid))
            parameters = {"hostname":metadata["host"], "port":str(metadata["port"])}
            parameters.update({field:body[field] for field in ("username","password","domain") if field in body})
            for name,value in parameters.items():
                db.execute("""INSERT INTO guacamole_connection_parameter VALUES (%s,%s,%s)
                    ON CONFLICT(connection_id,parameter_name) DO UPDATE SET parameter_value=EXCLUDED.parameter_value""", (cid,name,value))
        if row:
            db.execute("UPDATE cyberlab_connection SET metadata=%s::jsonb,version=%s,removed=%s WHERE lab=%s AND key=%s",
                       (json.dumps(metadata),version,deleting,lab,key))
        else:
            db.execute("INSERT INTO cyberlab_connection(lab,key,connection_id,owned,metadata) VALUES (%s,%s,%s,%s,%s::jsonb)",
                       (lab,key,cid,owned,json.dumps(metadata)))
        if deleting and owned and cid:
            db.execute("DELETE FROM guacamole_connection WHERE connection_id=%s", (cid,))
        result = dict(key=key, lab=lab, version=version, connectionId=cid, removed=deleting,
                      databaseDeleted=bool(deleting and owned and cid))
        db.execute("INSERT INTO cyberlab_connection_audit(lab,key,action,version) VALUES (%s,%s,%s,%s)",
                   (lab,key,"remove" if deleting else "update" if row else "create",version))
        db.execute("INSERT INTO cyberlab_connection_operation(lab,operation,fingerprint,result) VALUES (%s,%s,%s,%s::jsonb)",
                   (lab,operation,fingerprint,json.dumps(result)))
        return jsonify(result)


@api.put("/api/vm-connections/<key>")
def put_connection(key):
    return mutate(key)


@api.delete("/api/vm-connections/<key>")
def delete_connection(key):
    return mutate(key,True)
