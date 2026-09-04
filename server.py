#!/usr/bin/env python3
"""addon.checkyourself local-service entry (http-json on 127.0.0.1:4892).

ResonantOS add-on contract: protocol http-json, healthCommand checkyourself.status.
Wraps the FROZEN vendored checkyourself module in-process (no subprocess, no
shell, no secrets on argv) and exposes the same read-only verbs the upstream
MCP server exposes: scan (the deterministic production-readiness check),
score, backlog, validate, and schema. The upstream CLI/MCP surface never
modifies the scanned project; this wrapper adds no verbs that could.

Scans are confined by the same boundary as upstream MCP mode: paths must sit
under CHECKYOURSELF_SCAN_ROOT (default: the service process working directory).
All outbound payloads and everything persisted under var/ pass through
home-path redaction (scan results embed the project root as an absolute path).

Exit codes: 0 normal stop; 78 port bind failure.
"""

import json
import os
import re
import socket
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "tools"))
import checkyourself  # noqa: E402  (vendored, byte-identical, hash-pinned by tests)

PORT = int(os.environ.get("CHECKYOURSELF_PORT", "4892"))  # dev override; manifest port 4892 is the contract
MAX_BODY = 64 * 1024
MAX_STR = 2048
MAX_FILES_LIMIT = 6000  # upstream DEFAULT_MAX_FILES; do not allow scans beyond upstream's own default
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

ADDON_ROOT = os.path.dirname(os.path.abspath(__file__))
OUT_BASE = os.path.join(ADDON_ROOT, "var")

STRING_PARAMS = ("project", "kind", "name")  # string params: control chars rejected, length bounded

_state = {
    "busy": False,
    "last_scan_id": None,
}
_lock = threading.Lock()


def _check_string(name, value, enum=None):
    if not isinstance(value, str) or not (0 < len(value) <= MAX_STR):
        return f"{name} must be a non-empty string of at most {MAX_STR} characters"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return f"{name} contains control characters"
    if enum is not None and value not in enum:
        return f"unknown {name}: {value}"
    return None


def _validate_params(method, params):
    """Service-boundary validation. Returns upstream-argument dict or an error string.

    Anything not rejected here is handed to the vendored module, whose own
    CliError contract (same as its MCP server) becomes a 400.
    """
    if not isinstance(params, dict):
        return None, "params must be an object"
    per_method = {
        "checkyourself.scan": {"project", "deep", "max_files"},
        "checkyourself.score": {"findings", "coverage"},
        "checkyourself.backlog": {"findings"},
        "checkyourself.schema": {"name"},
        "checkyourself.validate": {"kind", "artifact"},
    }
    allowed = per_method.get(method)
    if allowed is None:
        return None, f"unknown method: {method}"
    for key in params:
        if key not in allowed:
            return None, f"unknown field: {key}"

    if method == "checkyourself.scan":
        project = params.get("project")
        if project is None:
            return None, "project is required (path under CHECKYOURSELF_SCAN_ROOT)"
        err = _check_string("project", project)
        if err:
            return None, err
        deep = params.get("deep")
        if deep is not None and not isinstance(deep, bool):
            return None, "deep must be a boolean"
        max_files = params.get("max_files")
        if max_files is not None and (
            not isinstance(max_files, int) or isinstance(max_files, bool) or not (1 <= max_files <= MAX_FILES_LIMIT)
        ):
            return None, f"max_files must be an integer in 1..{MAX_FILES_LIMIT}"
        args = {"project": project, "deep": bool(deep)}
        if max_files is not None:
            args["max_files"] = max_files
        return args, None

    if method == "checkyourself.score":
        findings = params.get("findings")
        if not isinstance(findings, (dict, list)):
            return None, "findings must be a scan result object or a list of finding objects"
        coverage = params.get("coverage")
        if coverage is not None and not isinstance(coverage, dict):
            return None, "coverage must be an object"
        return {"findings": findings, "coverage": coverage}, None

    if method == "checkyourself.backlog":
        findings = params.get("findings")
        if not isinstance(findings, (dict, list)):
            return None, "findings must be a scan result object or a list of finding objects"
        return {"findings": findings}, None

    if method == "checkyourself.validate":
        kind = params.get("kind")
        err = _check_string("kind", kind, enum=sorted(checkyourself.schema_registry()))
        if err:
            return None, err
        artifact = params.get("artifact")
        if not isinstance(artifact, dict):
            return None, "artifact must be an object"
        return {"kind": kind, "artifact": artifact}, None

    if method == "checkyourself.schema":
        name = params.get("name")
        err = _check_string("name", name, enum=sorted(checkyourself.schema_registry()))
        if err:
            return None, err
        return {"name": name}, None

    return None, f"unknown method: {method}"


def _redact_text(text):
    home = os.path.expanduser("~")
    return text.replace(home, "~") if home and home != "~" else text


def _redact_obj(obj):
    if isinstance(obj, str):
        return _redact_text(obj)
    if isinstance(obj, list):
        return [_redact_obj(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _redact_obj(value) for key, value in obj.items()}
    return obj


def _persist_scan(result):
    """Write the redacted scan result under var/ and return its addon-relative path."""
    scan_id = "scan-" + uuid.uuid4().hex[:8]
    out_dir = os.path.join(OUT_BASE, scan_id)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "scan.json")
    with open(path, "w") as f:
        json.dump(_redact_obj(result), f, indent=1)
    return scan_id, os.path.relpath(path, ADDON_ROOT)


def _run_scan(args):
    """Execute one scan. Returns (payload, status_code). Caller holds no lock."""
    with _lock:
        if _state["busy"]:
            return {"error": "a scan is already in progress", "last_scan_id": _state["last_scan_id"]}, 409
        _state["busy"] = True
    try:
        result = checkyourself.call_mcp_tool("scan", args)  # CliError = caller's problem (400), never a crash
        scan_id, record_path = _persist_scan(result)
        payload = dict(result)
        payload["scan_id"] = scan_id
        payload["record_path"] = record_path
        with _lock:
            _state["last_scan_id"] = scan_id
        return _redact_obj(payload), 200
    except checkyourself.CliError as exc:
        return _redact_obj({"error": str(exc)}), 400
    except Exception as exc:  # honest failure, never a server crash
        return _redact_obj({"error": "scan failed: " + str(exc)[:300]}), 500
    finally:
        with _lock:
            _state["busy"] = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30  # a lying Content-Length must not pin a thread forever

    def _reply(self, code, payload, close=False):
        if close:
            self.close_connection = True  # never leave undrained bodies on a keep-alive connection
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if close:
            self.send_header("Connection", "close")  # advertise what the socket is about to do
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._reply(200, self._status())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/":
            self._reply(404, {"error": "not found"}, close=True)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "bad content-length"}, close=True)
            return
        if length <= 0 or length > MAX_BODY:
            self._reply(413 if length > MAX_BODY else 400, {"error": "body must be 1..65536 bytes"}, close=True)
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except (TimeoutError, socket.timeout, OSError):
            self._reply(408, {"error": "request body incomplete (timeout)"}, close=True)
            return
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": "body must be valid JSON"}, close=True)
            return
        if not isinstance(req, dict):
            self._reply(400, {"error": "body must be a JSON object"}, close=True)
            return
        method = req.get("method")
        params = req.get("params", {})
        for key in req:
            if key not in ("method", "params"):
                self._reply(400, {"error": f"unknown field: {key}"}, close=True)
                return
        if method == "checkyourself.status":
            self._reply(200, self._status())
        elif method in ("checkyourself.scan", "checkyourself.score", "checkyourself.backlog",
                        "checkyourself.validate", "checkyourself.schema"):
            self._dispatch(method, params)
        else:
            self._reply(404, {"error": f"unknown method: {method}"})

    def _dispatch(self, method, params):
        args, err = _validate_params(method, params)
        if err:
            self._reply(400, {"error": err})
            return
        if method == "checkyourself.scan":
            payload, code = _run_scan(args)
            self._reply(code, payload)
            return
        try:
            result = checkyourself.call_mcp_tool(method.removeprefix("checkyourself."), args)
        except checkyourself.CliError as exc:
            self._reply(400, _redact_obj({"error": str(exc)}))
            return
        except Exception as exc:  # honest failure, never a server crash
            self._reply(500, _redact_obj({"error": "tool failed: " + str(exc)[:300]}))
            return
        self._reply(200, _redact_obj(result))

    def _status(self):
        with _lock:
            return _redact_obj({
                "ok": True,
                "tool": checkyourself.TOOL_NAME,
                "version": checkyourself.read_manifest_version(),
                "busy": _state["busy"],
                "last_scan_id": _state["last_scan_id"],
                "scan_root": str(checkyourself.mcp_scan_root()),
            })

    def log_message(self, fmt, *args):  # keep service logs quiet and content-free
        sys.stderr.write("checkyourself-service: " + (fmt % args) + "\n")


def main():
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        sys.stderr.write(f"checkyourself-service: cannot bind 127.0.0.1:{PORT} ({exc}); manifest entrypoint expects this port\n")
        return 78
    sys.stderr.write(f"checkyourself-service: listening on http://127.0.0.1:{PORT}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
