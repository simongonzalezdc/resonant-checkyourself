"""addon.checkyourself wrapper tests — vendored pin, service contract, privacy, abuse.

Run:  python3 -m unittest discover -s tests -v   (from the add-on root)
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
UPSTREAM = os.path.expanduser("~/workspaces/checkyourself")
SERVER = os.path.join(ADDON_ROOT, "server.py")
sys.path.insert(0, ADDON_ROOT)
sys.path.insert(0, os.path.join(ADDON_ROOT, "vendor", "tools"))

import server  # noqa: E402
import checkyourself  # noqa: E402

TEST_PORT = 4893
BASE = f"http://127.0.0.1:{TEST_PORT}"

VENDORED_FILES = [
    "tools/checkyourself.py",
    "checkyourself.manifest.json",
    "tests/test_checkyourself_cli.py",
    ".github/actions/checkyourself/action.yml",
    "LICENSE",
    "NOTICE.md",
] + [os.path.join("schemas", name) for name in sorted(os.listdir(os.path.join(ADDON_ROOT, "vendor", "schemas")))]


def post(payload, raw=None, timeout=60):
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(BASE + "/", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode())


def post_err(payload, raw=None, timeout=60):
    try:
        return post(payload, raw, timeout)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class ScanRoot:
    """A temporary CHECKYOURSELF_SCAN_ROOT with one vulnerable fixture project."""

    def __enter__(self):
        self.root = tempfile.mkdtemp(prefix="cyscan-")
        self.project = os.path.join(self.root, "fixture-app")
        os.makedirs(os.path.join(self.project, "api"))
        with open(os.path.join(self.project, "package.json"), "w") as f:
            json.dump({"name": "fixture-app", "dependencies": {"express": "^4"}}, f)
        with open(os.path.join(self.project, ".env"), "w") as f:
            f.write("API_KEY=sk-" + ("a" * 26) + "\nDEBUG=true\n")
        with open(os.path.join(self.project, "api", "routes.js"), "w") as f:
            f.write("const express = require('express');\nconst app = express();\n"
                    "app.get('/x', (req, res) => res.send(eval(req.query.e)));\n")
        self.resolved_project = os.path.realpath(self.project)
        self._old = os.environ.get("CHECKYOURSELF_SCAN_ROOT")
        os.environ["CHECKYOURSELF_SCAN_ROOT"] = self.root
        return self

    def __exit__(self, *exc):
        if self._old is None:
            os.environ.pop("CHECKYOURSELF_SCAN_ROOT", None)
        else:
            os.environ["CHECKYOURSELF_SCAN_ROOT"] = self._old


class Service:
    def __enter__(self):
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", TEST_PORT), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        server._state.update({"busy": False, "last_scan_id": None})


def wait_scan(run_reply, timeout=120):
    """run_reply: zero-arg post of the scan; returns the finished result payload."""
    code, body = run_reply()
    assert code == 200, body
    deadline = time.time() + timeout
    while "record_path" not in body and body.get("error") is None and time.time() < deadline:
        time.sleep(0.1)
        code, body = run_reply()
    return body


class TestVendorPin(unittest.TestCase):
    def test_vendored_files_hash_identical_to_upstream(self):
        for rel in VENDORED_FILES:
            ours, theirs = os.path.join(ADDON_ROOT, "vendor", rel), os.path.join(UPSTREAM, rel)
            self.assertTrue(os.path.exists(theirs), f"upstream missing: {rel}")
            self.assertEqual(sha256(ours), sha256(theirs), f"vendor drift: {rel}")


class TestInternalApiPin(unittest.TestCase):
    def test_module_exposes_the_verbs_the_service_dispatches(self):
        for fn in ("call_mcp_tool", "resolve_mcp_scan_path", "mcp_scan_root",
                   "read_manifest_version", "schema_registry", "CliError"):
            self.assertTrue(hasattr(checkyourself, fn), f"vendored module missing {fn}")
        self.assertEqual(checkyourself.TOOL_NAME, "checkyourself-cli")

    def test_scan_signature(self):
        import inspect
        params = list(inspect.signature(checkyourself.scan).parameters)
        self.assertEqual(params[:3], ["root", "deep", "max_files"])

    def test_manifest_enums_match_schema_registry(self):
        with open(os.path.join(ADDON_ROOT, "addon.json")) as f:
            manifest = json.load(f)
        registry = sorted(checkyourself.schema_registry())
        for tool in manifest["tools"]:
            enum = None
            props = tool.get("inputSchema", {}).get("properties", {})
            for field in ("kind", "name"):
                if field in props and "enum" in props[field]:
                    enum = props[field]["enum"]
            if enum is not None:
                self.assertEqual(sorted(enum), registry, tool["name"])

    def test_manifest_port_is_the_service_contract(self):
        with open(os.path.join(ADDON_ROOT, "addon.json")) as f:
            manifest = json.load(f)
        self.assertIn("4892", manifest["service"]["entrypoint"])
        self.assertEqual(server.PORT, 4892)


class TestStatus(unittest.TestCase):
    def test_status_roundtrip(self):
        with Service():
            code, body = post({"method": "checkyourself.status"})
            self.assertEqual(code, 200)
            self.assertTrue(body["ok"])
            self.assertEqual(body["tool"], checkyourself.TOOL_NAME)
            self.assertEqual(body["version"], checkyourself.read_manifest_version())
            self.assertNotEqual(body["version"], "unknown")
            self.assertFalse(body["busy"])
            self.assertIsNone(body["last_scan_id"])

    def test_get_health(self):
        with Service():
            with urllib.request.urlopen(BASE + "/health", timeout=10) as resp:
                body = json.loads(resp.read().decode())
            self.assertTrue(body["ok"])


class TestScan(unittest.TestCase):
    def scan_project(self):
        return lambda: post({"method": "checkyourself.scan", "params": {"project": "fixture-app"}})

    def test_scan_finds_the_fixture_risks_and_redacts(self):
        fake_key = "sk-" + ("a" * 26)  # built at runtime; a secret-looking literal must never sit in the tree
        with ScanRoot() as scan_root, Service():
            body = wait_scan(self.scan_project())
            self.assertEqual(body["schema"], "checkyourself-scan/1")
            self.assertGreaterEqual(body["counts"]["P0"], 1)
            self.assertGreater(body["files_scanned"], 0)
            serialized = json.dumps(body)
            self.assertNotIn(os.path.expanduser("~"), serialized)  # nothing home-anchored leaks
            self.assertNotIn(os.sep + "Users" + os.sep, serialized)
            self.assertNotIn(fake_key, serialized)  # secret value redacted upstream
            self.assertEqual(body["project"], scan_root.resolved_project)  # honest resolved root
            self.assertTrue(body["record_path"].startswith("var/"))
            # on-disk persisted copy must be redacted too
            with open(os.path.join(ADDON_ROOT, body["record_path"])) as f:
                on_disk = f.read()
            self.assertNotIn(os.path.expanduser("~"), on_disk)
            self.assertNotIn(fake_key, on_disk)

    def test_scan_outside_scan_root_refused(self):
        with ScanRoot(), Service():
            code, body = post_err({"method": "checkyourself.scan", "params": {"project": "/etc"}})
            self.assertEqual(code, 400)
            self.assertIn("outside the allowed scan root", body["error"])

    def test_scan_missing_dir_refused(self):
        with ScanRoot(), Service():
            code, body = post_err({"method": "checkyourself.scan", "params": {"project": "no-such-dir; rm -rf /"}})
            self.assertEqual(code, 400)

    def test_scan_param_bounds(self):
        with ScanRoot(), Service():
            for params, why in (
                ({"project": "fixture-app", "max_files": 0}, "max_files=0"),
                ({"project": "fixture-app", "max_files": 6001}, "max_files=6001"),
                ({"project": "fixture-app", "max_files": True}, "max_files bool"),
                ({"project": "fixture-app", "max_files": "5"}, "max_files str"),
                ({"project": "fixture-app", "deep": "yes"}, "deep str"),
                ({"project": "fixture-app\x01"}, "control char"),
                ({"project": "fixture-app", "nope": 1}, "unknown field"),
            ):
                code, _ = post_err({"method": "checkyourself.scan", "params": params})
                self.assertEqual(code, 400, why)
            code, _ = post_err({"method": "checkyourself.scan", "params": None})
            self.assertEqual(code, 400)

    def test_single_flight_409(self):
        original = checkyourself.scan
        release = threading.Event()

        def slow_scan(*args, **kwargs):
            release.wait(timeout=15)
            return original(*args, **kwargs)

        with ScanRoot(), Service():
            checkyourself.scan = slow_scan
            try:
                holder = {}

                def fire():
                    try:
                        holder["reply"] = post({"method": "checkyourself.scan",
                                                "params": {"project": "fixture-app"}})
                    except Exception as exc:  # surfaced by the assertions below
                        holder["reply"] = (0, {"error": str(exc)})

                worker = threading.Thread(target=fire, daemon=True)
                worker.start()
                status = {}
                deadline = time.time() + 15
                while time.time() < deadline:
                    _, status = post({"method": "checkyourself.status"})
                    if status["busy"]:
                        break
                    time.sleep(0.05)
                self.assertTrue(status["busy"])  # scan answers status WHILE it is live
                code, _ = post_err({"method": "checkyourself.scan", "params": {"project": "fixture-app"}})
                self.assertEqual(code, 409)  # second concurrent scan rejected
                release.set()
                worker.join(timeout=30)
                self.assertEqual(holder["reply"][0], 200)
                deadline = time.time() + 60
                while time.time() < deadline:
                    _, status = post({"method": "checkyourself.status"})
                    if not status["busy"]:
                        break
                    time.sleep(0.1)
                self.assertFalse(status["busy"])
                self.assertIsNotNone(status["last_scan_id"])
            finally:
                checkyourself.scan = original


class TestScoreBacklogValidateSchema(unittest.TestCase):
    FINDINGS = {"findings": [
        {"id": "SEC-001", "severity": "P0", "category": "C3", "title": "Committed .env",
         "finding": "Committed .env", "status": "open"},
        {"id": "TST-001", "severity": "P1", "category": "C5", "title": "No tests",
         "finding": "No tests", "status": "open"},
    ]}

    def test_score_roundtrip(self):
        with Service():
            code, body = post({"method": "checkyourself.score", "params": self.FINDINGS})
            self.assertEqual(code, 200)
            self.assertEqual(body["schema"], "checkyourself-score/1")
            self.assertLess(body["score"], 100)
            self.assertEqual(body["confidence"], "low")  # no coverage => honest low confidence
            self.assertEqual(body["score_mode"], "finding-only-estimate")

    def test_score_param_validation(self):
        with Service():
            code, _ = post_err({"method": "checkyourself.score", "params": {"findings": "nope"}})
            self.assertEqual(code, 400)
            code, _ = post_err({"method": "checkyourself.score", "params": {}})
            self.assertEqual(code, 400)
            code, _ = post_err({"method": "checkyourself.score", "params": {"findings": [], "coverage": []}})
            self.assertEqual(code, 400)

    def test_backlog_roundtrip(self):
        with Service():
            code, body = post({"method": "checkyourself.backlog", "params": self.FINDINGS})
            self.assertEqual(code, 200)
            self.assertEqual(body["schema"], "checkyourself-backlog/1")
            ids = [item["finding_id"] for item in body["remediation_backlog"]]
            self.assertEqual(ids, ["SEC-001", "TST-001"])  # P0 sorts first
            self.assertIn("SEC-001", body["first_approval_batch"])

    def test_validate_roundtrip(self):
        with Service():
            _, score = post({"method": "checkyourself.score", "params": self.FINDINGS})
            code, body = post({"method": "checkyourself.validate", "params": {
                "kind": "score", "artifact": score}})
            self.assertEqual(code, 200)
            self.assertTrue(body["valid"], body["errors"])
            code, body = post({"method": "checkyourself.validate", "params": {
                "kind": "score", "artifact": {"score": "not-an-int"}}})
            self.assertEqual(code, 200)
            self.assertFalse(body["valid"])
            self.assertTrue(body["errors"])

    def test_schema_roundtrip(self):
        with Service():
            code, body = post({"method": "checkyourself.schema", "params": {"name": "scan"}})
            self.assertEqual(code, 200)
            self.assertIsInstance(body, dict)
            code, _ = post_err({"method": "checkyourself.schema", "params": {"name": "bogus"}})
            self.assertEqual(code, 400)


class TestAdversarial(unittest.TestCase):
    def test_unknown_method_404(self):
        with Service():
            code, _ = post_err({"method": "checkyourself.run", "params": {}})
            self.assertEqual(code, 404)

    def test_unknown_envelope_field_400(self):
        with Service():
            code, _ = post_err({"method": "checkyourself.status", "params": {}, "extra": 1})
            self.assertEqual(code, 400)

    def test_non_object_body_400(self):
        with Service():
            code, _ = post_err(None, raw=b"[1,2,3]")
            self.assertEqual(code, 400)
            code, _ = post_err(None, raw=b"not json at all")
            self.assertEqual(code, 400)

    def test_bad_content_length_400(self):
        with Service():
            s = socket.create_connection(("127.0.0.1", TEST_PORT), timeout=10)
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: notanumber\r\n\r\n{}")
            data = s.recv(65536)
            self.assertTrue(data.startswith(b"HTTP/1.1 400"), data[:60])
            s.close()

    def test_chunked_transfer_encoding_400(self):
        with Service():
            s = socket.create_connection(("127.0.0.1", TEST_PORT), timeout=10)
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                      b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            data = s.recv(65536)
            self.assertTrue(data.startswith(b"HTTP/1.1 400"), data[:60])
            s.close()

    def test_oversized_body_413_and_connection_closed(self):
        with Service():
            big = json.dumps({"method": "checkyourself.scan", "params": {
                "project": "fixture-app", "deep": True, "padding": "x" * 100000}}).encode()
            self.assertGreater(len(big), server.MAX_BODY)
            # raw socket: the server may reject mid-send and close, so tolerate EPIPE
            s = socket.create_connection(("127.0.0.1", TEST_PORT), timeout=10)
            try:
                s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                          + f"Content-Length: {len(big)}\r\n\r\n".encode() + big)
            except OSError:
                pass  # server already refused and closed — that IS the rejection
            data = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            self.assertTrue(data.startswith(b"HTTP/1.1 413"), data[:60])
            s.close()
            code, body = post({"method": "checkyourself.status"})  # service unaffected
            self.assertEqual(code, 200)

    def test_lying_content_length_408_then_service_healthy(self):
        old_timeout = server.Handler.timeout
        server.Handler.timeout = 2
        try:
            with Service():
                s = socket.create_connection(("127.0.0.1", TEST_PORT), timeout=15)
                s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                          b"Content-Length: 1000\r\n\r\nshort")
                data = s.recv(65536)
                self.assertTrue(data.startswith(b"HTTP/1.1 408"), data[:60])
                s.close()
                code, body = post({"method": "checkyourself.status"})  # no thread pinned, service alive
                self.assertEqual(code, 200)
        finally:
            server.Handler.timeout = old_timeout

    def test_twenty_request_flood_all_answered(self):
        with Service():
            for i in range(20):
                if i % 3 == 0:
                    code, body = post({"method": "checkyourself.status"})
                    self.assertEqual(code, 200)
                elif i % 3 == 1:
                    code, _ = post_err({"method": "bogus.method"})
                    self.assertEqual(code, 404)
                else:
                    code, _ = post_err({"method": "checkyourself.scan", "params": {"project": "\x02"}})
                    self.assertEqual(code, 400)
            code, body = post({"method": "checkyourself.status"})  # still healthy after the flood
            self.assertEqual(code, 200)
            self.assertTrue(body["ok"])

    def test_bind_conflict_exit_78(self):
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.listen(1)
        try:
            env = dict(os.environ)
            env["CHECKYOURSELF_PORT"] = str(port)
            proc = subprocess.run([sys.executable, SERVER], env=env,
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 78, proc.stderr)
            self.assertIn("cannot bind", proc.stderr)
        finally:
            holder.close()


class TestPrivacy(unittest.TestCase):
    def test_redact_helpers(self):
        home = os.path.expanduser("~")
        self.assertEqual(server._redact_text("x" + home + "/y"), "x~/y")
        self.assertEqual(server._redact_obj({"a": [home + "/b"], "c": 3}), {"a": ["~/b"], "c": 3})

    def test_no_home_paths_or_secrets_in_tree(self):
        needle = (os.sep + "Users" + os.sep).encode()  # built at runtime so this file stays clean
        home = os.path.expanduser("~").encode()
        # marker literals are assembled at runtime so no secret-shaped literal sits in this tree
        markers = [b"sk-" + b"ant-", b"ghp" + b"_", b"xox" + b"b-", b"BEGIN RSA PRIVATE " + b"KEY"]
        for root, dirs, files in os.walk(ADDON_ROOT):
            if os.path.basename(root) == "vendor":
                # vendored upstream is a secret-DETECTION tool: its regex patterns are
                # detection data, not credentials, and must stay byte-identical. The
                # home-path check below still covers vendor/.
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in ("var", "__pycache__")]
            for name in files:
                path = os.path.join(root, name)
                if path.endswith(".pyc"):
                    continue
                with open(path, "rb") as f:
                    content = f.read()
                self.assertNotIn(needle, content, f"home path leaked in {path}")
                self.assertNotIn(home, content, f"home path leaked in {path}")
                for marker in markers:
                    self.assertNotIn(marker, content, f"secret marker {marker!r} in {path}")


if __name__ == "__main__":
    unittest.main()


class TestPerMethodParams(unittest.TestCase):
    def test_cross_method_field_rejected(self):
        import server as _srv
        for method, foreign in [
            ("checkyourself.score", {"project": "x"}),
            ("checkyourself.backlog", {"coverage": 1}),
            ("checkyourself.schema", {"findings": []}),
            ("checkyourself.validate", {"name": "x"}),
        ]:
            _, err = _srv._validate_params(method, dict(foreign))
            self.assertIsNotNone(err, f"{method} accepted foreign field {list(foreign)[0]}")
