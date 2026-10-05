"""Black-box failure tests for the configured runn command and production runbook."""

import base64
import http.server
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[2]
ISSUER = "http://localhost:18080"
COOKIE = "SYNTHETIC_SESSION_FOR_REGRESSION"
CODE = "SYNTHETIC_CODE_FOR_REGRESSION"


def token(label):
    payload = base64.urlsafe_b64encode(json.dumps({"jti": label}).encode()).decode().rstrip("=")
    return f"e30.{payload}.c2lnbmF0dXJl"


ACCESS_TOKEN = token("synthetic-access")
ID_TOKEN = token("synthetic-id")


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if status != 204:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.requests.append((path, self.headers.get("Cookie")))
        if path == "/actuator/health":
            self.respond(200, {"status": "UP"})
        elif path == "/.well-known/openid-configuration":
            self.respond(200, {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/oauth2/authorize",
                "token_endpoint": ISSUER + "/oauth2/token",
                "introspection_endpoint": ISSUER + "/oauth2/introspect",
                "jwks_uri": ISSUER + "/oauth2/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "scopes_supported": ["openid"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            })
        elif path == "/oauth2/authorize":
            state = "wrong-state" if self.server.failure == "state" else "scenario-state-0123456789"
            self.respond(302, {}, {
                "Location": f"http://127.0.0.1:8080/login/oauth2/code/client-123?code={CODE}&state={state}",
            })
        else:
            self.respond(404, {})

    def do_POST(self):
        path = urlsplit(self.path).path
        self.server.requests.append((path, self.headers.get("Cookie")))
        if path == "/api/login":
            if self.server.failure == "login-rejected":
                self.respond(401, {})
                return
            suffix = "" if self.server.failure == "cookie" else "; HttpOnly"
            self.respond(200, {
                "username": "user-123", "tenantId": "tenant-a",
                "resource": "https://api.example.com/tenants/tenant-a", "authorities": ["ROLE_USER"],
            }, {"Set-Cookie": f"JSESSIONID={COOKIE}; Path=/{suffix}"})
        elif path == "/oauth2/token":
            # A valid JWT response with insufficient scope triggers the token assertion.
            self.respond(200, {
                "token_type": "Bearer", "expires_in": 300,
                "access_token": ACCESS_TOKEN, "id_token": ID_TOKEN, "scope": "openid tenant.read",
            })
        elif path == "/api/logout":
            self.respond(204, None)
        else:
            self.respond(404, {})


class RunnCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([
            "docker", "compose", "-f", "docker-compose.dev.native.yaml", "--profile", "scenario",
            "config", "--format", "json",
        ], cwd=ROOT, capture_output=True, text=True, check=True)
        cls.runn = json.loads(result.stdout)["services"]["runn"]
        subprocess.run(["docker", "pull", cls.runn["image"]], capture_output=True, check=True, timeout=180)

    def check_failure(self, failure, last_path, cleanup):
        server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), FixtureHandler)
        server.failure, server.requests = failure, []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        name = "tolo-idp-runn-regression-" + uuid.uuid4().hex
        args = list(self.runn["command"])
        host = "127.0.0.1" if sys.platform == "linux" else "host.docker.internal"
        args[args.index("--host-rules") + 1] = f"localhost {host}:{server.server_port}"
        command = ["docker", "run", "--rm", "--name", name, "--entrypoint", self.runn["entrypoint"][0]]
        if sys.platform == "linux":
            command += ["--network", "host"]
        command += ["-e", f"IDP_ISSUER={ISSUER}", "-v", f"{ROOT / 'scenario'}:/books:ro", self.runn["image"], *args]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        finally:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=10)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(1, result.returncode, "The scenario must report assertion failure")
        requests = [path for path, _ in server.requests]
        self.assertIn(last_path, requests, "The intended assertion must be reached")
        if cleanup:
            self.assertEqual([(path, cookie) for path, cookie in server.requests if path == "/api/logout"],
                             [("/api/logout", f"JSESSIONID={COOKIE}")])
            self.assertEqual(last_path, requests[-2], "No authentication step may run after the failure")
        else:
            self.assertNotIn("/api/logout", requests)
            self.assertEqual(last_path, requests[-1])

    def test_login_cookie_assertion_failure_logs_out(self):
        self.check_failure("cookie", "/api/login", True)

    def test_authorization_state_assertion_failure_logs_out(self):
        self.check_failure("state", "/oauth2/authorize", True)

    def test_token_scope_assertion_failure_logs_out(self):
        self.check_failure("scope", "/oauth2/token", True)

    def test_rejected_login_does_not_attempt_logout(self):
        self.check_failure("login-rejected", "/api/login", False)


if __name__ == "__main__":
    unittest.main()
