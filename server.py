import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import time
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("DEVFLOW_DATABASE_PATH", BASE_DIR / "devflow.db"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "MAK")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "DEV")
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(32)
SESSION_DURATION = 12 * 60 * 60
COOKIE_SECURE = os.environ.get(
    "COOKIE_SECURE", str(HOST not in {"127.0.0.1", "localhost"})
).lower() in {"1", "true", "yes"}
VALID_STATUSES = {"Pending", "In Progress", "Completed"}


def initialize_database():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                concept TEXT NOT NULL,
                amount REAL NOT NULL,
                deadline TEXT NOT NULL,
                status TEXT NOT NULL
            )"""
        )


class DevFlowHandler(BaseHTTPRequestHandler):
    def is_authenticated(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie.get("mak_session")
            if token is None:
                return False
            expiry_text, supplied_signature = token.value.rsplit(".", 1)
            expiry = int(expiry_text)
        except (ValueError, TypeError):
            return False
        if expiry < time.time():
            return False
        expected_signature = hmac.new(
            SESSION_SECRET.encode(), expiry_text.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(supplied_signature, expected_signature)

    def require_authentication(self):
        if self.is_authenticated():
            return True
        self.send_json(401, {"error": "Authentication required"})
        return False

    def set_session_cookie(self):
        expiry = str(int(time.time()) + SESSION_DURATION)
        signature = hmac.new(
            SESSION_SECRET.encode(), expiry.encode(), hashlib.sha256
        ).hexdigest()
        cookie = f"mak_session={expiry}.{signature}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_DURATION}"
        if COOKIE_SECURE:
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("Request body is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def validate_project(self, data):
        if not isinstance(data, dict):
            raise ValueError("Expected a contract object")
        name = str(data.get("name", "")).strip()
        concept = str(data.get("concept", "")).strip()
        deadline = str(data.get("deadline", "")).strip()
        status = data.get("status")
        amount_value = data.get("amount")
        if isinstance(amount_value, bool) or not isinstance(amount_value, (int, float, str)):
            raise ValueError("Amount must be a number")
        try:
            amount = float(amount_value)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("Amount must be a number") from None
        if not name or not concept or not deadline:
            raise ValueError("Name, concept, and deadline are required")
        if not math.isfinite(amount):
            raise ValueError("Amount must be finite")
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        if status not in VALID_STATUSES:
            raise ValueError("Invalid contract status")
        return name, concept, amount, deadline, status

    def do_GET(self):
        if self.path == "/api/session":
            self.send_json(200, {"authenticated": self.is_authenticated()})
            return
        if self.path == "/api/projects":
            if not self.require_authentication():
                return
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.row_factory = sqlite3.Row
                projects = [dict(row) for row in connection.execute(
                    "SELECT id, name, concept, amount, deadline, status "
                    "FROM projects ORDER BY rowid DESC"
                )]
            self.send_json(200, projects)
            return
        if self.path == "/" or self.path == "/index.html":
            body = (BASE_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/login":
            try:
                credentials = self.read_json()
            except (ValueError, json.JSONDecodeError) as error:
                self.send_json(400, {"error": str(error)})
                return
            username = credentials.get("username") if isinstance(credentials, dict) else None
            password = credentials.get("password") if isinstance(credentials, dict) else None
            valid = (
                isinstance(username, str)
                and isinstance(password, str)
                and hmac.compare_digest(username, ADMIN_USERNAME)
                and hmac.compare_digest(password, ADMIN_PASSWORD)
            )
            if not valid:
                self.send_json(401, {"error": "Invalid admin name or password"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.set_session_cookie()
            body = json.dumps({"authenticated": True}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/logout":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "mak_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            body = json.dumps({"authenticated": False}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self.require_authentication():
            return
        if self.path != "/api/projects":
            self.send_error(404)
            return
        try:
            name, concept, amount, deadline, status = self.validate_project(self.read_json())
            project = {
                "id": str(uuid.uuid4()),
                "name": name,
                "concept": concept,
                "amount": amount,
                "deadline": deadline,
                "status": status,
            }
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.execute(
                    "INSERT INTO projects (id, name, concept, amount, deadline, status) "
                    "VALUES (:id, :name, :concept, :amount, :deadline, :status)",
                    project,
                )
            self.send_json(201, project)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})

    def do_PUT(self):
        if not self.require_authentication():
            return
        project_id = self.project_id_from_path()
        if not project_id:
            self.send_error(404)
            return
        try:
            name, concept, amount, deadline, status = self.validate_project(self.read_json())
            with sqlite3.connect(DATABASE_PATH) as connection:
                cursor = connection.execute(
                    "UPDATE projects SET name = ?, concept = ?, amount = ?, deadline = ?, status = ? "
                    "WHERE id = ?",
                    (name, concept, amount, deadline, status, project_id),
                )
                if cursor.rowcount == 0:
                    self.send_json(404, {"error": "Contract not found"})
                    return
            self.send_json(200, {
                "id": project_id,
                "name": name,
                "concept": concept,
                "amount": amount,
                "deadline": deadline,
                "status": status,
            })
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})

    def do_DELETE(self):
        if not self.require_authentication():
            return
        project_id = self.project_id_from_path()
        if not project_id:
            self.send_error(404)
            return
        with sqlite3.connect(DATABASE_PATH) as connection:
            cursor = connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        if cursor.rowcount == 0:
            self.send_json(404, {"error": "Contract not found"})
            return
        self.send_json(200, {"deleted": project_id})

    def project_id_from_path(self):
        prefix = "/api/projects/"
        path = urlparse(self.path).path
        if path.startswith(prefix) and path[len(prefix):] and "/" not in path[len(prefix):]:
            return path[len(prefix):]
        return None

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")


if __name__ == "__main__":
    if HOST not in {"127.0.0.1", "localhost"}:
        if ADMIN_PASSWORD == "DEV" or len(ADMIN_PASSWORD) < 12:
            raise RuntimeError("Set ADMIN_PASSWORD to a unique password of at least 12 characters before public hosting")
        if not os.environ.get("SESSION_SECRET"):
            raise RuntimeError("Set SESSION_SECRET before public hosting")
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), DevFlowHandler)
    print(f"DevFlow running on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DevFlow")
    finally:
        server.server_close()