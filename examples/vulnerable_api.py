"""A deliberately vulnerable API used to smoke-test gatecrash.

Run:  python examples/vulnerable_api.py           (listens on 127.0.0.1:5099)

Every weakness in here is intentional. Do not deploy it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import traceback

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)
JWT_SECRET = "secret"          # BUG: trivially guessable signing key

USERS = {
    "1001": {"id": "1001", "username": "alice", "email": "alice@example.com",
             "role": "user", "password_hash": "$2b$12$K3JNi5xUqQeJmnHnEXsO8uWq3aVGZ1FbmDp0aQ7ZQx2rN4tYv6Lay",
             "phone": "555-201-9944", "balance": 120},
    "1002": {"id": "1002", "username": "bob", "email": "bob@example.com",
             "role": "user", "password_hash": "$2b$12$L9MPk7yVrRfKnoIoFYtP9vXr4bWHA2GcnEq1bR8ARy3sO5uZw7Mbz",
             "phone": "555-330-1187", "balance": 8400},
    "1003": {"id": "1003", "username": "carol", "email": "carol@example.com",
             "role": "admin", "password_hash": "$2b$12$M0NQl8zWsSgLopJpGZuQ0wYs5cXIB3HdoFr2cS9BSz4tP6vAx8Nca",
             "phone": "555-884-2210", "balance": 15},
}
NEXT_ID = [1004]


# ---- token helpers -------------------------------------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64u(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def make_token(user: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": user["id"], "username": user["username"],
               "role": user["role"], "email": user["email"]}   # BUG: no exp
    h, p = b64u(json.dumps(header).encode()), b64u(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


def current_user():
    """BUG: decodes the token without ever verifying the signature."""
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    parts = auth[7:].strip().split(".")
    if len(parts) < 2:
        return None
    try:
        payload = json.loads(unb64u(parts[1]))
    except Exception:
        return None
    return USERS.get(str(payload.get("sub"))) or {"id": payload.get("sub"),
                                                  "role": payload.get("role", "user"),
                                                  "username": payload.get("username", "?")}


def require_auth():
    user = current_user()
    if not user:
        return None, (jsonify({"error": "unauthorized"}), 401)
    return user, None


@app.after_request
def headers(response):
    origin = request.headers.get("Origin")
    if origin:                                   # BUG: reflects any origin, with credentials
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Server"] = "gunicorn/20.1.0"     # BUG: version banner
    response.headers["X-Environment"] = "staging"      # BUG: environment disclosed
    return response                                    # BUG: no nosniff, no HSTS


# ---- routes --------------------------------------------------------------

@app.post("/api/login")
def login():                                     # BUG: no rate limiting at all
    body = request.get_json(silent=True) or {}
    for user in USERS.values():
        if user["username"] == body.get("username"):
            return jsonify({"token": make_token(user), "user_id": user["id"]})
    return jsonify({"error": "invalid credentials"}), 401


@app.get("/api/me")
def me():
    user, err = require_auth()
    if err:
        return err
    return jsonify({k: v for k, v in user.items() if k != "password_hash"})


@app.get("/api/users/<user_id>")
def get_user(user_id):                           # BUG: BOLA - no ownership check
    _, err = require_auth()
    if err:
        return err
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)                         # BUG: returns password_hash + PII


@app.post("/api/users")
def create_user():                               # BUG: mass assignment
    _, err = require_auth()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    new = {"id": str(NEXT_ID[0]), "role": "user", "balance": 0, "verified": False}
    new.update(body)                             # BUG: whole body bound to the model
    new["id"] = str(NEXT_ID[0])
    NEXT_ID[0] += 1
    USERS[new["id"]] = new
    return jsonify(new), 201


@app.get("/api/admin/users")
def admin_users():                               # BUG: BFLA - any authenticated caller
    _, err = require_auth()
    if err:
        return err
    return jsonify({"users": list(USERS.values())})


@app.get("/api/orders")
def orders():                                    # BUG: unbounded page size
    _, err = require_auth()
    if err:
        return err
    limit = int(request.args.get("limit", 5))
    return jsonify({"orders": [
        {"id": i, "customer_email": f"customer{i}@example.com", "total": i * 3.5,
         "card": "4111 1111 1111 1111" if i % 7 == 0 else None}
        for i in range(1, limit + 1)]})


@app.get("/api/reports/export")
def export():                                    # BUG: unhandled exception leaks a traceback
    _, err = require_auth()
    if err:
        return err
    try:
        raise ValueError("could not open /var/www/app/exports/report.csv")
    except ValueError:
        return make_response(traceback.format_exc(), 500)


@app.get("/.env")
def dotenv():                                    # BUG: environment file served
    return make_response(
        "DATABASE_URL=postgres://app:hunter2@10.0.4.19:5432/app\n"
        "JWT_SECRET=secret\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", 200,
        {"Content-Type": "text/plain"})


# -- API7: Server Side Request Forgery -------------------------------------

@app.get("/api/fetch")
def fetch():                                     # BUG: fetches any client-supplied URL
    _, err = require_auth()
    if err:
        return err
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=2) as resp:   # BUG: no scheme/host restriction
            return make_response(resp.read()[:4096], 200, {"Content-Type": "text/plain"})
    except Exception as exc:
        return make_response(f"fetch failed: {exc}", 502, {"Content-Type": "text/plain"})


# -- API8/API10: unvalidated redirect --------------------------------------

@app.get("/api/go")
def go():                                        # BUG: redirect target not validated
    return make_response("", 302, {"Location": request.args.get("next", "/")})


# -- API9: superseded version still live -----------------------------------

@app.get("/api/v2/orders")
def orders_v2():
    _, err = require_auth()
    if err:
        return err
    return jsonify({"orders": [{"id": i, "total": i * 3.5} for i in range(1, 4)],
                    "version": 2})


@app.get("/api/v1/orders")
def orders_v1():                                 # BUG: old version never retired
    _, err = require_auth()
    if err:
        return err
    return jsonify({"orders": [{"id": i, "total": i * 3.5, "customer_ssn": "078-05-1120"}
                               for i in range(1, 4)], "version": 1})


# -- API4: expensive query and no size limit -------------------------------

@app.get("/api/search")
def search():
    _, err = require_auth()
    if err:
        return err
    q = request.args.get("q", "")
    if q in ("*", "%", ".*", "a%"):              # BUG: unbounded wildcard scan
        time.sleep(1.6)
        return jsonify({"results": [{"id": i, "name": f"record-{i}"} for i in range(2000)]})
    return jsonify({"results": [{"id": 1, "name": f"match for {q[:40]}"}]})


# -- API6: sensitive business flow with no anti-automation -----------------

@app.post("/api/checkout")
def checkout():                                  # BUG: no idempotency, no velocity control
    _, err = require_auth()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    return jsonify({"order_id": "ord_8812", "status": "confirmed",
                    "item": body.get("item", "unknown"), "charged": body.get("amount", 0)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5099, threaded=True)
