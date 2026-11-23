#!/usr/bin/env python3
"""Smoke test of the admin API (docs/ADMIN-API.md) against a running server.

Usage: admin_smoke.py http://127.0.0.1:8097 [seed-hex]

The server must have CHATAPP_ADMIN_PUBLIC_KEYS set to the public key of the signing key
(default: the documented example key, seed bytes 00 01 .. 1f, public key
A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=), registration without proof-of-work
(CHATAPP_REGISTRATION_POW_BITS=0) and, ideally, CHATAPP_DISABLE_RATE_LIMITS=true. Use a
throw-away database: the test registers, bans and logs out accounts and changes settings
(it restores the settings at the end). Needs the `cryptography` package.
"""
import base64, hashlib, json, os, sys, time, urllib.error, urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8097"
SEED = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else bytes(range(32))
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PK = base64.b64encode(SK.public_key().public_bytes_raw()).decode()


def b64(b): return base64.b64encode(b).decode()


def sign_admin_request(sk, method, path, ts, nonce, body):
    """The reference algorithm: base64(Ed25519(sk, signing string))."""
    msg = "dialog-admin-v1\n%s\n%s\n%d\n%s\n%s" % (method, path, ts, nonce, hashlib.sha256(body).hexdigest())
    return base64.b64encode(sk.sign(msg.encode())).decode()


def raw(method, path, body=b"", headers=None):
    req = urllib.request.Request(BASE + path, data=body if body or method != "GET" else None, method=method, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        status = resp.status
    except urllib.error.HTTPError as e:
        resp, status = e, e.code
    payload = resp.read()
    return status, (json.loads(payload) if payload else None), resp.headers


def admin(method, path, body=None, *, sk=SK, pk=PK, ts=None, nonce=None, tamper=None):
    data = json.dumps(body).encode() if body is not None else b""
    ts = ts if ts is not None else int(time.time() * 1000)
    nonce = nonce or base64.urlsafe_b64encode(os.urandom(18)).decode()
    sig = sign_admin_request(sk, method, path, ts, nonce, data)
    if tamper:
        path, data = tamper(path, data)
    h = {"X-Admin-Key": pk, "X-Admin-Timestamp": str(ts), "X-Admin-Nonce": nonce, "X-Admin-Signature": sig}
    if body is not None:
        h["Content-Type"] = "application/json"
    return raw(method, path, data, h)


def register(i):
    r = os.urandom
    body = {"kdf": {"alg": "argon2id", "salt": b64(r(16)), "m": 65536, "t": 3, "p": 1},
            "auth_key": b64(r(32)), "wrapped_account_key": b64(r(60)), "identity_key": b64(b"\x05" + r(32)),
            "recovery_public_key": b64(r(32)), "device": {"name": "smoke %d" % i, "platform": "desktop", "registration_id": 100 + i}}
    st, js, _ = raw("POST", "/v1/accounts", json.dumps(body).encode(), {"Content-Type": "application/json"})
    assert st == 200, (st, js)
    return js


FAILS = []


def check(label, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + label + ("" if cond else "  " + str(detail)))
    if not cond:
        FAILS.append(label)


def main():
    a, b = register(1), register(2)
    # Spam report from a about b (with a reason).
    st, js, _ = raw("POST", "/v1/report", json.dumps({"account_id": b["account_id"], "reason": "spam"}).encode(),
                    {"Content-Type": "application/json", "Authorization": "Bearer " + a["token"]})
    check("report spam", st == 204, (st, js))

    # --- authentication
    st, js, _ = admin("GET", "/v1/admin/overview")
    check("overview signed", st == 200, (st, js))
    for k in ("server", "accounts", "devices", "messages", "storage", "database", "system", "features",
              "key_transparency", "moderation", "backup"):
        check("overview has " + k, k in js, list(js))
    check("overview accounts >= 2", js["accounts"]["total"] >= 2, js["accounts"])
    st, js, _ = raw("GET", "/v1/admin/overview")
    check("unsigned -> 401", st == 401 and js["error"] == "unauthorized", (st, js))
    other = Ed25519PrivateKey.from_private_bytes(bytes([9] * 32))
    other_pk = base64.b64encode(other.public_key().public_bytes_raw()).decode()
    st, js, _ = admin("GET", "/v1/admin/overview", sk=other, pk=other_pk)
    check("unknown key -> 401", st == 401, (st, js))
    st, js, _ = admin("GET", "/v1/admin/overview", sk=other)
    check("wrong signer -> 401", st == 401, (st, js))
    st, js, _ = admin("GET", "/v1/admin/overview", ts=int(time.time() * 1000) - 120_000)
    check("stale timestamp -> 401", st == 401, (st, js))
    nonce = "replay-nonce-" + os.urandom(6).hex()
    st1, _, _ = admin("GET", "/v1/admin/security", nonce=nonce)
    st2, js, _ = admin("GET", "/v1/admin/security", nonce=nonce)
    check("replayed nonce -> 401", st1 == 200 and st2 == 401, (st1, st2, js))
    st, js, _ = admin("PUT", "/v1/admin/settings", {"max_devices": 5},
                      tamper=lambda p, d: (p, json.dumps({"max_devices": 20}).encode()))
    check("tampered body -> 401", st == 401, (st, js))
    st, js, _ = admin("GET", "/v1/admin/reports?status=open", tamper=lambda p, d: ("/v1/admin/reports?status=all", d))
    check("tampered query -> 401", st == 401, (st, js))
    st, _, h = raw("OPTIONS", "/v1/admin/overview", headers={"Origin": "tauri://localhost", "Access-Control-Request-Method": "GET"})
    check("CORS preflight", st == 204 and h.get("Access-Control-Allow-Origin") == "*", (st, dict(h)))

    # --- data endpoints
    st, js, _ = admin("GET", "/v1/admin/stats?days=7")
    check("stats 7 days", st == 200 and len(js["days"]) == 7, (st, js))
    check("stats counts today's registrations", js["days"][-1]["registrations"] >= 2, js["days"][-1])
    st, js, _ = admin("GET", "/v1/admin/stats?days=0")
    check("stats days=0 -> 400", st == 400, (st, js))

    st, js, _ = admin("GET", "/v1/admin/reports?status=open&limit=50&offset=0")
    mine = [r for r in (js or {}).get("items", []) if r["reported_account_id"] == b["account_id"]]
    check("open report listed", st == 200 and len(mine) == 1 and mine[0]["reason"] == "spam" and mine[0]["status"] == "open", (st, js))
    rid = mine[0]["id"] if mine else 0

    st, js, _ = admin("GET", "/v1/admin/accounts?query=" + a["number"] + "&limit=20")
    check("search by number", st == 200 and [x["id"] for x in js["items"]] == [a["account_id"]], (st, js))
    st, js, _ = admin("GET", "/v1/admin/accounts?query=" + b["account_id"][:8])
    check("search by id prefix", st == 200 and b["account_id"] in [x["id"] for x in js["items"]], (st, js))
    st, js, _ = admin("GET", "/v1/admin/accounts?query=ab")
    check("short query -> 400", st == 400, (st, js))
    st, js, _ = admin("GET", "/v1/admin/accounts/" + b["account_id"])
    check("account detail", st == 200 and js["reports_against"] == 1 and len(js["devices"]) == 1
          and "name" not in js["devices"][0], (st, js))

    # Resolve the report with a ban: b's token stops working.
    st, js, _ = admin("POST", "/v1/admin/reports/%d/resolve" % rid, {"action": "ban", "note": "spam wave"})
    check("resolve with ban", st == 204, (st, js))
    st, js, _ = raw("GET", "/v1/account", headers={"Authorization": "Bearer " + b["token"]})
    check("banned token rejected", st == 401, (st, js))
    st, js, _ = admin("GET", "/v1/admin/accounts/" + b["account_id"])
    check("ban recorded", js["banned_at"] is not None and js["ban_reason"] == "spam wave", js)
    st, js, _ = admin("GET", "/v1/admin/reports?status=resolved")
    check("report resolved", any(r["id"] == rid and r["resolution"] == "banned" for r in js["items"]), js)
    st, js, _ = admin("POST", "/v1/admin/accounts/%s/unban" % b["account_id"])
    check("unban", st == 204, (st, js))
    st, js, _ = admin("POST", "/v1/admin/accounts/%s/ban" % a["account_id"], {"reason": "test"})
    check("direct ban", st == 204, (st, js))
    st, js, _ = admin("POST", "/v1/admin/accounts/%s/unban" % a["account_id"])
    st, js, _ = admin("POST", "/v1/admin/accounts/%s/logout" % a["account_id"])
    check("logout", st == 204, (st, js))
    st, js, _ = admin("GET", "/v1/admin/accounts/" + a["account_id"])
    check("logout removed devices", js["devices"] == [], js)
    st, js, _ = admin("POST", "/v1/admin/accounts/00000000-0000-4000-8000-000000000000/ban", {"reason": "x"})
    check("ban unknown -> 404", st == 404, (st, js))

    # --- settings
    st, before, _ = admin("GET", "/v1/admin/settings")
    check("settings", st == 200 and {"registration_enabled", "pow_bits", "max_devices",
                                     "attachment_max_bytes", "inactive_device_days"} <= set(before), before)
    st, js, _ = admin("PUT", "/v1/admin/settings", {"registration_enabled": False, "max_devices": 3})
    check("put settings", st == 200 and js["max_devices"] == {"value": 3, "source": "override"}, (st, js))
    st, info, _ = raw("GET", "/v1/info")
    check("runtime applied", info["registration_enabled"] is False and info["max_devices"] == 3, info)
    st, js, _ = raw("POST", "/v1/accounts", b"{}", {"Content-Type": "application/json"})
    check("registration disabled", st == 403, (st, js))
    st, js, _ = admin("PUT", "/v1/admin/settings", {"pow_bits": 29})
    check("pow_bits range -> 400", st == 400, (st, js))
    st, js, _ = admin("PUT", "/v1/admin/settings", {"registration_enabled": None, "max_devices": None})
    check("reset settings", st == 200 and js["max_devices"]["source"] == "env", (st, js))

    # --- security, logs, calls
    st, js, _ = admin("GET", "/v1/admin/security")
    check("security", st == 200 and js["failed_admin_auth"] >= 5, (st, js))
    st, js, _ = admin("GET", "/v1/admin/logs?level=warn&limit=200")
    check("logs", st == 200 and isinstance(js["items"], list), (st, js))
    st, js, _ = admin("GET", "/v1/admin/calls")
    check("calls", st == 200 and "pushes_sent_24h" in js, (st, js))

    # --- blocked usernames
    c, d, e = register(3), register(4), register(5)
    base = "helpdesk" + os.urandom(3).hex()  # a name nobody has in this database

    def set_name(acc, name):
        return raw("PUT", "/v1/account/username", json.dumps({"username": name}).encode(),
                   {"Content-Type": "application/json", "Authorization": "Bearer " + acc["token"]})

    def name_of(acc):
        return admin("GET", "/v1/admin/accounts/" + acc["account_id"])[1].get("username")

    for acc, name in ((c, base), (d, base + ".01"), (e, base + "_team")):
        st, js, _ = set_name(acc, name)
        check("take " + name, st == 204, (st, js))
    st, js, _ = admin("GET", "/v1/admin/usernames/matches?pattern=" + base)
    check("matches of a name", st == 200 and js["count"] == 2 and sorted(js["usernames"]) == [base, base + ".01"], (st, js))
    st, js, _ = raw("GET", "/v1/admin/usernames/matches?pattern=" + base)
    check("matches unsigned -> 401", st == 401, (st, js))
    st, js, _ = admin("POST", "/v1/admin/usernames/block", {"pattern": "@" + base.upper()})
    check("block a name", st == 200 and js == {"pattern": base, "released": 2}, (st, js))
    check("holders lost the name", name_of(c) is None and name_of(d) is None, (name_of(c), name_of(d)))
    check("another name is untouched", name_of(e) == base + "_team", name_of(e))
    st, js, _ = set_name(c, base)
    check("blocked name -> 409", st == 409, (st, js))
    st, js, _ = set_name(d, base + ".02")
    check("blocked name with a number -> 409", st == 409, (st, js))
    st, js, _ = set_name(c, base + "er")
    check("a longer name is free", st == 204, (st, js))
    st, js, _ = admin("GET", "/v1/admin/usernames")
    check("list", st == 200 and base in [i["pattern"] for i in js["items"]], (st, js))
    st, js, _ = admin("POST", "/v1/admin/usernames/block", {"pattern": base + "*", "release": False})
    check("block a prefix, keep holders", st == 200 and js["released"] == 0 and name_of(e) == base + "_team", (st, js, name_of(e)))
    set_name(e, None)
    st, js, _ = set_name(e, base + "_team")
    check("prefix blocked -> 409", st == 409, (st, js))
    for bad in ("ab", "*", "sup*port", "1admin"):
        st, js, _ = admin("POST", "/v1/admin/usernames/block", {"pattern": bad})
        check("pattern %r -> 400" % bad, st == 400, (st, js))
    st, js, _ = admin("POST", "/v1/admin/usernames/unblock", {"pattern": base + "*"})
    check("unblock", st == 204, (st, js))
    st, js, _ = admin("POST", "/v1/admin/usernames/unblock", {"pattern": base + "*"})
    check("unblock twice -> 404", st == 404, (st, js))
    st, js, _ = set_name(e, base + "_team")
    check("free again after unblock", st == 204, (st, js))
    st, js, _ = admin("POST", "/v1/admin/usernames/unblock", {"pattern": base})
    check("unblock the name", st == 204, (st, js))

    # --- daily activity: calls started, active accounts, countries
    def today(metric):
        return admin("GET", "/v1/admin/stats?days=1")[1]["days"][-1].get(metric)

    def connect(acc, ip):
        """Opens the delivery socket (the handshake is enough) as if from `ip`; returns the status."""
        import socket
        u = urllib.parse.urlparse(BASE)
        with socket.create_connection((u.hostname, u.port or 80), timeout=10) as sock:
            sock.sendall(("GET /v1/ws HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nX-Forwarded-For: %s\r\n"
                          "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n"
                          % (u.netloc, acc["token"], ip, b64(os.urandom(16)))).encode())
            head = sock.recv(64).decode("latin-1")
        return int(head.split(" ")[1]) if head.startswith("HTTP/1.1 ") else 0

    def call(frm, to, call_id):
        body = {"timestamp": int(time.time() * 1000), "call_id": call_id,
                "messages": [{"device_id": 1, "registration_id": to["_reg"], "type": 2, "content": b64(os.urandom(64))}]}
        return raw("PUT", "/v1/messages/" + to["account_id"], json.dumps(body).encode(),
                   {"Content-Type": "application/json", "Authorization": "Bearer " + frm["token"]})

    c["_reg"], d["_reg"] = 103, 104
    calls0, active0 = today("calls_started"), today("active_accounts")
    check("stats have the new counters", calls0 is not None and active0 is not None, (calls0, active0))
    cid = "smoke-" + os.urandom(6).hex()
    st, js, _ = call(c, d, cid)
    check("call offer accepted", st == 200, (st, js))
    call(c, d, cid)
    check("one call, however often its offer is sent", today("calls_started") == calls0 + 1, (calls0, today("calls_started")))
    call(c, d, "smoke-" + os.urandom(6).hex())
    check("another call id is another call", today("calls_started") == calls0 + 2, today("calls_started"))

    st, co, _ = admin("GET", "/v1/admin/countries?days=1")
    check("countries", st == 200 and isinstance(co["items"], list) and "attribution" in co, (st, co))
    by = lambda js: {i["country"]: i for i in js["items"]}
    check("first connection of the day counts", connect(c, "5.2.200.7") == 101 and today("active_accounts") == active0 + 1,
          (active0, today("active_accounts")))
    connect(c, "5.3.1.1")
    check("an account counts once a day", today("active_accounts") == active0 + 1, today("active_accounts"))
    if co["enabled"]:
        # tools/geoip-sample.csv: 5.2.128.0/17 is RO, 5.3.0.0/16 is DE; needs CHATAPP_TRUSTED_PROXY_HEADER.
        after = by(admin("GET", "/v1/admin/countries?days=1")[1])
        before = by(co)
        ro = lambda m, k: m.get("RO", {}).get(k, 0)
        check("counted where it first connected from", ro(after, "active_today") == ro(before, "active_today") + 1
              and after.get("DE", {}).get("active_today", 0) == before.get("DE", {}).get("active_today", 0), after)
        r = os.urandom
        body = {"kdf": {"alg": "argon2id", "salt": b64(r(16)), "m": 65536, "t": 3, "p": 1},
                "auth_key": b64(r(32)), "wrapped_account_key": b64(r(60)), "identity_key": b64(b"\x05" + r(32)),
                "recovery_public_key": b64(r(32)), "device": {"name": "smoke geo", "platform": "desktop", "registration_id": 177}}
        st, js, _ = raw("POST", "/v1/accounts", json.dumps(body).encode(), {"Content-Type": "application/json", "X-Forwarded-For": "5.3.1.1"})
        after2 = by(admin("GET", "/v1/admin/countries?days=1")[1])
        check("registration counted for its country", st == 200 and after2.get("DE", {}).get("registrations", 0)
              == after.get("DE", {}).get("registrations", 0) + 1, (st, after2))
        connect(js, "203.0.113.9")
        check("an address outside the database is unknown", by(admin("GET", "/v1/admin/countries?days=1")[1]).get("ZZ", {}).get("active_today", 0) >= 1)
    else:
        print("skip country checks (server without CHATAPP_GEOIP_DB)")

    print("\n%d failure(s)" % len(FAILS))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
