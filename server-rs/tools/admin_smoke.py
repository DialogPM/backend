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
    check("settings", st == 200 and set(before) == {"registration_enabled", "pow_bits", "max_devices",
                                                    "attachment_max_bytes", "inactive_device_days"}, before)
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

    print("\n%d failure(s)" % len(FAILS))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
