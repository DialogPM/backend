#!/usr/bin/env python3
"""Differential test: runs the same request sequence against two Dialog servers (Go and
Rust) and compares every response (status, error code/message, security headers, JSON
shape and values after normalizing server-generated ids, tokens and timestamps).

Usage: difftest.py http://127.0.0.1:8080 http://127.0.0.1:8081
Both servers must use the same CHATAPP_SERVER_SECRET, rate limits disabled, separate DBs.
"""
import base64, hashlib, hmac, json, os, random, re, struct, sys, time, urllib.request, urllib.error

def b64(b): return base64.b64encode(b).decode()
def rb(seed, n):
    r = random.Random(seed); return bytes(r.getrandbits(8) for _ in range(n))

def totp(secret_b32, t=None):
    s = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    step = int((t or time.time()) // 30)
    h = hmac.new(s, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)

class Srv:
    def __init__(self, base): self.base = base.rstrip("/")
    def req(self, method, path, body=None, token=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        h = {"Content-Type": "application/json"} if body is not None else {}
        if token: h["Authorization"] = "Bearer " + token
        h.update(headers or {})
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            resp = urllib.request.urlopen(r, timeout=30); status = resp.status
        except urllib.error.HTTPError as e:
            resp = e; status = e.code
        payload = resp.read()
        hdr = {k.lower(): v for k, v in resp.headers.items()}
        try: js = json.loads(payload) if payload else None
        except Exception: js = {"_raw_len": len(payload)}
        return status, hdr, js

KEEP_HEADERS = ("content-type", "cache-control", "x-content-type-options", "referrer-policy", "retry-after", "content-length")
TS_KEYS = {"expires", "server_timestamp", "created_at", "last_seen_at", "joined_at", "requested_at", "updated_at", "last_seen", "seq", "expires_at"}
OPAQUE_KEYS = {"token", "challenge", "secret", "uri", "poll_key", "link_token", "certificate", "id", "session_id", "number", "salt"}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

class Norm:
    def __init__(self): self.maps = {}
    def tag(self, kind, v):
        m = self.maps.setdefault(kind, {})
        return m.setdefault(v, f"<{kind}{len(m)}>")
    def __call__(self, v, key=None):
        if isinstance(v, dict): return {k: self(x, k) for k, x in sorted(v.items())}
        if isinstance(v, list):
            out = [self(x, key) for x in v]
            # Both servers sort these by account id, but ids are random per database: compare
            # as sets of normalized entries.
            if out and all(isinstance(x, dict) and "account_id" in x for x in out):
                out.sort(key=lambda x: json.dumps(x, sort_keys=True))
            return out
        if isinstance(v, bool) or v is None: return v
        if isinstance(v, (int, float)):
            if key in TS_KEYS: return "<ts>"
            return v
        if isinstance(v, str):
            if UUID.match(v): return self.tag("uuid", v)
            if re.fullmatch(r"[1-9][0-9]{15}", v): return self.tag("num", v)
            if re.fullmatch(r"[0-9a-f]{32}", v): return self.tag("hex", v)
            if key in OPAQUE_KEYS: return f"<{key}:{len(v)}>"
            return v
        return v

def scenario(s, out, suffix):
    def call(label, *a, **k):
        st, hdr, js = s.req(*a, **k)
        out.append((label, st, {h: hdr.get(h) for h in KEEP_HEADERS if h in hdr and h != "content-length" or (h == "content-length" and a[0] == "GET" and "attachments" in a[1])}, js))
        return st, js

    kdf = {"alg": "argon2id", "salt": b64(rb(1, 16)), "m": 65536, "t": 3, "p": 1}
    def reg_body(i, **over):
        b = {"kdf": kdf, "auth_key": b64(rb(10 + i, 32)), "wrapped_account_key": b64(rb(20 + i, 60)),
             "identity_key": b64(b"\x05" + rb(30 + i, 32)), "recovery_public_key": b64(rb(40 + i, 32)),
             "device": {"name": f"dev {i}", "platform": "desktop", "registration_id": 100 + i}}
        b.update(over); return b

    call("info", "GET", "/v1/info")
    call("404", "GET", "/v1/nope")
    call("405-ish", "PATCH", "/v1/info")
    call("health", "GET", "/healthz")
    call("noauth", "GET", "/v1/account")
    call("badtoken", "GET", "/v1/account", token="x" * 43)
    # --- registration validation
    call("reg empty", "POST", "/v1/accounts", raw=b"")
    call("reg badjson", "POST", "/v1/accounts", raw=b"{nope")
    call("reg trailing", "POST", "/v1/accounts", raw=b"{} {}")
    call("reg nokdf", "POST", "/v1/accounts", reg_body(0, kdf=None))
    call("reg badkdf alg", "POST", "/v1/accounts", reg_body(0, kdf=dict(kdf, alg="scrypt")))
    call("reg badkdf salt", "POST", "/v1/accounts", reg_body(0, kdf=dict(kdf, salt=b64(b"x"))))
    call("reg badkdf m", "POST", "/v1/accounts", reg_body(0, kdf=dict(kdf, m=1)))
    call("reg authkey len", "POST", "/v1/accounts", reg_body(0, auth_key=b64(b"x" * 5)))
    call("reg idkey len", "POST", "/v1/accounts", reg_body(0, identity_key=b64(b"x" * 5)))
    call("reg recovery len", "POST", "/v1/accounts", reg_body(0, recovery_public_key=b64(b"x")))
    call("reg wrapped big", "POST", "/v1/accounts", reg_body(0, wrapped_account_key=b64(b"x" * 2000)))
    call("reg no device", "POST", "/v1/accounts", reg_body(0, device=None))
    call("reg device platform", "POST", "/v1/accounts", reg_body(0, device={"name": "a", "platform": "tv", "registration_id": 5}))
    call("reg device regid", "POST", "/v1/accounts", reg_body(0, device={"name": "a", "platform": "desktop", "registration_id": 0}))
    call("reg device name", "POST", "/v1/accounts", reg_body(0, device={"name": " ", "platform": "desktop", "registration_id": 5}))
    call("reg bad b64", "POST", "/v1/accounts", reg_body(0, auth_key="!!!"))
    accts = []
    for i in range(3):
        st, js = call(f"reg ok {i}", "POST", "/v1/accounts", reg_body(i + 1))
        accts.append(js)
    A, B, C = accts
    ta, tb, tc = A["token"], B["token"], C["token"]
    # --- prelogin / login
    call("prelogin known", "POST", "/v1/auth/prelogin", {"number": A["number"]})
    call("prelogin unknown", "POST", "/v1/auth/prelogin", {"number": "1234567890123456"})
    call("prelogin bad", "POST", "/v1/auth/prelogin", {"number": "12"})
    call("login wrong", "POST", "/v1/auth/login", {"number": A["number"], "auth_key": b64(rb(99, 32)), "device": {"name": "x", "platform": "web", "registration_id": 7}})
    call("login unknown", "POST", "/v1/auth/login", {"number": "1234567890123456", "auth_key": b64(rb(11, 32)), "device": {"name": "x", "platform": "web", "registration_id": 7}})
    st, A2 = call("login ok", "POST", "/v1/auth/login", {"number": A["number"], "auth_key": b64(rb(11, 32)), "device": {"name": "laptop", "platform": "web", "registration_id": 7}})
    ta2 = A2["token"]
    call("account", "GET", "/v1/account", token=ta)
    call("privacy bad", "PUT", "/v1/account/privacy", {"last_seen": "friends"}, token=ta)
    call("privacy ok", "PUT", "/v1/account/privacy", {"last_seen": "nobody"}, token=ta)
    call("privacy back", "PUT", "/v1/account/privacy", {"last_seen": "everyone"}, token=ta)
    call("password wrong", "PUT", "/v1/account/password", {"auth_key": b64(rb(99, 32)), "kdf": kdf, "new_auth_key": b64(rb(50, 32)), "wrapped_account_key": b64(rb(51, 60))}, token=tc)
    call("password ok", "PUT", "/v1/account/password", {"auth_key": b64(rb(13, 32)), "kdf": kdf, "new_auth_key": b64(rb(50, 32)), "wrapped_account_key": b64(rb(51, 60))}, token=tc)
    call("account after pw", "GET", "/v1/account", token=tc)
    # --- phone
    call("phone bad", "POST", "/v1/account/phone", {"phone": "0722"}, token=ta)
    call("phone ok", "POST", "/v1/account/phone", {"phone": "+40722" + suffix[:6]}, token=ta)
    call("phone verify wrong", "POST", "/v1/account/phone/verify", {"phone": "+40722" + suffix[:6], "code": "000000"}, token=ta)
    call("phone verify other", "POST", "/v1/account/phone/verify", {"phone": "+40733000000", "code": "000000"}, token=ta)
    call("phone delete", "DELETE", "/v1/account/phone", token=ta)
    call("discoverable missing", "PUT", "/v1/account/discoverable", {}, token=ta)
    call("discoverable ok", "PUT", "/v1/account/discoverable", {"discoverable": True}, token=ta)
    # --- username
    call("username bad", "PUT", "/v1/account/username", {"username": "1x"}, token=ta)
    call("username ok", "PUT", "/v1/account/username", {"username": "Ana_" + suffix}, token=ta)
    call("username taken", "PUT", "/v1/account/username", {"username": "ana_" + suffix}, token=tb)
    call("username lookup", "GET", "/v1/directory/username/ANA_" + suffix, token=tb)
    call("username lookup missing", "GET", "/v1/directory/username/zz_" + suffix, token=tb)
    call("username clear", "PUT", "/v1/account/username", {"username": None}, token=tb)
    # --- devices
    call("devices", "GET", "/v1/devices", token=ta)
    call("rename bad", "PUT", "/v1/devices/current", {"name": ""}, token=ta2)
    call("rename ok", "PUT", "/v1/devices/current", {"name": "renamed"}, token=ta2)
    call("delete dev bad", "DELETE", "/v1/devices/abc", token=ta)
    call("delete dev missing", "DELETE", "/v1/devices/99", token=ta)
    # --- keys
    spk = {"id": 1, "public_key": b64(b"\x05" + rb(60, 32)), "signature": b64(rb(61, 64))}
    kyb = {"id": 1, "public_key": b64(rb(62, 1569)), "signature": b64(rb(63, 64))}
    call("keys bad spk", "PUT", "/v1/keys", {"signed_prekey": dict(spk, signature=b64(b"x"))}, token=tb)
    call("keys too many", "PUT", "/v1/keys", {"prekeys": [{"id": i, "public_key": b64(b"\x05" + rb(i, 32))} for i in range(201)]}, token=tb)
    for t, who in ((ta, "a"), (ta2, "a2"), (tb, "b"), (tc, "c")):
        call(f"keys ok {who}", "PUT", "/v1/keys", {"signed_prekey": spk, "kyber_last_resort": kyb,
             "prekeys": [{"id": i, "public_key": b64(b"\x05" + rb(100 + i, 32))} for i in range(1, 4)],
             "kyber_prekeys": [{"id": 10 + i, "public_key": b64(rb(200 + i, 1569)), "signature": b64(rb(300 + i, 64))} for i in range(2)]}, token=t)
    call("keys count", "GET", "/v1/keys/count", token=tb)
    call("keys get one", "GET", f"/v1/keys/{B['account_id']}/1", token=ta)
    call("keys get all", "GET", f"/v1/keys/{A['account_id']}/*", token=tb)
    call("keys get own", "GET", f"/v1/keys/{A['account_id']}/*", token=ta)
    for i in range(4):
        call(f"keys drain {i}", "GET", f"/v1/keys/{B['account_id']}/1", token=tc)
    call("keys count after", "GET", "/v1/keys/count", token=tb)
    call("keys bad device", "GET", f"/v1/keys/{B['account_id']}/x", token=ta)
    call("keys unknown acct", "GET", "/v1/keys/00000000-0000-4000-8000-000000000000/1", token=ta)
    # --- directory & profile
    call("dir number", "GET", f"/v1/directory/number/{B['number']}", token=ta)
    call("dir number bad", "GET", "/v1/directory/number/12", token=ta)
    call("dir number missing", "GET", "/v1/directory/number/1234567890123456", token=ta)
    call("dir account", "GET", f"/v1/directory/account/{B['account_id']}", token=ta)
    call("dir phones", "POST", "/v1/directory/phones", {"hashes": [b64(hashlib.sha256(b"+40700000000").digest())]}, token=ta)
    call("dir phones empty", "POST", "/v1/directory/phones", {"hashes": []}, token=ta)
    call("dir phones bad", "POST", "/v1/directory/phones", {"hashes": [b64(b"short")]}, token=ta)
    call("dir phone", "GET", "/v1/directory/phone/" + base64.urlsafe_b64encode(hashlib.sha256(b"+40700000000").digest()).decode().rstrip("="), token=ta)
    call("profile missing", "GET", f"/v1/profile/{B['account_id']}", token=ta)
    call("profile put bad avatar", "PUT", "/v1/profile", {"data": b64(b"p"), "avatar_id": "nope"}, token=tb)
    call("profile put", "PUT", "/v1/profile", {"data": b64(rb(70, 100)), "avatar_id": None}, token=tb)
    call("profile get", "GET", f"/v1/profile/{B['account_id']}", token=ta)
    # --- messages
    msg = lambda d, reg, t=2: {"device_id": d, "registration_id": reg, "type": t, "content": b64(rb(80 + d, 50))}
    call("send no ts", "PUT", f"/v1/messages/{B['account_id']}", {"messages": [msg(1, 102)]}, token=ta)
    call("send mismatch", "PUT", f"/v1/messages/{A['account_id']}", {"timestamp": 1, "messages": [msg(5, 1)]}, token=tb)
    call("send stale", "PUT", f"/v1/messages/{A['account_id']}", {"timestamp": 1, "messages": [msg(1, 999), msg(2, 999)]}, token=tb)
    call("send bad type", "PUT", f"/v1/messages/{B['account_id']}", {"timestamp": 1, "messages": [msg(1, 102, 6)]}, token=ta)
    call("send empty content", "PUT", f"/v1/messages/{B['account_id']}", {"timestamp": 1, "messages": [dict(msg(1, 102), content="")]}, token=ta)
    call("send unknown", "PUT", "/v1/messages/00000000-0000-4000-8000-000000000000", {"timestamp": 1, "messages": []}, token=ta)
    call("send ok", "PUT", f"/v1/messages/{B['account_id']}", {"timestamp": 1700000000000, "messages": [msg(1, 102)]}, token=ta)
    call("send own", "PUT", f"/v1/messages/{A['account_id']}", {"timestamp": 1700000000001, "messages": [msg(2, 7)]}, token=ta)
    call("send online", "PUT", f"/v1/messages/{B['account_id']}", {"timestamp": 1700000000002, "online": True, "messages": [msg(1, 102)]}, token=ta)
    st, js = call("fetch", "GET", "/v1/messages", token=tb)
    call("fetch limit bad", "GET", "/v1/messages?limit=0", token=tb)
    call("fetch limit", "GET", "/v1/messages?limit=1", token=tb)
    if js and js.get("envelopes"):
        call("ack", "DELETE", "/v1/messages/" + js["envelopes"][0]["id"], token=tb)
    call("ack bad", "DELETE", "/v1/messages/xyz", token=tb)
    call("fetch after ack", "GET", "/v1/messages", token=tb)
    # --- groups
    call("group bad meta", "POST", "/v1/groups", {"metadata": "", "members": []}, token=ta)
    call("group bad member", "POST", "/v1/groups", {"metadata": b64(b"m"), "members": ["x"]}, token=ta)
    call("group unknown member", "POST", "/v1/groups", {"metadata": b64(b"m"), "members": ["00000000-0000-4000-8000-000000000000"]}, token=ta)
    st, g = call("group create", "POST", "/v1/groups", {"metadata": b64(rb(90, 40)), "avatar_id": None, "members": [B["account_id"]]}, token=ta)
    gid = g["group_id"]
    call("groups list", "GET", "/v1/groups", token=tb)
    call("group get", "GET", f"/v1/groups/{gid}", token=tb)
    call("group get nonmember", "GET", f"/v1/groups/{gid}", token=tc)
    call("group meta member", "PUT", f"/v1/groups/{gid}/metadata", {"metadata": b64(rb(91, 40)), "avatar_id": None}, token=tb)
    call("group settings nonadmin", "PUT", f"/v1/groups/{gid}/settings", {"only_admins_send": True}, token=tb)
    call("group settings", "PUT", f"/v1/groups/{gid}/settings", {"only_admins_edit": True, "disappearing_seconds": 3600, "hide_members": False, "member_names": "number"}, token=ta)
    call("group settings bad", "PUT", f"/v1/groups/{gid}/settings", {"disappearing_seconds": -5}, token=ta)
    call("group meta member denied", "PUT", f"/v1/groups/{gid}/metadata", {"metadata": b64(rb(92, 40))}, token=tb)
    call("group add", "POST", f"/v1/groups/{gid}/members", {"account_ids": [C["account_id"]]}, token=ta)
    call("group add dup", "POST", f"/v1/groups/{gid}/members", {"account_ids": [C["account_id"]]}, token=ta)
    call("group role bad", "PUT", f"/v1/groups/{gid}/members/{B['account_id']}/role", {"role": "owner"}, token=ta)
    call("group role", "PUT", f"/v1/groups/{gid}/members/{B['account_id']}/role", {"role": "admin"}, token=ta)
    st, devs = call("group devices", "GET", f"/v1/groups/{gid}/devices", token=ta)
    call("group send mismatch", "PUT", f"/v1/groups/{gid}/messages", {"timestamp": 1, "content": b64(b"c"), "recipients": []}, token=ta)
    recips = [d for d in (devs or {}).get("devices", []) if not (d["account_id"] == A["account_id"] and d["device_id"] == 1)]
    call("group send stale", "PUT", f"/v1/groups/{gid}/messages", {"timestamp": 1, "content": b64(b"c"), "recipients": [dict(r, registration_id=999) for r in recips]}, token=ta)
    call("group send ok", "PUT", f"/v1/groups/{gid}/messages", {"timestamp": 1700000000005, "content": b64(rb(93, 60)), "recipients": recips}, token=ta)
    call("fetch group env", "GET", "/v1/messages", token=tc)
    call("group remove nonadmin other", "DELETE", f"/v1/groups/{gid}/members/{A['account_id']}", token=tc)
    call("group leave", "DELETE", f"/v1/groups/{gid}/members/{C['account_id']}", token=tc)
    call("group get after", "GET", f"/v1/groups/{gid}", token=ta)
    # --- invites
    tok = rb(95, 32)
    call("invite nonadmin", "PUT", f"/v1/groups/{gid}/invite", {"token": b64(tok), "approval": True, "blob": b64(b"blob")}, token=tc)
    call("invite bad token", "PUT", f"/v1/groups/{gid}/invite", {"token": b64(b"x"), "approval": True, "blob": b64(b"blob")}, token=ta)
    call("invite put", "PUT", f"/v1/groups/{gid}/invite", {"token": b64(tok), "approval": True, "blob": b64(rb(96, 80))}, token=ta)
    call("invite lookup", "POST", "/v1/invites/lookup", {"token": b64(tok)}, token=tc)
    call("invite lookup missing", "POST", "/v1/invites/lookup", {"token": b64(rb(97, 32))}, token=tc)
    call("invite join", "POST", "/v1/invites/join", {"token": b64(tok), "intro": b64(rb(98, 30))}, token=tc)
    call("invite join again", "POST", "/v1/invites/join", {"token": b64(tok), "intro": b64(rb(98, 30))}, token=tc)
    call("invite requests nonadmin", "GET", f"/v1/groups/{gid}/requests", token=tc)
    call("invite requests", "GET", f"/v1/groups/{gid}/requests", token=ta)
    call("group get with invite", "GET", f"/v1/groups/{gid}", token=ta)
    call("invite approve", "POST", f"/v1/groups/{gid}/requests/{C['account_id']}/approve", token=ta)
    call("invite approve again", "POST", f"/v1/groups/{gid}/requests/{C['account_id']}/approve", token=ta)
    call("invite join member", "POST", "/v1/invites/join", {"token": b64(tok)}, token=tc)
    call("invite put open", "PUT", f"/v1/groups/{gid}/invite", {"token": b64(rb(99, 32)), "approval": False, "blob": b64(b"b")}, token=ta)
    call("invite old token", "POST", "/v1/invites/lookup", {"token": b64(tok)}, token=tc)
    call("invite delete", "DELETE", f"/v1/groups/{gid}/invite", token=ta)
    call("invite delete request missing", "DELETE", f"/v1/groups/{gid}/requests/{B['account_id']}", token=ta)
    # --- attachments
    call("att too big", "POST", "/v1/attachments", {"size": 10**12, "kind": "message"}, token=ta)
    call("att bad kind", "POST", "/v1/attachments", {"size": 10, "kind": "video"}, token=ta)
    call("att zero", "POST", "/v1/attachments", {"size": 0, "kind": "message"}, token=ta)
    st, att = call("att create", "POST", "/v1/attachments", {"size": 1000, "kind": "message"}, token=ta)
    aid = att["id"]
    call("att upload other", "PUT", f"/v1/attachments/{aid}", raw=rb(1, 1000), token=tb, headers={"Content-Type": "application/octet-stream"})
    call("att upload short", "PUT", f"/v1/attachments/{aid}", raw=rb(1, 10), token=ta, headers={"Content-Type": "application/octet-stream"})
    call("att upload long", "PUT", f"/v1/attachments/{aid}", raw=rb(1, 2000), token=ta, headers={"Content-Type": "application/octet-stream"})
    call("att download early", "GET", f"/v1/attachments/{aid}", token=tb)
    call("att upload ok", "PUT", f"/v1/attachments/{aid}", raw=rb(1, 1000), token=ta, headers={"Content-Type": "application/octet-stream"})
    call("att upload twice", "PUT", f"/v1/attachments/{aid}", raw=rb(1, 1000), token=ta, headers={"Content-Type": "application/octet-stream"})
    call("att download", "GET", f"/v1/attachments/{aid}", token=tb)
    call("att download bad", "GET", "/v1/attachments/xyz", token=tb)
    call("att download missing", "GET", "/v1/attachments/" + "0" * 32, token=tb)
    # --- vault
    call("vault bad id", "PUT", "/v1/vault/records", {"records": [{"id": "", "data": b64(b"x")}]}, token=ta)
    call("vault put", "PUT", "/v1/vault/records", {"records": [{"id": "r1", "data": b64(rb(5, 100))}, {"id": "r2", "data": None}, {"id": "r1", "data": b64(rb(6, 10))}]}, token=ta)
    call("vault get", "GET", "/v1/vault/records?since=0&limit=10", token=ta2)
    call("vault get bad", "GET", "/v1/vault/records?limit=0", token=ta2)
    # --- sealed sender
    call("cert", "GET", "/v1/certificate/delivery", token=tb)
    call("uak bad", "PUT", "/v1/account/unidentified-access", {"key": b64(b"x")}, token=tb)
    uak = rb(7, 16)
    call("uak ok", "PUT", "/v1/account/unidentified-access", {"key": b64(uak)}, token=tb)
    sealed = {"timestamp": 1700000000009, "messages": [dict(msg(1, 102), type=6)]}
    call("sealed no key", "PUT", f"/v1/sealed/messages/{B['account_id']}", sealed)
    call("sealed wrong key", "PUT", f"/v1/sealed/messages/{B['account_id']}", sealed, headers={"Unidentified-Access-Key": b64(rb(8, 16))})
    call("sealed not sealed", "PUT", f"/v1/sealed/messages/{B['account_id']}", {"timestamp": 1, "messages": [msg(1, 102)]}, headers={"Unidentified-Access-Key": b64(uak)})
    call("sealed ok", "PUT", f"/v1/sealed/messages/{B['account_id']}", sealed, headers={"Unidentified-Access-Key": b64(uak)})
    call("sealed keys", "GET", f"/v1/sealed/keys/{B['account_id']}/1", headers={"Unidentified-Access-Key": b64(uak)})
    call("sealed keys nokey", "GET", f"/v1/sealed/keys/{B['account_id']}/1")
    call("fetch sealed", "GET", "/v1/messages", token=tb)
    # --- totp
    st, ts = call("totp setup", "POST", "/v1/account/totp/setup", {}, token=tb)
    call("totp enable wrong", "POST", "/v1/account/totp/enable", {"code": "000000"}, token=tb)
    if ts and "secret" in ts:
        call("totp enable ok", "POST", "/v1/account/totp/enable", {"code": totp(ts["secret"])}, token=tb)
        call("login needs totp", "POST", "/v1/auth/login", {"number": B["number"], "auth_key": b64(rb(12, 32)), "device": {"name": "x", "platform": "web", "registration_id": 8}})
        call("login wrong totp", "POST", "/v1/auth/login", {"number": B["number"], "auth_key": b64(rb(12, 32)), "totp": "000000", "device": {"name": "x", "platform": "web", "registration_id": 8}})
        call("totp disable wrong", "DELETE", "/v1/account/totp", {"code": "000000"}, token=tb)
    call("account totp", "GET", "/v1/account", token=tb)
    # --- push, calls, provisioning, recovery
    call("push bad provider", "PUT", "/v1/devices/current/push", {"provider": "apns", "token": "t"}, token=ta)
    call("push ok", "PUT", "/v1/devices/current/push", {"provider": "fcm", "token": "tok-" + suffix}, token=ta)
    call("push delete", "DELETE", "/v1/devices/current/push", token=ta)
    call("ice", "GET", "/v1/calls/ice", token=ta)
    call("prov bad mode", "POST", "/v1/provisioning", {"mode": "weird"})
    st, pv = call("prov create new", "POST", "/v1/provisioning", {"mode": "new", "device_name": "phone"})
    call("prov create existing noauth", "POST", "/v1/provisioning", {"mode": "existing"})
    call("prov get missing", "GET", "/v1/provisioning/nope", token=ta)
    if pv and "id" in pv:
        call("prov get", "GET", f"/v1/provisioning/{pv['id']}", token=ta)
        call("prov poll nokey", "GET", f"/v1/provisioning/{pv['id']}/poll")
        call("prov poll", "GET", f"/v1/provisioning/{pv['id']}/poll", headers={"Authorization": "Bearer " + pv.get("poll_key", "")})
        call("prov approve bad", "POST", f"/v1/provisioning/{pv['id']}/payload", {"payload": ""}, token=ta)
        call("prov approve", "POST", f"/v1/provisioning/{pv['id']}/payload", {"payload": b64(rb(9, 100))}, token=ta)
        call("prov poll after", "GET", f"/v1/provisioning/{pv['id']}/poll", headers={"Authorization": "Bearer " + pv.get("poll_key", "")})
    call("link bad", "POST", "/v1/auth/link", {"link_token": "x", "device": {"name": "a", "platform": "web", "registration_id": 3}})
    call("recover challenge", "POST", "/v1/auth/recover/challenge", {"number": A["number"]})
    call("recover bad sig", "POST", "/v1/auth/recover", {"number": A["number"], "challenge": b64(rb(1, 32)), "signature": b64(rb(2, 64)),
         "kdf": kdf, "auth_key": b64(rb(3, 32)), "wrapped_account_key": b64(rb(4, 50)), "device": {"name": "r", "platform": "web", "registration_id": 9}})
    # --- unlink & deletion
    call("unlink a2", "DELETE", "/v1/devices/2", token=ta)
    call("a2 after unlink", "GET", "/v1/account", token=ta2)
    call("delete wrong", "DELETE", "/v1/account", {"auth_key": b64(rb(99, 32))}, token=tc)
    call("delete ok", "DELETE", "/v1/account", {"auth_key": b64(rb(50, 32))}, token=tc)
    call("deleted token", "GET", "/v1/account", token=tc)
    call("group after delete", "GET", f"/v1/groups/{gid}", token=ta)
    call("dir deleted", "GET", f"/v1/directory/account/{C['account_id']}", token=ta)

def main():
    go, rs = Srv(sys.argv[1]), Srv(sys.argv[2])
    suffix = "%06d" % random.randrange(10**6)
    outs = []
    for s in (go, rs):
        out = []
        try:
            scenario(s, out, suffix)
        except Exception as e:
            out.append(("SCENARIO CRASH", 0, {}, repr(e)))
        outs.append(out)
    n1, n2 = Norm(), Norm()
    diffs = 0
    for i in range(max(len(outs[0]), len(outs[1]))):
        a = outs[0][i] if i < len(outs[0]) else ("<missing>", None, None, None)
        b = outs[1][i] if i < len(outs[1]) else ("<missing>", None, None, None)
        na = (a[1], a[2], n1(a[3]))
        nb = (b[1], b[2], n2(b[3]))
        if a[0] != b[0] or na != nb:
            diffs += 1
            print(f"\n### DIFF #{i} {a[0]}")
            print("  GO  :", a[1], json.dumps(a[2]), json.dumps(na[2])[:600])
            print("  RUST:", b[1], json.dumps(b[2]), json.dumps(nb[2])[:600])
    print(f"\n{len(outs[0])} requests compared, {diffs} differences")

if __name__ == "__main__":
    main()
