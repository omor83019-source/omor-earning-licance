#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMOR EARNING - Telegram Admin Bot + License Backend (single file, Python 3.8+, stdlib only)

Copyright (c) OMOR EARNING. All rights reserved.
NOTE: This notice is a legal/copyright statement only. It is NOT encryption or
reverse-engineering protection.

Run:   python3 OMOR_EARNING_BOT.py
Needs: no pip packages. Files created at runtime next to this script:
       omor_earning.db (SQLite), omor_earning_config.json (token/admin/url, chmod 600)

Config (first match wins): environment variables -> saved config file -> interactive prompt
  BOT_TOKEN      Telegram bot token (from @BotFather). If missing, the script waits for the token on
                 stdin (hosting console: send  > TOKEN ); it is then saved in the config file.
  PUBLIC_URL     Public base URL of this backend, e.g. https://example.com  (can also be set
                 later from Telegram with: /seturl https://example.com)
  PORT           HTTP port (default: $PORT or 8080)
  HOST           bind address (default 0.0.0.0)
  ADMIN_ID       optional numeric admin Telegram ID (otherwise bound by /start from @Omor_Faruk789)
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ADMIN_USERNAME = "Omor_Faruk789"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("OMOR_DB", os.path.join(BASE_DIR, "omor_earning.db"))
CFG_PATH = os.environ.get("OMOR_CONFIG", os.path.join(BASE_DIR, "omor_earning_config.json"))
TG_BASE = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
MAX_BODY = 16 * 1024
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_PREFIX = "OMOR1"

_db_lock = threading.RLock()
_db = None
_cfg = {}
_cfg_lock = threading.Lock()
BOT_USERNAME = ""


def now():
    return int(time.time())


def fmt_time(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(ts)))


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def esc(s):
    return html.escape(str(s if s is not None else ""), quote=False)


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


# ----------------------------------------------------------------- config
def cfg_load():
    global _cfg
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            _cfg = json.load(f)
    except Exception:
        _cfg = {}


def cfg_save():
    with _cfg_lock:
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_cfg, f)
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, CFG_PATH)


def cfg_set(k, v):
    _cfg[k] = v
    cfg_save()


def detect_public_url():
    u = os.environ.get("PUBLIC_URL", "").strip()
    if u:
        return u
    for var, tpl in (("RENDER_EXTERNAL_URL", "{}"), ("RAILWAY_PUBLIC_DOMAIN", "https://{}"),
                     ("KOYEB_PUBLIC_DOMAIN", "https://{}"), ("FLY_APP_NAME", "https://{}.fly.dev")):
        v = os.environ.get(var, "").strip()
        if v:
            return tpl.format(v)
    return _cfg.get("public_url", "")


def norm_url(u):
    u = (u or "").strip().rstrip("/")
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.netloc:
        return ""
    return u


def setup_config():
    cfg_load()
    tok = os.environ.get("BOT_TOKEN", "").strip() or _cfg.get("bot_token", "")
    if not tok:
        # works in a terminal (hidden input) AND in hosting panels that forward text to stdin (e.g. "> TOKEN")
        print("BOT TOKEN not found. Send it now through the console input (hosting 'Cmd' box):  > 123456:ABC...", flush=True)
        try:
            if sys.stdin and sys.stdin.isatty():
                import getpass
                tok = getpass.getpass("Telegram BOT TOKEN (hidden input): ").strip()
            else:
                tok = (sys.stdin.readline() if sys.stdin else "").strip()
        except Exception:
            tok = ""
        tok = tok.lstrip("> ").strip()
        if not tok:
            print("ERROR: no BOT_TOKEN received. Restart, then send the token via the console input, "
                  "or set the BOT_TOKEN environment variable.")
            sys.exit(1)
    if not re.match(r"^\d{5,}:[A-Za-z0-9_-]{20,}$", tok):
        print("ERROR: BOT_TOKEN format looks invalid.")
        sys.exit(1)
    _cfg["bot_token"] = tok
    if os.environ.get("ADMIN_ID", "").strip().isdigit():
        _cfg["admin_id"] = int(os.environ["ADMIN_ID"].strip())
    url = norm_url(detect_public_url())
    if not url and sys.stdin and sys.stdin.isatty():
        url = norm_url(input("Public URL of this server (e.g. https://example.com) or press Enter to set later via /seturl: "))
    if url:
        _cfg["public_url"] = url
    cfg_save()


def token():
    return _cfg["bot_token"]


# --------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS conn_codes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  max_uses INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE NOT NULL, code_id INTEGER NOT NULL,
  device_id TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  verify_code TEXT, verify_exp INTEGER, tg_id INTEGER, tg_username TEXT, verified_at INTEGER);
CREATE TABLE IF NOT EXISTS users(
  tg_id INTEGER PRIMARY KEY, username TEXT, banned INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY, client_id INTEGER NOT NULL, tg_id INTEGER NOT NULL, tg_username TEXT,
  device_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL, decided_at INTEGER, notified INTEGER NOT NULL DEFAULT 0,
  admin_msg_id INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_request ON requests(tg_id) WHERE status IN ('pending','approved');
CREATE TABLE IF NOT EXISTS licenses(
  license_key TEXT PRIMARY KEY, tg_id INTEGER NOT NULL, request_id TEXT, created_at INTEGER NOT NULL,
  expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0, device_id TEXT, activated_at INTEGER);
"""


def db_init():
    global _db
    _db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    _db.row_factory = sqlite3.Row
    with _db_lock:
        _db.execute("PRAGMA journal_mode=WAL")
        _db.executescript(SCHEMA)
    try:
        os.chmod(DB_PATH, 0o600)
    except Exception:
        pass


def q(sql, args=(), one=False):
    with _db_lock:
        cur = _db.execute(sql, args)  # always parameterised -> no SQL injection
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    with _db_lock:
        return _db.execute(sql, args).rowcount


# ----------------------------------------------------------- telegram api
def tg(method, params=None, timeout=40):
    data = json.dumps(params or {}).encode("utf-8")
    req = urllib.request.Request("%s/bot%s/%s" % (TG_BASE, token(), method), data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"ok": False, "description": "HTTP %s" % e.code}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def send(chat_id, text, markup=None):
    p = {"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML", "disable_web_page_preview": True}
    if markup:
        p["reply_markup"] = markup
    return tg("sendMessage", p)


def admin_id():
    return _cfg.get("admin_id")


def is_admin(uid):
    return admin_id() is not None and uid == admin_id()


# ------------------------------------------------------------ rate limits
class Limiter:
    def __init__(self):
        self.h = {}
        self.l = threading.Lock()

    def hit(self, key, limit, window):
        t = time.time()
        with self.l:
            arr = [a for a in self.h.get(key, []) if t - a < window]
            if len(arr) >= limit:
                self.h[key] = arr
                return False
            arr.append(t)
            self.h[key] = arr
            if len(self.h) > 20000:
                self.h = {k: v for k, v in self.h.items() if v and t - v[-1] < 3600}
            return True

    def count(self, key, window):
        t = time.time()
        with self.l:
            return len([a for a in self.h.get(key, []) if t - a < window])


LIM = Limiter()


# ------------------------------------------------------------- core logic
def new_license_key():
    while True:
        parts = ["".join(secrets.choice(KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
        k = "OMOR-" + "-".join(parts)
        if not q("SELECT 1 FROM licenses WHERE license_key=?", (k,), one=True):
            return k


def make_connection_code(hours, max_uses):
    url = norm_url(_cfg.get("public_url", ""))
    if not url:
        return None, "Public URL is not set. Use /seturl https://your-public-url first."
    tokn = secrets.token_urlsafe(18)
    code = "%s.%s.%s" % (CODE_PREFIX, base64.urlsafe_b64encode(url.encode()).decode().rstrip("="), tokn)
    exp = now() + int(hours * 3600)
    x("INSERT INTO conn_codes(code_hash,created_at,expires_at,max_uses) VALUES(?,?,?,?)",
      (sha(tokn), now(), exp, max_uses))
    cid = q("SELECT id FROM conn_codes WHERE code_hash=?", (sha(tokn),), one=True)["id"]
    return (code, cid, exp), None


def session_from_token(tokn):
    if not tokn or len(tokn) > 200:
        return None
    c = q("SELECT c.*, cc.revoked AS code_revoked FROM clients c JOIN conn_codes cc ON cc.id=c.code_id "
          "WHERE c.token_hash=?", (sha(tokn),), one=True)
    if not c or c["code_revoked"]:
        return None
    x("UPDATE clients SET last_seen=? WHERE id=?", (now(), c["id"]))
    return c


def lic_state(lic, device_id=None, user=None):
    """Server-side license evaluation. Returns (valid, reason)."""
    if not lic:
        return False, "no_license"
    if lic["revoked"]:
        return False, "revoked"
    if lic["expires_at"] and lic["expires_at"] < now():
        return False, "expired"
    u = user or q("SELECT * FROM users WHERE tg_id=?", (lic["tg_id"],), one=True)
    if u and u["banned"]:
        return False, "banned"
    if device_id is not None and lic["device_id"] and lic["device_id"] != device_id:
        return False, "device_mismatch"
    return True, "ok"


def do_decision(req_id, approve, by_admin=True):
    """Atomic approve / reject. Returns (status, license_key or None, row)."""
    with _db_lock:
        r = q("SELECT * FROM requests WHERE id=?", (req_id,), one=True)
        if not r:
            return "not_found", None, None
        if r["status"] != "pending":
            lk = q("SELECT license_key FROM licenses WHERE request_id=?", (req_id,), one=True)
            return "already_" + r["status"], (lk["license_key"] if lk else None), r
        if approve:
            u = q("SELECT banned FROM users WHERE tg_id=?", (r["tg_id"],), one=True)
            if u and u["banned"]:
                return "banned", None, r
            key = new_license_key()
            x("INSERT INTO licenses(license_key,tg_id,request_id,created_at) VALUES(?,?,?,?)",
              (key, r["tg_id"], req_id, now()))
            x("UPDATE requests SET status='approved', decided_at=? WHERE id=?", (now(), req_id))
            return "approved", key, r
        x("UPDATE requests SET status='rejected', decided_at=? WHERE id=?", (now(), req_id))
        return "rejected", None, r


def notify_admin_request(req_id):
    """Send the admin notification exactly once (atomic claim on notified flag)."""
    aid = admin_id()
    if aid is None:
        return False
    if x("UPDATE requests SET notified=1 WHERE id=? AND notified=0 AND status='pending'", (req_id,)) != 1:
        return False
    r = q("SELECT * FROM requests WHERE id=?", (req_id,), one=True)
    text = ("🆕 <b>New License Request</b>\n\nRequest ID: <code>%s</code>\nUsername: @%s\nTelegram ID: <code>%s</code>\n"
            "Device: <code>%s</code>\nTime: %s") % (esc(r["id"]), esc(r["tg_username"] or "-"), r["tg_id"],
                                                  esc(r["device_id"][:12]), fmt_time(r["created_at"]))
    kb = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": "ap:" + r["id"]},
                               {"text": "❌ Reject", "callback_data": "rj:" + r["id"]}]]}
    res = send(aid, text, kb)
    if res.get("ok"):
        x("UPDATE requests SET admin_msg_id=? WHERE id=?", (res["result"]["message_id"], r["id"]))
        return True
    x("UPDATE requests SET notified=0 WHERE id=?", (r["id"],))  # retry later by the retry loop
    log("admin notify failed:", res.get("description"))
    return False


def retry_loop():
    while True:
        time.sleep(30)
        try:
            for r in q("SELECT id FROM requests WHERE status='pending' AND notified=0"):
                notify_admin_request(r["id"])
        except Exception as e:
            log("retry_loop error:", e)


# --------------------------------------------------------------- HTTP API
class ApiError(Exception):
    def __init__(self, status, code, msg=""):
        self.status, self.code, self.msg = status, code, msg


def need_str(body, key, maxlen=200, pattern=None):
    v = body.get(key)
    if not isinstance(v, str) or not v or len(v) > maxlen or (pattern and not re.match(pattern, v)):
        raise ApiError(400, "bad_" + key)
    return v


DEV_RE = r"^[A-Za-z0-9_-]{16,80}$"


def api_connect(body, ip):
    if LIM.count("cfail:" + ip, 600) >= 10:
        raise ApiError(429, "too_many_failures")
    code = need_str(body, "code", 400)
    device = need_str(body, "device_id", 80, DEV_RE)
    parts = code.strip().split(".")
    ok = False
    if len(parts) == 3 and parts[0] == CODE_PREFIX and 10 <= len(parts[2]) <= 80:
        with _db_lock:
            c = q("SELECT * FROM conn_codes WHERE code_hash=?", (sha(parts[2]),), one=True)
            if c and not c["revoked"] and c["expires_at"] > now() and c["used"] < c["max_uses"]:
                # a device that already has a session from this code does not use another slot
                x("UPDATE conn_codes SET used=used+1 WHERE id=?", (c["id"],))
                ok = True
    if not ok:
        LIM.hit("cfail:" + ip, 10 ** 6, 600)
        raise ApiError(403, "invalid_or_expired_code")
    tokn = secrets.token_urlsafe(32)
    x("INSERT INTO clients(token_hash,code_id,device_id,created_at,last_seen) VALUES(?,?,?,?,?)",
      (sha(tokn), c["id"], device, now(), now()))
    return {"ok": True, "token": tokn, "bot_username": BOT_USERNAME}


def api_verify_start(body, sess):
    if sess["tg_id"]:
        return {"ok": True, "verified": True, "tg_id": sess["tg_id"], "tg_username": sess["tg_username"],
                "bot_username": BOT_USERNAME}
    vc = sess["verify_code"]
    if not vc or (sess["verify_exp"] or 0) < now():
        vc = "".join(secrets.choice(KEY_ALPHABET) for _ in range(8))
        x("UPDATE clients SET verify_code=?, verify_exp=? WHERE id=?", (vc, now() + 900, sess["id"]))
    return {"ok": True, "verified": False, "verify_code": vc, "expires_in": 900, "bot_username": BOT_USERNAME,
            "link": ("https://t.me/%s?start=ver_%s" % (BOT_USERNAME, vc)) if BOT_USERNAME else ""}


def api_verify_status(body, sess):
    c = q("SELECT * FROM clients WHERE id=?", (sess["id"],), one=True)
    return {"ok": True, "verified": bool(c["tg_id"]), "tg_id": c["tg_id"], "tg_username": c["tg_username"]}


def api_license_request(body, sess):
    if not sess["tg_id"]:
        raise ApiError(403, "telegram_not_verified")
    u = q("SELECT * FROM users WHERE tg_id=?", (sess["tg_id"],), one=True)
    if u and u["banned"]:
        raise ApiError(403, "banned")
    with _db_lock:
        r = q("SELECT * FROM requests WHERE tg_id=? AND status IN ('pending','approved')", (sess["tg_id"],), one=True)
        if r:
            dup = True
        else:
            dup = False
            rid = "REQ-" + "".join(secrets.choice(KEY_ALPHABET) for _ in range(8))
            x("INSERT INTO requests(id,client_id,tg_id,tg_username,device_id,created_at) VALUES(?,?,?,?,?,?)",
              (rid, sess["id"], sess["tg_id"], sess["tg_username"], sess["device_id"], now()))
            r = q("SELECT * FROM requests WHERE id=?", (rid,), one=True)
    if not dup:
        threading.Thread(target=notify_admin_request, args=(r["id"],), daemon=True).start()
    return {"ok": True, "request_id": r["id"], "status": r["status"], "duplicate": dup,
            "created_at": r["created_at"]}


def api_license_status(body, sess):
    if not sess["tg_id"]:
        return {"ok": True, "state": "unverified"}
    lic = q("SELECT * FROM licenses WHERE tg_id=? ORDER BY created_at DESC", (sess["tg_id"],), one=True)
    if lic:
        valid, reason = lic_state(lic, sess["device_id"])
        # key is shown only to the verified Telegram owner of that license
        return {"ok": True, "state": "approved", "license_key": lic["license_key"], "valid": valid,
                "reason": reason, "device_bound": bool(lic["device_id"])}
    r = q("SELECT * FROM requests WHERE tg_id=? ORDER BY created_at DESC", (sess["tg_id"],), one=True)
    if not r:
        return {"ok": True, "state": "none"}
    return {"ok": True, "state": r["status"], "request_id": r["id"]}


def api_license_activate(body, sess):
    key = need_str(body, "license_key", 40, r"^OMOR-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")
    if not sess["tg_id"]:
        raise ApiError(403, "telegram_not_verified")
    with _db_lock:
        lic = q("SELECT * FROM licenses WHERE license_key=?", (key,), one=True)
        if not lic or lic["tg_id"] != sess["tg_id"]:
            raise ApiError(403, "license_not_for_this_user")
        valid, reason = lic_state(lic)
        if not valid:
            raise ApiError(403, reason)
        if lic["device_id"] and lic["device_id"] != sess["device_id"]:
            raise ApiError(403, "already_activated_on_another_device")
        if not lic["device_id"]:
            x("UPDATE licenses SET device_id=?, activated_at=? WHERE license_key=?",
              (sess["device_id"], now(), key))
    return {"ok": True, "valid": True}


def api_license_verify(body, sess):
    key = need_str(body, "license_key", 40, r"^OMOR-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")
    lic = q("SELECT * FROM licenses WHERE license_key=?", (key,), one=True)
    if not lic or not sess["tg_id"] or lic["tg_id"] != sess["tg_id"]:
        return {"ok": True, "valid": False, "reason": "invalid_license"}
    if not lic["device_id"]:
        return {"ok": True, "valid": False, "reason": "not_activated"}
    valid, reason = lic_state(lic, sess["device_id"])
    return {"ok": True, "valid": valid, "reason": reason, "expires_at": lic["expires_at"]}


ROUTES = {
    "/api/verify/start": api_verify_start,
    "/api/verify/status": api_verify_status,
    "/api/license/request": api_license_request,
    "/api/license/status": api_license_status,
    "/api/license/activate": api_license_activate,
    "/api/license/verify": api_license_verify,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "OmorEarning"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _ip(self):
        xf = self.headers.get("X-Forwarded-For", "")
        return (xf.split(",")[0].strip() if xf else self.client_address[0])[:64]

    def _out(self, status, obj):
        b = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_OPTIONS(self):
        self._out(204, {})

    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/health", "/api/health"):
            return self._out(200, {"ok": True, "service": "omor-earning-backend", "bot": BOT_USERNAME})
        self._out(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        ip = self._ip()
        try:
            path = self.path.split("?")[0]
            if not LIM.hit("ip:" + ip, 120, 60):
                raise ApiError(429, "rate_limited")
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                raise ApiError(413, "body_too_large")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                raise ApiError(400, "bad_json")
            if not isinstance(body, dict):
                raise ApiError(400, "bad_json")
            if path == "/api/connect":
                if not LIM.hit("conn:" + ip, 20, 60):
                    raise ApiError(429, "rate_limited")
                return self._out(200, api_connect(body, ip))
            fn = ROUTES.get(path)
            if not fn:
                raise ApiError(404, "not_found")
            auth = self.headers.get("Authorization", "")
            sess = session_from_token(auth[7:].strip()) if auth.startswith("Bearer ") else None
            if not sess:
                LIM.hit("authfail:" + ip, 10 ** 6, 600)
                if LIM.count("authfail:" + ip, 600) > 60:
                    raise ApiError(429, "rate_limited")
                raise ApiError(401, "unauthorized")
            if not LIM.hit("tok:%s" % sess["id"], 60, 60):
                raise ApiError(429, "rate_limited")
            return self._out(200, fn(body, sess))
        except ApiError as e:
            self._out(e.status, {"ok": False, "error": e.code})
        except Exception as e:
            log("api error:", repr(e))
            self._out(500, {"ok": False, "error": "server_error"})


# ------------------------------------------------------------ bot commands
HELP = ("<b>OMOR EARNING Admin Bot</b>\n\n"
        "/connect [hours] [max_uses] - new Connection Code (default 24h, 100 uses)\n"
        "/codes - list connection codes\n"
        "/revokecode ID - revoke a connection code (cuts off its clients)\n"
        "/requests - pending license requests\n"
        "/licenses - latest licenses\n"
        "/license KEY - license info\n"
        "/revoke KEY - revoke a license\n"
        "/resetdevice KEY - unbind device of a license\n"
        "/ban ID|@user - ban user\n"
        "/unban ID|@user - unban user\n"
        "/seturl URL - set the public backend URL\n"
        "/status - server status")


def find_user(arg):
    arg = (arg or "").strip()
    if arg.lstrip("-").isdigit():
        return int(arg)
    arg = arg.lstrip("@").lower()
    r = q("SELECT tg_id FROM users WHERE lower(username)=?", (arg,), one=True)
    return r["tg_id"] if r else None


def cmd_verify(msg, code):
    code = (code or "").strip().upper()
    u = msg["from"]
    if not re.match(r"^[A-Z0-9]{8}$", code):
        return send(msg["chat"]["id"], "Send: /verify CODE (the 8-character code shown in the extension).")
    if not LIM.hit("vtry:%s" % u["id"], 10, 600):
        return send(msg["chat"]["id"], "Too many attempts. Try later.")
    with _db_lock:
        c = q("SELECT * FROM clients WHERE verify_code=? AND verify_exp>?", (code, now()), one=True)
        if not c:
            return send(msg["chat"]["id"], "❌ Invalid or expired code. Create a new one in the extension.")
        uname = u.get("username") or ""
        x("INSERT INTO users(tg_id,username,created_at) VALUES(?,?,?) ON CONFLICT(tg_id) DO UPDATE SET username=excluded.username",
          (u["id"], uname, now()))
        x("UPDATE clients SET tg_id=?, tg_username=?, verified_at=?, verify_code=NULL WHERE id=?",
          (u["id"], uname, now(), c["id"]))
    send(msg["chat"]["id"], "✅ Telegram verified. Go back to the extension and press <b>Request License</b>.")


def cmd_admin(msg, cmd, arg):
    chat = msg["chat"]["id"]
    if cmd == "/help":
        return send(chat, HELP)
    if cmd == "/connect":
        nums = arg.split()
        try:
            hours = float(nums[0]) if nums else 24
            uses = int(nums[1]) if len(nums) > 1 else 100
            if not (0 < hours <= 24 * 90 and 1 <= uses <= 100000):
                raise ValueError
        except ValueError:
            return send(chat, "Usage: /connect [hours 1-2160] [max_uses]")
        res, err = make_connection_code(hours, uses)
        if err:
            return send(chat, "⚠️ " + esc(err))
        code, cid, exp = res
        return send(chat, "🔗 <b>Connection Code</b> (ID %d)\n\n<code>%s</code>\n\nExpires: %s\nMax uses: %d\n"
                          "Revoke: /revokecode %d\n\nPut this code in the extension's Connect screen. "
                          "It is not a bot token and gives no admin rights." % (cid, esc(code), fmt_time(exp), uses, cid))
    if cmd == "/codes":
        rows = q("SELECT * FROM conn_codes ORDER BY id DESC LIMIT 15")
        if not rows:
            return send(chat, "No codes yet. Use /connect")
        out = []
        for r in rows:
            st = "revoked" if r["revoked"] else ("expired" if r["expires_at"] < now() else "active")
            out.append("ID %d - %s - used %d/%d - exp %s" % (r["id"], st, r["used"], r["max_uses"], fmt_time(r["expires_at"])))
        return send(chat, "<b>Connection codes</b>\n" + esc("\n".join(out)))
    if cmd == "/revokecode":
        if not arg.strip().isdigit():
            return send(chat, "Usage: /revokecode ID")
        n = x("UPDATE conn_codes SET revoked=1 WHERE id=?", (int(arg),))
        return send(chat, "✅ Revoked." if n else "Not found.")
    if cmd == "/requests":
        rows = q("SELECT * FROM requests WHERE status='pending' ORDER BY created_at LIMIT 20")
        if not rows:
            return send(chat, "No pending requests.")
        for r in rows:
            kb = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": "ap:" + r["id"]},
                                       {"text": "❌ Reject", "callback_data": "rj:" + r["id"]}]]}
            send(chat, "<b>%s</b>\n@%s | <code>%s</code>\n%s" % (esc(r["id"]), esc(r["tg_username"] or "-"), r["tg_id"],
                                                                fmt_time(r["created_at"])), kb)
        return
    if cmd == "/licenses":
        rows = q("SELECT l.*, u.username, u.banned FROM licenses l LEFT JOIN users u ON u.tg_id=l.tg_id "
                 "ORDER BY l.created_at DESC LIMIT 20")
        if not rows:
            return send(chat, "No licenses yet.")
        out = []
        for r in rows:
            st = "revoked" if r["revoked"] else ("banned" if r["banned"] else "active")
            out.append("%s | @%s | %s | %s" % (r["license_key"], r["username"] or "-", st, "bound" if r["device_id"] else "unbound"))
        return send(chat, "<b>Licenses</b>\n<code>" + esc("\n".join(out)) + "</code>")
    if cmd in ("/license", "/revoke", "/resetdevice"):
        key = arg.strip().upper()
        lic = q("SELECT * FROM licenses WHERE license_key=?", (key,), one=True)
        if not lic:
            return send(chat, "License not found.")
        if cmd == "/revoke":
            x("UPDATE licenses SET revoked=1 WHERE license_key=?", (key,))
            return send(chat, "✅ License revoked.")
        if cmd == "/resetdevice":
            x("UPDATE licenses SET device_id=NULL, activated_at=NULL WHERE license_key=?", (key,))
            return send(chat, "✅ Device binding cleared. The owner can activate on a new device.")
        u = q("SELECT * FROM users WHERE tg_id=?", (lic["tg_id"],), one=True)
        valid, reason = lic_state(lic, None, u)
        return send(chat, "<b>License</b> <code>%s</code>\nUser: @%s (<code>%s</code>)\nStatus: %s (%s)\nType: Lifetime\n"
                          "Created: %s\nDevice: %s\nActivated: %s\nRequest: %s" % (
                              esc(key), esc(u["username"] if u else "-"), lic["tg_id"], "valid" if valid else "invalid",
                              reason, fmt_time(lic["created_at"]), esc((lic["device_id"] or "not bound")[:12]),
                              fmt_time(lic["activated_at"]), esc(lic["request_id"])))
    if cmd in ("/ban", "/unban"):
        tid = find_user(arg)
        if tid is None:
            return send(chat, "User not found (user must have verified at least once). Use the numeric ID.")
        if cmd == "/ban" and tid == admin_id():
            return send(chat, "You cannot ban the admin.")
        x("INSERT INTO users(tg_id,username,banned,created_at) VALUES(?,?,?,?) ON CONFLICT(tg_id) DO UPDATE SET banned=excluded.banned",
          (tid, "", 1 if cmd == "/ban" else 0, now()))
        return send(chat, ("🚫 Banned " if cmd == "/ban" else "✅ Unbanned ") + "<code>%s</code>" % tid)
    if cmd == "/seturl":
        u = norm_url(arg)
        if not u:
            return send(chat, "Usage: /seturl https://your-public-url")
        cfg_set("public_url", u)
        return send(chat, "✅ Public URL set: <code>%s</code>\nNew connection codes will use it. Old codes keep their old URL." % esc(u))
    if cmd == "/status":
        return send(chat, "Backend OK\nPublic URL: %s\nPending requests: %d\nLicenses: %d\nCodes: %d" % (
            esc(_cfg.get("public_url") or "NOT SET (use /seturl)"),
            q("SELECT count(*) c FROM requests WHERE status='pending'", one=True)["c"],
            q("SELECT count(*) c FROM licenses", one=True)["c"],
            q("SELECT count(*) c FROM conn_codes WHERE revoked=0 AND expires_at>?", (now(),), one=True)["c"]))
    send(chat, "Unknown command. /help")


def handle_message(msg):
    if "from" not in msg or msg.get("chat", {}).get("type") != "private":
        return
    u = msg["from"]
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"):
        return
    parts = text.split(None, 1)
    cmd = parts[0].split("@")[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    chat = msg["chat"]["id"]
    if cmd == "/start":
        # admin binding comes first, so the admin is recognised even if the first /start is a verify link
        if admin_id() is None and (u.get("username") or "").lower() == ADMIN_USERNAME.lower():
            cfg_set("admin_id", u["id"])
            log("Admin bound: id", u["id"])
            send(chat, "✅ Admin verified. Numeric ID saved: <code>%s</code>\n\n%s" % (u["id"], HELP))
            if arg.startswith("ver_"):
                cmd_verify(msg, arg[4:])
            return
        if arg.startswith("ver_"):
            return cmd_verify(msg, arg[4:])
        if is_admin(u["id"]):
            return send(chat, "Welcome back, admin.\n\n" + HELP)
        return send(chat, "Hello! To get a license, open the OMOR EARNING extension, connect, and use the "
                          "Telegram verify step. Then send /verify CODE here.")
    if cmd == "/verify":
        return cmd_verify(msg, arg)
    if cmd == "/myid":
        return send(chat, "Your Telegram ID: <code>%s</code>" % u["id"])
    if not is_admin(u["id"]):
        if cmd in ("/help", "/connect", "/codes", "/requests", "/licenses", "/license", "/revoke", "/revokecode",
                   "/resetdevice", "/ban", "/unban", "/seturl", "/status"):
            log("unauthorized admin command from", u["id"], cmd)
            return send(chat, "⛔ Not authorized.")
        return
    cmd_admin(msg, cmd, arg)


def handle_callback(cb):
    uid = cb["from"]["id"]
    if not is_admin(uid):
        tg("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Not authorized", "show_alert": True})
        log("unauthorized callback from", uid)
        return
    data = cb.get("data", "")
    m = re.match(r"^(ap|rj):(REQ-[A-Z0-9]{8})$", data)
    if not m:
        return tg("answerCallbackQuery", {"callback_query_id": cb["id"]})
    approve = m.group(1) == "ap"
    status, key, r = do_decision(m.group(2), approve)
    tg("answerCallbackQuery", {"callback_query_id": cb["id"], "text": status.replace("_", " ")})
    if r is None:
        return
    label = {"approved": "✅ APPROVED", "rejected": "❌ REJECTED", "already_approved": "✅ Already approved",
             "already_rejected": "❌ Already rejected", "banned": "🚫 User is banned"}.get(status, status)
    txt = "%s\nRequest <code>%s</code>\n@%s | <code>%s</code>" % (label, esc(r["id"]), esc(r["tg_username"] or "-"), r["tg_id"])
    if key:
        txt += "\nLicense: <code>%s</code>" % esc(key)
    if cb.get("message"):
        tg("editMessageText", {"chat_id": cb["message"]["chat"]["id"], "message_id": cb["message"]["message_id"],
                               "text": txt, "parse_mode": "HTML"})
    if status == "approved":
        send(r["tg_id"], "🎉 Your OMOR EARNING license was approved!\n\nLicense key: <code>%s</code>\n\n"
                         "It is also shown inside the extension." % esc(key))
    elif status == "rejected":
        send(r["tg_id"], "Your license request was rejected.")


def poll_loop():
    offset = 0
    while True:
        res = tg("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]}, timeout=40)
        if not res.get("ok"):
            log("getUpdates error:", res.get("description"))
            time.sleep(5)
            continue
        for upd in res["result"]:
            offset = upd["update_id"] + 1
            try:
                if "message" in upd:
                    handle_message(upd["message"])
                elif "callback_query" in upd:
                    handle_callback(upd["callback_query"])
            except Exception as e:
                log("update error:", repr(e))


def main():
    global BOT_USERNAME
    setup_config()
    db_init()
    me = tg("getMe")
    if not me.get("ok"):
        print("ERROR: Telegram rejected the bot token / cannot reach Telegram:", me.get("description"))
        sys.exit(1)
    BOT_USERNAME = me["result"].get("username", "")
    tg("deleteWebhook", {})
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "0.0.0.0")
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=retry_loop, daemon=True).start()
    log("Bot @%s started. HTTP API on %s:%d" % (BOT_USERNAME, host, port))
    log("Public URL:", _cfg.get("public_url") or "NOT SET (admin: /seturl https://...)")
    if admin_id() is None:
        log("Waiting for admin: send /start to the bot from @%s" % ADMIN_USERNAME)
    try:
        poll_loop()
    except KeyboardInterrupt:
        log("bye")


if __name__ == "__main__":
    main()
