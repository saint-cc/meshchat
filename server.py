import asyncio
import base64
import glob
import hashlib
import json
import logging
import multiprocessing
import os
import re
import secrets
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import websockets
from flask import Flask, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

# ══════════════════════════════════════════
#   CONFIGURATION
# ══════════════════════════════════════════

# HTTP server
HTTP_HOST  = "0.0.0.0"
HTTP_PORT  = int(os.environ.get("HTTP_PORT", 8000))
HTTP_DEBUG = False
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# WebSocket signal server
WS_HOST = "0.0.0.0"
WS_PORT = int(os.environ.get("WS_PORT", 8888))

# Relay identity — sent to clients on request
RELAY_WSS_URL = os.environ.get("RELAY_WSS_URL", "")   # e.g. wss://yourrelay.example.com/ws/

# Connection limits
MAX_CONNECTIONS        = int(os.environ.get("MAX_CONNECTIONS",        50))   # total WS sessions
MAX_CONNECTIONS_PER_IP = int(os.environ.get("MAX_CONNECTIONS_PER_IP", 15))   # per source IP

# Rate limiter
RATE_LIMIT_RATE  = 10   # tokens refilled per second
RATE_LIMIT_BURST = 20   # max burst size

# WebSocket
WS_MAX_SIZE = int(os.environ.get("WS_MAX_SIZE", 2 * 1024 * 1024))   # 2 MB per frame

# ID validation — base64url chars only, 8–64 chars
_ID_RE = re.compile(r'^[A-Za-z0-9\-_]{8,64}$')
def valid_id(s): return isinstance(s, str) and bool(_ID_RE.match(s))

# Online presence
ONLINE_EXPIRY_SECONDS = 300   # prune peers not seen within this window

# Offline buffer — file-based queue for messages to offline clients
BUF_DIR      = os.environ.get("BUF_DIR",      os.path.join(os.getcwd(), "relay_buf"))
BUF_MAX_MSGS = int(os.environ.get("BUF_MAX_MSGS", 100))     # max packets per recipient
BUF_MAX_AGE  = int(os.environ.get("BUF_MAX_AGE",  86400))   # seconds before expiry (24h)
BUF_MAX_MB   = float(os.environ.get("BUF_MAX_MB",  10))     # max MB per recipient
BUF_EXPIRE_INTERVAL = 300                                    # seconds between expiry sweeps

# app:migrate packets get their own (much longer) TTL — they're address
# corrections, not conversation, and are useless if lost. 1 week for now
# while testing; production target is closer to a year.
BUF_MAX_AGE_MIGRATE = int(os.environ.get("BUF_MAX_AGE_MIGRATE", 7 * 86400))
MIGRATE_SUFFIX       = "_migrate.json"   # filename tag — lets buf_expire pick the TTL bucket without opening the file

# Logging
LOG_FORMAT   = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATE_FMT = "%H:%M:%S"
LOG_LEVEL    = logging.INFO

# Auth
AUTH_TIMEOUT = 15   # seconds to complete challenge-response before disconnect

# Stats interval
STATS_INTERVAL = 60   # seconds between periodic stat dumps

# ══════════════════════════════════════════
#   LOGGING SETUP
# ══════════════════════════════════════════

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FMT)

class _HandshakeFilter(logging.Filter):
    def filter(self, record):
        return "opening handshake failed" not in record.getMessage()

logging.getLogger("websockets.server").addFilter(_HandshakeFilter())
logging.getLogger("websockets.asyncio.server").addFilter(_HandshakeFilter())

log = logging.getLogger("signal")

# ══════════════════════════════════════════
#   SIGNAL SERVER STATE
# ══════════════════════════════════════════

connected: dict[str, set] = {}   # publicId → set of websockets
pending_auth: dict = {}          # ws → { enc_key, nonce, ts, bits }
ip_conns: dict[str, int] = {}    # ip → active connection count

stats = {
    "bytes_in":  0, "bytes_out": 0,
    "msgs_in":   0, "msgs_out":  0,
    "buf_in":    0, "buf_out":   0,
}

# ══════════════════════════════════════════
#   HELPERS
# ══════════════════════════════════════════

def fmt_bytes(b):
    if b < 1024:    return f"{b}B"
    if b < 1024**2: return f"{b/1024:.1f}KB"
    return f"{b/1024**2:.1f}MB"

def short(id_str):
    if not id_str: return "?"
    return id_str[:8] + "…"

def peer_info(ws):
    try:
        headers = ws.request.headers
        ip = (headers.get("X-Real-IP")
              or headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or ws.remote_address[0])
        return ip
    except Exception:
        try:    return str(ws.remote_address)
        except: return "unknown"

def unique_keys():
    """Number of distinct registered public IDs."""
    return len(connected)

def session_count():
    """Total number of active WebSocket connections (one client may have 2)."""
    return sum(len(s) for s in connected.values())

# ══════════════════════════════════════════
#   RATE LIMITER
# ══════════════════════════════════════════

class RateLimiter:
    def __init__(self, rate=RATE_LIMIT_RATE, burst=RATE_LIMIT_BURST):
        self.rate = rate; self.burst = burst
        self.tokens = burst; self.last_time = time.monotonic()

    def allow(self):
        now = time.monotonic()
        elapsed = now - self.last_time
        self.last_time = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

# ══════════════════════════════════════════
#   ROUTING HELPERS
# ══════════════════════════════════════════

async def send_to(ws, obj):
    try:
        raw = json.dumps(obj, separators=(",", ":"))
        await ws.send(raw)
        stats["bytes_out"] += len(raw)
        stats["msgs_out"]  += 1
        return True
    except Exception as e:
        log.warning("  send failed: %s", e)
        # actively prune dead socket from all registered IDs
        for id_, sockets in list(connected.items()):
            sockets.discard(ws)
            if not sockets:
                del connected[id_]
        return False

async def deliver(to_id, obj, exclude=None):
    sessions = connected.get(to_id, set())
    reached  = 0
    for ws in list(sessions):
        if ws is exclude: continue
        if await send_to(ws, obj): reached += 1
    return reached

async def route_or_buffer(kind, frm, to, msg, ws):
    """Shared delivery path for from-authenticated, to-routed packet types
    (app:message, app:migrate). Delivers live if the recipient is
    connected, otherwise falls back to the offline buffer — buf_write
    handles per-type overwrite/TTL behaviour on its own."""
    reached = await deliver(to, msg, exclude=ws)
    if reached:
        log.info("%-10s from=%s  to=%s  reached=%d", kind.upper(), short(frm), short(to), reached)
    else:
        buf_write(to, msg)
        log.info("BUF Q      from=%s  to=%s  (offline)  type=%s", short(frm), short(to), kind)

# ══════════════════════════════════════════
#   AUTH HELPERS
#   derive_public_id  — mirrors client JS logic exactly
#   auth_challenge    — encrypt nonce to client's enc key, store pending
#   auth_verify       — check proof, register, flush buffer
# ══════════════════════════════════════════

def derive_public_id(enc_key_bytes: bytes) -> str:
    """SHA-256(enc_key)[0..12] encoded as base64url — mirrors client derivePublicId()."""
    digest = hashlib.sha256(enc_key_bytes).digest()[:12]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

async def auth_challenge(ws, enc_key_bytes: bytes, bits: int):
    """Generate a random nonce, encrypt it to the client's enc key, send challenge."""
    nonce_plain = secrets.token_bytes(32)
    iv          = secrets.token_bytes(12)
    aesgcm      = AESGCM(enc_key_bytes)
    ciphertext  = aesgcm.encrypt(iv, nonce_plain, None)
    pending_auth[id(ws)] = {
        "enc_key": enc_key_bytes,
        "nonce":   nonce_plain,
        "ts":      time.monotonic(),
        "bits":    bits,
    }
    await send_to(ws, {
        "type": "sig:auth_challenge",
        "bits": bits,
        "iv":   list(iv),
        "data": list(ciphertext),
    })
    log.info("AUTH       challenge sent  bits=%d  peer=%s", bits, peer_info(ws))

async def auth_verify(ws, nonce_back: list, addr: str) -> str | None:
    """Verify proof, register identity, flush buffer. Returns public_id or None on failure."""
    entry = pending_auth.pop(id(ws), None)
    if not entry:
        log.warning("AUTH       proof with no pending challenge  peer=%s", addr)
        return None
    if time.monotonic() - entry["ts"] > AUTH_TIMEOUT:
        log.warning("AUTH       challenge expired  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "timeout"})
        return None
    if bytes(nonce_back) != entry["nonce"]:
        log.warning("AUTH       proof mismatch  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "proof_invalid"})
        return None

    public_id = derive_public_id(entry["enc_key"])
    if public_id not in connected:
        connected[public_id] = set()
    connected[public_id].add(ws)
    log.info("AUTH OK    id=%s  bits=%d  peer=%s  keys=%d  sessions=%d",
             short(public_id), entry["bits"], addr, unique_keys(), session_count())
    await send_to(ws, {"type": "sig:auth_ok", "public_id": public_id})
    await buf_deliver(public_id, ws)
    return public_id

# ══════════════════════════════════════════
#   OFFLINE BUFFER
#   Layout: BUF_DIR/<publicId>/<ts>_<uuid>.json
#   Limits: BUF_MAX_MSGS, BUF_MAX_AGE, BUF_MAX_MB per recipient.
#   On connect: flush all buffered packets oldest-first, delete on success.
#   Expiry sweep: background task removes files older than their TTL bucket.
#
#   app:migrate packets are tagged <ts>_<uuid>_migrate.json (MIGRATE_SUFFIX):
#     - overwrite: only the latest packet per sender is kept (buf_write)
#     - longer TTL: BUF_MAX_AGE_MIGRATE instead of BUF_MAX_AGE (buf_expire)
#   Everything else (count/size limits, delivery, flush-on-connect) is
#   identical to regular packets — same files, same directory, same flow.
# ══════════════════════════════════════════

def buf_dir(to_id):
    path = os.path.realpath(os.path.join(BUF_DIR, to_id))
    if not path.startswith(os.path.realpath(BUF_DIR) + os.sep):
        raise ValueError(f"path traversal attempt: {to_id!r}")
    return path

def buf_files(to_id):
    """Return list of buffer files for recipient, oldest first."""
    d = buf_dir(to_id)
    if not os.path.isdir(d): return []
    pattern = os.path.join(d, "*.json")
    return sorted(glob.glob(pattern, recursive=False))

def buf_write(to_id, msg):
    """Write a packet to the offline buffer. Enforces per-recipient limits.

    app:migrate packets use overwrite semantics: only the most recent
    packet from a given sender is kept (any older buffered migrate from
    that same sender is dropped first), and they're tagged with
    MIGRATE_SUFFIX so buf_expire applies the longer TTL bucket."""
    try:
        d = buf_dir(to_id)
    except ValueError as e:
        log.warning("BUF        rejected  to=%s  reason=%s", short(to_id), e)
        return
    try:
        os.makedirs(d, exist_ok=True)
    except Exception as e:
        log.warning("BUF        mkdir failed  to=%s  err=%s", short(to_id), e)
        return

    is_migrate = msg.get("type") == "app:migrate"
    frm        = msg.get("from")

    files = buf_files(to_id)

    if is_migrate and frm:
        # overwrite — drop any existing buffered migrate packet(s) from this sender
        for fpath in files:
            if not fpath.endswith(MIGRATE_SUFFIX):
                continue
            try:
                with open(fpath) as f:
                    old = json.load(f)
            except Exception:
                continue
            if old.get("from") == frm:
                try:
                    os.remove(fpath)
                    log.info("BUF        migrate overwrite  to=%s  from=%s", short(to_id), short(frm))
                except Exception:
                    pass
        files = buf_files(to_id)   # refresh after removals

    # enforce message count limit — drop oldest
    while len(files) >= BUF_MAX_MSGS:
        try:
            os.remove(files.pop(0))
            log.info("BUF        drop oldest (count limit)  to=%s", short(to_id))
        except Exception:
            pass

    # enforce size limit
    total = sum(os.path.getsize(f) for f in files if os.path.exists(f))
    raw   = json.dumps(msg).encode()
    if total + len(raw) > BUF_MAX_MB * 1024 * 1024:
        log.warning("BUF        size limit reached  to=%s  dropping", short(to_id))
        return

    suffix = MIGRATE_SUFFIX if is_migrate else ".json"
    fname  = os.path.join(d, f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}{suffix}")
    try:
        with open(fname, "w") as f:
            json.dump(msg, f)
        stats["buf_in"] += 1
        log.info("BUF        write  to=%s  file=%s%s", short(to_id), os.path.basename(fname),
                  "  [migrate]" if is_migrate else "")
    except Exception as e:
        log.warning("BUF        write failed  to=%s  err=%s", short(to_id), e)

async def buf_deliver(to_id, ws):
    """Flush all buffered packets for a reconnecting client. Delete on success."""
    files = buf_files(to_id)
    if not files:
        return
    log.info("BUF        flush  to=%s  count=%d", short(to_id), len(files))
    for fpath in files:
        try:
            with open(fpath) as f:
                msg = json.load(f)
            if await send_to(ws, msg):
                os.remove(fpath)
                stats["buf_out"] += 1
        except Exception as e:
            log.warning("BUF        flush error  to=%s  file=%s  err=%s",
                        short(to_id), os.path.basename(fpath), e)

async def buf_expire():
    """Background task — remove buffer files older than their TTL bucket.
    Regular packets use BUF_MAX_AGE; migrate packets (tagged via
    MIGRATE_SUFFIX) use the much longer BUF_MAX_AGE_MIGRATE."""
    while True:
        await asyncio.sleep(BUF_EXPIRE_INTERVAL)
        now     = time.time()
        dropped = 0
        try:
            if not os.path.isdir(BUF_DIR): continue
            for rec_dir in os.scandir(BUF_DIR):
                if not rec_dir.is_dir():
                    continue
                for entry in os.scandir(rec_dir.path):
                    if not entry.name.endswith(".json"):
                        continue
                    max_age = BUF_MAX_AGE_MIGRATE if entry.name.endswith(MIGRATE_SUFFIX) else BUF_MAX_AGE
                    if now - entry.stat().st_mtime > max_age:
                        try:
                            os.remove(entry.path)
                            dropped += 1
                        except Exception:
                            pass
                # clean up empty recipient dirs
                if not os.listdir(rec_dir.path):
                    try: os.rmdir(rec_dir.path)
                    except Exception: pass
        except Exception as e:
            log.warning("BUF        expire sweep error: %s", e)
        if dropped:
            log.info("BUF        expired %d file(s)", dropped)

# ══════════════════════════════════════════
#   STATS
# ══════════════════════════════════════════

async def log_stats():
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        log.info("STATS      keys=%d  sessions=%d  in=%s(%d msgs)  out=%s(%d msgs)  "
                 "buf_in=%d  buf_out=%d",
                 unique_keys(), session_count(),
                 fmt_bytes(stats["bytes_in"]),  stats["msgs_in"],
                 fmt_bytes(stats["bytes_out"]), stats["msgs_out"],
                 stats["buf_in"], stats["buf_out"])

# ══════════════════════════════════════════
#   WEBSOCKET HANDLER
# ══════════════════════════════════════════

async def handler(ws):
    client_ids = []   # public_ids authed this socket, sequential (128-bit first if any)
    limiter    = RateLimiter()
    addr       = peer_info(ws)

    # ── connection limits ──
    if session_count() >= MAX_CONNECTIONS:
        log.warning("LIMIT      max_connections=%d reached  peer=%s", MAX_CONNECTIONS, addr)
        await ws.close(1013, "server full")
        return

    ip_conns[addr] = ip_conns.get(addr, 0) + 1
    if ip_conns[addr] > MAX_CONNECTIONS_PER_IP:
        log.warning("LIMIT      per_ip=%d reached  peer=%s", MAX_CONNECTIONS_PER_IP, addr)
        ip_conns[addr] -= 1
        await ws.close(1013, "too many connections from your address")
        return

    log.info("CONNECT    peer=%s  sessions=%d/%d  from_ip=%d/%d",
             addr, session_count(), MAX_CONNECTIONS,
             ip_conns[addr], MAX_CONNECTIONS_PER_IP)

    def is_authed():
        return len(client_ids) > 0

    def last_id():
        return client_ids[-1] if client_ids else None

    try:
        async for raw in ws:

            if not limiter.allow():
                log.warning("RATELIMIT  peer=%s  ids=%s", addr, client_ids)
                await send_to(ws, {"type": "error", "reason": "rate_limited"})
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("BAD JSON   peer=%s  raw=%r", addr, raw[:120])
                continue

            if len(raw) > WS_MAX_SIZE:
                log.warning("OVERSIZE   peer=%s  size=%d  dropped", addr, len(raw))
                continue

            stats["bytes_in"] += len(raw)
            stats["msgs_in"]  += 1

            kind = msg.get("type", "?")
            log.info("IN  %-20s peer=%s  size=%-8s total_in=%s  total_out=%s",
                     kind, addr,
                     fmt_bytes(len(raw)),
                     fmt_bytes(stats["bytes_in"]),
                     fmt_bytes(stats["bytes_out"]))

            # ── auth_init: client presents enc key, server sends challenge ──
            if kind == "sig:auth_init":
                enc_key_list = msg.get("enc_key")
                bits         = msg.get("bits", 256)
                if not enc_key_list or bits not in (128, 256):
                    log.warning("AUTH       bad auth_init  peer=%s", addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_init"})
                    continue
                enc_key_bytes = bytes(enc_key_list)
                expected_len  = 16 if bits == 128 else 32
                if len(enc_key_bytes) != expected_len:
                    log.warning("AUTH       wrong key length  bits=%d  got=%d  peer=%s",
                                bits, len(enc_key_bytes), addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_key_length"})
                    continue
                await auth_challenge(ws, enc_key_bytes, bits)

            # ── auth_proof: client returns decrypted nonce ──
            elif kind == "sig:auth_proof":
                nonce_back = msg.get("nonce")
                if not nonce_back:
                    log.warning("AUTH       empty proof  peer=%s", addr)
                    continue
                public_id = await auth_verify(ws, nonce_back, addr)
                if public_id:
                    client_ids.append(public_id)

            # ── everything below requires at least one authed identity ──
            elif not is_authed():
                frm = msg.get("from", "?")
                log.warning("UNAUTHED   type=%r  from=%s  peer=%s  dropped", kind, short(frm), addr)
                await send_to(ws, {"type": "sig:auth_fail", "reason": "not_authenticated"})

            # ── message / migrate: from must match an authed identity on this socket ──
            elif kind in ("app:message", "app:migrate"):
                frm = msg.get("from", "?")
                to  = msg.get("to")
                if not valid_id(to):
                    log.warning("  %s with invalid 'to', dropped", kind)
                    continue
                if frm not in client_ids:
                    log.warning("%-10s from=%s  not authed  peer=%s  dropped", kind.upper(), short(frm), addr)
                    await send_to(ws, {"type": "error", "reason": "not_authenticated"})
                    continue
                await route_or_buffer(kind, frm, to, msg, ws)

            elif kind == "sig:announce":
                ids = msg.get("ids", [])
                if not isinstance(ids, list):
                    log.warning("  announce bad payload, dropped")
                    continue
                ids     = [i for i in ids[:10] if valid_id(i)]
                matched = [i for i in ids if i in connected]
                for matched_id in matched:
                    await deliver(matched_id, {"type": "sig:seen", "id": last_id()}, exclude=ws)

            elif kind in ("app:sync", "sync:backup_offer", "sync:backup_accept",
                          "sync:backup_push", "sync:restore_req",
                          "sync:restore_ack", "sync:restore_push",
                          "sync:token_req", "sync:token_resp"):
                frm = msg.get("from", "?")
                to  = msg.get("to")
                if not valid_id(to):
                    log.warning("  %s with invalid 'to', dropped", kind)
                    continue
                reached = await deliver(to, msg, exclude=ws)
                log.info("%-12s from=%s  to=%s  reached=%d",
                         kind.upper()[:12], short(frm), short(to), reached)

            elif kind == "sig:relay_req":
                if RELAY_WSS_URL:
                    await send_to(ws, {"type": "sig:relay_info", "wss": RELAY_WSS_URL})
                    log.info("RELAY_INFO sent to %s", short(last_id()))
                else:
                    log.debug("RELAY_INFO requested but not configured, skipped")

            elif kind == "sig:ping":
                await send_to(ws, {"type": "sig:pong"})

            else:
                log.warning("UNKNOWN    type=%r  peer=%s  dropped", kind, addr)

    except websockets.exceptions.ConnectionClosedOK:
        log.info("CLOSE OK   peer=%s  ids=%s", addr, client_ids)
    except websockets.exceptions.ConnectionClosedError as e:
        log.warning("CLOSE ERR  peer=%s  ids=%s  reason=%s", addr, client_ids, e)
    except Exception as e:
        log.error("HANDLER EX peer=%s  ids=%s  error=%s", addr, client_ids, e)
    finally:
        # release per-IP slot
        if addr in ip_conns:
            ip_conns[addr] -= 1
            if ip_conns[addr] <= 0:
                del ip_conns[addr]
        # clean up any pending challenge if socket dropped mid-auth
        pending_auth.pop(id(ws), None)
        # unregister all authed identities on this socket
        for cid in client_ids:
            if cid in connected:
                connected[cid].discard(ws)
                remaining = len(connected[cid])
                if remaining == 0:
                    del connected[cid]
                    log.info("REMOVED    id=%s  peer=%s  total=%d",
                             short(cid), addr, session_count())
                else:
                    log.info("SESSION-   id=%s  peer=%s  sessions_left=%d",
                             short(cid), addr, remaining)

# ══════════════════════════════════════════
#   SIGNAL SERVER ENTRYPOINT (async)
# ══════════════════════════════════════════

async def run_signal_server():
    #os.makedirs(BUF_DIR, exist_ok=True)
    log.info("=" * 50)
    log.info("MeshChat signal server")
    log.info("Listening on %s:%d", WS_HOST, WS_PORT)
    log.info("Buffer dir: %s  max_msgs=%d  max_age=%ds  migrate_age=%ds  max_mb=%.1f",
             BUF_DIR, BUF_MAX_MSGS, BUF_MAX_AGE, BUF_MAX_AGE_MIGRATE, BUF_MAX_MB)
    log.info("=" * 50)
    async with websockets.serve(handler, WS_HOST, WS_PORT):
        asyncio.create_task(log_stats())
        asyncio.create_task(buf_expire())
        await asyncio.Future()

# ══════════════════════════════════════════
#   HTTP SERVER (Flask, separate process)
# ══════════════════════════════════════════

def run_http_server():
    """Runs in its own process so Flask's WSGI loop doesn't block asyncio."""
    http_log = logging.getLogger("http")
    http_log.info("HTTP server starting on %s:%d  static=%s", HTTP_HOST, HTTP_PORT, STATIC_DIR)

    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.after_request
    def no_cache(r):
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return r
        
    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/<path:path>")
    def static_proxy(path):
        file_path = os.path.join(app.static_folder, path)
        if os.path.isfile(file_path):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

    app.run(host=HTTP_HOST, port=HTTP_PORT, debug=HTTP_DEBUG)

# ══════════════════════════════════════════
#   MAIN
# ══════════════════════════════════════════

if __name__ == "__main__":
    http_proc = multiprocessing.Process(target=run_http_server, name="http", daemon=True)
    http_proc.start()
    log.info("HTTP       process started  pid=%d", http_proc.pid)

    try:
        asyncio.run(run_signal_server())
    except KeyboardInterrupt:
        log.info("Shutting down")
        log.info("FINAL      in=%s(%d msgs)  out=%s(%d msgs)  buf_in=%d  buf_out=%d",
                 fmt_bytes(stats["bytes_in"]),  stats["msgs_in"],
                 fmt_bytes(stats["bytes_out"]), stats["msgs_out"],
                 stats["buf_in"], stats["buf_out"])
    finally:
        http_proc.terminate()
        http_proc.join()