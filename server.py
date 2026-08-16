import asyncio
import base64
import glob
import hashlib
import ipaddress
import json
import logging
import multiprocessing
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)
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

# Protocol version — informational only for now, surfaced in sig:relay_info
# so client/server version drift shows up in both logs. Not enforced yet;
# room to add real backwards-compat handling once this is actually needed.
PROTOCOL_VERSION = os.environ.get("PROTOCOL_VERSION", "0.4.5")

# Connection limits
MAX_CONNECTIONS        = int(os.environ.get("MAX_CONNECTIONS",        100))   # total WS sessions
MAX_CONNECTIONS_PER_IP = int(os.environ.get("MAX_CONNECTIONS_PER_IP", 15))   # per source IP

# Trusted proxy addresses/ranges — X-Real-IP / X-Forwarded-For are only
# honoured when the actual TCP peer falls inside one of these. Without
# this, anyone who can reach WS_PORT directly (not just through nginx) can
# set an arbitrary X-Real-IP per connection and make MAX_CONNECTIONS_PER_IP
# (and per-IP rate limiting below) a no-op — every "different IP" they
# claim gets its own fresh allowance.
# Accepts a mix of bare IPs and CIDR ranges, e.g.
# "127.0.0.1,::1,192.168.1.20,172.20.0.0/16" — a bare IP is treated as its
# own /32 (or /128) network. CIDR support matters for anyone running nginx
# in a container: the peer address the relay actually sees there is nginx's
# address on the docker network (or the bridge gateway), which can drift
# across redeploys even when the subnet itself stays fixed — a range
# survives that, an exact single-IP match doesn't.
# Default assumes nginx runs on the same host as this process (matches the
# README's reverse-proxy setup); add whatever else applies to your topology.
_TRUSTED_PROXIES_INVALID = []   # entries that failed to parse — logged once the logger exists, below

def _parse_trusted_proxies(raw):
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            _TRUSTED_PROXIES_INVALID.append(entry)
    return networks

TRUSTED_PROXIES = _parse_trusted_proxies(os.environ.get("TRUSTED_PROXIES", "127.0.0.1,::1"))

def is_trusted_proxy(addr):
    """True if addr (a plain IP string) falls inside any TRUSTED_PROXIES
    network — exact match or CIDR range, either way."""
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in TRUSTED_PROXIES)

# Buffer — cap on total distinct recipient directories under BUF_DIR.
# BUF_MAX_MSGS/BUF_MAX_MB already bound each recipient's own footprint, but
# `to` only has to satisfy valid_id() — it never has to correspond to an
# identity that has ever authenticated. Without this, an authed sender can
# fan a single app:migrate/app:burn (long TTL, always durably buffered
# regardless of delivery) out to an unbounded number of fabricated
# recipient IDs, each getting its own small-but-persistent directory.
# Existing recipients are never affected — this only stops NEW directories
# from being created once the ceiling is hit.
MAX_BUF_RECIPIENTS = int(os.environ.get("MAX_BUF_RECIPIENTS", 10000))

# Endpoint-bucket cap — same spirit as MAX_BUF_RECIPIENTS, one level down.
# MAX_BUF_RECIPIENTS bounds how many distinct <publicId> directories can
# exist under BUF_DIR at once; this bounds how many distinct
# <publicId>/_endpoints/<endpointId> subdirectories a SINGLE identity can
# accumulate. Unlike `to` (which only has to satisfy valid_id() — see
# MAX_BUF_RECIPIENTS' own comment), endpoint_id is only ever set by a
# socket that has already completed the full auth handshake (see
# auth_verify) — it isn't a stranger-facing surface the way `to` is, so
# the abuse case here is narrower: an already-authed identity spinning up
# many distinct endpoint_ids against itself. Bounded anyway, same "brake
# on unbounded directory growth" reasoning, just a smaller blast radius.
MAX_ENDPOINTS_PER_RECIPIENT = int(os.environ.get("MAX_ENDPOINTS_PER_RECIPIENT", 20))

# Rate limiter
RATE_LIMIT_RATE  = 10   # tokens refilled per second
RATE_LIMIT_BURST = 20   # max burst size

# Global auth admission limiter — shared across ALL connections regardless
# of source IP. Per-IP limiting (rate limiter + MAX_CONNECTIONS_PER_IP)
# does nothing against a genuinely distributed flood (many real, distinct
# IPs — a botnet/proxy pool, not spoofed packets, since WS/TCP can't
# complete a handshake with a forged source address). Since identity here
# has zero creation cost by design (no registration, no stake), the only
# lever that still works independent of source diversity is capping how
# fast NEW auth completions can happen server-wide, full stop. Blunt on
# purpose — it will also throttle a legitimate burst (e.g. many real users
# reconnecting after this relay restarts), so defaults have headroom.
GLOBAL_AUTH_RATE  = float(os.environ.get("GLOBAL_AUTH_RATE",  50))    # new auth completions/sec, server-wide
GLOBAL_AUTH_BURST = float(os.environ.get("GLOBAL_AUTH_BURST", 100))   # burst allowance

# Per-recipient buffer write-rate limit — separate from BUF_MAX_MSGS/MB,
# which cap total stored, not the RATE of new arrivals. Without this, a
# distributed flood of one-shot senders (many distinct identities/IPs, one
# message each) targeting one specific real, existing recipient can blow
# through BUF_MAX_MSGS in well under a second, evicting genuine buffered
# messages from that person's real contacts before they ever reconnect to
# read them. Deliberately independent of sender identity — the whole
# premise of this attack is many different senders, so nothing keyed by
# sender would help. Only gates the OFFLINE buffering path (buf_write is
# only reached when live delivery failed, or for app:migrate/app:burn's
# durability exception) — has zero effect on live delivery between two
# people who are both online.
BUF_WRITE_RATE_LIMIT = float(os.environ.get("BUF_WRITE_RATE_LIMIT",  2))   # new buffered msgs/sec allowed, per recipient
BUF_WRITE_RATE_BURST = float(os.environ.get("BUF_WRITE_RATE_BURST", 20))   # burst allowance, per recipient
# How long a recipient's write-rate limiter sits idle before being pruned.
# MAX_BUF_RECIPIENTS only bounds directories that exist AT ONCE — over a
# server's lifetime, directories get created, flushed/expired, and later
# recreated for different fabricated IDs, so the total distinct recipient
# IDs ever seen isn't bounded the same way. Without pruning, this dict
# would grow slowly forever under a patient, rotating attacker.
BUF_RATE_LIMITER_IDLE_S = 600

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

# app:burn packets get their own long TTL, same reasoning as app:migrate —
# these are "make sure this is eventually seen" packets, not conversation.
# Separate from BUF_MAX_AGE_MIGRATE (and its own suffix) so a stray/late
# migrate can never overwrite a pending burn notice in the buffer, or vice
# versa — they don't share a slot.
BUF_MAX_AGE_BURN = int(os.environ.get("BUF_MAX_AGE_BURN", 7 * 86400))
BURN_SUFFIX       = "_burn.json"   # filename tag — same role as MIGRATE_SUFFIX

# ══════════════════════════════════════════
#   VAPID / WEB PUSH — configuration
#   Push is opt-in per-device (client-side checkbox) and deliberately
#   payload-less — a push here only ever means "wake up and check", never
#   carries message content. That's what lets this whole feature skip
#   pywebpush/aes128gcm payload encryption entirely: an empty-body push
#   only needs a VAPID keypair and a signed JWT per request, both doable
#   with `cryptography` (already a dependency) — see the VAPID section
#   below. Only fired for genuinely-offline app:message deliveries;
#   app:migrate/app:burn are not user-facing and never trigger one.
#
#   VAPID_KEY_FILE/PUSH_SUBS_DIR default to sitting next to BUF_DIR rather
#   than under it — same "fresh relay boots with sane defaults" spirit as
#   BUF_DIR's own default, just its own sibling directory rather than a
#   subdirectory, since a push subscription isn't a buffered packet.
# ══════════════════════════════════════════
VAPID_SUBJECT    = os.environ.get("VAPID_SUBJECT", "mailto:admin@example.com")
VAPID_KEY_FILE   = os.environ.get("VAPID_KEY_FILE",
                                   os.path.join(os.path.dirname(os.path.abspath(BUF_DIR)), "vapid_key.pem"))
PUSH_SUBS_DIR    = os.environ.get("PUSH_SUBS_DIR",
                                   os.path.join(os.path.dirname(os.path.abspath(BUF_DIR)), "push_subs"))
PUSH_TTL_SECONDS = int(os.environ.get("PUSH_TTL_SECONDS", 60))   # how long the push service should hold this if the device is unreachable

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

for _bad_entry in _TRUSTED_PROXIES_INVALID:
    log.warning("CONFIG     TRUSTED_PROXIES invalid entry skipped: %r", _bad_entry)

# ══════════════════════════════════════════
#   SIGNAL SERVER STATE
# ══════════════════════════════════════════

connected: dict[str, set] = {}   # publicId → set of websockets
# connected_by_endpoint — publicId → endpointId → set of websockets. Additive,
# NOT a replacement for `connected`: a socket that presents a endpoint_id at
# auth ends up in both. endpointId is a separate HKDF derivation off the same
# device seed as deviceId, deliberately unlinkable from it (see
# deriveDeviceEndpointId in meshchat-lib.js / derive_device_endpoint_id in
# Agent.py) — this map is what lets route_or_buffer target one specific
# device ("bob::laptop") instead of fanning an app:message out to every live
# session under a publicId. A set (not a bare ws) per endpointId in case a
# device briefly holds two sockets across a reconnect race.
connected_by_endpoint: dict[str, dict[str, set]] = {}
pending_auth: dict = {}          # ws → { x25519_pub, ed25519_pub, nonce, ts, bits, endpoint_id, ws }
ip_conns: dict[str, int] = {}    # ip → active connection count
ip_limiters: dict = {}           # ip → RateLimiter shared across all that IP's sockets
ws_to_ids: dict = {}             # ws → set of publicIds (reverse of connected; O(1) cleanup)
ws_to_endpoint: dict = {}         # ws → list of (publicId, endpointId) (reverse of connected_by_endpoint; O(1) cleanup)
buf_locks: dict = {}             # to_id → asyncio.Lock (serializes per-recipient buffer writes)
buf_recipient_limiters: dict = {}   # to_id → RateLimiter, governs rate of NEW buffer writes for that recipient

stats = {
    "bytes_in":  0, "bytes_out": 0,
    "msgs_in":   0, "msgs_out":  0,
    "buf_in":    0, "buf_out":   0,
    "buf_cap_rejected":  0,   # writes dropped for hitting MAX_BUF_RECIPIENTS
    "buf_endpoint_cap_rejected": 0,   # writes dropped for hitting MAX_ENDPOINTS_PER_RECIPIENT
    "buf_rate_rejected": 0,   # writes dropped for hitting a recipient's write-rate limit
    "auth_admission_rejected": 0,   # auth completions dropped by the global admission limiter
    "push_sent":    0,   # pushes that got a non-error response from the push service
    "push_pruned":  0,   # subscriptions removed after a permanent failure (404/410)
    "push_failed":  0,   # transient push failures (network error, 5xx, etc.) — left on file, no retry
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
        raw_addr = ws.remote_address[0]
    except Exception:
        raw_addr = None

    # Only honour forwarded-for headers if the actual TCP peer is a known
    # proxy — otherwise a direct connection to WS_PORT can claim to be any
    # IP it likes, defeating MAX_CONNECTIONS_PER_IP and per-IP rate limiting
    # outright. See TRUSTED_PROXIES comment above.
    if not is_trusted_proxy(raw_addr):
        return raw_addr or "unknown"

    try:
        headers = ws.request.headers
        ip = (headers.get("X-Real-IP")
              or headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or raw_addr)
        return ip
    except Exception:
        return raw_addr or "unknown"

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

# Single shared instance — deliberately NOT one-per-IP or one-per-socket.
# See GLOBAL_AUTH_RATE comment near its definition for why this needs to
# be global to be effective at all.
global_auth_limiter = RateLimiter(rate=GLOBAL_AUTH_RATE, burst=GLOBAL_AUTH_BURST)

# ══════════════════════════════════════════
#   VAPID / WEB PUSH
#   Hand-rolled rather than pulling in pywebpush — see the config comment
#   above for why an empty-payload push doesn't need a full webpush
#   library. What's actually needed: an EC P-256 keypair (VAPID mandates
#   this curve), a signed ES256 JWT per push, and a bodyless POST. All of
#   that is `cryptography` (already a dependency) plus stdlib urllib.
# ══════════════════════════════════════════

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def _load_or_create_vapid_key():
    if os.path.exists(VAPID_KEY_FILE):
        try:
            with open(VAPID_KEY_FILE, "rb") as f:
                return load_pem_private_key(f.read(), password=None)
        except Exception as e:
            log.warning("VAPID      key file unreadable (%s) — generating a new one", e)
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        os.makedirs(os.path.dirname(VAPID_KEY_FILE) or ".", exist_ok=True)
        with open(VAPID_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        log.info("VAPID      new keypair generated  file=%s", VAPID_KEY_FILE)
    except Exception as e:
        log.warning("VAPID      couldn't persist key (%s) — a new one will be generated next boot", e)
    return key

VAPID_PRIVATE_KEY = _load_or_create_vapid_key()
# Uncompressed EC point (0x04 || X || Y, 65 bytes) — this is the exact
# format applicationServerKey expects client-side (pushManager.subscribe),
# and what goes in the Authorization header's k= parameter server-side.
VAPID_PUBLIC_KEY_B64 = _b64url(
    VAPID_PRIVATE_KEY.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
)

def _vapid_jwt(aud: str) -> str:
    """Signed ES256 JWT — the possession proof a push service checks
    against the public key presented alongside it. `aud` must be the
    scheme+host (origin) of the specific push endpoint being called, not
    a fixed value — each push service (FCM, Mozilla's, etc.) checks its
    own origin against this claim."""
    header = _b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = _b64url(json.dumps({
        "aud": aud,
        "exp": int(time.time()) + 12 * 3600,   # spec allows up to 24h; 12h is plenty for a "wake up" ping
        "sub": VAPID_SUBJECT,
    }, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode()
    # cryptography's ECDSA sign() returns a DER-encoded signature; JWS ES256
    # wants raw r||s (32 bytes each, big-endian, concatenated) — this is the
    # one non-obvious conversion step in hand-rolling VAPID.
    der_sig = VAPID_PRIVATE_KEY.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header}.{claims}.{_b64url(raw_sig)}"

def _send_web_push_sync(endpoint: str) -> tuple[bool, int | None]:
    """Sync body — runs in a worker thread (urllib is blocking). Sends an
    empty-body push: no content, no aes128gcm encryption layer, purely a
    wake-up. Returns (permanent_failure, http_status). permanent_failure
    is True only on 404/410 — the push service telling us the subscription
    itself is dead, not just that this one attempt failed."""
    try:
        parsed = urllib.parse.urlparse(endpoint)
        aud = f"{parsed.scheme}://{parsed.netloc}"
        jwt = _vapid_jwt(aud)
        req = urllib.request.Request(
            endpoint, data=b"", method="POST",
            headers={
                "TTL": str(PUSH_TTL_SECONDS),
                "Authorization": f"vapid t={jwt}, k={VAPID_PUBLIC_KEY_B64}",
                "Content-Length": "0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return False, resp.status
    except urllib.error.HTTPError as e:
        return e.code in (404, 410), e.code
    except Exception as e:
        log.debug("PUSH       send error  endpoint=%s…  err=%s", endpoint[:40], e)
        return False, None

# ══════════════════════════════════════════
#   PUSH SUBSCRIPTION STORAGE
#   Layout: PUSH_SUBS_DIR/<publicId>/<deviceId>.json — one file per
#   (identity, device) pair, mirrors BUF_DIR's per-recipient directory
#   shape. No locking: writes are whole-file replacements keyed by a
#   caller-controlled deviceId, so concurrent writes to the SAME file
#   would only ever be the same device re-subscribing — last-write-wins
#   is fine, same tier of concern as localStorage overwrites client-side.
# ══════════════════════════════════════════

def push_sub_dir(to_id):
    path = os.path.realpath(os.path.join(PUSH_SUBS_DIR, to_id))
    if not path.startswith(os.path.realpath(PUSH_SUBS_DIR) + os.sep):
        raise ValueError(f"path traversal attempt: {to_id!r}")
    return path

def _push_sub_write_sync(to_id, device_id, subscription):
    try:
        d = push_sub_dir(to_id)
    except ValueError as e:
        log.warning("PUSH_SUB   rejected  to=%s  reason=%s", short(to_id), e)
        return
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{device_id}.json"), "w") as f:
            json.dump(subscription, f)
        log.info("PUSH_SUB   subscribed  id=%s  device=%s", short(to_id), short(device_id))
    except Exception as e:
        log.warning("PUSH_SUB   write failed  to=%s  err=%s", short(to_id), e)

def _push_sub_delete_sync(to_id, device_id):
    try:
        d = push_sub_dir(to_id)
    except ValueError:
        return
    try:
        os.remove(os.path.join(d, f"{device_id}.json"))
        log.info("PUSH_SUB   unsubscribed  id=%s  device=%s", short(to_id), short(device_id))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("PUSH_SUB   unsubscribe failed  to=%s  err=%s", short(to_id), e)

def _push_subs_list_sync(to_id):
    """Returns [(deviceId, subscriptionDict), ...] for every subscription
    on file for to_id. Corrupt/unreadable entries are skipped rather than
    aborting the whole read — one bad file shouldn't silence pushes to a
    recipient's other devices."""
    try:
        d = push_sub_dir(to_id)
    except ValueError:
        return []
    if not os.path.isdir(d):
        return []
    out = []
    for fpath in glob.glob(os.path.join(d, "*.json")):
        try:
            with open(fpath) as f:
                sub = json.load(f)
            device_id = os.path.basename(fpath)[:-len(".json")]
            out.append((device_id, sub))
        except Exception:
            continue
    return out

async def push_notify(to_id):
    """Fire a best-effort, empty-payload push to every subscription on
    file for to_id. Only called from route_or_buffer for a genuinely-
    offline app:message delivery — never for app:migrate/app:burn (not
    user-facing) and never when a live session was already reached.
    Pushes are inherently best-effort: no retry on transient failure,
    same as everything else in this protocol that isn't durably buffered."""
    subs = await asyncio.to_thread(_push_subs_list_sync, to_id)
    if not subs:
        return
    for device_id, sub in subs:
        endpoint = sub.get("endpoint")
        if not endpoint:
            continue
        dead, status = await asyncio.to_thread(_send_web_push_sync, endpoint)
        if dead:
            await asyncio.to_thread(_push_sub_delete_sync, to_id, device_id)
            stats["push_pruned"] += 1
            log.info("PUSH       subscription dead (status=%s) — pruned  id=%s  device=%s",
                      status, short(to_id), short(device_id))
        elif status is not None and 200 <= status < 300:
            stats["push_sent"] += 1
            log.debug("PUSH       sent  id=%s  device=%s  status=%s", short(to_id), short(device_id), status)
        else:
            stats["push_failed"] += 1
            log.debug("PUSH       transient failure  id=%s  device=%s  status=%s", short(to_id), short(device_id), status)

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
        # Prune dead socket via reverse map — O(ids_per_socket) instead of
        # O(unique_keys). ws_to_ids is populated in auth_verify.
        for cid in ws_to_ids.pop(ws, set()):
            sockets = connected.get(cid)
            if sockets:
                sockets.discard(ws)
                if not sockets:
                    del connected[cid]
        # same pruning for the routing-id map, via its own reverse index
        for (cid, rid) in ws_to_endpoint.pop(ws, []):
            devmap = connected_by_endpoint.get(cid)
            if devmap:
                sockets = devmap.get(rid)
                if sockets:
                    sockets.discard(ws)
                    if not sockets:
                        del devmap[rid]
                if not devmap:
                    del connected_by_endpoint[cid]
        return False

async def deliver(to_id, obj, exclude=None):
    sessions = connected.get(to_id, set())
    reached  = 0
    for ws in list(sessions):
        if ws is exclude: continue
        if await send_to(ws, obj): reached += 1
    return reached

async def deliver_to_endpoint(to_id, endpoint_id, obj, exclude=None):
    """Same shape as deliver(), scoped to the socket(s) registered under
    this specific (identity, endpointId) pair — see connected_by_endpoint.
    Used when an app:message envelope carries an optional toEndpoint field.
    Deliberately does NOT fall back to every session under to_id if the
    named device isn't currently registered — a device-targeted send
    reaching nobody is exactly the "offline" case route_or_buffer already
    handles via the shared identity-level buffer; broadcasting instead
    would silently defeat the whole point of asking for one device."""
    sessions = connected_by_endpoint.get(to_id, {}).get(endpoint_id, set())
    reached  = 0
    for ws in list(sessions):
        if ws is exclude: continue
        if await send_to(ws, obj): reached += 1
    return reached

async def route_or_buffer(kind, frm, to, msg, ws):
    """Shared delivery path for from-authenticated, to-routed packet types
    (app:message, app:migrate). Delivers live if the recipient is
    connected, otherwise falls back to the offline buffer — buf_write
    handles per-type overwrite/TTL behaviour on its own.

    app:migrate is the one exception to "buffer only if delivery failed":
    it always gets written to the durable buffer in addition to any live
    delivery. Its entire purpose is to be found later by a device that
    isn't online yet — including, critically, another session of the
    SAME identity that's still mid-disconnect from the relay being left
    behind. `deliver()` only excludes the literal sending socket, not
    other live sessions for the same publicId, so a self-targeted
    breadcrumb can be "reached" by a stale-but-not-yet-closed session of
    ours and never make it into the buffer at all — exactly the case
    this packet type exists to survive. The overwrite-per-sender,
    long-TTL semantics in buf_write already make this free when nobody
    ends up needing the buffered copy.
    
    app:burn follows the identical exception as app:migrate, for the
    identical reason: it must survive being "reached" by a stale session
    of the same identity that's mid-disconnect. Kept as its own kind
    throughout — never merged into the migrate buffer slot — so a routing
    update can't clobber a pending burn notice or vice versa.

    Push (app:message only): fired only when live delivery genuinely
    failed — a push exists to tell someone to open the app and check,
    which is meaningless if they're already connected and about to
    receive the message live. app:migrate/app:burn never push — neither
    is something a human needs to be woken up for.

    Device targeting (app:message only): an envelope carrying `toEndpoint`
    (a endpointId — see connected_by_endpoint) is delivered only to that
    specific registered device via deliver_to_endpoint(), not fanned out to
    every live session under `to`. The offline buffer now honours this too
    (see buf_write's endpoint_id param / buf_endpoint_dir): a device-
    targeted send that misses live delivery lands in that device's OWN
    bucket (BUF_DIR/<to>/_endpoints/<toEndpoint>/) rather than the shared
    identity-level one, and is only ever flushed to a connection that
    later presents that exact endpoint_id at auth — never to whichever
    device happens to reconnect first. Nothing upstream of this function
    sets toEndpoint yet (no client send path targets a specific device
    today — see meshchat.js), so this bucket is currently dormant, wired
    ahead of need the same way connected_by_endpoint/deliver_to_endpoint
    were before anything used them either."""
    to_endpoint = msg.get("toEndpoint") if kind == "app:message" else None
    if to_endpoint:
        reached = await deliver_to_endpoint(to, to_endpoint, msg, exclude=ws)
    else:
        reached = await deliver(to, msg, exclude=ws)
    if reached:
        log.info("%-10s from=%s  to=%s  reached=%d%s", kind.upper(), short(frm), short(to), reached,
                  f"  endpoint={short(to_endpoint)}" if to_endpoint else "")
    if not reached or kind in ("app:migrate", "app:burn"):
        await buf_write(to, msg, to_endpoint)
        if reached:
            log.info("BUF Q      from=%s  to=%s  (also buffered — %s, durability required)  type=%s",
                      short(frm), short(to), "migrate" if kind == "app:migrate" else "burn", kind)
        else:
            log.info("BUF Q      from=%s  to=%s  (offline)  type=%s", short(frm), short(to), kind)
    if not reached and kind == "app:message":
        await push_notify(to)

# ══════════════════════════════════════════
#   AUTH HELPERS
#   derive_public_id  — mirrors client JS logic exactly
#   auth_challenge    — encrypt nonce to client's enc key, store pending
#   auth_verify       — check proof, register, flush buffer
# ══════════════════════════════════════════

def derive_public_id(x25519_pub: bytes, ed25519_pub: bytes) -> str:
    """SHA-256(x25519_pub || ed25519_pub)[0..12] encoded as base64url — mirrors
    client deriveIdentityPublicId(). Deliberately hashes BOTH keys together,
    not just the X25519 one: if publicId only depended on the X25519 key,
    someone could present a victim's real (public) x25519_pub alongside
    their OWN ed25519_pub, sign the challenge with their own private key,
    and get registered under the victim's publicId — never able to decrypt
    anything routed to it, but able to silently swallow it. Binding both
    keys means a valid publicId can only come from one specific pair."""
    digest = hashlib.sha256(x25519_pub + ed25519_pub).digest()[:12]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

async def auth_challenge(ws, x25519_pub: bytes, ed25519_pub: bytes, bits: int, no_receive: bool = False,
                          endpoint_id: str | None = None):
    """Generate a random nonce and send it in the clear — there is no
    longer a shared secret to encrypt it with (that was the whole bug:
    the old scheme's "auth" was decrypting a nonce with the same AES key
    the client had just handed the server in plaintext one message
    earlier, which proved nothing). The nonce here exists purely as
    something for the client to SIGN with its Ed25519 private key in
    auth_verify — that signature is the actual possession proof.

    no_receive: caller is a disposable probe (e.g. testRelayConnection) that
    has no business being treated as a reachable recipient — it intends to
    close itself the moment auth_ok arrives. Carried through to auth_verify
    so registration and buffer flush can be skipped for it specifically.

    endpoint_id: optional per-device routing token (see connected_by_endpoint) —
    already validated (valid_id) by the caller before this is reached. It's
    presented in the clear here for the same reason x25519_pub/ed25519_pub
    are: nothing about it is secret on its own (it's only unlinkable to
    deviceId, not hidden from the relay it's addressed to), and possession
    of the matching identity is still what auth_verify actually proves.
    Carried through pending_auth so it's only ever registered once the
    challenge is genuinely answered, same as everything else here."""
    nonce_plain = secrets.token_bytes(32)
    pending_auth[id(ws)] = {
        "x25519_pub":  x25519_pub,
        "ed25519_pub": ed25519_pub,
        "nonce":       nonce_plain,
        "ts":          time.monotonic(),
        "bits":        bits,
        "no_receive":  no_receive,
        "endpoint_id":  endpoint_id,
        "ws":          ws,   # so sweep_pending_auth() can actively close stale entries
    }
    await send_to(ws, {
        "type":  "sig:auth_challenge",
        "nonce": list(nonce_plain),
    })
    log.info("AUTH       challenge sent  bits=%d  peer=%s%s", bits, peer_info(ws),
              "  [no_receive]" if no_receive else "")

async def auth_verify(ws, sig_bytes: list, addr: str) -> str | None:
    """Verify the Ed25519 signature over the nonce, register identity, flush
    buffer. Returns public_id or None on failure."""
    entry = pending_auth.pop(id(ws), None)
    if not entry:
        log.warning("AUTH       proof with no pending challenge  peer=%s", addr)
        return None
    if time.monotonic() - entry["ts"] > AUTH_TIMEOUT:
        log.warning("AUTH       challenge expired  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "timeout"})
        return None
    try:
        Ed25519PublicKey.from_public_bytes(entry["ed25519_pub"]).verify(bytes(sig_bytes), entry["nonce"])
    except Exception:
        log.warning("AUTH       proof invalid  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "proof_invalid"})
        return None

    # Global admission gate — checked only after the proof is confirmed
    # valid, so a flood of garbage/incorrect proofs doesn't spend from the
    # shared budget, only completions that would actually have succeeded.
    # Deliberately independent of source IP (see GLOBAL_AUTH_RATE comment)
    # — this is the one lever that still works when the flood is genuinely
    # distributed across many real, distinct addresses rather than one.
    if not global_auth_limiter.allow():
        log.warning("AUTH       global admission limit reached  peer=%s", addr)
        stats["auth_admission_rejected"] += 1
        await send_to(ws, {"type": "sig:auth_fail", "reason": "server_busy"})
        return None

    public_id  = derive_public_id(entry["x25519_pub"], entry["ed25519_pub"])
    no_receive = entry.get("no_receive", False)
    endpoint_id = entry.get("endpoint_id")
    if not no_receive:
        if public_id not in connected:
            connected[public_id] = set()
        connected[public_id].add(ws)
        ws_to_ids.setdefault(ws, set()).add(public_id)
        if endpoint_id:
            connected_by_endpoint.setdefault(public_id, {}).setdefault(endpoint_id, set()).add(ws)
            ws_to_endpoint.setdefault(ws, []).append((public_id, endpoint_id))
    log.info("AUTH OK    id=%s  bits=%d  peer=%s  keys=%d  sessions=%d%s%s",
             short(public_id), entry["bits"], addr, unique_keys(), session_count(),
             "  [no_receive — not registered]" if no_receive else "",
             f"  endpoint={short(endpoint_id)}" if (endpoint_id and not no_receive) else "")
    await send_to(ws, {"type": "sig:auth_ok", "public_id": public_id})
    if not no_receive:
        await buf_deliver(public_id, ws, endpoint_id)
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
    """Return list of buffer files for recipient, oldest first. Identity-
    level only — deliberately does NOT glob into _endpoints/ (a directory
    name, never matches the *.json pattern, so this is naturally scoped
    without an explicit exclusion)."""
    d = buf_dir(to_id)
    if not os.path.isdir(d): return []
    pattern = os.path.join(d, "*.json")
    return sorted(glob.glob(pattern, recursive=False))

def buf_endpoint_dir(to_id, endpoint_id):
    """BUF_DIR/<to_id>/_endpoints/<endpoint_id> — a second, independent
    bucket alongside the identity-level one, for app:message packets that
    carried toEndpoint and missed live delivery to that specific device
    (see route_or_buffer/deliver_to_endpoint). Never used for
    app:migrate/app:burn — those aren't device-targeted and stay
    identity-level exclusively, same as today."""
    parent = buf_dir(to_id)   # raises ValueError on traversal attempt in to_id itself
    path = os.path.realpath(os.path.join(parent, "_endpoints", endpoint_id))
    if not path.startswith(os.path.realpath(parent) + os.sep):
        raise ValueError(f"path traversal attempt: {endpoint_id!r}")
    return path

def buf_endpoint_files(to_id, endpoint_id):
    """Return list of buffer files in one identity's endpoint-specific
    bucket, oldest first."""
    try:
        d = buf_endpoint_dir(to_id, endpoint_id)
    except ValueError:
        return []
    if not os.path.isdir(d): return []
    return sorted(glob.glob(os.path.join(d, "*.json"), recursive=False))

def _buf_write_sync(to_id, msg, endpoint_id=None):
    """Sync body of buf_write — runs in a worker thread, no awaits.

    endpoint_id present → this is a device-targeted app:message that
    missed live delivery (see route_or_buffer/deliver_to_endpoint) and
    goes into to_id's own _endpoints/<endpoint_id> bucket instead of the
    identity-level one. app:migrate/app:burn never carry an endpoint_id —
    they aren't device-targeted — so this branch is exclusively an
    app:message path in practice, though nothing here assumes that beyond
    what route_or_buffer already guarantees by only ever passing
    endpoint_id through for that kind.

    app:migrate packets use overwrite semantics: only the most recent
    packet from a given sender is kept (any older buffered migrate from
    that same sender is dropped first), and they're tagged with
    MIGRATE_SUFFIX so buf_expire applies the longer TTL bucket.
    
    app:burn uses the same overwrite-per-sender + own-suffix treatment as
    app:migrate, kept as a fully separate bucket — the overwrite scan below
    only ever drops files carrying the SAME suffix as the incoming packet,
    so a migrate can never evict a buffered burn notice and a burn can
    never evict a buffered migrate breadcrumb. Both are identity-level
    only — this overwrite logic never runs for an endpoint_id write."""
    try:
        top_dir = buf_dir(to_id)
        d = buf_endpoint_dir(to_id, endpoint_id) if endpoint_id else top_dir
    except ValueError as e:
        log.warning("BUF        rejected  to=%s  reason=%s", short(to_id), e)
        return

    # Recipient cap — only matters for a NEW recipient directory (the
    # top-level <to_id> dir itself, whether this particular write is
    # identity- or endpoint-level — both create it). An existing recipient
    # is never turned away by this; it's purely a brake on an attacker
    # fanning out to unlimited fabricated recipient IDs. See
    # MAX_BUF_RECIPIENTS comment near its definition.
    if not os.path.isdir(top_dir):
        try:
            existing = sum(1 for e in os.scandir(BUF_DIR) if e.is_dir()) if os.path.isdir(BUF_DIR) else 0
        except Exception:
            existing = 0
        if existing >= MAX_BUF_RECIPIENTS:
            stats["buf_cap_rejected"] += 1
            log.warning("BUF        recipient cap reached (%d) — rejecting new recipient  to=%s",
                        MAX_BUF_RECIPIENTS, short(to_id))
            return

    # Endpoint-bucket cap — only matters for a NEW endpoint bucket under
    # an ALREADY-admitted recipient. See MAX_ENDPOINTS_PER_RECIPIENT
    # comment near its definition.
    if endpoint_id and not os.path.isdir(d):
        endpoints_root = os.path.join(top_dir, "_endpoints")
        try:
            existing_eps = sum(1 for e in os.scandir(endpoints_root) if e.is_dir()) if os.path.isdir(endpoints_root) else 0
        except Exception:
            existing_eps = 0
        if existing_eps >= MAX_ENDPOINTS_PER_RECIPIENT:
            stats["buf_endpoint_cap_rejected"] += 1
            log.warning("BUF        endpoint cap reached (%d) — rejecting new endpoint bucket  to=%s  endpoint=%s",
                        MAX_ENDPOINTS_PER_RECIPIENT, short(to_id), short(endpoint_id))
            return

    try:
        os.makedirs(d, exist_ok=True)
    except Exception as e:
        log.warning("BUF        mkdir failed  to=%s  err=%s", short(to_id), e)
        return

    kind       = msg.get("type")
    is_migrate = kind == "app:migrate"
    is_burn    = kind == "app:burn"
    frm        = msg.get("from")

    files = buf_endpoint_files(to_id, endpoint_id) if endpoint_id else buf_files(to_id)

    if (is_migrate or is_burn) and frm:
        own_suffix = MIGRATE_SUFFIX if is_migrate else BURN_SUFFIX
        kept = []
        for fpath in files:
            if not fpath.endswith(own_suffix):
                kept.append(fpath)
                continue
            try:
                with open(fpath) as f:
                    old = json.load(f)
            except Exception:
                kept.append(fpath)
                continue
            if old.get("from") == frm:
                try:
                    os.remove(fpath)
                    log.info("BUF        %s overwrite  to=%s  from=%s",
                              "migrate" if is_migrate else "burn", short(to_id), short(frm))
                except Exception:
                    kept.append(fpath)
            else:
                kept.append(fpath)
        files = kept

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

    suffix = MIGRATE_SUFFIX if is_migrate else (BURN_SUFFIX if is_burn else ".json")
    fname  = os.path.join(d, f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}{suffix}")
    try:
        with open(fname, "w") as f:
            json.dump(msg, f)
        stats["buf_in"] += 1
        log.info("BUF        write  to=%s  file=%s%s%s", short(to_id), os.path.basename(fname),
                  "  [migrate]" if is_migrate else ("  [burn]" if is_burn else ""),
                  f"  endpoint={short(endpoint_id)}" if endpoint_id else "")
    except Exception as e:
        log.warning("BUF        write failed  to=%s  err=%s", short(to_id), e)

buf_lock_refs: dict = {}         # to_id → active reference count for buf_locks[to_id]
buf_locks_guard = asyncio.Lock()  # protects buf_locks/buf_lock_refs dict structure only —
                                   # held only for the brief get-or-create / refcount bookkeeping,
                                   # never across the actual (potentially slow) file I/O below.

async def _acquire_buf_lock(to_id):
    """Get-or-create the per-recipient lock and acquire it, registering a
    reference so a concurrent release elsewhere can't evict it out from
    under us. Incrementing the refcount happens BEFORE we wait on the lock
    itself, so anyone trying to evict while we're queued will see the
    non-zero count and back off."""
    async with buf_locks_guard:
        lock = buf_locks.get(to_id)
        if lock is None:
            lock = asyncio.Lock()
            buf_locks[to_id] = lock
        buf_lock_refs[to_id] = buf_lock_refs.get(to_id, 0) + 1
    await lock.acquire()
    return lock

async def _release_buf_lock(to_id, lock):
    """Release the lock, then drop our reference. Only the holder that
    brings the refcount to zero evicts the dict entries — and only if
    buf_locks[to_id] is still the exact same Lock object we held (guards
    against a pathological reorder where the entry was already replaced)."""
    lock.release()
    async with buf_locks_guard:
        remaining = buf_lock_refs.get(to_id, 1) - 1
        if remaining <= 0:
            buf_lock_refs.pop(to_id, None)
            if buf_locks.get(to_id) is lock:
                del buf_locks[to_id]
        else:
            buf_lock_refs[to_id] = remaining

async def buf_write(to_id, msg, endpoint_id=None):
    """Async wrapper: serializes per-recipient (or per-recipient-device)
    writes via a lock, offloads sync file I/O to a worker thread so the
    event loop stays unblocked. The lock prevents count/size-check races
    between concurrent writes for the same bucket. Unlike a plain
    key → Lock dict, the lock entry is evicted once unreferenced —
    otherwise any syntactically-valid `to` (it need not correspond to a
    real identity — see valid_id) leaves a permanent Lock object behind,
    an unbounded memory leak an authenticated client could trigger at
    will simply by sending to junk recipient ids.

    endpoint_id present → rate limiter and lock are keyed on
    "<to_id>::<endpoint_id>", a bucket independent of to_id's own
    identity-level key and of every other endpoint under the same
    identity. Without this, a flood targeted at one of a recipient's
    devices would spend the SAME rate budget as traffic aimed at the
    recipient generally (or at their other devices) — device targeting
    is supposed to isolate delivery, and sharing a limiter here would
    quietly undo that isolation.

    Write-rate limited per bucket BEFORE any of that — see
    BUF_WRITE_RATE_LIMIT comment near its definition. This is what actually
    stops a distributed flood of one-shot senders from blowing through a
    specific real recipient's BUF_MAX_MSGS cap fast enough to evict their
    genuine buffered messages; the lock/thread machinery below only cares
    about serializing writes that get past this gate."""
    limiter_key = f"{to_id}::{endpoint_id}" if endpoint_id else to_id
    limiter = buf_recipient_limiters.get(limiter_key)
    if limiter is None:
        limiter = RateLimiter(rate=BUF_WRITE_RATE_LIMIT, burst=BUF_WRITE_RATE_BURST)
        buf_recipient_limiters[limiter_key] = limiter
    if not limiter.allow():
        stats["buf_rate_rejected"] += 1
        log.warning("BUF        write-rate limit reached  to=%s%s — dropped", short(to_id),
                     f"  endpoint={short(endpoint_id)}" if endpoint_id else "")
        return

    lock = await _acquire_buf_lock(limiter_key)
    try:
        await asyncio.to_thread(_buf_write_sync, to_id, msg, endpoint_id)
    finally:
        await _release_buf_lock(limiter_key, lock)

def _buf_read_all(files):
    """Read all buffer files in one thread call. Returns list parallel to
    `files`: parsed msg dict on success, None on failure."""
    results = []
    for fpath in files:
        try:
            with open(fpath) as f:
                results.append(json.load(f))
        except Exception:
            results.append(None)
    return results

async def buf_deliver(to_id, ws, endpoint_id=None):
    """Flush all buffered packets for a reconnecting client. Delete on
    success. File reads are batched into a single worker-thread call so
    the event loop stays unblocked even when the buffer is large.

    endpoint_id present → this connection also gets its own device's
    endpoint bucket flushed, IN ADDITION TO the shared identity-level
    bucket it always gets regardless. A connection that authenticates
    WITHOUT an endpoint_id only ever sees the identity-level bucket —
    exactly as before this feature existed — since there's no device
    identity to match a targeted packet against. That's deliberate: a
    device-targeted message sitting in someone else's endpoint bucket
    must never leak to a connection that didn't present the matching
    endpoint_id, and doesn't — buf_endpoint_files only ever reads the
    one bucket asked for."""
    files    = await asyncio.to_thread(buf_files, to_id)
    ep_files = await asyncio.to_thread(buf_endpoint_files, to_id, endpoint_id) if endpoint_id else []
    all_files = files + ep_files
    if not all_files:
        return
    log.info("BUF        flush  to=%s  count=%d%s", short(to_id), len(all_files),
              f"  (identity=%d endpoint=%d)" % (len(files), len(ep_files)) if endpoint_id else "")
    messages = await asyncio.to_thread(_buf_read_all, all_files)
    for fpath, msg in zip(all_files, messages):
        if msg is None:
            log.warning("BUF        flush error  to=%s  file=%s  err=read failed",
                        short(to_id), os.path.basename(fpath))
            continue
        try:
            if await send_to(ws, msg):
                os.remove(fpath)
                stats["buf_out"] += 1
        except Exception as e:
            log.warning("BUF        flush error  to=%s  file=%s  err=%s",
                        short(to_id), os.path.basename(fpath), e)

async def buf_expire():
    """Background task — remove buffer files older than their TTL bucket.
    Regular packets use BUF_MAX_AGE; migrate packets (tagged via
    MIGRATE_SUFFIX) use the much longer BUF_MAX_AGE_MIGRATE. Endpoint
    buckets (_endpoints/<endpointId>/) always use plain BUF_MAX_AGE — an
    app:message is the only kind that ever lands there, migrate/burn are
    never device-targeted, so MIGRATE_SUFFIX/BURN_SUFFIX simply never
    appear under _endpoints/ in practice."""
    while True:
        await asyncio.sleep(BUF_EXPIRE_INTERVAL)
        now     = time.time()
        dropped = 0
        try:
            if os.path.isdir(BUF_DIR):
                for rec_dir in os.scandir(BUF_DIR):
                    if not rec_dir.is_dir():
                        continue
                    for entry in os.scandir(rec_dir.path):
                        if not entry.name.endswith(".json"):
                            continue
                        if entry.name.endswith(MIGRATE_SUFFIX):
                            max_age = BUF_MAX_AGE_MIGRATE
                        elif entry.name.endswith(BURN_SUFFIX):
                            max_age = BUF_MAX_AGE_BURN
                        else:
                            max_age = BUF_MAX_AGE
                        if now - entry.stat().st_mtime > max_age:
                            try:
                                os.remove(entry.path)
                                dropped += 1
                            except Exception:
                                pass

                    # sweep this recipient's per-device endpoint buckets —
                    # same TTL logic, one directory level down. Always plain
                    # BUF_MAX_AGE (see docstring above re: migrate/burn).
                    endpoints_root = os.path.join(rec_dir.path, "_endpoints")
                    if os.path.isdir(endpoints_root):
                        for ep_dir in os.scandir(endpoints_root):
                            if not ep_dir.is_dir():
                                continue
                            for entry in os.scandir(ep_dir.path):
                                if not entry.name.endswith(".json"):
                                    continue
                                if now - entry.stat().st_mtime > BUF_MAX_AGE:
                                    try:
                                        os.remove(entry.path)
                                        dropped += 1
                                    except Exception:
                                        pass
                            # clean up an emptied-out endpoint bucket
                            if not os.listdir(ep_dir.path):
                                try: os.rmdir(ep_dir.path)
                                except Exception: pass
                        # clean up the _endpoints dir itself once every
                        # bucket under it is gone
                        if not os.listdir(endpoints_root):
                            try: os.rmdir(endpoints_root)
                            except Exception: pass

                    # clean up empty recipient dirs — checked last, after
                    # _endpoints/ has had a chance to empty out above, so a
                    # recipient with nothing left in EITHER bucket is
                    # correctly pruned rather than kept alive by a now-empty
                    # _endpoints/ directory still sitting inside it.
                    if not os.listdir(rec_dir.path):
                        try: os.rmdir(rec_dir.path)
                        except Exception: pass
        except Exception as e:
            log.warning("BUF        expire sweep error: %s", e)
        if dropped:
            log.info("BUF        expired %d file(s)", dropped)

        # Prune idle per-recipient write-rate limiters. MAX_BUF_RECIPIENTS
        # bounds directories that exist AT ONCE; it does NOT bound the total
        # distinct recipient IDs ever seen across create/expire/recreate
        # cycles over the server's lifetime — a patient, rotating attacker
        # could otherwise grow buf_recipient_limiters slowly forever. Same
        # cadence as the file-expiry sweep above, piggybacked on the same
        # loop rather than a separate task.
        now_mono  = time.monotonic()
        idle_keys = [k for k, lim in buf_recipient_limiters.items()
                     if now_mono - lim.last_time > BUF_RATE_LIMITER_IDLE_S]
        for k in idle_keys:
            buf_recipient_limiters.pop(k, None)
        if idle_keys:
            log.info("BUF        pruned %d idle write-rate limiter(s)", len(idle_keys))

# ══════════════════════════════════════════
#   STATS
# ══════════════════════════════════════════

async def log_stats():
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        log.info("STATS      keys=%d  sessions=%d  in=%s(%d msgs)  out=%s(%d msgs)  "
                 "buf_in=%d  buf_out=%d  buf_cap_rejected=%d  buf_endpoint_cap_rejected=%d  buf_rate_rejected=%d  auth_admission_rejected=%d  "
                 "push_sent=%d  push_failed=%d  push_pruned=%d",
                 unique_keys(), session_count(),
                 fmt_bytes(stats["bytes_in"]),  stats["msgs_in"],
                 fmt_bytes(stats["bytes_out"]), stats["msgs_out"],
                 stats["buf_in"], stats["buf_out"], stats["buf_cap_rejected"], stats["buf_endpoint_cap_rejected"],
                 stats["buf_rate_rejected"], stats["auth_admission_rejected"],
                 stats["push_sent"], stats["push_failed"], stats["push_pruned"])

# ══════════════════════════════════════════
#   PENDING AUTH SWEEP
#   AUTH_TIMEOUT was previously only enforced reactively — checked inside
#   auth_verify() when a client finally sent sig:auth_proof. A client that
#   sends sig:auth_init and then simply never sends proof (and never closes
#   the socket) was never kicked: the connection sat in pending_auth and
#   held a connection slot — one of MAX_CONNECTIONS_PER_IP — indefinitely.
#   This sweep actively closes anything that's been mid-challenge longer
#   than AUTH_TIMEOUT, same interval-based pattern as buf_expire/log_stats.
# ══════════════════════════════════════════

PENDING_AUTH_SWEEP_INTERVAL = 5   # seconds between sweeps — independent of AUTH_TIMEOUT itself

async def sweep_pending_auth():
    while True:
        await asyncio.sleep(PENDING_AUTH_SWEEP_INTERVAL)
        now   = time.monotonic()
        stale = [key for key, entry in pending_auth.items() if now - entry["ts"] > AUTH_TIMEOUT]
        for key in stale:
            entry = pending_auth.pop(key, None)
            if not entry:
                continue
            ws = entry.get("ws")
            if ws is not None:
                try:
                    await ws.close(1013, "auth timeout")
                except Exception:
                    pass
        if stale:
            log.info("AUTH       swept %d stale half-authed connection(s)", len(stale))

# ══════════════════════════════════════════
#   WEBSOCKET HANDLER
# ══════════════════════════════════════════

async def handler(ws):
    client_ids = []   # public_ids authed this socket
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

    # Shared across every socket this IP currently has open — without this,
    # MAX_CONNECTIONS_PER_IP sockets each got their own independent 10/s
    # budget, so an IP's effective throughput scaled with how many
    # connections it opened rather than staying capped at one connection's
    # worth. get-or-create rather than always-new so it persists (and its
    # token bucket state carries over) across this IP's concurrent sockets.
    if addr not in ip_limiters:
        ip_limiters[addr] = RateLimiter()
    ip_limiter = ip_limiters[addr]

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

            if not ip_limiter.allow():
                log.warning("RATELIMIT(ip)  peer=%s  ids=%s  sockets_from_ip=%d",
                            addr, client_ids, ip_conns.get(addr, 0))
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
            #log.info("IN  %-20s peer=%s  size=%-8s total_in=%s  total_out=%s",
            #         kind, addr,
            #         fmt_bytes(len(raw)),
            #         fmt_bytes(stats["bytes_in"]),
            #         fmt_bytes(stats["bytes_out"]))

            # ── auth_init: client presents both public keys, server sends challenge ──
            if kind == "sig:auth_init":
                x25519_list  = msg.get("x25519_pub")
                ed25519_list = msg.get("ed25519_pub")
                bits         = 256
                no_receive   = bool(msg.get("no_receive", False))
                endpoint_id   = msg.get("endpoint_id")
                if not x25519_list or not ed25519_list:
                    log.warning("AUTH       bad auth_init  peer=%s", addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_init"})
                    continue
                x25519_pub  = bytes(x25519_list)
                ed25519_pub = bytes(ed25519_list)
                if len(x25519_pub) != 32 or len(ed25519_pub) != 32:
                    log.warning("AUTH       wrong key length  bits=%d  x25519=%d  ed25519=%d  peer=%s",
                                bits, len(x25519_pub), len(ed25519_pub), addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_key_length"})
                    continue
                # optional — old clients simply omit it, falling back to
                # today's broadcast-to-every-session-under-publicId behavior
                if endpoint_id is not None and not valid_id(endpoint_id):
                    log.warning("AUTH       bad endpoint_id  peer=%s", addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_endpoint_id"})
                    continue
                await auth_challenge(ws, x25519_pub, ed25519_pub, bits, no_receive, endpoint_id)

            # ── auth_proof: client returns a signature over the nonce ──
            elif kind == "sig:auth_proof":
                sig_back = msg.get("sig")
                if not sig_back:
                    log.warning("AUTH       empty proof  peer=%s", addr)
                    continue
                public_id = await auth_verify(ws, sig_back, addr)
                if public_id:
                    if not client_ids:
                        client_ids.append(public_id)
                    elif client_ids[0] != public_id:
                        log.warning("AUTH       socket already authed as %s, rejecting %s  peer=%s",
                                    short(client_ids[0]), short(public_id), addr)
                        await send_to(ws, {"type": "sig:auth_fail", "reason": "already_authenticated"})
                    # else: re-auth with same identity — no-op (idempotent), useful for session refresh)

            # ── everything below requires at least one authed identity ──
            elif not is_authed():
                frm = msg.get("from", "?")
                log.warning("UNAUTHED   type=%r  from=%s  peer=%s  dropped", kind, short(frm), addr)
                await send_to(ws, {"type": "sig:auth_fail", "reason": "not_authenticated"})

            # ── message / migrate: from must match an authed identity on this socket ──
            elif kind in ("app:message", "app:migrate", "app:burn"):
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

            # ── push subscribe/unsubscribe: from must match an authed
            #    identity on this socket, same rule as app:message et al.
            #    No mandatory signature — this doesn't redirect routing or
            #    drive an irreversible action the way app:migrate/app:burn
            #    do, it's "start/stop sending pushes to this endpoint",
            #    same trust tier as the sync:* group. ──
            elif kind == "sig:push_subscribe":
                frm       = msg.get("from", "?")
                device_id = msg.get("deviceId")
                sub       = msg.get("subscription")
                if frm not in client_ids:
                    log.warning("PUSH_SUB   from=%s  not authed  peer=%s  dropped", short(frm), addr)
                    await send_to(ws, {"type": "error", "reason": "not_authenticated"})
                    continue
                if not valid_id(device_id):
                    log.warning("PUSH_SUB   from=%s  bad deviceId, dropped", short(frm))
                    continue
                if not isinstance(sub, dict):
                    log.warning("PUSH_SUB   from=%s  bad subscription shape, dropped", short(frm))
                    continue
                endpoint = sub.get("endpoint")
                keys     = sub.get("keys") if isinstance(sub.get("keys"), dict) else {}
                # https-only — a ws://, http://, or garbage endpoint has no
                # business being POSTed to later; WS_MAX_SIZE already caps
                # the overall frame this arrives in, so no separate size
                # check is needed on top of that for now.
                if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
                    log.warning("PUSH_SUB   from=%s  endpoint not https, dropped", short(frm))
                    continue
                if not keys.get("p256dh") or not keys.get("auth"):
                    log.warning("PUSH_SUB   from=%s  missing keys.p256dh/auth, dropped", short(frm))
                    continue
                await asyncio.to_thread(_push_sub_write_sync, frm, device_id, {
                    "endpoint": endpoint,
                    "p256dh":   keys["p256dh"],
                    "auth":     keys["auth"],
                })

            elif kind == "sig:push_unsubscribe":
                frm       = msg.get("from", "?")
                device_id = msg.get("deviceId")
                if frm not in client_ids:
                    log.warning("PUSH_UNSUB from=%s  not authed  peer=%s  dropped", short(frm), addr)
                    await send_to(ws, {"type": "error", "reason": "not_authenticated"})
                    continue
                if not valid_id(device_id):
                    log.warning("PUSH_UNSUB from=%s  bad deviceId, dropped", short(frm))
                    continue
                await asyncio.to_thread(_push_sub_delete_sync, frm, device_id)

            elif kind == "sig:announce":
                ids = msg.get("ids", [])
                if not isinstance(ids, list):
                    log.warning("  announce bad payload, dropped")
                    continue
                ids     = [i for i in ids[:10] if valid_id(i)]
                matched = [i for i in ids if i in connected]
                if matched:
                    seen_msg = {"type": "sig:seen", "id": last_id()}
                    # Fan out in parallel — sequential awaits would serialize
                    # delivery across all matched recipients.
                    await asyncio.gather(
                        *(deliver(mid, seen_msg, exclude=ws) for mid in matched),
                        return_exceptions=True,
                    )

            elif kind in ("app:sync", "sync:backup_offer", "sync:backup_accept",
                          "sync:backup_push", "sync:restore_req",
                          "sync:restore_ack", "sync:restore_push",
                          "sync:token_req", "sync:token_resp",
                          "call:invite", "call:claim", "call:cancel", "call:end",
                          "call:offer", "call:answer", "call:ice",
                          "shell:invite", "shell:claim", "shell:cancel", "shell:end",
                          "shell:offer", "shell:answer", "shell:ice"):
                frm = msg.get("from", "?")
                to  = msg.get("to")
                if not valid_id(to):
                    log.warning("  %s with invalid 'to', dropped", kind)
                    continue
                if frm not in client_ids:
                    log.warning("%-10s from=%s  not authed  peer=%s  dropped", kind.upper(), short(frm), addr)
                    await send_to(ws, {"type": "error", "reason": "not_authenticated"})
                    continue
                # toEndpoint — same device-targeting field app:message already
                # honors (see route_or_buffer/deliver_to_endpoint), generalized
                # onto this shared branch. Live-only here, same as everything
                # else in this branch already is — none of these types are
                # durably buffered, so a toEndpoint aimed at a currently-
                # offline device simply reaches nobody, exactly like an
                # untargeted send to an offline recipient already does today.
                # call:*/shell:* never set this field, so their behavior is
                # byte-for-byte unchanged; sync:backup_push is the first type
                # to actually use it, for self-device-targeted backup pushes.
                to_endpoint = msg.get("toEndpoint")
                if to_endpoint and not valid_id(to_endpoint):
                    log.warning("  %s with invalid toEndpoint, dropped", kind)
                    continue
                if to_endpoint:
                    reached = await deliver_to_endpoint(to, to_endpoint, msg, exclude=ws)
                else:
                    reached = await deliver(to, msg, exclude=ws)
                log.info("%-16s from=%s  to=%s  reached=%d%s",
                         kind.upper()[:16], short(frm), short(to), reached,
                         f"  endpoint={short(to_endpoint)}" if to_endpoint else "")

            elif kind == "sig:relay_req":
                await send_to(ws, {
                    "type":           "sig:relay_info",
                    "wss":            RELAY_WSS_URL or None,
                    "version":        PROTOCOL_VERSION,
                    "vapidPublicKey": VAPID_PUBLIC_KEY_B64,
                })
                log.info("RELAY_INFO sent to %s  wss=%s  version=%s",
                         short(last_id()), RELAY_WSS_URL or "—", PROTOCOL_VERSION)

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
        # release per-IP slot — and the shared limiter along with it, once
        # this IP has no sockets left (otherwise ip_limiters grows forever
        # under normal IP churn, one entry per address ever seen).
        if addr in ip_conns:
            ip_conns[addr] -= 1
            if ip_conns[addr] <= 0:
                del ip_conns[addr]
                ip_limiters.pop(addr, None)
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
        # drop reverse-map entry (send_to's failure path may have popped it already)
        ws_to_ids.pop(ws, None)
        # same for the routing-id map — a clean close reaches here without
        # ever going through send_to's failure branch, so this path needs
        # its own cleanup rather than relying on that one
        for (cid, rid) in ws_to_endpoint.pop(ws, []):
            devmap = connected_by_endpoint.get(cid)
            if devmap:
                sockets = devmap.get(rid)
                if sockets:
                    sockets.discard(ws)
                    if not sockets:
                        del devmap[rid]
                if not devmap:
                    del connected_by_endpoint[cid]

# ══════════════════════════════════════════
#   SIGNAL SERVER ENTRYPOINT (async)
# ══════════════════════════════════════════

async def run_signal_server():
    #os.makedirs(BUF_DIR, exist_ok=True)
    log.info("=" * 50)
    log.info("MeshChat signal server")
    log.info("Listening on %s:%d", WS_HOST, WS_PORT)
    log.info("Buffer dir: %s  max_msgs=%d  max_age=%ds  migrate_age=%ds  burn_age=%ds  max_mb=%.1f  max_recipients=%d  max_endpoints_per_recipient=%d",
             BUF_DIR, BUF_MAX_MSGS, BUF_MAX_AGE, BUF_MAX_AGE_MIGRATE, BUF_MAX_AGE_BURN, BUF_MAX_MB, MAX_BUF_RECIPIENTS, MAX_ENDPOINTS_PER_RECIPIENT)
    log.info("Buffer write-rate: %.1f/s per recipient  burst=%.0f  idle_prune=%ds",
             BUF_WRITE_RATE_LIMIT, BUF_WRITE_RATE_BURST, BUF_RATE_LIMITER_IDLE_S)
    log.info("Global auth admission: %.1f/s  burst=%.0f", GLOBAL_AUTH_RATE, GLOBAL_AUTH_BURST)
    log.info("Trusted proxies: %s", ", ".join(str(n) for n in TRUSTED_PROXIES) or "(none)")
    log.info("Push: subs_dir=%s  vapid_key=%s  vapid_pub=%s…  ttl=%ds  subject=%s",
             PUSH_SUBS_DIR, VAPID_KEY_FILE, VAPID_PUBLIC_KEY_B64[:16], PUSH_TTL_SECONDS, VAPID_SUBJECT)
    log.info("=" * 50)
    async with websockets.serve(handler, WS_HOST, WS_PORT, max_size=WS_MAX_SIZE):
        asyncio.create_task(log_stats())
        asyncio.create_task(buf_expire())
        asyncio.create_task(sweep_pending_auth())
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