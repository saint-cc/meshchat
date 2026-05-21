import asyncio
import json
import logging
import multiprocessing
import os
import time
from email import message_from_bytes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

import aiosmtplib
import aioimaplib
import websockets
from flask import Flask, send_from_directory

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
RELAY_EMAIL   = os.environ.get("RELAY_EMAIL",   "")   # e.g. meshchat@yourrelay.example.com

# Rate limiter
RATE_LIMIT_RATE  = 10   # tokens refilled per second
RATE_LIMIT_BURST = 20   # max burst size

# Online presence
ONLINE_EXPIRY_SECONDS = 300   # prune peers not seen within this window

# Email relay (offline message delivery)
EMAIL_HOST     = os.environ.get("EMAIL_HOST",     "mail.somemail.cc")
EMAIL_PORT_OUT = int(os.environ.get("EMAIL_PORT_OUT", 587))
EMAIL_PORT_IN  = int(os.environ.get("EMAIL_PORT_IN",  993))
EMAIL_USER     = os.environ.get("EMAIL_USER",     "meshchat@somemail.cc")
EMAIL_PASS     = os.environ.get("EMAIL_PASS",     "")
EMAIL_FROM     = os.environ.get("EMAIL_FROM",     EMAIL_USER)
EMAIL_TLS      = os.environ.get("EMAIL_TLS",      "starttls")  # "starttls" or "ssl"
EMAIL_TICK     = int(os.environ.get("EMAIL_TICK", 60))         # seconds between email cycles
EMAIL_STARTUP_DELAY = int(os.environ.get("EMAIL_STARTUP_DELAY", 10))

# Logging
LOG_FORMAT   = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATE_FMT = "%H:%M:%S"
LOG_LEVEL    = logging.INFO

# Stats interval
STATS_INTERVAL = 60   # seconds between periodic stat dumps

# ══════════════════════════════════════════
#   LOGGING SETUP
# ══════════════════════════════════════════

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FMT)
log = logging.getLogger("signal")

# ══════════════════════════════════════════
#   SIGNAL SERVER STATE
# ══════════════════════════════════════════

connected:   dict[str, set]  = {}   # commID → set of websockets
email_queue: dict[str, list] = {}   # commID → [raw msg dict, ...]

stats = {
    "bytes_in":  0, "bytes_out":  0,
    "msgs_in":   0, "msgs_out":   0,
    "email_in":  0, "email_out":  0,
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
    try:    return str(ws.remote_address)
    except: return "unknown"

def session_count():
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
        raw = json.dumps(obj)
        await ws.send(raw)
        stats["bytes_out"] += len(raw)
        stats["msgs_out"]  += 1
        return True
    except Exception as e:
        log.warning("  send failed: %s", e)
        return False

async def deliver(to_id, obj, exclude=None):
    sessions = connected.get(to_id, set())
    reached  = 0
    for ws in list(sessions):
        if ws is exclude: continue
        if await send_to(ws, obj): reached += 1
    return reached

# ══════════════════════════════════════════
#   EMAIL OUTBOUND
# ══════════════════════════════════════════

async def flush_email_queue():
    """Send one email per queued recipient, body = JSON array of packets."""
    if not email_queue:
        return
    for comm_id, entry in list(email_queue.items()):
        msgs   = entry["msgs"]
        target = entry.get("target") or EMAIL_USER
        if not msgs:
            continue
        try:
            body = json.dumps(msgs)
            mail = MIMEMultipart()
            mail["From"]    = EMAIL_FROM
            mail["To"]      = target
            mail["Subject"] = f"MC:{comm_id}"
            mail["Date"]    = formatdate(localtime=True)
            mail.attach(MIMEText(body, "plain"))

            await aiosmtplib.send(
                mail,
                hostname=EMAIL_HOST,
                port=EMAIL_PORT_OUT,
                username=EMAIL_USER,
                password=EMAIL_PASS,
                sender=EMAIL_FROM,
                recipients=[target],
                **({ "use_tls": True } if EMAIL_TLS == "ssl" else { "start_tls": True }),
            )
            stats["email_out"] += 1
            log.info("EMAIL OUT  to=%s  target=%s  packets=%d", short(comm_id), target, len(msgs))
            del email_queue[comm_id]
        except Exception as e:
            log.warning("EMAIL OUT fail  to=%s  target=%s  error=%s", short(comm_id), target, e)

# ══════════════════════════════════════════
#   EMAIL INBOUND
# ══════════════════════════════════════════

async def poll_email_inbox():
    """Poll IMAP, deliver any MC:<commID> emails to online peers."""
    try:
        imap = aioimaplib.IMAP4_SSL(host=EMAIL_HOST, port=EMAIL_PORT_IN)
        await imap.wait_hello_from_server()
        await imap.login(EMAIL_USER, EMAIL_PASS)
        await imap.select("INBOX")

        _, data_uid = await imap.uid_search("UNSEEN")
        log.info("EMAIL IN   UID UNSEEN raw: %r", data_uid)

        uids = data_uid[0].split() if data_uid and data_uid[0] else []
        uids = [u for u in uids if u and u != b'']

        _, data_all = await imap.uid_search("ALL")
        log.info("EMAIL IN   UID ALL raw: %r", data_all)

        if not uids:
            log.info("EMAIL IN   no unseen messages")
            await imap.logout()
            return

        log.info("EMAIL IN   found %d unseen uid(s): %r", len(uids), uids)

        for uid in uids:
            try:
                uid_str = uid.decode() if isinstance(uid, bytes) else uid
                status, msg_data = await imap.uid("fetch", uid_str, "(RFC822)")

                raw_email = bytes(msg_data[1]) if isinstance(msg_data[1], (bytes, bytearray)) else None
                if not raw_email:
                    log.warning("EMAIL IN   unexpected fetch structure: %r",
                                [type(p).__name__ for p in msg_data])
                    continue

                parsed  = message_from_bytes(raw_email)
                subject = parsed.get("Subject", "")

                if not subject.startswith("MC:"):
                    log.info("EMAIL IN   uid=%s  not a meshchat email, skipping", uid_str)
                    continue

                comm_id = subject[3:].strip()
                if not comm_id:
                    continue

                body = ""
                if parsed.is_multipart():
                    for part in parsed.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                            break
                else:
                    body = parsed.get_payload(decode=True).decode("utf-8", errors="replace")

                packets = json.loads(body)
                if not isinstance(packets, list):
                    packets = [packets]

                log.info("EMAIL IN   uid=%s  to=%s  packets=%d",
                         uid_str, short(comm_id), len(packets))

                delivered = 0
                for pkt in packets:
                    reached = await deliver(comm_id, pkt)
                    delivered += reached

                stats["email_in"] += 1

                if delivered > 0:
                    await imap.uid("store", uid_str, "+FLAGS", "\\Seen")
                    log.info("EMAIL IN   to=%s  delivered=%d  marked seen",
                             short(comm_id), delivered)
                else:
                    await imap.uid("store", uid_str, "-FLAGS", "\\Seen")
                    log.info("EMAIL IN   to=%s  offline — kept unseen for retry",
                             short(comm_id))

            except Exception as e:
                log.warning("EMAIL IN   parse/deliver fail uid=%s  error=%s", uid, e)

        await imap.logout()

    except Exception as e:
        log.warning("EMAIL IN   imap error: %s", e, exc_info=True)

# ══════════════════════════════════════════
#   EMAIL TICK
# ══════════════════════════════════════════

async def email_tick():
    """Combined inbound + outbound cycle, runs every EMAIL_TICK seconds."""
    await asyncio.sleep(EMAIL_STARTUP_DELAY)
    while True:
        log.info("EMAIL TICK outbound flush + inbound poll")
        await flush_email_queue()
        await poll_email_inbox()
        await asyncio.sleep(EMAIL_TICK)

# ══════════════════════════════════════════
#   STATS
# ══════════════════════════════════════════

async def log_stats():
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        log.info("STATS      sessions=%d  in=%s(%d msgs)  out=%s(%d msgs)  "
                 "email_in=%d  email_out=%d",
                 session_count(),
                 fmt_bytes(stats["bytes_in"]),  stats["msgs_in"],
                 fmt_bytes(stats["bytes_out"]), stats["msgs_out"],
                 stats["email_in"], stats["email_out"])

# ══════════════════════════════════════════
#   WEBSOCKET HANDLER
# ══════════════════════════════════════════

async def handler(ws):
    client_id = None
    limiter   = RateLimiter()
    addr      = peer_info(ws)
    log.info("CONNECT    peer=%s", addr)

    try:
        async for raw in ws:

            if not limiter.allow():
                log.warning("RATELIMIT  peer=%s  id=%s", addr, short(client_id))
                await send_to(ws, {"type": "error", "reason": "rate_limited"})
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("BAD JSON   peer=%s  raw=%r", addr, raw[:120])
                continue

            stats["bytes_in"] += len(raw)
            stats["msgs_in"]  += 1

            kind = msg.get("type", "?")
            log.info("IN  %-20s peer=%s  size=%-8s total_in=%s  total_out=%s",
                     kind, addr,
                     fmt_bytes(len(raw)),
                     fmt_bytes(stats["bytes_in"]),
                     fmt_bytes(stats["bytes_out"]))

            if kind == "connect":
                client_id = msg.get("id")
                if not client_id:
                    log.warning("  connect with no id, ignored")
                    continue
                if client_id not in connected:
                    connected[client_id] = set()
                connected[client_id].add(ws)
                log.info("REGISTERED id=%s  peer=%s  sessions=%d  total=%d",
                         short(client_id), addr,
                         len(connected[client_id]), session_count())

            elif kind == "get_relay_info":
                if RELAY_WSS_URL or RELAY_EMAIL:
                    await send_to(ws, {
                        "type":  "relay_info",
                        "wss":   RELAY_WSS_URL,
                        "email": RELAY_EMAIL,
                    })
                    log.info("RELAY_INFO sent to %s", short(client_id))
                else:
                    log.debug("RELAY_INFO requested but not configured, skipped")

            elif kind == "who_online":
                ids = msg.get("ids", [])
                if not isinstance(ids, list):
                    log.warning("  who_online bad payload, dropped")
                    continue
                ids     = ids[:10]
                matched = [id for id in ids if id in connected]
                if client_id:
                    for matched_id in matched:
                        await deliver(matched_id, {"type": "seen", "id": client_id}, exclude=ws)

            elif kind == "message":
                frm = msg.get("from", "?")
                to  = msg.get("to")
                if not to:
                    log.warning("  message with no 'to', dropped")
                    continue
                reached = await deliver(to, msg, exclude=ws)
                if reached:
                    log.info("MESSAGE    from=%s  to=%s  reached=%d", short(frm), short(to), reached)
                else:
                    target = msg.get("relay_email") or EMAIL_USER
                    if to not in email_queue:
                        email_queue[to] = {"target": target, "msgs": []}
                    email_queue[to]["msgs"].append(msg)
                    log.info("EMAIL Q    from=%s  to=%s  target=%s  queued (offline)",
                             short(frm), short(to), target)

            elif kind in ("msg_exchange", "backup_offer", "backup_accept",
                          "backup_push", "push_restore_request",
                          "push_restore_ack", "restore_push"):
                frm = msg.get("from", "?")
                to  = msg.get("to")
                if not to:
                    log.warning("  %s with no 'to', dropped", kind)
                    continue
                reached = await deliver(to, msg, exclude=ws)
                log.info("%-12s from=%s  to=%s  reached=%d",
                         kind.upper()[:12], short(frm), short(to), reached)

            elif kind == "ping":
                await send_to(ws, {"type": "pong"})

            else:
                log.warning("UNKNOWN    type=%r  peer=%s  dropped", kind, addr)

    except websockets.exceptions.ConnectionClosedOK:
        log.info("CLOSE OK   peer=%s  id=%s", addr, short(client_id))
    except websockets.exceptions.ConnectionClosedError as e:
        log.warning("CLOSE ERR  peer=%s  id=%s  reason=%s", addr, short(client_id), e)
    except Exception as e:
        log.error("HANDLER EX peer=%s  id=%s  error=%s", addr, short(client_id), e)
    finally:
        if client_id and client_id in connected:
            connected[client_id].discard(ws)
            remaining = len(connected[client_id])
            if remaining == 0:
                del connected[client_id]
                log.info("REMOVED    id=%s  peer=%s  total=%d",
                         short(client_id), addr, session_count())
            else:
                log.info("SESSION-   id=%s  peer=%s  sessions_left=%d",
                         short(client_id), addr, remaining)

# ══════════════════════════════════════════
#   SIGNAL SERVER ENTRYPOINT (async)
# ══════════════════════════════════════════

async def run_signal_server():
    log.info("=" * 50)
    log.info("MeshChat signal server")
    log.info("Listening on %s:%d", WS_HOST, WS_PORT)
    log.info("Email host: %s  tick: %ds  tls: %s", EMAIL_HOST, EMAIL_TICK, EMAIL_TLS)
    log.info("=" * 50)
    async with websockets.serve(handler, WS_HOST, WS_PORT):
        asyncio.create_task(log_stats())
        asyncio.create_task(email_tick())
        await asyncio.Future()

# ══════════════════════════════════════════
#   HTTP SERVER (Flask, separate process)
# ══════════════════════════════════════════

def run_http_server():
    """Runs in its own process so Flask's WSGI loop doesn't block asyncio."""
    http_log = logging.getLogger("http")
    http_log.info("HTTP server starting on %s:%d  static=%s", HTTP_HOST, HTTP_PORT, STATIC_DIR)

    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

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
        log.info("FINAL      in=%s(%d msgs)  out=%s(%d msgs)  email_in=%d  email_out=%d",
                 fmt_bytes(stats["bytes_in"]),  stats["msgs_in"],
                 fmt_bytes(stats["bytes_out"]), stats["msgs_out"],
                 stats["email_in"], stats["email_out"])
    finally:
        http_proc.terminate()
        http_proc.join()