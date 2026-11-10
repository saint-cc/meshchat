import asyncio
import base64
import glob
import hashlib
import http.client
import ipaddress
import json
import logging
import multiprocessing
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

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

# Hostnames this relay accepts a client's auth proof for — see AUTH_HOSTS in
# the AUTH HELPERS section. The host of RELAY_WSS_URL is always included and
# is REQUIRED: with no valid RELAY_WSS_URL the relay refuses every
# sig:auth_init ("relay_not_configured") rather than guessing its own name.
# RELAY_AUTH_HOSTS adds extra names, comma-separated — bare hostnames or
# full URLs — for a relay that is reachable under more than one name (a
# client signs the host IT dialed, so a second name that isn't listed here
# fails with proof_invalid). Never derived from the Host header: that's
# chosen by whoever is connecting, which is the one party that must not
# get to decide what the proof is bound to.
RELAY_AUTH_HOSTS_RAW = os.environ.get("RELAY_AUTH_HOSTS", "")

# Protocol version — informational only for now, surfaced in sig:relay_info
# so client/server version drift shows up in both logs. Not enforced yet;
# room to add real backwards-compat handling once this is actually needed.
PROTOCOL_VERSION = os.environ.get("PROTOCOL_VERSION", "0.6.4")

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

# Rate limiter — two separate tiers, deliberately not one shared constant
# pair. Every connection gets its own per-socket RateLimiter (below) *and*
# every socket from the same source IP shares one additional RateLimiter
# via ip_limiters[addr] (see handler()) — the per-socket one caps a single
# misbehaving/bugged connection, the per-IP one caps a flood spread across
# many sockets from one address. Both used to default from the same two
# constants, which meant there was no way to give "one connection" a
# different budget than "everything behind this NAT combined": loosening
# the shared pair to accommodate several legitimate clients on one IP
# (a household, a NAT'd office) also loosened the per-socket ceiling for
# the single-bad-actor case that limiter actually exists for. Split so
# each can be tuned independently — the per-socket pair stays tight
# (10/20 is plenty for one real client), the per-IP pair is sized for a
# small household of concurrent clients sharing an address by default,
# and either can move without touching the other.
RATE_LIMIT_RATE  = int(os.environ.get("RATE_LIMIT_RATE",  20))   # per-socket: tokens refilled per second
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", 60))   # per-socket: max burst size

# Per-IP shared budget — defaults to 3x the per-socket pair, a reasonable
# "small household, not an attacker" assumption rather than a literal
# per-client multiple (four clients each getting their old individual
# budget would need 4x; 3x leaves genuine concurrent traffic from several
# clients some headroom without handing a single-IP flood a proportionally
# larger allowance just because more sockets happen to share that address).
# Tune upward if a legitimate deployment still sees per-IP warnings after
# checking they're not actually MAX_CONNECTIONS_PER_IP or a buffer-side
# limit instead (see BUF_WRITE_RATE_LIMIT below) — those are separate
# knobs and bumping this one won't touch them.
IP_RATE_LIMIT_RATE  = int(os.environ.get("IP_RATE_LIMIT_RATE",  RATE_LIMIT_RATE * 3))
IP_RATE_LIMIT_BURST = int(os.environ.get("IP_RATE_LIMIT_BURST", RATE_LIMIT_BURST * 3))

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

# ══════════════════════════════════════════
#   RESOURCE PROTECTION
#   The relay is the open part of the network and identities cost nothing,
#   so everything below bounds what ONE socket / ONE address / ONE identity
#   can make the process spend: sockets held, bytes parsed, CPU burnt on
#   JSON, disk written, outbound HTTP made, log lines produced. None of it
#   changes the wire protocol — a well-behaved client never notices.
#   Every number is a named constant; the ones worth tuning have env overrides.
# ══════════════════════════════════════════

def _env_int(name, default):
    return int(os.environ.get(name, default))

def _env_float(name, default):
    return float(os.environ.get(name, default))

# ── sockets ──
# MAX_CONNECTIONS / MAX_CONNECTIONS_PER_IP (above) now count EVERY open
# socket, authed or not — they used to count only registered (authed) ones,
# so unauthenticated sockets were free to pile up without bound.
#
# Unauthenticated sockets get their own, much smaller, per-address cap and a
# hard deadline: a real client sends sig:auth_init within milliseconds of
# connecting and has its proof signed a round-trip later.
MAX_UNAUTH_PER_IP = _env_int("MAX_UNAUTH_PER_IP", 4)         # unauthed sockets one address may hold at once
UNAUTH_DEADLINE_S = _env_float("UNAUTH_DEADLINE_S", 10)      # seconds from connect to a COMPLETED auth, else closed
# When the relay is full a new connection EVICTS (unauthed first, oldest
# first; then an authed socket that has been silent longer than this)
# instead of being refused. Clients send sig:announce about every 30 s, so a
# live client is never silent for minutes; 180 s leaves room for a
# backgrounded tab whose timers are throttled.
WS_IDLE_EVICT_S = _env_float("WS_IDLE_EVICT_S", 180)
# Sockets that are closing still hold a slot until their close handshake
# ends (up to websockets' close_timeout). Refuse outright past this multiple
# of MAX_CONNECTIONS so evicting can never snowball.
CONN_HARD_CAP_FACTOR = 2
IPV6_KEY_PREFIX = 64        # IPv6 clients are keyed by their /64 — one customer holds a whole /64, so per-address caps on /128 are meaningless
CLOSE_GRACE_S = 5           # how long a relay-initiated close may take before the transport is aborted

# One identity may be connected this many times at once (devices + tabs +
# outbound relay connections from its contacts' clients). Past it the OLDEST
# session is dropped. Without a cap, one free identity multiplies into
# MAX_CONNECTIONS_PER_IP sockets per address, every one of them a
# registered fan-out target.
MAX_SESSIONS_PER_IDENTITY = _env_int("MAX_SESSIONS_PER_IDENTITY", 8)

# A send that cannot complete in this long means the peer is not reading
# (or is reading very slowly on purpose); the socket is closed instead of
# letting one stalled peer hold up every handler that delivers to it.
SEND_TIMEOUT_S = _env_float("SEND_TIMEOUT_S", 8)

# ── frame size caps ──
# Checked on the raw text BEFORE json.loads, so an oversized frame costs a
# length comparison, not a parse. The library's own max_size (WS_MAX_SIZE)
# stays the outer bound; before auth it is lowered to FRAME_CAP_PREAUTH on
# the connection itself so the library refuses to even buffer more.
#   PREAUTH   — sig:auth_init / sig:auth_proof are a few hundred bytes
#   TINY      — id-only / key-only packets: session:*, app:burn, sig:announce,
#               sig:ping, sig:relay_req
#   HANDSHAKE — small encrypted/signed handshake packets: app:migrate,
#               sync:backup_offer/accept, sync:restore_req/ack,
#               sync:token_req/resp, sig:push_subscribe/unsubscribe
#   SIGNAL    — call:* / data:* (SDP and ICE blobs; an int-array-encoded
#               SDP is tens of KiB)
#   BULK      — frames whose whole purpose is carrying a blob: app:sync,
#               sync:backup_push, sync:restore_push (a self-sync push is the
#               full contact store). Deliberately NOT capped at the
#               "handshake" size — a real backup is far larger than that.
#   MESSAGE   — app:message (media rides inside it)
# All clamped to WS_MAX_SIZE.
def _frame_cap(name, default):
    return min(WS_MAX_SIZE, _env_int(name, default))

FRAME_CAP_PREAUTH   = _frame_cap("FRAME_CAP_PREAUTH",   1024)
FRAME_CAP_TINY      = _frame_cap("FRAME_CAP_TINY",      4 * 1024)
FRAME_CAP_HANDSHAKE = _frame_cap("FRAME_CAP_HANDSHAKE", 16 * 1024)
FRAME_CAP_SIGNAL    = _frame_cap("FRAME_CAP_SIGNAL",    128 * 1024)
FRAME_CAP_BULK      = _frame_cap("FRAME_CAP_BULK",      WS_MAX_SIZE)
FRAME_CAP_MESSAGE   = _frame_cap("FRAME_CAP_MESSAGE",   WS_MAX_SIZE)

# ── byte budgets ──
# Token buckets counted in BYTES (the packet-count limiters above cannot see
# a 2 MiB frame from a 100-byte one). One per socket and one shared by every
# socket of an address. The burst must hold at least one maximum-size frame
# or such a frame could never be admitted at all.
BYTE_RATE_SOCKET  = _env_float("BYTE_RATE_SOCKET",  1024 * 1024)            # bytes/s refilled, per socket
BYTE_BURST_SOCKET = _env_float("BYTE_BURST_SOCKET", max(6 * 1024 * 1024, 3 * WS_MAX_SIZE))
BYTE_RATE_IP      = _env_float("BYTE_RATE_IP",      2 * 1024 * 1024)        # bytes/s refilled, per address
BYTE_BURST_IP     = _env_float("BYTE_BURST_IP",     max(12 * 1024 * 1024, 6 * WS_MAX_SIZE))

# ── per-type budgets (per socket) ──
# The general per-socket limiter treats every packet alike, so one socket
# could spend all of it on the most expensive kind. Each class below is its
# own bucket: (refill/s, burst). A client's normal traffic is far under all
# of these — sig:announce, for one, is sent about every 30 s.
# Classes with no entry here (app:message) are governed by the general
# limiters and the byte buckets only.
TYPE_LIMITS = {
    "announce": (_env_float("LIMIT_ANNOUNCE_RATE", 0.1), _env_float("LIMIT_ANNOUNCE_BURST", 3)),    # 1 per 10 s, burst 3
    "push":     (_env_float("LIMIT_PUSH_RATE",     0.2), _env_float("LIMIT_PUSH_BURST",     5)),    # push_subscribe/unsubscribe: disk + directory scans
    "session":  (_env_float("LIMIT_SESSION_RATE",  5),   _env_float("LIMIT_SESSION_BURST",  40)),   # session:propose/ack: always durably buffered
    "migrate":  (_env_float("LIMIT_MIGRATE_RATE",  2),   _env_float("LIMIT_MIGRATE_BURST",  60)),   # app:migrate/burn: one per contact in a burst; always durably buffered
    "sync":     (_env_float("LIMIT_SYNC_RATE",     5),   _env_float("LIMIT_SYNC_BURST",     30)),   # app:sync, sync:*
    "signal":   (_env_float("LIMIT_SIGNAL_RATE",   10),  _env_float("LIMIT_SIGNAL_BURST",   40)),   # call:*, data:* (ICE candidates arrive in bursts)
    "misc":     (_env_float("LIMIT_MISC_RATE",     2),   _env_float("LIMIT_MISC_BURST",     10)),   # sig:ping, sig:relay_req
}

# ── strikes ──
# Replying to every over-limit packet turns a flood into twice the traffic
# and a log line per packet. Instead each violation is a STRIKE, strikes
# leak away over time, and a socket that piles them up is closed. Only the
# first rate-limit / unauthenticated reply on a socket is actually sent.
STRIKE_LIMIT     = _env_float("STRIKE_LIMIT", 10)         # closed when the (decayed) count exceeds this
STRIKE_DECAY_S   = _env_float("STRIKE_DECAY_S", 10)       # one strike forgiven per this many quiet seconds
STRIKE_WEIGHT_IP = 0.5                                    # hitting the SHARED per-address limiter counts for less: a neighbour behind the same NAT can hit it too
CLOSE_CODE_POLICY   = 1008   # malformed / oversized / unauthenticated abuse
CLOSE_CODE_BUSY     = 1013   # rate limits, capacity ("try again later")
CLOSE_CODE_BINARY   = 1003   # binary frame — the protocol is text-only
CLOSE_CODE_TOO_BIG  = 1009   # what the library itself closes with when a frame exceeds its max size

# Warning lines an attacker can trigger per packet are collapsed: at most one
# line per key per this many seconds, carrying a "(+N suppressed)" count.
LOG_THROTTLE_S = _env_float("LOG_THROTTLE_S", 10)

# ── push ──
# A push is outbound HTTP to a third party, each send holding a thread for
# up to PUSH_TIMEOUT_SECONDS × PUSH_MAX_ADDRS_TRIED. It runs as a background
# task on its OWN thread pool, never inside the sender's handler and never on
# the default executor that buffer I/O shares.
PUSH_COOLDOWN_S            = _env_float("PUSH_COOLDOWN_S", 45)     # at most one push per recipient per this long (a push only means "wake up and check")
PUSH_MAX_CONCURRENT        = _env_int("PUSH_MAX_CONCURRENT", 4)    # pushes in flight (= push worker threads)
PUSH_MAX_QUEUE             = _env_int("PUSH_MAX_QUEUE", 200)      # pushes waiting + in flight; beyond it new ones are dropped
PUSH_COOLDOWN_MAX_ENTRIES  = 50000   # ceiling on remembered per-recipient cooldowns (see push_last)
MAX_PUSH_IDENTITIES        = _env_int("MAX_PUSH_IDENTITIES", 10000)   # distinct identity directories under PUSH_SUBS_DIR — same role as MAX_BUF_RECIPIENTS

# ── buffer sweep ──
BUF_EXPIRE_CHUNK = _env_int("BUF_EXPIRE_CHUNK", 200)   # recipient directories swept per worker-thread call (the loop gets control between chunks)

# ID validation — base64url chars only, 8–64 chars
_ID_RE = re.compile(r'^[A-Za-z0-9\-_]{8,64}$')
def valid_id(s): return isinstance(s, str) and bool(_ID_RE.match(s))

# ── COMPOUND ADDRESSING — "id::endpointId" ──
# `to` may now carry an optional device-routing suffix, the same way a
# house number carries an optional unit letter: "1534" routes to the
# building, "1534b" to one specific unit inside it. `id::endpointId`
# replaces the old separate `toEndpoint` field entirely — one field to
# read instead of two, and a human glancing at a log line sees the whole
# routing story in one string.
#
# Deliberately NOT folded into valid_id() itself: valid_id() is reused for
# deviceId, callId, sessionId, and endpoint_id — none of which should ever
# accept the compound form, only `to` should. base64url (valid_id's own
# charset) never contains ':', so the split is unambiguous with no
# escaping needed — the same property that already makes the shareable
# address's '.'-joined segments unambiguous.
#
# `from` deliberately stays bare — it's not a routing instruction, it's
# "who sent this", and the relay derives the true sender from the authed
# socket regardless of what's written there. Only `to` ever carries a unit.
ADDR_SEP = "::"

def parse_address(addr):
    """"id" or "id::endpointId" -> (id, endpoint_or_None). Returns
    (None, None) if addr isn't a string, or either half fails valid_id() —
    callers treat that identically to today's `not valid_id(to)` check."""
    if not isinstance(addr, str):
        return None, None
    if ADDR_SEP in addr:
        parts = addr.split(ADDR_SEP)
        if len(parts) != 2:
            return None, None
        base_id, endpoint_id = parts
        if not (valid_id(base_id) and valid_id(endpoint_id)):
            return None, None
        return base_id, endpoint_id
    return (addr, None) if valid_id(addr) else (None, None)

def build_address(base_id, endpoint_id=None):
    """Inverse of parse_address() — mirrors the client's buildAddress() in
    meshchat-lib.js exactly. Used server-side only for constructing log
    lines / any packet the relay itself originates that might need one;
    routing always goes through parse_address() on the way in."""
    return f"{base_id}{ADDR_SEP}{endpoint_id}" if endpoint_id else base_id

# Online presence
ONLINE_EXPIRY_SECONDS = 300   # prune peers not seen within this window

# Offline buffer — file-based queue for messages to offline clients
BUF_DIR      = os.environ.get("BUF_DIR",      os.path.join(os.getcwd(), "relay_buf"))
BUF_MAX_MSGS = int(os.environ.get("BUF_MAX_MSGS", 100))     # max packets per recipient
BUF_MAX_AGE  = int(os.environ.get("BUF_MAX_AGE",  86400))   # seconds before expiry (24h)
BUF_MAX_MB   = float(os.environ.get("BUF_MAX_MB",  10))     # max MB per recipient
BUF_EXPIRE_INTERVAL = 300                                    # seconds between expiry sweeps

# Fair share and reserved slots inside ONE recipient's buffer (or one device
# bucket). The per-recipient cap (BUF_MAX_MSGS / BUF_MAX_MB) used to be
# "drop the oldest", across everybody — so one sender writing 100 packets
# pushed out the genuine packets other senders had left, migrate/burn notices
# included. Now:
#   - REGULAR packets (app:message, session:*, …) may use at most
#     BUF_MAX_MSGS - BUF_RESERVED_SLOTS slots. The reserved slots are for
#     app:migrate / app:burn only, and a regular packet never evicts one.
#   - when something has to go, it comes from the sender holding the MOST
#     (slots, or bytes for the size limit) — that sender's own oldest packet.
#     A single sender therefore still gets the whole buffer when nobody else
#     is writing, but can never push out another sender's packets by flooding.
BUF_RESERVED_SLOTS = _env_int("BUF_RESERVED_SLOTS", 10)

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

# session:propose packets get overwrite-per-sender treatment too (see
# X4DH.md §13.2) — a fresh proposal fully supersedes an older buffered
# one from the same sender toward the same device, same reasoning as
# app:migrate/app:burn. Deliberately NOT given the long migrate/burn TTL
# though — plain BUF_MAX_AGE applies (own suffix just keeps it out of
# MIGRATE_SUFFIX/BURN_SUFFIX's own overwrite scans, never a new TTL
# bucket in buf_expire). An unanswered handshake attempt isn't something
# that must eventually be seen no matter what; a fresh one follows
# naturally whenever the conversation actually resumes. session:ack is
# NOT in this overwrite group — see route_or_buffer's docstring.
X4DH_PROPOSE_SUFFIX = "_x4dh_propose.json"

# ══════════════════════════════════════════
#   KNOWN-IDENTITY REGISTRY + PROBATION
#   `to` only has to satisfy valid_id(): a sender can aim packets at an
#   identity that has never connected here, and every one of those used to get
#   a full recipient directory (up to MAX_BUF_RECIPIENTS of them, 100 packets /
#   10 MB each). The relay now remembers which identities have actually
#   authenticated to RECEIVE here (and which of their devices), and treats a
#   recipient it has never seen differently:
#     - known identity                → the normal buffer, as before
#     - never-seen identity           → PROBATION: ONE packet, keep-first, in a
#                                       small separate pool (BUF_DIR/.probation)
#                                       that can never touch real capacity
#     - known identity, unknown device→ ONE packet per bucket, and only a couple
#                                       of such buckets, so the real
#                                       MAX_ENDPOINTS_PER_RECIPIENT slots can't
#                                       be squatted
#   The first packet a legitimate stranger needs to send (a content-free
#   session:propose / HELLO) fits in one slot; anything more waits until the
#   recipient has connected once, which promotes them to known and flushes
#   whatever sat in probation. Live delivery is never affected.
#
#   The registry is a SQLite file under STATE_DIR. It is only a cache of
#   "who has authed here" — losing it is never fatal: a missing / corrupt /
#   newer-format file is replaced by a fresh one, seeded from the existing
#   BUF_DIR and PUSH_SUBS_DIR directories, and for REGISTRY_GRACE_S afterwards
#   every recipient is treated as known (so nobody's offline messages are
#   refused just because the relay forgot who they were). If STATE_DIR can't
#   be written at all the registry simply lives in memory.
# ══════════════════════════════════════════
# One place for the relay's own small state. It defaults to the directory that
# holds BUF_DIR — exactly where VAPID_KEY_FILE and PUSH_SUBS_DIR have always
# defaulted — so an existing setup changes nothing. Mount it as a volume to
# keep the registry (and, optionally, the VAPID key and push subscriptions)
# across container updates; mounting it is optional.
STATE_DIR   = os.environ.get("STATE_DIR", os.path.dirname(os.path.abspath(BUF_DIR)))
REGISTRY_DB = os.environ.get("REGISTRY_DB", os.path.join(STATE_DIR, "known_ids.sqlite3"))
REGISTRY_FORMAT = 1                  # PRAGMA user_version this code reads and writes
REGISTRY_GRACE_S        = _env_float("REGISTRY_GRACE_S", BUF_MAX_AGE)   # after a NEW registry: treat every recipient as known this long
REGISTRY_TTL_S          = _env_float("REGISTRY_TTL_S", 30 * 86400)      # forget an identity not seen for this long
REGISTRY_MAX_IDENTITIES = _env_int("REGISTRY_MAX_IDENTITIES", 50000)    # least-recently-seen evicted past this
REGISTRY_MAX_ENDPOINTS  = _env_int("REGISTRY_MAX_ENDPOINTS", 32)        # remembered devices per identity (LRU)
REGISTRY_FLUSH_S        = 5          # seconds between write-behind flushes to disk
REGISTRY_TOUCH_GRANULARITY_S = 600   # a re-auth only rewrites an already-known identity's row this often

PROBATION_DIRNAME = ".probation"     # under BUF_DIR; the leading dot can never be a valid_id(), so it can't collide with a recipient
MAX_PROBATION_RECIPIENTS = _env_int("MAX_PROBATION_RECIPIENTS", 500)    # never-seen recipients holding a packet at once; the OLDEST is evicted for a new one
PROBATION_MAX_BYTES      = _env_int("PROBATION_MAX_BYTES", FRAME_CAP_HANDSHAKE)   # largest packet accepted into probation (a handshake fits; media doesn't)
PROBATION_ENDPOINTS_PER_RECIPIENT = _env_int("PROBATION_ENDPOINTS_PER_RECIPIENT", 2)   # unknown-device buckets a KNOWN identity may hold at once
# Creating a probation slot costs the relay a directory; per ADDRESS, so one
# machine can't churn the pool. Counted only for writes that would start a new slot.
PROBATION_IP_RATE  = _env_float("PROBATION_IP_RATE", 0.2)    # new probation slots/sec per address
PROBATION_IP_BURST = _env_float("PROBATION_IP_BURST", 10)

# ── auth admission, per address and for known identities ──
# GLOBAL_AUTH_RATE (above) caps how fast ANY auth can complete. Two additions:
#   - AUTH_RATE_IP: a per-address ceiling checked BEFORE the signature is
#     verified, so one machine can't make the relay spend CPU on proofs (or
#     burn the shared budget) faster than this. Sized for a NAT full of
#     clients reconnecting at once.
#   - AUTH_KNOWN_*: when the global budget is exhausted, an identity this relay
#     already knows still gets in through its own lane, so a flood of brand-new
#     identities can't lock real users out.
AUTH_RATE_IP     = _env_float("AUTH_RATE_IP",     2)
AUTH_BURST_IP    = _env_float("AUTH_BURST_IP",    20)
AUTH_KNOWN_RATE  = _env_float("AUTH_KNOWN_RATE",  GLOBAL_AUTH_RATE)
AUTH_KNOWN_BURST = _env_float("AUTH_KNOWN_BURST", GLOBAL_AUTH_BURST)

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
#   VAPID_KEY_FILE/PUSH_SUBS_DIR default to sitting in STATE_DIR (which itself
#   defaults to the directory next to BUF_DIR) rather than under BUF_DIR —
#   same "fresh relay boots with sane defaults" spirit as BUF_DIR's own
#   default, just their own entries rather than a subdirectory, since a push
#   subscription isn't a buffered packet.
# ══════════════════════════════════════════
VAPID_SUBJECT    = os.environ.get("VAPID_SUBJECT", "mailto:admin@example.com")
VAPID_KEY_FILE   = os.environ.get("VAPID_KEY_FILE", os.path.join(STATE_DIR, "vapid_key.pem"))
PUSH_SUBS_DIR    = os.environ.get("PUSH_SUBS_DIR",  os.path.join(STATE_DIR, "push_subs"))
PUSH_TTL_SECONDS = int(os.environ.get("PUSH_TTL_SECONDS", 60))   # how long the push service should hold this if the device is unreachable

# ── push endpoint policy (SSRF) ──
# A push subscription's `endpoint` is a URL chosen by the CLIENT, and this
# relay later POSTs to it. Taken as-is that makes the relay an HTTP client any
# authed identity (free to create) can aim wherever it likes: internal
# services, cloud metadata, other hosts it wants to hammer. The old check was
# just startswith("https://"), and the sender used urllib, which also FOLLOWS
# redirects — a POST to a public endpoint answering 302 → http://127.0.0.1/…
# became a GET on the internal address (with the VAPID Authorization header
# along for the ride), so even a perfect check at subscribe time was not enough.
#
# Real browser push endpoints only ever live on a handful of vendor hosts, so
# the policy is an ALLOWLIST (below), enforced at subscribe time AND again at
# send time, on top of the address checks in _send_web_push_sync. An entry is
# an exact hostname, or — with a leading dot — a suffix that needs at least one
# more label in front (".push.services.mozilla.com" matches
# "updates.push.services.mozilla.com", not the bare name). Deliberately no
# ".googleapis.com": anyone can get a hostname under it.
# PUSH_ALLOWED_HOSTS REPLACES the defaults (comma-separated); a push service
# that isn't listed is rejected and the rejected HOST is logged, so adding one
# is a config change. Empty = push effectively off.
PUSH_ALLOWED_HOSTS_DEFAULT = ",".join((
    "fcm.googleapis.com", "android.googleapis.com",   # Chrome / Edge / Brave / Opera / Samsung (FCM)
    ".push.services.mozilla.com",                      # Firefox (updates.push.services.mozilla.com)
    ".notify.windows.com",                             # Edge on Windows (WNS)
    "web.push.apple.com",                              # Safari
))
PUSH_MAX_ENDPOINT_LEN        = 2048   # characters; real endpoints are a few hundred
PUSH_MAX_KEY_LEN             = 256    # p256dh / auth are ~87 / ~22 base64url chars
PUSH_MAX_SUBS_PER_IDENTITY   = int(os.environ.get("PUSH_MAX_SUBS_PER_IDENTITY", 10))   # one file per endpointId, and an identity costs nothing to make
PUSH_TIMEOUT_SECONDS         = 10     # per connect / read
PUSH_MAX_ADDRS_TRIED         = 3      # resolved addresses attempted per send (all must be public — see _send_web_push_sync)

# A plain DNS name: at least two labels, ASCII letters/digits/hyphens, and a
# TLD that starts with a letter — which is what keeps dotted-quad, decimal
# ("2130706433") and hex ("0x7f.1") spellings of an IP out, however a resolver
# would read them. IDN hosts must arrive in punycode.
_PUSH_HOST_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$')
_PUSH_ALLOWLIST_INVALID = []   # entries that failed to parse — logged once the logger exists, below

def _parse_push_allowlist(raw):
    exact, suffixes = set(), []
    for entry in raw.split(","):
        entry = entry.strip().lower()
        if not entry:
            continue
        bare = entry[1:] if entry.startswith(".") else entry
        if not _PUSH_HOST_RE.match(bare):
            _PUSH_ALLOWLIST_INVALID.append(entry)
            continue
        if entry.startswith("."):
            suffixes.append(entry)
        else:
            exact.add(entry)
    return frozenset(exact), tuple(suffixes)

PUSH_ALLOWED_EXACT, PUSH_ALLOWED_SUFFIXES = _parse_push_allowlist(
    os.environ.get("PUSH_ALLOWED_HOSTS", PUSH_ALLOWED_HOSTS_DEFAULT))

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

for _bad_entry in _PUSH_ALLOWLIST_INVALID:
    log.warning("CONFIG     PUSH_ALLOWED_HOSTS invalid entry skipped: %r", _bad_entry)

# ══════════════════════════════════════════
#   SIGNAL SERVER STATE
# ══════════════════════════════════════════

connected: dict[str, set] = {}   # publicId → set of websockets
# connected_by_endpoint — publicId → endpointId → set of websockets. Additive,
# NOT a replacement for `connected`: a socket that presents a endpoint_id at
# auth ends up in both. endpointId is a separate HKDF derivation off the same
# device seed as deviceId, deliberately unlinkable from it (see
# deriveDeviceEndpointId in meshchat-lib.js) — this map is what lets
# route_or_buffer target one specific
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
ip_auth_limiters: dict = {}         # ip key → RateLimiter on auth proofs (checked before signature verification); pruned when idle
probation_ip_limiters: dict = {}    # ip key → RateLimiter on starting NEW probation slots; pruned when idle
sock_state: dict = {}            # ws → SockState — EVERY open socket, authed or not (connected/ws_to_ids only know registered ones)
ip_byte_limiters: dict = {}      # ip key → byte RateLimiter shared across all that address's sockets (lifetime tied to ip_conns, like ip_limiters)
push_last: dict = {}             # to_id → monotonic time of the last push scheduled for that recipient (cooldown)
push_tasks: set = set()          # in-flight/queued push tasks — bounded by PUSH_MAX_QUEUE, held so they aren't garbage-collected
bg_tasks: set = set()            # fire-and-forget closes — held so they aren't garbage-collected

stats = {
    "bytes_in":  0, "bytes_out": 0,
    "msgs_in":   0, "msgs_out":  0,
    "buf_in":    0, "buf_out":   0,
    "buf_cap_rejected":  0,   # writes dropped for hitting MAX_BUF_RECIPIENTS
    "buf_endpoint_cap_rejected": 0,   # writes dropped for hitting MAX_ENDPOINTS_PER_RECIPIENT
    "buf_fair_evicted":  0,   # packets evicted from the heaviest sender to make room (count or size limit)
    "buf_reserved_full": 0,   # migrate/burn refused: no regular packet left to evict and the buffer is full
    "buf_size_rejected": 0,   # writes dropped because they could never fit BUF_MAX_MB / the size limit held only migrate/burn
    "buf_rate_rejected": 0,   # writes dropped for hitting a recipient's write-rate limit
    "auth_admission_rejected": 0,   # auth completions dropped by the global admission limiter
    "push_sent":    0,   # pushes that got a non-error response from the push service
    "push_pruned":  0,   # subscriptions removed after a permanent failure (404/410)
    "push_failed":  0,   # transient push failures (network error, 5xx, etc.) — left on file, no retry
    # ── resource protection ──
    "conn_refused":        0,   # new sockets turned away (per-IP, per-IP-unauthed, hard cap, or full with nothing evictable)
    "conn_evicted":        0,   # sockets closed to make room for a new one
    "unauth_deadline":     0,   # sockets closed for not completing auth in UNAUTH_DEADLINE_S
    "rate_rejected":       0,   # frames dropped by the per-socket / per-IP packet-count limiters
    "byte_rejected":       0,   # frames dropped by the per-socket / per-IP byte budgets
    "type_rejected":       0,   # frames dropped by a per-type budget
    "frame_rejected":      0,   # frames over their size cap (pre-auth cap, per-type cap, or the library's)
    "binary_rejected":     0,   # binary frames (the protocol is text-only)
    "malformed":           0,   # frames that were not a JSON object with a string "type"
    "strike_closed":       0,   # sockets closed for piling up strikes
    "session_cap_evicted": 0,   # oldest sessions dropped by MAX_SESSIONS_PER_IDENTITY
    "send_timeout":        0,   # sockets closed because a send stalled for SEND_TIMEOUT_S
    "push_cooldown":       0,   # pushes skipped by the per-recipient cooldown
    "push_dropped":        0,   # pushes dropped because the push queue was full
    # ── known-identity registry / probation ──
    "probation_stored":    0,   # packets accepted into probation (never-seen recipient / unknown device)
    "probation_kept_first":0,   # packets refused because that probation slot already held one
    "probation_oversize":  0,   # packets refused for exceeding PROBATION_MAX_BYTES
    "probation_ip_limited":0,   # new probation slots refused by the per-address creation limiter
    "probation_endpoint_cap": 0,  # unknown-device buckets refused by PROBATION_ENDPOINTS_PER_RECIPIENT
    "probation_evicted":   0,   # oldest probation entries evicted to make room
    "probation_promoted":  0,   # probation packets handed to a recipient when it first authenticated
    "auth_ip_rejected":    0,   # auth proofs refused by the per-address auth limiter (before verification)
    "auth_known_lane":     0,   # auths admitted through the known-identity lane after the global budget ran out
}

# ══════════════════════════════════════════
#   HELPERS
# ══════════════════════════════════════════

def fmt_bytes(b):
    if b < 1024:    return f"{b}B"
    if b < 1024**2: return f"{b/1024:.1f}KB"
    return f"{b/1024**2:.1f}MB"

def short(id_str):
    # `from` / `to` are attacker-controlled and only sometimes strings — this
    # sits in log lines on rejection paths, which must never raise.
    if not id_str or not isinstance(id_str, str): return "?"
    return id_str[:8] + "…"

def short_addr(addr):
    """Same truncation as short(), but shape-aware for a compound
    'id::endpointId' address — truncates each half independently so a log
    line still reads as 'Bob…::laptop…' rather than swallowing the
    endpoint half entirely under a flat 8-char cut of the whole string."""
    if not addr or not isinstance(addr, str):
        return "?"
    if ADDR_SEP in addr:
        base_id, _, endpoint_id = addr.partition(ADDR_SEP)
        return f"{short(base_id)}{ADDR_SEP}{short(endpoint_id)}"
    return short(addr)

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

def ip_key(addr):
    """The key per-address limits are counted under. IPv4 is the address
    itself; IPv4-mapped IPv6 is unwrapped to it; any other IPv6 address is
    reduced to its /IPV6_KEY_PREFIX network — a single customer controls a
    whole /64, so keying on the full /128 would hand them 2^64 "different"
    addresses and make every per-address limit a no-op. Anything that doesn't
    parse as an IP (the "unknown" fallback) is used as-is."""
    if not addr:
        return "unknown"
    try:
        ip = ipaddress.ip_address(str(addr).split("%", 1)[0])
    except ValueError:
        return str(addr)[:64]
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/{IPV6_KEY_PREFIX}", strict=False))
    return str(ip)

def unique_keys():
    """Number of distinct registered public IDs."""
    return len(connected)

def socket_count(include_closing=True):
    """Every open socket, registered or not. session_count() only sees the
    ones that completed auth — which is why a pile of unauthenticated sockets
    never showed up against MAX_CONNECTIONS."""
    if include_closing:
        return len(sock_state)
    return sum(1 for st in sock_state.values() if not st.closing)

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

    def allow(self, cost=1):
        """Take `cost` tokens (1 packet; or N bytes for a byte bucket).
        cost is clamped to the burst so a misconfigured burst smaller than one
        maximum frame degrades to "needs a full bucket" rather than "never"."""
        now = time.monotonic()
        elapsed = now - self.last_time
        self.last_time = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        cost = min(cost, self.burst)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

class LogThrottle:
    """At most one line per key per `interval` seconds. A suppressed call
    returns False and is counted; the next line that does go out reports the
    count. Keyed by a SHORT fixed label (never by peer or id), so its own
    memory is bounded by the number of call sites, not by the attacker."""
    def __init__(self, interval=LOG_THROTTLE_S):
        self.interval = interval
        self._state = {}   # key → [last_emit_monotonic, suppressed_since]

    def ok(self, key):
        """(emit, suppressed) — suppressed is how many calls were swallowed
        since the last emitted line for this key."""
        now = time.monotonic()
        st = self._state.get(key)
        if st is None:
            self._state[key] = [now, 0]
            return True, 0
        if now - st[0] >= self.interval:
            suppressed, st[0], st[1] = st[1], now, 0
            return True, suppressed
        st[1] += 1
        return False, 0

_log_throttle = LogThrottle()

def warn_throttled(key, fmt, *args):
    """log.warning(fmt, *args), collapsed per `key` — see LogThrottle."""
    emit, suppressed = _log_throttle.ok(key)
    if emit:
        log.warning(fmt + ("  (+%d similar suppressed)" % suppressed if suppressed else ""), *args)

class SockState:
    """Everything the relay tracks per OPEN socket, from the moment it
    connects (connected/ws_to_ids only learn a socket once it authenticates)."""
    __slots__ = ("ws", "addr", "ipk", "t_connect", "t_last", "authed", "closing",
                 "strikes", "t_strike", "replied", "limiter", "bytes", "type_limiters",
                 "deadline")

    def __init__(self, ws, addr, ipk):
        now = time.monotonic()
        self.ws, self.addr, self.ipk = ws, addr, ipk
        self.t_connect = self.t_last = self.t_strike = now
        self.authed  = False     # completed auth (set in auth_verify, before the buffer flush)
        self.closing = False     # a close has been requested; not counted against capacity, never picked as a victim twice
        self.strikes = 0.0
        self.replied = set()     # reply keys already sent once on this socket (see reply_once)
        self.limiter = RateLimiter()
        self.bytes   = RateLimiter(rate=BYTE_RATE_SOCKET, burst=BYTE_BURST_SOCKET)
        self.type_limiters = {}  # class → RateLimiter, created on first use
        self.deadline = None     # asyncio.TimerHandle for the unauthenticated deadline

    def type_allow(self, cls):
        spec = TYPE_LIMITS.get(cls)
        if spec is None:
            return True
        lim = self.type_limiters.get(cls)
        if lim is None:
            lim = self.type_limiters[cls] = RateLimiter(rate=spec[0], burst=spec[1])
        return lim.allow()

    def add_strike(self, weight=1.0):
        """Record a violation; True once the (decayed) count is over STRIKE_LIMIT."""
        now = time.monotonic()
        self.strikes = max(0.0, self.strikes - (now - self.t_strike) / STRIKE_DECAY_S) + weight
        self.t_strike = now
        return self.strikes > STRIKE_LIMIT

class DirCounter:
    """In-memory count of the immediate subdirectories of a directory.
    Scanned once, lazily; kept current by add() on every create/remove and
    re-scanned by resync() on each expiry sweep to absorb drift. Replaces a
    scandir over up to MAX_BUF_RECIPIENTS entries on EVERY write to a new
    recipient — a cost an attacker could trigger at will. Thread-safe: it is
    used from worker threads. Concurrent creators can overshoot the cap by a
    few; it is a brake on unbounded growth, not an exact quota."""
    def __init__(self, path_fn):
        self._path_fn = path_fn     # a function, so a changed BUF_DIR is honoured
        self._lock = threading.Lock()
        self._n = None

    def _scan(self):
        path = self._path_fn()
        if not os.path.isdir(path):
            return 0
        try:
            with os.scandir(path) as it:
                # dot-names (BUF_DIR/.probation) are relay bookkeeping, never recipients
                return sum(1 for e in it if e.is_dir() and not e.name.startswith("."))
        except OSError:
            return 0

    def count(self):
        with self._lock:
            if self._n is None:
                self._n = self._scan()
            return self._n

    def add(self, k=1):
        with self._lock:
            if self._n is not None:
                self._n = max(0, self._n + k)

    def resync(self):
        n = self._scan()
        with self._lock:
            self._n = n
        return n

buf_recipient_count  = DirCounter(lambda: BUF_DIR)
push_identity_count  = DirCounter(lambda: PUSH_SUBS_DIR)

# ══════════════════════════════════════════
#   KNOWN-IDENTITY REGISTRY  (see the config block near BUF_DIR)
#   Memory is the source of truth for lookups — they happen on the event loop
#   and in buffer worker threads and must never wait on disk. SQLite is a
#   write-behind mirror that exists only so a restart doesn't forget everyone.
# ══════════════════════════════════════════

class _RegistryUnusable(Exception):
    """The database file exists but this code can't use it (wrong format
    version, failed integrity check, not a database)."""

class KnownRegistry:
    def __init__(self, path=None):
        self._path = path or REGISTRY_DB
        self._lock = threading.Lock()      # guards _ids and the pending-change sets
        self._db_lock = threading.Lock()   # serialises everything that touches the sqlite connection
        # id → [last_seen, {endpoint_id: last_seen}, persisted_at]; ordered least → most recently seen
        self._ids = OrderedDict()
        self._dirty = set()                # ids whose rows need (re)writing
        self._gone = set()                 # ids whose rows need deleting
        self._meta_dirty = False
        self._db = None
        self.mode = "memory"               # "sqlite" once a database is open
        self.grace_until = 0.0             # wall-clock; recipients count as known until then
        self.note = ""                     # one line for the startup log: how the registry came up

    # ── lookups (hot path: cheap, memory only) ──
    def is_known(self, pid):
        with self._lock:
            return pid in self._ids

    def endpoint_known(self, pid, endpoint_id):
        with self._lock:
            e = self._ids.get(pid)
            return e is not None and endpoint_id in e[1]

    def endpoints(self, pid):
        with self._lock:
            e = self._ids.get(pid)
            return set(e[1]) if e else set()

    def in_grace(self, now=None):
        return (time.time() if now is None else now) < self.grace_until

    def accepts(self, pid):
        """True when `pid` should get the normal buffer: it is known, or the
        registry is still inside its post-creation grace window."""
        return self.in_grace() or self.is_known(pid)

    def size(self):
        with self._lock:
            return len(self._ids)

    # ── updates ──
    def touch(self, pid, endpoint_id=None, now=None):
        """Record that `pid` (and its device `endpoint_id`) just authenticated
        to receive here. Returns True if the identity was already known."""
        now = time.time() if now is None else now
        with self._lock:
            e = self._ids.get(pid)
            was_known = e is not None
            if e is None:
                while len(self._ids) >= REGISTRY_MAX_IDENTITIES:      # least recently seen goes first
                    old, _ = self._ids.popitem(last=False)
                    self._dirty.discard(old)
                    self._gone.add(old)
                e = [now, {}, 0.0]
                self._ids[pid] = e
                dirty = True
            else:
                dirty = (now - e[2]) >= REGISTRY_TOUCH_GRANULARITY_S
                e[0] = now
                self._ids.move_to_end(pid)
            eps = e[1]
            for ep in [k for k, ts in eps.items() if now - ts > REGISTRY_TTL_S]:
                del eps[ep]
                dirty = True
            if endpoint_id:
                if endpoint_id not in eps:
                    dirty = True
                    while len(eps) >= REGISTRY_MAX_ENDPOINTS:
                        del eps[min(eps, key=eps.get)]
                eps[endpoint_id] = now
            if dirty:
                self._dirty.add(pid)
                self._gone.discard(pid)
            return was_known

    def expire(self, now=None):
        """Forget identities not seen for REGISTRY_TTL_S. Returns how many."""
        now = time.time() if now is None else now
        cutoff = now - REGISTRY_TTL_S
        n = 0
        with self._lock:
            while self._ids:
                pid, e = next(iter(self._ids.items()))
                if e[0] >= cutoff:
                    break
                del self._ids[pid]
                self._dirty.discard(pid)
                self._gone.add(pid)
                n += 1
        return n

    # ── bring-up ──
    def open(self, now=None):
        """Open (create, or rebuild) the database. Always leaves the registry
        usable — the worst outcome is memory-only mode — and never raises."""
        now = time.time() if now is None else now
        for attempt in (1, 2):
            try:
                os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
                db = sqlite3.connect(self._path, timeout=5, check_same_thread=False, isolation_level=None)
            except (OSError, sqlite3.Error) as e:
                return self._memory_mode("cannot open %s (%s)" % (self._path, e), now)
            try:
                db.execute("PRAGMA synchronous=NORMAL")
                ver    = db.execute("PRAGMA user_version").fetchone()[0]
                tables = db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
                if ver == 0 and tables == 0:
                    self._create(db)
                    self._db, self.mode = db, "sqlite"
                    return self._fresh("no registry found — created %s" % self._path, now)
                if ver != REGISTRY_FORMAT:
                    raise _RegistryUnusable("format version %s (this relay uses %d)" % (ver, REGISTRY_FORMAT))
                check = db.execute("PRAGMA quick_check").fetchone()[0]
                if check != "ok":
                    raise _RegistryUnusable("integrity check failed (%s)" % str(check)[:80])
                self._load(db, now)
                self._db, self.mode = db, "sqlite"
                return
            except sqlite3.OperationalError as e:
                # locked / read-only / I/O trouble — not a verdict on the file itself
                try: db.close()
                except Exception: pass
                return self._memory_mode("%s unusable (%s)" % (self._path, e), now)
            except (_RegistryUnusable, sqlite3.DatabaseError) as e:
                try: db.close()
                except Exception: pass
                if attempt == 2:
                    return self._memory_mode("%s unusable even after starting over (%s)" % (self._path, e), now)
                aside = "%s.unusable-%d" % (self._path, int(now))
                try:
                    os.replace(self._path, aside)
                    for ext in ("-wal", "-shm", "-journal"):
                        try: os.remove(self._path + ext)
                        except OSError: pass
                except OSError as e2:
                    return self._memory_mode("%s unusable (%s) and can't be moved aside (%s)" % (self._path, e, e2), now)
                log.warning("REGISTRY  %s is unusable (%s) — kept as %s, starting a new one", self._path, e, aside)

    @staticmethod
    def _create(db):
        db.executescript("""
            CREATE TABLE identities(id TEXT PRIMARY KEY, last_seen REAL NOT NULL) WITHOUT ROWID;
            CREATE TABLE endpoints(id TEXT NOT NULL, endpoint TEXT NOT NULL, last_seen REAL NOT NULL,
                                   PRIMARY KEY(id, endpoint)) WITHOUT ROWID;
            CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
        """)
        db.execute("PRAGMA user_version=%d" % REGISTRY_FORMAT)

    def _load(self, db, now):
        rows = db.execute("SELECT id, last_seen FROM identities ORDER BY last_seen").fetchall()
        eps = {}
        for pid, ep, ts in db.execute("SELECT id, endpoint, last_seen FROM endpoints"):
            eps.setdefault(pid, {})[ep] = ts
        cutoff = now - REGISTRY_TTL_S
        with self._lock:
            for pid, ts in rows:
                if ts < cutoff:
                    self._gone.add(pid)
                    continue
                self._ids[pid] = [ts, eps.get(pid, {}), ts]      # persisted_at = last_seen: no rewrite until it's touched again
            while len(self._ids) > REGISTRY_MAX_IDENTITIES:
                old, _ = self._ids.popitem(last=False)
                self._gone.add(old)
        row = db.execute("SELECT v FROM meta WHERE k='grace_until'").fetchone()
        try:    self.grace_until = float(row[0]) if row else 0.0
        except ValueError: self.grace_until = 0.0
        self.note = "loaded %d identities from %s%s" % (
            len(self._ids), self._path,
            ("  (grace window open for another %ds)" % (self.grace_until - now)) if self.grace_until > now else "")

    def _fresh(self, why, now):
        """A registry with no memory of its own: seed it from what is on disk
        and open the grace window."""
        n = self._seed(now)
        self.grace_until = now + REGISTRY_GRACE_S
        self._meta_dirty = True
        self.note = "%s; seeded %d identities from existing data; grace window %ds" % (why, n, REGISTRY_GRACE_S)
        self.flush()

    def _memory_mode(self, why, now):
        self._db, self.mode = None, "memory"
        n = self._seed(now)
        self.grace_until = now + REGISTRY_GRACE_S
        self.note = "MEMORY ONLY — %s; seeded %d identities; grace window %ds (restarts will forget who was seen)" % (why, n, REGISTRY_GRACE_S)
        log.warning("REGISTRY  %s", self.note)

    def _seed(self, now):
        """Rebuild what we can from the data directories: every recipient that
        has a buffer directory or a push subscription. Their timestamps are the
        files' own, so identities that were never heard from again still age out."""
        found = {}
        def _add(pid, ep, ts):
            ts = min(ts, now)
            if now - ts > REGISTRY_TTL_S:
                return
            cur = found.setdefault(pid, [ts, {}])
            cur[0] = max(cur[0], ts)
            if ep:
                cur[1][ep] = max(cur[1].get(ep, 0.0), ts)
        def _subdirs(path):
            try:
                with os.scandir(path) as it:
                    return [e for e in it if e.is_dir()]
            except OSError:
                return []
        for d in _subdirs(BUF_DIR):
            if not valid_id(d.name):
                continue
            try: _add(d.name, None, d.stat().st_mtime)
            except OSError: continue
            for ep in _subdirs(os.path.join(d.path, "_endpoints")):
                if valid_id(ep.name):
                    try: _add(d.name, ep.name, ep.stat().st_mtime)
                    except OSError: pass
        for d in _subdirs(PUSH_SUBS_DIR):
            if not valid_id(d.name):
                continue
            try:
                with os.scandir(d.path) as it:
                    for f in it:
                        if f.is_file() and f.name.endswith(".json") and valid_id(f.name[:-5]):
                            try: _add(d.name, f.name[:-5], f.stat().st_mtime)
                            except OSError: pass
            except OSError:
                continue
        newest = sorted(found.items(), key=lambda kv: kv[1][0])[-REGISTRY_MAX_IDENTITIES:]
        with self._lock:
            for pid, (ts, eps) in newest:
                self._ids[pid] = [ts, dict(list(sorted(eps.items(), key=lambda kv: kv[1]))[-REGISTRY_MAX_ENDPOINTS:]), 0.0]
                self._dirty.add(pid)
        return len(newest)

    # ── persistence ──
    def flush(self):
        """Write pending changes to disk (worker thread, or shutdown). Never
        raises; a failed write is retried on the next flush."""
        with self._lock:
            dirty = {pid: (e[0], dict(e[1])) for pid in self._dirty if (e := self._ids.get(pid)) is not None}
            gone  = list(self._gone)
            meta  = self._meta_dirty
            self._dirty.clear(); self._gone.clear(); self._meta_dirty = False
        db = self._db
        if db is None:
            return                                    # memory mode: nothing to write, nothing to retry
        if not (dirty or gone or meta):
            return
        now = time.time()
        with self._db_lock:
            try:
                db.execute("BEGIN")
                if gone:
                    db.executemany("DELETE FROM identities WHERE id=?", [(g,) for g in gone])
                    db.executemany("DELETE FROM endpoints WHERE id=?",  [(g,) for g in gone])
                for pid, (ts, eps) in dirty.items():
                    db.execute("INSERT OR REPLACE INTO identities(id, last_seen) VALUES(?,?)", (pid, ts))
                    db.execute("DELETE FROM endpoints WHERE id=?", (pid,))
                    if eps:
                        db.executemany("INSERT INTO endpoints(id, endpoint, last_seen) VALUES(?,?,?)",
                                       [(pid, ep, t) for ep, t in eps.items()])
                if meta:
                    db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('grace_until', ?)", (repr(self.grace_until),))
                db.execute("COMMIT")
            except sqlite3.Error as e:
                try: db.execute("ROLLBACK")
                except sqlite3.Error: pass
                with self._lock:                      # put the work back for the next attempt
                    for pid in dirty:
                        if pid in self._ids: self._dirty.add(pid)
                    self._gone.update(g for g in gone if g not in self._ids)
                    self._meta_dirty = self._meta_dirty or meta
                warn_throttled("registry_flush", "REGISTRY  write failed (%s) — will retry", e)
                return
        with self._lock:
            for pid in dirty:
                e = self._ids.get(pid)
                if e is not None:
                    e[2] = now

    def close(self):
        self.flush()
        with self._db_lock:
            if self._db is not None:
                try: self._db.close()
                except sqlite3.Error: pass
                self._db = None

known_registry = KnownRegistry()

class ProbationPool:
    """Never-seen recipients that hold ONE keep-first packet each, kept apart
    from the real buffer: BUF_DIR/.probation/<id>/…, same inner layout as a
    real recipient directory (identity-level files, _endpoints/<ep>/…) so that
    promoting a recipient is a single rename. The index lives in memory in
    arrival order, so evicting the oldest and expiring are O(1) per entry."""
    def __init__(self):
        self._lock = threading.Lock()
        self._order = OrderedDict()      # id → created (wall clock); oldest first

    @staticmethod
    def root():
        return os.path.join(BUF_DIR, PROBATION_DIRNAME)

    def path(self, pid):
        return os.path.join(self.root(), pid)     # pid is valid_id()-checked by every caller: no separators, no dots

    def load(self):
        """Rebuild the index from disk (startup)."""
        try:
            with os.scandir(self.root()) as it:
                found = sorted(((e.stat().st_mtime, e.name) for e in it if e.is_dir() and valid_id(e.name)))
        except OSError:
            found = []
        with self._lock:
            self._order = OrderedDict((name, ts) for ts, name in found)
            extra = []
            while len(self._order) > MAX_PROBATION_RECIPIENTS:
                extra.append(self._order.popitem(last=False)[0])
        for name in extra:
            shutil.rmtree(self.path(name), ignore_errors=True)
        return len(self._order)

    def __len__(self):
        with self._lock:
            return len(self._order)

    def has(self, pid):
        with self._lock:
            return pid in self._order

    def claim(self, pid):
        """Reserve the slot for `pid`. None if it already holds a packet
        (keep-first); otherwise the slot's directory, with the OLDEST entry
        evicted first when the pool is full. Returns (path, evicted_count)."""
        victims = []
        with self._lock:
            if pid in self._order:
                return None
            while len(self._order) >= max(1, MAX_PROBATION_RECIPIENTS):
                victims.append(self._order.popitem(last=False)[0])
            self._order[pid] = time.time()
        for v in victims:
            shutil.rmtree(self.path(v), ignore_errors=True)
        return self.path(pid), len(victims)

    def release(self, pid):
        """Give a slot back (the write that claimed it failed)."""
        with self._lock:
            self._order.pop(pid, None)
        shutil.rmtree(self.path(pid), ignore_errors=True)

    def pop(self, pid):
        """Take `pid` out of the index (it is being promoted); True if it was there."""
        with self._lock:
            return self._order.pop(pid, None) is not None

    def sweep(self, now=None):
        """Drop entries older than BUF_MAX_AGE. Returns how many."""
        cutoff = (time.time() if now is None else now) - BUF_MAX_AGE
        victims = []
        with self._lock:
            while self._order:
                pid, ts = next(iter(self._order.items()))
                if ts >= cutoff:
                    break
                del self._order[pid]
                victims.append(pid)
        for v in victims:
            shutil.rmtree(self.path(v), ignore_errors=True)
        return len(victims)

probation_pool = ProbationPool()

# Single shared instance — deliberately NOT one-per-IP or one-per-socket.
# See GLOBAL_AUTH_RATE comment near its definition for why this needs to
# be global to be effective at all.
global_auth_limiter = RateLimiter(rate=GLOBAL_AUTH_RATE, burst=GLOBAL_AUTH_BURST)
known_auth_limiter  = RateLimiter(rate=AUTH_KNOWN_RATE, burst=AUTH_KNOWN_BURST)   # lane for identities already in known_registry

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

# ── push endpoint validation + SSRF-safe sender ──

class PushEndpointRejected(ValueError):
    """An endpoint failed the policy. .reason is safe to log; .host is the
    hostname if one could be parsed (the URL itself is never logged — path and
    query carry the device's push token)."""
    def __init__(self, reason, host=None):
        super().__init__(reason)
        self.reason = reason
        self.host = host

def push_host_allowed(host):
    return host in PUSH_ALLOWED_EXACT or any(host.endswith(sfx) for sfx in PUSH_ALLOWED_SUFFIXES)

def parse_push_endpoint(endpoint):
    """Validate a push endpoint against the policy. Returns (host, target) —
    the lowercase hostname and the request target (path + query) to POST to —
    or raises PushEndpointRejected. Strict on purpose: https only, port 443
    only, no userinfo, ASCII only (no unicode lookalike dots or normalisation
    games; urlsplit would also silently drop tabs/newlines, so control
    characters are refused up front), a plain DNS name (never an IP literal),
    and on the allowlist."""
    if not isinstance(endpoint, str):
        raise PushEndpointRejected("not a string")
    if not endpoint or len(endpoint) > PUSH_MAX_ENDPOINT_LEN:
        raise PushEndpointRejected("empty or too long")
    if any(ord(c) <= 0x20 or ord(c) >= 0x7f for c in endpoint):
        raise PushEndpointRejected("control, space or non-ASCII character")
    try:
        parts = urllib.parse.urlsplit(endpoint)
        port  = parts.port
    except ValueError:
        raise PushEndpointRejected("unparseable URL")
    if parts.scheme != "https":
        raise PushEndpointRejected("not https")
    if "@" in parts.netloc:
        raise PushEndpointRejected("userinfo in URL")
    host = parts.hostname
    if not host:
        raise PushEndpointRejected("no host")
    if port not in (None, 443):
        raise PushEndpointRejected("non-default port", host)
    if not _PUSH_HOST_RE.match(host):
        raise PushEndpointRejected("not a plain DNS name", host)
    if not push_host_allowed(host):
        raise PushEndpointRejected("host not on the push allowlist", host)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return host, target

_NON_PUBLIC_V6_PREFIXES = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b::/96",     # NAT64 well-known prefix — embeds ANY v4 address, private ones included (is_global says True)
    "64:ff9b:1::/48",   # local-use NAT64
    "2002::/16",        # 6to4 — embeds a v4 address
    "2001::/32",        # Teredo — embeds a v4 address
))

def ip_is_public(addr):
    """True only for an address that is plain, globally routable unicast.
    IPv4-mapped IPv6 is unwrapped first (::ffff:127.0.0.1 must be judged as
    127.0.0.1, and ipaddress doesn't do that consistently across versions),
    and the v6 transition prefixes that can smuggle in a v4 address are refused
    outright. A scope id (fe80::1%eth0) is stripped before parsing."""
    try:
        ip = ipaddress.ip_address(str(addr).split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6 and any(ip in net for net in _NON_PUBLIC_V6_PREFIXES):
        return False
    return ip.is_global and not ip.is_multicast

def _push_resolve(host, port):
    """Every distinct address the name resolves to, as strings. Its own
    function so a test can stand in for DNS."""
    seen = []
    for family, _t, _p, _c, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen

def _push_ssl_context():
    return ssl.create_default_context()

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to `host` (Host header, SNI and certificate check all use the
    NAME) over a socket opened to one specific, already-vetted IP. Resolving
    the name a second time inside http.client would leave a window for DNS
    rebinding: the first lookup answers with a public address that passes the
    check, the second with 127.0.0.1."""
    def __init__(self, host, pinned_ip, port=443, timeout=PUSH_TIMEOUT_SECONDS, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise

def _send_web_push_sync(endpoint: str) -> tuple[bool, int | None]:
    """Sync body — runs in a worker thread (blocking sockets). Sends an
    empty-body push: no content, no aes128gcm encryption layer, purely a
    wake-up. Returns (permanent_failure, http_status). permanent_failure
    is True only on 404/410 — the push service telling us the subscription
    itself is dead, not just that this one attempt failed — or when the stored
    endpoint no longer passes the policy at all (a subscription from before
    the allowlist existed, or one for a service since removed from it): that
    one is dropped rather than re-tried and re-logged on every push, and the
    client re-subscribes at its next login.

    SSRF defences, in order: the endpoint is re-validated (see
    parse_push_endpoint); the host is resolved here and EVERY address must be
    public (ip_is_public) — one private answer among public ones fails the
    send, since which one a client would pick is not ours to gamble on; the
    connection is made to a vetted address, not to the name (see
    _PinnedHTTPSConnection); and redirects are NEVER followed — a 3xx is just
    a failed push. Nothing of the response beyond its status line is read."""
    try:
        host, target = parse_push_endpoint(endpoint)
    except PushEndpointRejected as e:
        log.warning("PUSH       stored endpoint no longer allowed (%s)  host=%s — dropping it", e.reason, e.host or "?")
        return True, None
    try:
        addrs = _push_resolve(host, 443)
    except OSError as e:
        log.debug("PUSH       resolve failed  host=%s  err=%s", host, e)
        return False, None
    if not addrs or not all(ip_is_public(a) for a in addrs):
        log.warning("PUSH       %s resolves to a non-public address (%s) — not sending", host, ", ".join(addrs) or "nothing")
        return False, None
    try:
        jwt = _vapid_jwt(f"https://{host}")
    except Exception as e:
        log.warning("PUSH       VAPID signing failed: %s", e)
        return False, None
    headers = {
        "TTL": str(PUSH_TTL_SECONDS),
        "Authorization": f"vapid t={jwt}, k={VAPID_PUBLIC_KEY_B64}",
        "User-Agent": "meshchat-relay",
    }
    ctx = _push_ssl_context()
    last_err = None
    for ip in addrs[:PUSH_MAX_ADDRS_TRIED]:
        conn = _PinnedHTTPSConnection(host, ip, context=ctx)
        try:
            conn.connect()                       # only a failed CONNECT moves on to the next address
        except (OSError, ssl.SSLError) as e:
            last_err = e
            conn.close()
            continue
        try:
            conn.request("POST", target, body=b"", headers=headers)
            status = conn.getresponse().status
        except (OSError, http.client.HTTPException) as e:
            log.debug("PUSH       send error  host=%s  err=%s", host, e)
            return False, None
        finally:
            conn.close()
        if 300 <= status < 400:
            log.info("PUSH       redirect not followed  host=%s  status=%s", host, status)
        return status in (404, 410), status
    log.debug("PUSH       connect failed  host=%s  err=%s", host, last_err)
    return False, None

# ══════════════════════════════════════════
#   PUSH SUBSCRIPTION STORAGE
#   Layout: PUSH_SUBS_DIR/<publicId>/<endpointId>.json — one file per
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

def _push_sub_write_sync(to_id, endpoint_id, subscription):
    """Files are keyed by endpointId, NOT deviceId. deviceId is the value
    contacts recognise from their own device popover; endpointId is the one
    the relay already sees at auth. Storing push state under deviceId let the
    relay join the two views — exactly the correlation the split exists to
    prevent. See deriveDeviceEndpointId (meshchat-lib.js)."""
    try:
        d = push_sub_dir(to_id)
    except ValueError as e:
        log.warning("PUSH_SUB   rejected  to=%s  reason=%s", short(to_id), e)
        return
    try:
        # Global cap on identity directories — same role as MAX_BUF_RECIPIENTS
        # for the buffer. `from` is an authed identity, but identities cost
        # nothing, so without it each fresh one can leave a directory (and a
        # subscription file) behind forever. An identity that already has a
        # directory is never turned away by this.
        new_identity = not os.path.isdir(d)
        if new_identity and push_identity_count.count() >= MAX_PUSH_IDENTITIES:
            log.warning("PUSH_SUB   identity cap reached (%d) — rejecting new identity  id=%s",
                        MAX_PUSH_IDENTITIES, short(to_id))
            return
        os.makedirs(d, exist_ok=True)
        if new_identity:
            push_identity_count.add(1)
        fname = f"{endpoint_id}.json"
        # Same browser endpoint URL under a different filename is a stale
        # duplicate of this subscription — most importantly the old
        # <deviceId>.json files from before this keying change, which would
        # otherwise double-push the same browser forever (and, holding a
        # deviceId filename, keep the old correlation on disk). Drop them.
        for fpath in glob.glob(os.path.join(d, "*.json")):
            if os.path.basename(fpath) == fname:
                continue
            try:
                with open(fpath) as f:
                    old = json.load(f)
                if old.get("endpoint") == subscription.get("endpoint"):
                    os.remove(fpath)
                    log.info("PUSH_SUB   dropped stale duplicate  id=%s  file=%s", short(to_id), os.path.basename(fpath)[:12])
            except Exception:
                continue
        # Cap per identity — counted AFTER the stale-duplicate sweep above, which
        # may have just freed a slot, and excluding this device's own file (a
        # re-subscribe replaces it). Not locked: two subscribes racing in worker
        # threads can overshoot by a file or two; this is a brake on unbounded
        # growth, not an exact quota.
        others = [fp for fp in glob.glob(os.path.join(d, "*.json")) if os.path.basename(fp) != fname]
        if len(others) >= PUSH_MAX_SUBS_PER_IDENTITY:
            log.warning("PUSH_SUB   subscription cap reached (%d)  id=%s — rejecting", PUSH_MAX_SUBS_PER_IDENTITY, short(to_id))
            return
        with open(os.path.join(d, fname), "w") as f:
            json.dump(subscription, f)
        log.info("PUSH_SUB   subscribed  id=%s  endpoint=%s", short(to_id), short(endpoint_id))
    except Exception as e:
        log.warning("PUSH_SUB   write failed  to=%s  err=%s", short(to_id), e)

def _push_sub_delete_sync(to_id, endpoint_id):
    try:
        d = push_sub_dir(to_id)
    except ValueError:
        return
    try:
        os.remove(os.path.join(d, f"{endpoint_id}.json"))
        log.info("PUSH_SUB   unsubscribed  id=%s  endpoint=%s", short(to_id), short(endpoint_id))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("PUSH_SUB   unsubscribe failed  to=%s  err=%s", short(to_id), e)
    # An identity directory with no subscriptions left still counts against
    # MAX_PUSH_IDENTITIES — remove it once empty (rmdir fails, harmlessly, if
    # a concurrent subscribe just put a file back).
    try:
        os.rmdir(d)
        push_identity_count.add(-1)
    except OSError:
        pass

def _push_subs_list_sync(to_id):
    """Returns [(endpointId, subscriptionDict), ...] for every subscription
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
            endpoint_id = os.path.basename(fpath)[:-len(".json")]
            out.append((endpoint_id, sub))
        except Exception:
            continue
    return out

# Dedicated pool for everything push does on a thread (subscription reads,
# the outbound HTTPS POSTs, subscription deletes). Separate from the default
# executor on purpose: a push send can sit on a socket for
# PUSH_TIMEOUT_SECONDS × PUSH_MAX_ADDRS_TRIED, and a handful of slow push
# services must not be able to starve the buffer reads/writes that share the
# default pool.
PUSH_EXECUTOR = ThreadPoolExecutor(max_workers=PUSH_MAX_CONCURRENT, thread_name_prefix="push")
_push_sem = None   # asyncio.Semaphore(PUSH_MAX_CONCURRENT), created on first use — needs the running loop on older Pythons

async def _push_thread(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(PUSH_EXECUTOR, fn, *args)

def schedule_push(to_id):
    """Queue a push for to_id as a BACKGROUND task and return at once. The
    sender's handler never waits on it — before, push_notify was awaited
    inline in route_or_buffer, so every offline app:message held its sender's
    whole receive loop (and every packet queued behind it) for the length of
    the push round trips, which a sender could stretch by targeting a
    recipient with slow subscriptions.

    Bounded three ways: a per-recipient cooldown (a push only means "wake up
    and check", so a second one 5 s after the first adds nothing but load on
    the push service), a ceiling on queued+running pushes, and a concurrency
    limit inside the task. The cooldown is claimed HERE, synchronously, so a
    burst to one recipient schedules exactly one task."""
    now = time.monotonic()
    last = push_last.get(to_id)
    if last is not None and now - last < PUSH_COOLDOWN_S:
        stats["push_cooldown"] += 1
        return
    if len(push_tasks) >= PUSH_MAX_QUEUE:
        stats["push_dropped"] += 1
        warn_throttled("push_dropped", "PUSH       queue full (%d) — dropping push  id=%s", PUSH_MAX_QUEUE, short(to_id))
        return
    if len(push_last) >= PUSH_COOLDOWN_MAX_ENTRIES:
        _prune_push_last(now)
    push_last[to_id] = now
    task = asyncio.create_task(_push_worker(to_id))
    push_tasks.add(task)
    task.add_done_callback(push_tasks.discard)

def _prune_push_last(now=None):
    """Drop cooldown entries that have expired (they no longer suppress
    anything). Called from the expiry sweep and, as a safety valve, when the
    table hits PUSH_COOLDOWN_MAX_ENTRIES."""
    now = time.monotonic() if now is None else now
    for k in [k for k, t in push_last.items() if now - t >= PUSH_COOLDOWN_S]:
        push_last.pop(k, None)

async def _push_worker(to_id):
    global _push_sem
    if _push_sem is None:
        _push_sem = asyncio.Semaphore(PUSH_MAX_CONCURRENT)
    try:
        async with _push_sem:
            await push_notify(to_id)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        log.warning("PUSH       worker error  id=%s  err=%s", short(to_id), e)

async def push_notify(to_id):
    """Fire a best-effort, empty-payload push to every subscription on
    file for to_id. Only reached (via schedule_push) from route_or_buffer
    for a genuinely-offline app:message delivery — never for
    app:migrate/app:burn (not user-facing) and never when a live session
    was already reached. Pushes are inherently best-effort: no retry on
    transient failure, same as everything else in this protocol that isn't
    durably buffered."""
    subs = await _push_thread(_push_subs_list_sync, to_id)
    if not subs:
        return
    for endpoint_id, sub in subs:
        endpoint = sub.get("endpoint")
        if not endpoint:
            continue
        dead, status = await _push_thread(_send_web_push_sync, endpoint)
        if dead:
            await _push_thread(_push_sub_delete_sync, to_id, endpoint_id)
            stats["push_pruned"] += 1
            log.info("PUSH       subscription dead (status=%s) — pruned  id=%s  endpoint=%s",
                      status, short(to_id), short(endpoint_id))
        elif status is not None and 200 <= status < 300:
            stats["push_sent"] += 1
            log.debug("PUSH       sent  id=%s  endpoint=%s  status=%s", short(to_id), short(endpoint_id), status)
        else:
            stats["push_failed"] += 1
            log.debug("PUSH       transient failure  id=%s  endpoint=%s  status=%s", short(to_id), short(endpoint_id), status)

# ══════════════════════════════════════════
#   ROUTING HELPERS
# ══════════════════════════════════════════

def wire(obj):
    """The text frame for `obj`. A str is taken to be already-serialised (the
    frame a sender gave us, which handler() has just parsed as a JSON object)
    and passed through untouched; anything else is serialised here. Fan-out
    callers do this ONCE and hand the str to every recipient, instead of
    json.dumps per recipient."""
    return obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))

def _prune_dead(ws):
    """Remove a socket from the routing maps. Via the reverse maps —
    O(ids_per_socket) instead of O(unique_keys). ws_to_ids is populated in
    auth_verify."""
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

def _spawn(coro):
    task = asyncio.create_task(coro)
    bg_tasks.add(task)
    task.add_done_callback(bg_tasks.discard)

async def _close_quiet(ws, code, reason):
    """Close a socket from outside its handler. close() already bounds itself
    by the library's close_timeout; if it still raises, the transport is
    aborted so the slot is not held by a peer that won't answer."""
    try:
        await asyncio.wait_for(ws.close(code, reason), CLOSE_GRACE_S)
    except Exception:
        transport = getattr(ws, "transport", None)
        if transport is not None:
            try: transport.abort()
            except Exception: pass

def request_close(ws, code, reason):
    """Close `ws` in the background (never blocks the caller) and mark it
    closing, so it stops counting against capacity and can't be picked as a
    victim twice. Safe to call repeatedly."""
    st = sock_state.get(ws)
    if st is not None:
        if st.closing:
            return
        st.closing = True
    _spawn(_close_quiet(ws, code, reason))

async def send_raw(ws, raw):
    """Send an already-serialised frame. Bounded by SEND_TIMEOUT_S: a peer
    that doesn't read can't hold up the caller (which is usually ANOTHER
    client's handler, delivering to it) — it is closed instead."""
    try:
        await asyncio.wait_for(ws.send(raw), SEND_TIMEOUT_S)
        stats["bytes_out"] += len(raw)
        stats["msgs_out"]  += 1
        return True
    except asyncio.TimeoutError:
        stats["send_timeout"] += 1
        warn_throttled("send_timeout", "  send timed out after %.0fs — closing slow consumer  peer=%s",
                       SEND_TIMEOUT_S, getattr(sock_state.get(ws), "addr", "?"))
        request_close(ws, CLOSE_CODE_BUSY, "slow consumer")
        _prune_dead(ws)
        return False
    except Exception as e:
        warn_throttled("send_failed", "  send failed: %s", e)
        _prune_dead(ws)
        return False

async def send_to(ws, obj):
    return await send_raw(ws, wire(obj))

async def reply_once(ws, key, obj):
    """Send `obj` to ws only the FIRST time `key` comes up on this socket.
    Answering every bad packet doubles a flood's traffic; the first error
    already told a real client everything it needs."""
    st = sock_state.get(ws)
    if st is not None:
        if key in st.replied:
            return False
        st.replied.add(key)
    return await send_to(ws, obj)

async def _fan_out(sessions, obj, exclude):
    targets = [ws for ws in list(sessions) if ws is not exclude]
    if not targets:
        return 0
    raw = wire(obj)   # once, not per recipient
    if len(targets) == 1:
        return 1 if await send_raw(targets[0], raw) else 0
    # concurrently — sequential awaits would let one slow recipient delay the rest
    results = await asyncio.gather(*(send_raw(ws, raw) for ws in targets), return_exceptions=True)
    return sum(1 for r in results if r is True)

async def deliver(to_id, obj, exclude=None):
    return await _fan_out(connected.get(to_id, set()), obj, exclude)

async def deliver_to_endpoint(to_id, endpoint_id, obj, exclude=None):
    """Same shape as deliver(), scoped to the socket(s) registered under
    this specific (identity, endpointId) pair — see connected_by_endpoint.
    Used when a `to` address carries a compound "id::endpointId" suffix
    (see parse_address() near valid_id). Deliberately does NOT fall back
    to every session under to_id if the named device isn't currently
    registered — a device-targeted send reaching nobody is exactly the
    "offline" case route_or_buffer already handles via the shared
    identity-level buffer; broadcasting instead would silently defeat the
    whole point of asking for one device."""
    return await _fan_out(connected_by_endpoint.get(to_id, {}).get(endpoint_id, set()), obj, exclude)

async def route_or_buffer(kind, frm, to_id, to_endpoint, msg, ws, raw=None):
    """Shared delivery path for from-authenticated, to-routed packet types
    (app:message, app:migrate, app:burn, session:propose, session:ack).
    Delivers live if the recipient is connected, otherwise falls back to
    the offline buffer — buf_write handles per-type overwrite/TTL
    behaviour on its own.

    to_id/to_endpoint are pre-parsed by the caller from the wire's single
    compound `to` field ("id" or "id::endpointId" — see parse_address()
    near valid_id) rather than parsed again here — one parse point, not
    two. Migrate/burn are never device-targeted, so their caller already
    rejects a compound address before this function is ever reached;
    to_endpoint is non-None here for an app:message (optional, live-only
    fanout targeting) or for a session:propose/session:ack (mandatory —
    a session is always device-to-device, see X4DH.md §13.3 — the caller
    rejects a BARE `to` for these two, the inverse of migrate/burn's own
    compound-`to` rejection).

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

    session:propose and session:ack get the same "always durably buffer
    regardless of live delivery" treatment, for a narrower version of the
    same race: propose/ack are device-targeted via deliver_to_endpoint(),
    not deliver(), so the exposure is scoped to one specific endpoint
    session momentarily still connected-but-about-to-drop rather than
    migrate/burn's identity-wide broadcast race — smaller, but not zero,
    and a lost handshake packet is comparatively costlier to silently
    drop than an ordinary chat message (nothing yet retries it — see
    Roadmap.md's X4DH trigger-logic item). propose additionally gets
    buf_write's overwrite-per-sender treatment (X4DH.md §13.2); ack does
    not, since a stale ack for an already-superseded sessionEpoch simply
    fails upgradeX4DHSessionToRK1's epoch-match guard client-side and is
    otherwise harmless sitting in the buffer until it expires normally.

    Push (app:message only): fired only when live delivery genuinely
    failed — a push exists to tell someone to open the app and check,
    which is meaningless if they're already connected and about to
    receive the message live. app:migrate/app:burn/session:propose/
    session:ack never push — none of them are something a human needs to
    be woken up for (the handshake is transparent crypto housekeeping,
    same reasoning call:*/data:* signaling packets never push either).

    Device targeting (app:message only): a `to` address carrying a
    "::endpointId" suffix is delivered only to that specific registered
    device via deliver_to_endpoint(), not fanned out to every live session
    under `to_id`. The offline buffer honours this too (see buf_write's
    endpoint_id param / buf_endpoint_dir): a device-targeted send that
    misses live delivery lands in that device's OWN bucket
    (BUF_DIR/<to_id>/_endpoints/<endpointId>/) rather than the shared
    identity-level one, and is only ever flushed to a connection that
    later presents that exact endpoint_id at auth — never to whichever
    device happens to reconnect first.

    raw — the frame exactly as the sender sent it (handler() has already
    parsed it as a JSON object). When given, it is what gets forwarded: no
    re-serialisation at all. `msg` (the parsed dict) is still what is
    buffered."""
    fwd = raw if raw is not None else msg
    if to_endpoint:
        reached = await deliver_to_endpoint(to_id, to_endpoint, fwd, exclude=ws)
    else:
        reached = await deliver(to_id, fwd, exclude=ws)
    addr_disp = build_address(to_id, to_endpoint)
    if reached:
        log.info("%-10s from=%s  to=%s  reached=%d", kind.upper(), short(frm), short_addr(addr_disp), reached)
    DURABLE_KINDS = ("app:migrate", "app:burn", "session:propose", "session:ack")
    if not reached or kind in DURABLE_KINDS:
        _st = sock_state.get(ws)
        await buf_write(to_id, msg, to_endpoint, src=_st.ipk if _st is not None else None)
        if reached:
            durable_tag = {
                "app:migrate": "migrate", "app:burn": "burn",
                "session:propose": "x4dh_propose", "session:ack": "x4dh_ack",
            }.get(kind, kind)
            log.info("BUF Q      from=%s  to=%s  (also buffered — %s, durability required)  type=%s",
                      short(frm), short_addr(addr_disp), durable_tag, kind)
        else:
            log.info("BUF Q      from=%s  to=%s  (offline)  type=%s", short(frm), short_addr(addr_disp), kind)
    # A self-addressed app:message (frm == to_id) is a client-side "selfsync"
    # copy of our own outgoing message for another of our devices — never
    # push-worthy: waking a sibling to say "open the app and check" about
    # something we ourselves just sent is noise. Ordinary buffering above
    # still applies to it (that's what lets an offline sibling catch up).
    # Scheduled, not awaited: see schedule_push.
    if not reached and kind == "app:message" and frm != to_id:
        schedule_push(to_id)

# ══════════════════════════════════════════
#   AUTH HELPERS
#   derive_public_id  — mirrors client JS logic exactly
#   auth_challenge    — encrypt nonce to client's enc key, store pending
#   auth_verify       — check proof, register, flush buffer
# ══════════════════════════════════════════

# ── relay-bound auth proof (auth_v 2) ──
# Mirrors meshchat-lib.js (AUTH_LABEL / buildAuthMessage / authHostFromUrl)
# byte for byte — read the comment there for what each field is for. The
# short version: the client no longer signs the raw nonce (which made every
# relay a signing oracle for the identity key); it signs
#   "meshchat-auth-v1" 00 host 00 nonce(32) x25519_pub ed25519_pub
#   endpoint_id 00 no_receive(1)
# and this side rebuilds exactly those bytes from what it ISSUED (nonce) and
# what the client PRESENTED in auth_init (keys, endpoint_id, no_receive),
# against its own configured host(s) — never against anything the peer
# claims about where it connected.
AUTH_VERSION   = 2
AUTH_LABEL     = b"meshchat-auth-v1"
AUTH_NONCE_LEN = 32

def _norm_auth_host(h):
    """Same normalisation as the client's authHostFromUrl: lowercase, IPv6
    brackets and trailing dot stripped, IDNA/punycode ASCII form. None if it
    can't be turned into a plain ASCII hostname."""
    if not h or not isinstance(h, str):
        return None
    h = h.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return h or None

def _load_auth_hosts():
    hosts = set()
    if RELAY_WSS_URL:
        h = None
        try:
            parsed = urllib.parse.urlparse(RELAY_WSS_URL)
            if parsed.scheme in ("ws", "wss"):
                h = _norm_auth_host(parsed.hostname)
        except ValueError:
            pass
        if h:
            hosts.add(h)
        else:
            log.error("CONFIG     RELAY_WSS_URL=%r is not a usable ws(s):// URL — treated as unset", RELAY_WSS_URL)
    for entry in RELAY_AUTH_HOSTS_RAW.split(","):
        entry = entry.strip()
        if not entry:
            continue
        h = None
        try:
            h = _norm_auth_host(urllib.parse.urlparse(entry).hostname if "://" in entry else entry)
        except ValueError:
            pass
        if h:
            hosts.add(h)
        else:
            log.warning("CONFIG     RELAY_AUTH_HOSTS invalid entry skipped: %r", entry)
    # Extra names are only meaningful ON TOP of a valid RELAY_WSS_URL —
    # alone they'd let a half-configured relay start authenticating.
    if hosts and not (RELAY_WSS_URL and _norm_auth_host(urllib.parse.urlparse(RELAY_WSS_URL).hostname) in hosts):
        log.error("CONFIG     RELAY_AUTH_HOSTS set but RELAY_WSS_URL missing/invalid — auth stays disabled")
        return frozenset()
    return frozenset(hosts)

AUTH_HOSTS = _load_auth_hosts()

def build_auth_message(host: str, nonce: bytes, x25519_pub: bytes, ed25519_pub: bytes,
                       endpoint_id, no_receive: bool) -> bytes:
    """endpoint_id has already passed valid_id() (base64url ASCII) or is None."""
    return b"".join((
        AUTH_LABEL, b"\x00",
        host.encode("ascii"), b"\x00",
        nonce, x25519_pub, ed25519_pub,
        (endpoint_id or "").encode("ascii"), b"\x00",
        b"\x01" if no_receive else b"\x00",
    ))

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

def enforce_session_cap(public_id, new_ws):
    """Make room for `new_ws` under MAX_SESSIONS_PER_IDENTITY by dropping the
    OLDEST existing sessions of that identity (closing ones aren't counted —
    they're already on their way out). Oldest-first, because the likeliest
    "extra" session is a zombie of a device that has since reconnected."""
    live = [w for w in connected.get(public_id, ())
            if w is not new_ws and not getattr(sock_state.get(w), "closing", False)]
    if len(live) < MAX_SESSIONS_PER_IDENTITY:
        return
    live.sort(key=lambda w: getattr(sock_state.get(w), "t_connect", 0.0))
    for victim in live[: len(live) - MAX_SESSIONS_PER_IDENTITY + 1]:
        stats["session_cap_evicted"] += 1
        log.info("SESSION CAP id=%s  max=%d — dropping oldest session  peer=%s",
                 short(public_id), MAX_SESSIONS_PER_IDENTITY, getattr(sock_state.get(victim), "addr", "?"))
        request_close(victim, CLOSE_CODE_BUSY, "too many sessions for this identity")
        _prune_dead(victim)   # out of the routing maps now, not whenever its close handshake finishes

async def auth_challenge(ws, x25519_pub: bytes, ed25519_pub: bytes, bits: int, no_receive: bool = False,
                          endpoint_id: str | None = None):
    """Generate a random nonce and send it in the clear — there is no
    longer a shared secret to encrypt it with (that was the whole bug:
    the old scheme's "auth" was decrypting a nonce with the same AES key
    the client had just handed the server in plaintext one message
    earlier, which proved nothing). The nonce here exists purely as
    something for the client to SIGN with its Ed25519 private key in
    auth_verify — that signature is the actual possession proof. What it
    signs is NOT the bare nonce: see build_auth_message.

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
    nonce_plain = secrets.token_bytes(AUTH_NONCE_LEN)
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

async def auth_verify(ws, sig_bytes: list, addr: str, authed_as: str | None = None) -> str | None:
    """Verify the Ed25519 signature over the domain-separated auth message
    (build_auth_message), register identity, flush buffer. Returns
    public_id or None on failure.

    authed_as: the identity this SOCKET already authenticated as, if any
    (handler's client_ids[0]). A socket is exactly one identity: a second
    proof that is valid for a DIFFERENT identity is refused here, BEFORE
    anything is registered. This used to be checked by the caller after
    auth_verify returned — by which point the socket was already in
    `connected` / `ws_to_ids` under the second identity, so a client could
    stack up any number of identities on one socket (all inflating
    session_count() toward MAX_CONNECTIONS, none ever cleaned up on close,
    since cleanup only walked client_ids). The same identity again is still
    an idempotent no-op re-auth, as before."""
    entry = pending_auth.pop(id(ws), None)
    if not entry:
        log.warning("AUTH       proof with no pending challenge  peer=%s", addr)
        return None
    if time.monotonic() - entry["ts"] > AUTH_TIMEOUT:
        log.warning("AUTH       challenge expired  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "timeout"})
        return None
    # Per-address ceiling on proofs, BEFORE any signature work — see
    # AUTH_RATE_IP. Charged for valid and invalid proofs alike: both cost the
    # relay a verification. Same reply as the global gate, so clients back off
    # the way they already do for server_busy.
    _st = sock_state.get(ws)
    _ipk = _st.ipk if _st is not None else addr
    _alim = ip_auth_limiters.get(_ipk)
    if _alim is None:
        _alim = ip_auth_limiters[_ipk] = RateLimiter(rate=AUTH_RATE_IP, burst=AUTH_BURST_IP)
    if not _alim.allow():
        stats["auth_ip_rejected"] += 1
        warn_throttled("auth_ip", "AUTH       per-address auth rate limit reached  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "server_busy"})
        return None
    # The signature must verify against OUR host name(s), rebuilt from what
    # we issued (nonce) and what the client presented in auth_init. A proof
    # a client made for some other relay's host — e.g. one forwarded by a
    # relay that was handed OUR challenge — signs different bytes and fails
    # here. A set, not a single host, only because one relay may legitimately
    # answer to several names (RELAY_AUTH_HOSTS); a handful of verifies at
    # worst, and only a proof that fails them all is rejected.
    verified_host = None
    try:
        pub = Ed25519PublicKey.from_public_bytes(entry["ed25519_pub"])
        sig = bytes(sig_bytes)
        for host in AUTH_HOSTS:
            message = build_auth_message(host, entry["nonce"], entry["x25519_pub"], entry["ed25519_pub"],
                                         entry.get("endpoint_id"), entry.get("no_receive", False))
            try:
                pub.verify(sig, message)
                verified_host = host
                break
            except Exception:
                continue
    except Exception:
        verified_host = None
    if verified_host is None:
        log.warning("AUTH       proof invalid  peer=%s", addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "proof_invalid"})
        return None

    public_id = derive_public_id(entry["x25519_pub"], entry["ed25519_pub"])

    # One socket, one identity — see the authed_as note in the docstring.
    # Checked right after the proof, before the admission gate (a refused
    # second identity should not spend from the shared budget) and, above
    # all, before any registration below.
    if authed_as is not None and public_id != authed_as:
        log.warning("AUTH       socket already authed as %s, rejecting %s  peer=%s",
                    short(authed_as), short(public_id), addr)
        await send_to(ws, {"type": "sig:auth_fail", "reason": "already_authenticated"})
        return None

    # Global admission gate — checked only after the proof is confirmed
    # valid, so a flood of garbage/incorrect proofs doesn't spend from the
    # shared budget, only completions that would actually have succeeded.
    # Deliberately independent of source IP (see GLOBAL_AUTH_RATE comment)
    # — this is the one lever that still works when the flood is genuinely
    # distributed across many real, distinct addresses rather than one.
    #
    # Known identities have a lane of their own behind it: when the shared
    # budget is spent (a flood of brand-new identities), one this relay has
    # already seen authenticate still gets through, within AUTH_KNOWN_RATE.
    if not global_auth_limiter.allow():
        if known_registry.is_known(public_id) and known_auth_limiter.allow():
            stats["auth_known_lane"] += 1
        else:
            warn_throttled("auth_global", "AUTH       global admission limit reached  peer=%s", addr)
            stats["auth_admission_rejected"] += 1
            await send_to(ws, {"type": "sig:auth_fail", "reason": "server_busy"})
            return None

    no_receive = entry.get("no_receive", False)
    endpoint_id = entry.get("endpoint_id")
    # Authenticated from here on: stops the unauthenticated deadline and
    # makes the socket count as a real session for eviction. Set BEFORE the
    # buffer flush below, which can take a while and must not be cut short by
    # a deadline that has nothing left to wait for.
    st = sock_state.get(ws)
    if st is not None:
        st.authed = True
        if st.deadline is not None:
            st.deadline.cancel()
            st.deadline = None
    # The library's own frame cap goes back up NOW — before auth_ok leaves.
    # The library parses incoming frames as bytes arrive, not when the
    # handler next reads: raising it only once this function returns (after
    # the buffer flush, which can take a while) would disconnect a client
    # that sends its first real message right after auth_ok.
    set_max_frame(ws, WS_MAX_SIZE)
    if not no_receive:
        enforce_session_cap(public_id, ws)   # before the set is (re)created below — it prunes victims out of `connected`
        if public_id not in connected:
            connected[public_id] = set()
        connected[public_id].add(ws)
        ws_to_ids.setdefault(ws, set()).add(public_id)
        if endpoint_id:
            connected_by_endpoint.setdefault(public_id, {}).setdefault(endpoint_id, set()).add(ws)
            ws_to_endpoint.setdefault(ws, []).append((public_id, endpoint_id))
        # Only a socket that registers to RECEIVE makes the identity (and its
        # device) known — a send-only (no_receive) connection never gets a
        # buffer here. Done together with the registration above so a durable
        # packet that arrives from now on takes the normal path, not probation.
        known_registry.touch(public_id, endpoint_id)
    log.info("AUTH OK    id=%s  bits=%d  host=%s  peer=%s  keys=%d  sessions=%d%s%s",
             short(public_id), entry["bits"], verified_host, addr, unique_keys(), session_count(),
             "  [no_receive — not registered]" if no_receive else "",
             f"  endpoint={short(endpoint_id)}" if (endpoint_id and not no_receive) else "")
    await send_to(ws, {"type": "sig:auth_ok", "public_id": public_id})
    if not no_receive:
        # A first-time identity's probation packet is handed over before the
        # flush below, so it is delivered with everything else.
        await promote_probation(public_id)
        await buf_deliver(public_id, ws, endpoint_id)
    return public_id

# ══════════════════════════════════════════
#   OFFLINE BUFFER
#   Layout: BUF_DIR/<publicId>/<ts>_<uuid>[_s<sendertag>].json
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
    bucket alongside the identity-level one, for app:message packets whose
    `to` address carried a device-targeted "::endpointId" suffix (see
    parse_address() near valid_id) and missed live delivery to that
    specific device (see route_or_buffer/deliver_to_endpoint). Never used
    for app:migrate/app:burn — those aren't device-targeted and stay
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

_BUF_SENDER_RE = re.compile(r"^\d+_[0-9a-f]{8}_s([0-9a-f]{8})")

def _sender_tag(frm):
    """Short stable tag for a sender identity, carried in the buffer filename
    so fair-share decisions never have to open a file. Not a secret; only
    used to tell senders apart (a collision just means two senders share a
    share)."""
    if not isinstance(frm, str) or not frm:
        return None
    return hashlib.sha256(frm.encode("utf-8", "replace")).hexdigest()[:8]

def _buf_filename(msg, suffix):
    """<ms>_<uuid8>[_s<sendertag>]<suffix>. Sorts by time exactly as before;
    files written by older versions (no tag) count as sender "?"."""
    tag = _sender_tag(msg.get("from"))
    return f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}{'_s' + tag if tag else ''}{suffix}"

def _buf_sender_of(path):
    m = _BUF_SENDER_RE.match(os.path.basename(path))
    return m.group(1) if m else "?"

def _buf_is_protected(path):
    """migrate/burn notices: long-lived, must eventually be seen."""
    return path.endswith(MIGRATE_SUFFIX) or path.endswith(BURN_SUFFIX)

def _pick_victim(candidates, sizes=None):
    """Fair-share eviction. `candidates` is oldest-first. Returns the oldest
    file of the sender holding the most files — or the most bytes when
    `sizes` ({path: bytes}) is given. Ties go to the sender whose file is
    oldest overall."""
    groups = {}
    for p in candidates:
        g = groups.setdefault(_buf_sender_of(p), [0, p])      # [weight, oldest file]
        g[0] += sizes.get(p, 0) if sizes is not None else 1
    return max(groups.values(), key=lambda g: g[0])[1]        # max() keeps the first maximum → oldest sender wins ties

def _buf_suffix_for(kind):
    """Filename tag for a packet kind (same mapping _buf_write_sync applies)."""
    return (MIGRATE_SUFFIX if kind == "app:migrate" else
            BURN_SUFFIX if kind == "app:burn" else
            X4DH_PROPOSE_SUFFIX if kind == "session:propose" else ".json")

def _probation_write_sync(to_id, msg, endpoint_id=None):
    """Buffer ONE packet for a recipient this relay has never seen. Keep-first:
    if the recipient's probation slot already holds a packet this one is
    dropped (nothing is overwritten, so a squatter can't push out the packet
    that is already waiting). Lives in BUF_DIR/.probation, a pool of at most
    MAX_PROBATION_RECIPIENTS recipients whose oldest entry makes room for a new
    one — it can never use real buffer capacity. Runs in a worker thread."""
    try:
        raw = json.dumps(msg)
    except (TypeError, ValueError):
        return
    if len(raw) > PROBATION_MAX_BYTES:
        stats["probation_oversize"] += 1
        warn_throttled("prob_size", "PROBATION  packet too large for an unseen recipient (%d > %d)  to=%s",
                       len(raw), PROBATION_MAX_BYTES, short(to_id))
        return
    slot = probation_pool.claim(to_id)
    if slot is None:
        stats["probation_kept_first"] += 1
        warn_throttled("prob_first", "PROBATION  slot already holds a packet — keeping the first  to=%s", short(to_id))
        return
    base, evicted = slot
    if evicted:
        stats["probation_evicted"] += evicted
        warn_throttled("prob_evict", "PROBATION  pool full (%d) — evicted %d oldest", MAX_PROBATION_RECIPIENTS, evicted)
    try:
        d = os.path.join(base, "_endpoints", endpoint_id) if endpoint_id else base
        os.makedirs(d, exist_ok=True)
        fname = os.path.join(d, _buf_filename(msg, _buf_suffix_for(msg.get('type'))))
        with open(fname, "w") as f:
            f.write(raw)
    except Exception as e:
        log.warning("PROBATION  write failed  to=%s  err=%s", short(to_id), e)
        probation_pool.release(to_id)
        return
    stats["probation_stored"] += 1
    stats["buf_in"] += 1
    log.info("PROBATION  write  to=%s  type=%s%s", short(to_id), msg.get("type"),
             f"  endpoint={short(endpoint_id)}" if endpoint_id else "")

def _unknown_endpoint_ok(to_id, endpoint_id, d, top_dir, msg):
    """A packet for a device of a KNOWN identity that has never authenticated
    here. True if it may be written to that device's bucket. The bucket holds
    ONE packet (keep-first) and an identity may hold only
    PROBATION_ENDPOINTS_PER_RECIPIENT such buckets at once — so a stranger
    can't fill the identity's real MAX_ENDPOINTS_PER_RECIPIENT slots with
    devices that don't exist. Once the device authenticates, the registry
    learns it and the bucket becomes an ordinary one."""
    try:
        size = len(json.dumps(msg))
    except (TypeError, ValueError):
        return False
    if size > PROBATION_MAX_BYTES:
        stats["probation_oversize"] += 1
        warn_throttled("prob_size", "PROBATION  packet too large for an unseen device (%d > %d)  to=%s",
                       size, PROBATION_MAX_BYTES, short(to_id))
        return False
    if os.path.isdir(d):
        try:
            with os.scandir(d) as it:
                if any(e.name.endswith(".json") for e in it):
                    stats["probation_kept_first"] += 1
                    warn_throttled("prob_first", "PROBATION  device bucket already holds a packet — keeping the first  to=%s  endpoint=%s",
                                   short(to_id), short(endpoint_id))
                    return False
        except OSError:
            pass
        return True   # an empty bucket that was already admitted
    known = known_registry.endpoints(to_id)
    try:
        with os.scandir(os.path.join(top_dir, "_endpoints")) as it:
            unknown_n = sum(1 for e in it if e.is_dir() and e.name not in known)
    except OSError:
        unknown_n = 0
    if unknown_n >= PROBATION_ENDPOINTS_PER_RECIPIENT:
        stats["probation_endpoint_cap"] += 1
        warn_throttled("prob_ep_cap", "PROBATION  unseen-device allowance reached (%d)  to=%s  endpoint=%s",
                       PROBATION_ENDPOINTS_PER_RECIPIENT, short(to_id), short(endpoint_id))
        return False
    stats["probation_stored"] += 1
    return True

def _probation_adopt_sync(to_id):
    """Hand a recipient's probation packet to its real buffer — it has just
    authenticated, so it is known now. A rename when it has no directory yet
    (the usual case), otherwise a file-by-file merge. Worker thread."""
    if not probation_pool.pop(to_id):
        return 0
    src = probation_pool.path(to_id)
    if not os.path.isdir(src):
        return 0
    try:
        dst = buf_dir(to_id)
    except ValueError:
        shutil.rmtree(src, ignore_errors=True)
        return 0
    moved = 0
    try:
        if not os.path.exists(dst):
            if buf_recipient_count.count() >= MAX_BUF_RECIPIENTS:
                stats["buf_cap_rejected"] += 1
                shutil.rmtree(src, ignore_errors=True)
                return 0
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.rename(src, dst)
            buf_recipient_count.add(1)
            moved = 1
        else:
            for root, _dirs, names in os.walk(src):
                rel = os.path.relpath(root, src)
                target = dst if rel == "." else os.path.join(dst, rel)
                for n in names:
                    os.makedirs(target, exist_ok=True)
                    os.replace(os.path.join(root, n), os.path.join(target, n))
                    moved += 1
            shutil.rmtree(src, ignore_errors=True)
    except OSError as e:
        log.warning("PROBATION  promote failed  to=%s  err=%s", short(to_id), e)
        shutil.rmtree(src, ignore_errors=True)
        return 0
    return moved

async def promote_probation(to_id):
    """Called when `to_id` authenticates, BEFORE its buffer is flushed."""
    if not probation_pool.has(to_id):
        return
    lock = await _acquire_buf_lock(to_id)
    try:
        n = await asyncio.to_thread(_probation_adopt_sync, to_id)
    finally:
        await _release_buf_lock(to_id, lock)
    if n:
        stats["probation_promoted"] += 1
        log.info("PROBATION  promoted  id=%s", short(to_id))

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

    # Known-identity gate — see the KNOWN-IDENTITY REGISTRY + PROBATION config
    # block. A recipient this relay has never seen authenticate (and that is
    # not inside the registry's grace window) gets one keep-first packet in the
    # probation pool instead of a real directory; an unknown DEVICE of a known
    # identity gets one packet per bucket, a couple of buckets at most.
    if not known_registry.accepts(to_id):
        _probation_write_sync(to_id, msg, endpoint_id)
        return
    if endpoint_id and not known_registry.in_grace() and not known_registry.endpoint_known(to_id, endpoint_id):
        if not _unknown_endpoint_ok(to_id, endpoint_id, d, top_dir, msg):
            return

    # Recipient cap — only matters for a NEW recipient directory (the
    # top-level <to_id> dir itself, whether this particular write is
    # identity- or endpoint-level — both create it). An existing recipient
    # is never turned away by this; it's purely a brake on an attacker
    # fanning out to unlimited fabricated recipient IDs. See
    # MAX_BUF_RECIPIENTS comment near its definition.
    new_recipient = not os.path.isdir(top_dir)
    if new_recipient:
        # In-memory count (DirCounter) — not a scandir over up to
        # MAX_BUF_RECIPIENTS entries per new recipient, which an attacker
        # could make this thread do on every write.
        if buf_recipient_count.count() >= MAX_BUF_RECIPIENTS:
            stats["buf_cap_rejected"] += 1
            warn_throttled("buf_cap", "BUF        recipient cap reached (%d) — rejecting new recipient  to=%s",
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
            warn_throttled("buf_ep_cap", "BUF        endpoint cap reached (%d) — rejecting new endpoint bucket  to=%s  endpoint=%s",
                           MAX_ENDPOINTS_PER_RECIPIENT, short(to_id), short(endpoint_id))
            return

    try:
        os.makedirs(d, exist_ok=True)
    except Exception as e:
        log.warning("BUF        mkdir failed  to=%s  err=%s", short(to_id), e)
        return
    if new_recipient:
        buf_recipient_count.add(1)

    kind       = msg.get("type")
    is_migrate = kind == "app:migrate"
    is_burn    = kind == "app:burn"
    is_propose = kind == "session:propose"
    frm        = msg.get("from")

    files = buf_endpoint_files(to_id, endpoint_id) if endpoint_id else buf_files(to_id)

    if (is_migrate or is_burn or is_propose) and frm:
        own_suffix = MIGRATE_SUFFIX if is_migrate else (BURN_SUFFIX if is_burn else X4DH_PROPOSE_SUFFIX)
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
                              "migrate" if is_migrate else ("burn" if is_burn else "x4dh_propose"), short(to_id), short(frm))
                except Exception:
                    kept.append(fpath)
            else:
                kept.append(fpath)
        files = kept

    # Make room — fair share + reserved slots (see BUF_RESERVED_SLOTS).
    raw   = json.dumps(msg).encode()
    sizes = {}
    for fpath in list(files):
        try:
            sizes[fpath] = os.path.getsize(fpath)
        except OSError:
            files.remove(fpath)                 # vanished under us (delivery / expiry)

    def evict(candidates, by_bytes, why):
        victim = _pick_victim(candidates, sizes if by_bytes else None)
        try:
            os.remove(victim)
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("BUF        evict failed  to=%s  err=%s", short(to_id), e)
        for lst in (files, candidates):
            if victim in lst:
                lst.remove(victim)
        sizes.pop(victim, None)
        stats["buf_fair_evicted"] += 1
        log.info("BUF        evict (%s)  to=%s  sender-tag=%s  incoming-from=%s", why, short(to_id),
                 _buf_sender_of(victim), short(frm))

    protected_in = is_migrate or is_burn
    regular      = [f for f in files if not _buf_is_protected(f)]
    regular_cap  = max(1, BUF_MAX_MSGS - max(0, BUF_RESERVED_SLOTS))
    if protected_in:
        # migrate/burn may use every slot, including the reserved ones; when
        # full they displace regular packets, heaviest sender first.
        while len(files) >= BUF_MAX_MSGS:
            if not regular:
                stats["buf_reserved_full"] += 1
                warn_throttled("buf_resv_full", "BUF        full of migrate/burn notices — dropping  to=%s  from=%s", short(to_id), short(frm))
                return
            evict(regular, False, "count, for migrate/burn")
    else:
        while len(regular) >= regular_cap:
            evict(regular, False, "count")
        while len(files) >= BUF_MAX_MSGS:                        # protected notices took more than the reserved share
            if not regular:
                stats["buf_reserved_full"] += 1
                warn_throttled("buf_resv_full", "BUF        full of migrate/burn notices — dropping  to=%s  from=%s", short(to_id), short(frm))
                return
            evict(regular, False, "count")

    # size limit — same rule, by bytes. A packet bigger than the whole limit
    # can never fit, so it is refused without evicting anyone for nothing.
    limit = BUF_MAX_MB * 1024 * 1024
    if len(raw) > limit:
        stats["buf_size_rejected"] += 1
        log.warning("BUF        size limit reached  to=%s  dropping", short(to_id))
        return
    while sum(sizes.values()) + len(raw) > limit:
        if not regular:
            stats["buf_size_rejected"] += 1
            log.warning("BUF        size limit reached  to=%s  dropping", short(to_id))
            return
        evict(regular, True, "size")

    suffix = MIGRATE_SUFFIX if is_migrate else (BURN_SUFFIX if is_burn else (X4DH_PROPOSE_SUFFIX if is_propose else ".json"))
    fname  = os.path.join(d, _buf_filename(msg, suffix))
    try:
        try:
            f = open(fname, "w")
        except FileNotFoundError:
            # The expiry sweep removes empty directories; it can have removed
            # this one between the makedirs above and now. Recreate and retry
            # once rather than losing the packet to that race.
            os.makedirs(d, exist_ok=True)
            f = open(fname, "w")
        with f:
            json.dump(msg, f)
        stats["buf_in"] += 1
        log.info("BUF        write  to=%s  file=%s%s%s", short(to_id), os.path.basename(fname),
                  "  [migrate]" if is_migrate else ("  [burn]" if is_burn else ("  [x4dh_propose]" if is_propose else "")),
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

async def buf_write(to_id, msg, endpoint_id=None, src=None):
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
    # A write that would START a new probation slot (never-seen recipient, or an
    # unseen device of a known one) costs the relay a directory: limited per
    # sending ADDRESS (`src`, the sender socket's address key) so one machine
    # can't churn the pool. Writes to recipients the relay knows, or into a
    # slot that already exists (those are refused as keep-first anyway), skip it.
    if src is not None and not known_registry.in_grace():
        starts_slot = (not known_registry.is_known(to_id) and not probation_pool.has(to_id)) or \
                      (endpoint_id and known_registry.is_known(to_id) and not known_registry.endpoint_known(to_id, endpoint_id))
        if starts_slot:
            plim = probation_ip_limiters.get(src)
            if plim is None:
                plim = probation_ip_limiters[src] = RateLimiter(rate=PROBATION_IP_RATE, burst=PROBATION_IP_BURST)
            if not plim.allow():
                stats["probation_ip_limited"] += 1
                warn_throttled("prob_ip", "PROBATION  per-address limit on new slots reached  src=%s  to=%s", src, short(to_id))
                return

    limiter_key = f"{to_id}::{endpoint_id}" if endpoint_id else to_id
    limiter = buf_recipient_limiters.get(limiter_key)
    if limiter is None:
        limiter = RateLimiter(rate=BUF_WRITE_RATE_LIMIT, burst=BUF_WRITE_RATE_BURST)
        buf_recipient_limiters[limiter_key] = limiter
    if not limiter.allow():
        stats["buf_rate_rejected"] += 1
        warn_throttled("buf_rate", "BUF        write-rate limit reached  to=%s%s — dropped", short(to_id),
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

def _buf_expire_chunk_sync(names, now):
    """Sweep one chunk of recipient directories (names under BUF_DIR) — runs in
    a worker thread. Returns (files_dropped, recipient_dirs_removed).

    Regular packets use BUF_MAX_AGE; migrate packets (tagged via
    MIGRATE_SUFFIX) use the much longer BUF_MAX_AGE_MIGRATE and burn packets
    BUF_MAX_AGE_BURN. Endpoint buckets (_endpoints/<endpointId>/) always use
    plain BUF_MAX_AGE — an app:message is the only kind that ever lands
    there, migrate/burn are never device-targeted, so
    MIGRATE_SUFFIX/BURN_SUFFIX simply never appear under _endpoints/ in
    practice. Every filesystem call is individually guarded: a directory a
    writer or the flush path is touching concurrently can vanish or change
    under the scan, and that must cost one entry, never the sweep."""
    dropped = 0
    removed_dirs = 0
    for name in names:
        rec_path = os.path.join(BUF_DIR, name)
        try:
            with os.scandir(rec_path) as it:
                entries = list(it)
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith(".json"):
                continue
            if entry.name.endswith(MIGRATE_SUFFIX):
                max_age = BUF_MAX_AGE_MIGRATE
            elif entry.name.endswith(BURN_SUFFIX):
                max_age = BUF_MAX_AGE_BURN
            else:
                max_age = BUF_MAX_AGE
            try:
                if now - entry.stat().st_mtime > max_age:
                    os.remove(entry.path)
                    dropped += 1
            except OSError:
                pass

        # sweep this recipient's per-device endpoint buckets — same TTL
        # logic, one directory level down. Always plain BUF_MAX_AGE (see
        # docstring above re: migrate/burn).
        endpoints_root = os.path.join(rec_path, "_endpoints")
        try:
            with os.scandir(endpoints_root) as it:
                ep_dirs = [e for e in it if e.is_dir()]
        except OSError:
            ep_dirs = None
        if ep_dirs is not None:
            for ep_dir in ep_dirs:
                try:
                    with os.scandir(ep_dir.path) as it:
                        ep_entries = list(it)
                except OSError:
                    continue
                for entry in ep_entries:
                    if not entry.name.endswith(".json"):
                        continue
                    try:
                        if now - entry.stat().st_mtime > BUF_MAX_AGE:
                            os.remove(entry.path)
                            dropped += 1
                    except OSError:
                        pass
                # clean up an emptied-out endpoint bucket (rmdir only ever
                # removes an EMPTY directory — a concurrent write wins)
                try: os.rmdir(ep_dir.path)
                except OSError: pass
            # clean up the _endpoints dir itself once every bucket under it is gone
            try: os.rmdir(endpoints_root)
            except OSError: pass

        # clean up empty recipient dirs — checked last, after _endpoints/ has
        # had a chance to empty out above, so a recipient with nothing left in
        # EITHER bucket is correctly pruned rather than kept alive by a
        # now-empty _endpoints/ directory still sitting inside it.
        try:
            os.rmdir(rec_path)
            removed_dirs += 1
        except OSError:
            pass
    return dropped, removed_dirs

def _buf_recipient_names_sync():
    try:
        with os.scandir(BUF_DIR) as it:
            return [e.name for e in it if e.is_dir() and not e.name.startswith(".")]
    except OSError:
        return []

async def buf_expire_sweep():
    """One full expiry pass. The directory listing and every chunk of
    BUF_EXPIRE_CHUNK recipients run in a worker thread; the event loop gets
    control back between chunks. This used to be one synchronous scandir tree
    walk ON the loop — with MAX_BUF_RECIPIENTS directories and a full bucket
    each, every connection stalled for the length of it, every
    BUF_EXPIRE_INTERVAL."""
    now = time.time()
    names = await asyncio.to_thread(_buf_recipient_names_sync)
    dropped = 0
    for i in range(0, len(names), BUF_EXPIRE_CHUNK):
        chunk_dropped, chunk_dirs = await asyncio.to_thread(_buf_expire_chunk_sync, names[i:i + BUF_EXPIRE_CHUNK], now)
        dropped += chunk_dropped
        buf_recipient_count.add(-chunk_dirs)
        await asyncio.sleep(0)
    # absorb any drift (a writer that re-created a directory the sweep had
    # just removed, a directory deleted by hand) — cheap, and off the loop
    await asyncio.to_thread(buf_recipient_count.resync)
    return dropped

async def buf_expire():
    """Background task — see buf_expire_sweep / _buf_expire_chunk_sync."""
    while True:
        await asyncio.sleep(BUF_EXPIRE_INTERVAL)
        dropped = 0
        try:
            dropped = await buf_expire_sweep()
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
        # same housekeeping for the push cooldown table
        _prune_push_last(now_mono)
        # registry / probation housekeeping, same cadence
        try:
            forgotten = known_registry.expire()
            swept = await asyncio.to_thread(probation_pool.sweep)
            if forgotten:
                log.info("REGISTRY  forgot %d identit%s not seen for %.0f days", forgotten,
                         "y" if forgotten == 1 else "ies", REGISTRY_TTL_S / 86400)
            if swept:
                log.info("PROBATION  expired %d unclaimed entr%s", swept, "y" if swept == 1 else "ies")
        except Exception as e:
            log.warning("REGISTRY  housekeeping error: %s", e)
        for table in (ip_auth_limiters, probation_ip_limiters):
            for k in [k for k, lim in table.items() if now_mono - lim.last_time > BUF_RATE_LIMITER_IDLE_S]:
                table.pop(k, None)

async def registry_flush_loop():
    """Write-behind: push registry changes to SQLite every REGISTRY_FLUSH_S,
    in a worker thread so a slow disk can't stall the loop."""
    while True:
        await asyncio.sleep(REGISTRY_FLUSH_S)
        try:
            await asyncio.to_thread(known_registry.flush)
        except Exception as e:
            warn_throttled("registry_flush_loop", "REGISTRY  flush error: %s", e)

# ══════════════════════════════════════════
#   STATS
# ══════════════════════════════════════════

async def log_stats():
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        log.info("STATS      sockets=%d  push_queue=%d  push_last=%d  buf_recipients=%d  push_identities=%d",
                 socket_count(), len(push_tasks), len(push_last),
                 buf_recipient_count.count(), push_identity_count.count())
        log.info("BUFFER     fair_evicted=%d  reserved_full=%d  size_rejected=%d",
                 stats["buf_fair_evicted"], stats["buf_reserved_full"], stats["buf_size_rejected"])
        log.info("REGISTRY   mode=%s  known=%d  grace=%s  probation=%d/%d  stored=%d  kept_first=%d  oversize=%d  ip_limited=%d  "
                 "endpoint_cap=%d  evicted=%d  promoted=%d  auth_ip_rejected=%d  auth_known_lane=%d",
                 known_registry.mode, known_registry.size(),
                 ("open %ds" % (known_registry.grace_until - time.time())) if known_registry.in_grace() else "closed",
                 len(probation_pool), MAX_PROBATION_RECIPIENTS,
                 stats["probation_stored"], stats["probation_kept_first"], stats["probation_oversize"],
                 stats["probation_ip_limited"], stats["probation_endpoint_cap"], stats["probation_evicted"],
                 stats["probation_promoted"], stats["auth_ip_rejected"], stats["auth_known_lane"])
        log.info("REJECTED   conn_refused=%d  conn_evicted=%d  unauth_deadline=%d  rate=%d  bytes=%d  type=%d  "
                 "frame=%d  binary=%d  malformed=%d  strike_closed=%d  session_cap=%d  send_timeout=%d  "
                 "push_cooldown=%d  push_dropped=%d",
                 stats["conn_refused"], stats["conn_evicted"], stats["unauth_deadline"],
                 stats["rate_rejected"], stats["byte_rejected"], stats["type_rejected"],
                 stats["frame_rejected"], stats["binary_rejected"], stats["malformed"],
                 stats["strike_closed"], stats["session_cap_evicted"], stats["send_timeout"],
                 stats["push_cooldown"], stats["push_dropped"])
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
                request_close(ws, CLOSE_CODE_BUSY, "auth timeout")   # background: a peer that won't answer the close can't stall the sweep
        if stale:
            log.info("AUTH       swept %d stale half-authed connection(s)", len(stale))

# ── per-kind rules ──
# kind → (budget class, frame size cap in bytes). The class picks the
# per-type token bucket (TYPE_LIMITS); the cap is enforced on the raw frame
# (see handler). A kind that isn't listed is dropped as unknown anyway, so it
# is held to the smallest cap.
KIND_RULES: dict = {}

def _rules(kinds, cls, cap):
    for k in kinds:
        KIND_RULES[k] = (cls, cap)

_rules(("sig:auth_init", "sig:auth_proof"),                      "auth",     FRAME_CAP_PREAUTH)
_rules(("session:propose", "session:ack"),                       "session",  FRAME_CAP_TINY)
_rules(("app:burn",),                                            "migrate",  FRAME_CAP_TINY)
_rules(("app:migrate",),                                         "migrate",  FRAME_CAP_HANDSHAKE)
_rules(("app:message",),                                         "message",  FRAME_CAP_MESSAGE)
_rules(("sig:push_subscribe", "sig:push_unsubscribe"),           "push",     FRAME_CAP_HANDSHAKE)
_rules(("sig:announce",),                                        "announce", FRAME_CAP_TINY)
_rules(("sig:ping", "sig:relay_req"),                            "misc",     FRAME_CAP_TINY)
_rules(("sync:backup_offer", "sync:backup_accept", "sync:restore_req", "sync:restore_ack",
        "sync:token_req", "sync:token_resp"),                    "sync",     FRAME_CAP_HANDSHAKE)
_rules(("app:sync", "sync:backup_push", "sync:restore_push"),    "sync",     FRAME_CAP_BULK)
_rules(("call:invite", "call:claim", "call:cancel", "call:end", "call:offer", "call:answer", "call:ice",
        "data:invite", "data:claim", "data:cancel", "data:end", "data:offer", "data:answer", "data:ice"),
                                                                 "signal",   FRAME_CAP_SIGNAL)

DEFAULT_RULE = ("other", FRAME_CAP_TINY)

# Frames up to this size are simply parsed and then held to their own type's
# cap. Anything bigger is only worth parsing if it CLAIMS to be a type that is
# allowed to be that big — judged by peeking at the frame's "type" key
# without parsing it (see peek_type).
SMALL_FRAME_MAX = max(FRAME_CAP_PREAUTH, FRAME_CAP_TINY, FRAME_CAP_HANDSHAKE, FRAME_CAP_SIGNAL)

_TYPE_PEEK = re.compile(r'"type"\s*:\s*"([^"\\]{1,48})"')

def peek_type(raw):
    """The value of the first "type" key in a frame, found by text search —
    no parse. Packets carry no key named "type" other than the top-level one
    (blobs are {v, iv, data}), so the first occurrence is the real one in any
    well-formed frame; a sender can only fake it to get its frame PARSED,
    after which the exact type's cap and budgets apply."""
    i = raw.find('"type"')
    if i < 0:
        return None
    m = _TYPE_PEEK.match(raw, i)
    return m.group(1) if m else None

def frame_size(raw):
    """Size of a text frame in BYTES (len() counts characters). str.isascii()
    is O(1), so the common all-ASCII frame costs nothing extra."""
    return len(raw) if raw.isascii() else len(raw.encode("utf-8", "replace"))

def set_max_frame(ws, size):
    """Change the library's own per-message cap on THIS connection (lowered
    before auth, raised once authenticated), so an oversized pre-auth frame is
    refused by the library without ever being buffered. Best-effort: touches a
    protocol attribute, so a websockets version without it just keeps
    WS_MAX_SIZE and handler()'s own checks do the work."""
    try:
        proto = getattr(ws, "protocol", None)
        if proto is not None and hasattr(proto, "max_message_size"):
            proto.max_message_size = size
            return True
        if hasattr(ws, "max_size"):          # legacy implementation
            ws.max_size = size
            return True
    except Exception:
        pass
    return False

def pick_eviction_victim(now=None):
    """Which open socket to close to make room: an unauthenticated one first
    (oldest first — the newest is the likeliest to be a real client mid
    handshake), otherwise the authed socket silent for longest, but only if
    it has been silent past WS_IDLE_EVICT_S. None when everything is a live,
    recently-active session — then the newcomer is refused."""
    now = time.monotonic() if now is None else now
    unauthed = [s for s in sock_state.values() if not s.authed and not s.closing]
    if unauthed:
        return min(unauthed, key=lambda s: s.t_connect)
    idle = [s for s in sock_state.values() if s.authed and not s.closing and now - s.t_last > WS_IDLE_EVICT_S]
    if idle:
        return max(idle, key=lambda s: now - s.t_last)
    return None

def _unauth_deadline_expired(st):
    st.deadline = None
    if st.authed or st.closing:
        return
    stats["unauth_deadline"] += 1
    warn_throttled("unauth_deadline", "UNAUTH     no completed auth within %.0fs — closing  peer=%s",
                   UNAUTH_DEADLINE_S, st.addr)
    request_close(st.ws, CLOSE_CODE_POLICY, "authentication deadline")

def strike(st, weight, code, why):
    """Record a violation on this socket; if it has piled up too many, start
    closing it (in the background — see handler(): the receive loop keeps
    reading and discarding until the close completes, because a handler that
    stops reading stalls the close handshake behind the peer's unread data)."""
    if st.closing or not st.add_strike(weight):
        return
    stats["strike_closed"] += 1
    warn_throttled("strike_closed", "STRIKES    closing — too many violations (last: %s)  peer=%s", why, st.addr)
    request_close(st.ws, code, "too many violations")

# ══════════════════════════════════════════
#   WEBSOCKET HANDLER
# ══════════════════════════════════════════

async def handler(ws):
    client_ids = []   # public_ids authed this socket
    addr       = peer_info(ws)
    ipk        = ip_key(addr)   # what per-address limits are counted under — see ip_key()

    # ── connection limits ──
    # All of these count sockets of ANY auth state. A socket that has only
    # connected and said nothing is a slot held like any other.
    async def refuse(key, what):
        stats["conn_refused"] += 1
        warn_throttled("limit_" + key, "LIMIT      %s  peer=%s", what, addr)
        await _close_quiet(ws, CLOSE_CODE_BUSY, what)

    if socket_count() >= MAX_CONNECTIONS * CONN_HARD_CAP_FACTOR:
        await refuse("hard", "server full")
        return
    if ip_conns.get(ipk, 0) >= MAX_CONNECTIONS_PER_IP:
        await refuse("ip", "too many connections from your address")
        return
    if sum(1 for s in sock_state.values() if s.ipk == ipk and not s.authed and not s.closing) >= MAX_UNAUTH_PER_IP:
        await refuse("unauth_ip", "too many unauthenticated connections from your address")
        return
    if socket_count(include_closing=False) >= MAX_CONNECTIONS:
        # Full. Make room by dropping the least valuable socket instead of
        # turning the newcomer away — otherwise whoever connects first and
        # idles wins every slot, and real clients are the ones locked out.
        victim = pick_eviction_victim()
        if victim is None:
            await refuse("full", "server full")
            return
        stats["conn_evicted"] += 1
        warn_throttled("evict", "EVICT      relay full (%d) — dropping %s socket  peer=%s",
                       MAX_CONNECTIONS, "an authed idle" if victim.authed else "an unauthenticated", victim.addr)
        request_close(victim.ws, CLOSE_CODE_BUSY, "evicted: server full")
        _prune_dead(victim.ws)

    st = SockState(ws, addr, ipk)
    sock_state[ws] = st
    ip_conns[ipk] = ip_conns.get(ipk, 0) + 1

    # Shared across every socket this address currently has open — without
    # this, MAX_CONNECTIONS_PER_IP sockets each got their own independent
    # budget, so an IP's effective throughput scaled with how many
    # connections it opened rather than staying capped. Deliberately its own,
    # wider tier (IP_RATE_LIMIT_RATE/BURST) rather than reusing the
    # per-socket RateLimiter() defaults — see that pair's own comment near
    # their definition for why sharing one constant between "one connection"
    # and "everything behind this NAT" was the wrong call. get-or-create
    # rather than always-new so it persists (and its token bucket state
    # carries over) across this address's concurrent sockets. Same for the
    # byte budget.
    if ipk not in ip_limiters:
        ip_limiters[ipk] = RateLimiter(rate=IP_RATE_LIMIT_RATE, burst=IP_RATE_LIMIT_BURST)
    ip_limiter = ip_limiters[ipk]
    if ipk not in ip_byte_limiters:
        ip_byte_limiters[ipk] = RateLimiter(rate=BYTE_RATE_IP, burst=BYTE_BURST_IP)
    ip_bytes = ip_byte_limiters[ipk]

    log.info("CONNECT    peer=%s  sockets=%d/%d  sessions=%d  from_ip=%d/%d",
             addr, socket_count(), MAX_CONNECTIONS, session_count(),
             ip_conns[ipk], MAX_CONNECTIONS_PER_IP)

    def is_authed():
        return len(client_ids) > 0

    def last_id():
        return client_ids[-1] if client_ids else None

    try:
        # Until it authenticates a socket gets a short leash: the library
        # itself refuses frames over FRAME_CAP_PREAUTH, and the connection is
        # closed unless auth COMPLETES within UNAUTH_DEADLINE_S.
        set_max_frame(ws, FRAME_CAP_PREAUTH)
        st.deadline = asyncio.get_running_loop().call_later(UNAUTH_DEADLINE_S, _unauth_deadline_expired, st)

        async for raw in ws:
            st.t_last = time.monotonic()

            # A socket that is being closed (strikes, eviction, deadline, slow
            # consumer, session cap) keeps its receive loop running but
            # discards everything: if nothing reads, the peer's unread data
            # holds the close handshake up until the transport is aborted.
            if st.closing:
                continue

            # The protocol is text frames only. A binary frame is never a
            # mistake a client makes by accident.
            if not isinstance(raw, str):
                stats["binary_rejected"] += 1
                warn_throttled("binary", "BINARY     frame rejected  peer=%s", addr)
                request_close(ws, CLOSE_CODE_BINARY, "text frames only")
                continue

            # ── packet-count limiters ──
            # First violation gets one error reply, later ones none (see
            # reply_once); every one is a strike, and a socket that keeps
            # going is closed rather than answered forever.
            if not st.limiter.allow():
                stats["rate_rejected"] += 1
                warn_throttled("ratelimit", "RATELIMIT  peer=%s  ids=%s", addr, client_ids)
                await reply_once(ws, "rate_limited", {"type": "error", "reason": "rate_limited"})
                strike(st, 1.0, CLOSE_CODE_BUSY, "rate")
                continue

            if not ip_limiter.allow():
                stats["rate_rejected"] += 1
                warn_throttled("ratelimit_ip", "RATELIMIT(ip)  peer=%s  ids=%s  sockets_from_ip=%d",
                               addr, client_ids, ip_conns.get(ipk, 0))
                await reply_once(ws, "rate_limited", {"type": "error", "reason": "rate_limited"})
                strike(st, STRIKE_WEIGHT_IP, CLOSE_CODE_BUSY, "rate(ip)")
                continue

            # ── size, BEFORE any parsing ──
            size = frame_size(raw)
            if not st.authed:
                over = size > FRAME_CAP_PREAUTH
            elif size > SMALL_FRAME_MAX:
                peeked = peek_type(raw)
                over = size > KIND_RULES.get(peeked, DEFAULT_RULE)[1]
            else:
                over = False   # parsed below, then held to its own type's cap
            if over:
                stats["frame_rejected"] += 1
                warn_throttled("oversize", "OVERSIZE   peer=%s  size=%d  authed=%s  dropped", addr, size, st.authed)
                strike(st, 1.0, CLOSE_CODE_POLICY, "oversize")
                continue

            # ── byte budgets ──
            if not st.bytes.allow(size):
                stats["byte_rejected"] += 1
                warn_throttled("bytes", "BYTELIMIT  peer=%s  ids=%s  size=%d", addr, client_ids, size)
                await reply_once(ws, "rate_limited", {"type": "error", "reason": "rate_limited"})
                strike(st, 1.0, CLOSE_CODE_BUSY, "bytes")
                continue
            if not ip_bytes.allow(size):
                stats["byte_rejected"] += 1
                warn_throttled("bytes_ip", "BYTELIMIT(ip)  peer=%s  ids=%s  size=%d", addr, client_ids, size)
                await reply_once(ws, "rate_limited", {"type": "error", "reason": "rate_limited"})
                strike(st, STRIKE_WEIGHT_IP, CLOSE_CODE_BUSY, "bytes(ip)")
                continue

            # ── parse: must be a JSON object with a string "type" ──
            try:
                msg = json.loads(raw)
            except (ValueError, RecursionError):
                msg = None
            if not isinstance(msg, dict) or not isinstance(msg.get("type"), str):
                stats["malformed"] += 1
                warn_throttled("malformed", "MALFORMED  peer=%s  size=%d  head=%r", addr, size, raw[:60])
                strike(st, 1.0, CLOSE_CODE_POLICY, "malformed")
                continue

            stats["bytes_in"] += size
            stats["msgs_in"]  += 1

            kind = msg["type"]
            cls, cap = KIND_RULES.get(kind, DEFAULT_RULE)
            if st.authed and size > cap:
                # exact per-type cap — the pre-parse check above only had a
                # peeked guess for frames over SMALL_FRAME_MAX
                stats["frame_rejected"] += 1
                warn_throttled("oversize", "OVERSIZE   peer=%s  type=%.48s  size=%d  cap=%d  dropped", addr, kind, size, cap)
                strike(st, 1.0, CLOSE_CODE_POLICY, "oversize")
                continue
            if not st.type_allow(cls):
                stats["type_rejected"] += 1
                warn_throttled("type_" + cls, "TYPELIMIT  peer=%s  ids=%s  class=%s  type=%.48s", addr, client_ids, cls, kind)
                strike(st, 1.0, CLOSE_CODE_BUSY, "type " + cls)
                continue

            # ── auth_init: client presents both public keys, server sends challenge ──
            if kind == "sig:auth_init":
                # Strict: with no valid RELAY_WSS_URL there is no host to bind
                # the proof to, and guessing one from the Host header would
                # hand that choice to the connecting party. Refuse, loudly.
                if not AUTH_HOSTS:
                    log.warning("AUTH       relay not configured (RELAY_WSS_URL unset/invalid) — refusing auth  peer=%s", addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "relay_not_configured"})
                    continue
                # Hard cutover, no dual-version path. An auth_v 1 (raw-nonce)
                # client gets a clear reason instead of a generic proof_invalid.
                if msg.get("auth_v") != AUTH_VERSION:
                    log.warning("AUTH       auth_v mismatch  got=%r  want=%d  peer=%s", msg.get("auth_v"), AUTH_VERSION, addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "auth_version"})
                    continue
                x25519_list  = msg.get("x25519_pub")
                ed25519_list = msg.get("ed25519_pub")
                bits         = 256
                # strictly a bool (or absent): it is inside the signed message as
                # one byte, so a loosely-coerced value could never match anyway —
                # reject it here with a useful reason instead of at proof time
                no_receive   = msg.get("no_receive", False)
                if not isinstance(no_receive, bool):
                    log.warning("AUTH       bad no_receive  peer=%s", addr)
                    await send_to(ws, {"type": "sig:auth_fail", "reason": "bad_init"})
                    continue
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
                # authed_as: a socket already authed as one identity may only
                # re-auth as that SAME identity — auth_verify refuses any
                # other one before registering anything (see its docstring).
                public_id = await auth_verify(ws, sig_back, addr,
                                              authed_as=client_ids[0] if client_ids else None)
                if public_id and not client_ids:
                    client_ids.append(public_id)
                # else: re-auth with the same identity — no-op (idempotent), useful for session refresh

            # ── everything below requires at least one authed identity ──
            elif not is_authed():
                frm = msg.get("from", "?")
                warn_throttled("unauthed", "UNAUTHED   type=%.48r  from=%s  peer=%s  dropped", kind, short(frm), addr)
                await reply_once(ws, "not_authenticated", {"type": "sig:auth_fail", "reason": "not_authenticated"})
                strike(st, 1.0, CLOSE_CODE_POLICY, "unauthenticated")

            # ── message / migrate: from must match an authed identity on this socket ──
            elif kind in ("app:message", "app:migrate", "app:burn", "session:propose", "session:ack"):
                frm = msg.get("from", "?")
                to_id, to_endpoint = parse_address(msg.get("to"))
                if to_id is None:
                    warn_throttled("bad_to", "  %s with invalid 'to', dropped  peer=%s", kind, addr)
                    continue
                # migrate/burn are never device-targeted by design — a
                # compound address here is either a bug or something
                # probing the boundary, dropped outright rather than
                # silently treated as the bare identity.
                if to_endpoint and kind in ("app:migrate", "app:burn"):
                    warn_throttled("bad_to_dev", "  %s with device-targeted 'to' — not allowed for this type, dropped  peer=%s", kind, addr)
                    continue
                # session:propose/session:ack are the inverse case — a
                # session is always device-to-device (X4DH.md §13.3), so
                # a BARE 'to' has no defined meaning here, unlike
                # app:message's broadcast-to-every-session fallback.
                if not to_endpoint and kind in ("session:propose", "session:ack"):
                    warn_throttled("bad_to_bare", "  %s without device-targeted 'to' — required for this type, dropped  peer=%s", kind, addr)
                    continue
                if frm not in client_ids:
                    warn_throttled("from_not_authed", "%-10s from=%s  not authed  peer=%s  dropped", kind.upper(), short(frm), addr)
                    await reply_once(ws, "not_authenticated", {"type": "error", "reason": "not_authenticated"})
                    continue
                await route_or_buffer(kind, frm, to_id, to_endpoint, msg, ws, raw=raw)

            # ── push subscribe/unsubscribe: from must match an authed
            #    identity on this socket, same rule as app:message et al.
            #    No mandatory signature — this doesn't redirect routing or
            #    drive an irreversible action the way app:migrate/app:burn
            #    do, it's "start/stop sending pushes to this endpoint",
            #    same trust tier as the sync:* group. ──
            elif kind == "sig:push_subscribe":
                frm         = msg.get("from", "?")
                endpoint_id = msg.get("endpointId")
                sub         = msg.get("subscription")
                if frm not in client_ids:
                    log.warning("PUSH_SUB   from=%s  not authed  peer=%s  dropped", short(frm), addr)
                    await reply_once(ws, "not_authenticated", {"type": "error", "reason": "not_authenticated"})
                    continue
                if not valid_id(endpoint_id):
                    log.warning("PUSH_SUB   from=%s  bad/missing endpointId, dropped", short(frm))
                    continue
                if not isinstance(sub, dict):
                    log.warning("PUSH_SUB   from=%s  bad subscription shape, dropped", short(frm))
                    continue
                endpoint = sub.get("endpoint")
                keys     = sub.get("keys") if isinstance(sub.get("keys"), dict) else {}
                # The endpoint is a URL the client chose and this relay will
                # later POST to: full policy check (https, port 443, plain DNS
                # name, on the allowlist — see parse_push_endpoint and the
                # "push endpoint policy" config above), repeated at send time.
                # Only the HOST is logged on a rejection: the path is the
                # device's push token.
                try:
                    parse_push_endpoint(endpoint)
                except PushEndpointRejected as e:
                    log.warning("PUSH_SUB   from=%s  endpoint rejected (%s)  host=%s, dropped", short(frm), e.reason, e.host or "?")
                    continue
                p256dh, auth_key = keys.get("p256dh"), keys.get("auth")
                if not (isinstance(p256dh, str) and isinstance(auth_key, str) and p256dh and auth_key):
                    log.warning("PUSH_SUB   from=%s  missing keys.p256dh/auth, dropped", short(frm))
                    continue
                if len(p256dh) > PUSH_MAX_KEY_LEN or len(auth_key) > PUSH_MAX_KEY_LEN:
                    log.warning("PUSH_SUB   from=%s  oversized keys.p256dh/auth, dropped", short(frm))
                    continue
                await _push_thread(_push_sub_write_sync, frm, endpoint_id, {
                    "endpoint": endpoint,
                    "p256dh":   p256dh,
                    "auth":     auth_key,
                })

            elif kind == "sig:push_unsubscribe":
                frm         = msg.get("from", "?")
                endpoint_id = msg.get("endpointId")
                if frm not in client_ids:
                    log.warning("PUSH_UNSUB from=%s  not authed  peer=%s  dropped", short(frm), addr)
                    await reply_once(ws, "not_authenticated", {"type": "error", "reason": "not_authenticated"})
                    continue
                if not valid_id(endpoint_id):
                    log.warning("PUSH_UNSUB from=%s  bad/missing endpointId, dropped", short(frm))
                    continue
                await _push_thread(_push_sub_delete_sync, frm, endpoint_id)

            elif kind == "sig:announce":
                ids = msg.get("ids", [])
                if not isinstance(ids, list):
                    warn_throttled("announce_bad", "  announce bad payload, dropped  peer=%s", addr)
                    continue
                # de-duplicated: the same id listed ten times must not mean
                # ten deliveries to it
                ids     = list(dict.fromkeys(i for i in ids[:10] if valid_id(i)))
                matched = [i for i in ids if i in connected]
                if matched:
                    seen_raw = wire({"type": "sig:seen", "id": last_id()})   # serialised once for every recipient
                    # Fan out in parallel — sequential awaits would serialize
                    # delivery across all matched recipients.
                    await asyncio.gather(
                        *(deliver(mid, seen_raw, exclude=ws) for mid in matched),
                        return_exceptions=True,
                    )

            elif kind in ("app:sync", "sync:backup_offer", "sync:backup_accept",
                          "sync:backup_push", "sync:restore_req",
                          "sync:restore_ack", "sync:restore_push",
                          "sync:token_req", "sync:token_resp",
                          "call:invite", "call:claim", "call:cancel", "call:end",
                          "call:offer", "call:answer", "call:ice",
                          "data:invite", "data:claim", "data:cancel", "data:end",
                          "data:offer", "data:answer", "data:ice"):
                frm = msg.get("from", "?")
                # `to` may carry a compound "id::endpointId" address — see
                # parse_address()'s comment near valid_id for the format.
                # This replaces the old separate `toEndpoint` field
                # entirely: one field to read instead of two. Live-only
                # here, same as everything else in this branch already is
                # — none of these types are durably buffered, so a
                # device-targeted `to` aimed at a currently-offline device
                # simply reaches nobody, exactly like an untargeted send to
                # an offline recipient already does today. call:*/data:*
                # never send a device-targeted address, so their behavior
                # is byte-for-byte unchanged; sync:backup_push/accept are
                # the first types to actually use it, for self-device-
                # targeted backup pushes and their acks.
                to_id, to_endpoint = parse_address(msg.get("to"))
                if to_id is None:
                    warn_throttled("bad_to", "  %s with invalid 'to', dropped  peer=%s", kind, addr)
                    continue
                # sync:backup_offer/accept/push and sync:restore_ack/push
                # (contact-path variants) are the deliberate exception
                # letting `from` itself carry a compound "id::endpointId"
                # address — see build_address/parse_address's own comments
                # and protocol.md's Compound Addressing section for the
                # general "from always stays bare" rule this departs from.
                # sync:restore_req is NOT in this set — its `from` stays
                # bare (decrypting it already requires an established
                # mutual contact, so there's no fresh-recipient case here
                # needing the address to carry anything extra). Every
                # other type in this branch is completely unaffected:
                # frm_id falls straight through to the original bare
                # string, so the client_ids membership check below is
                # byte-for-byte the same check it always was for
                # app:sync/restore_req/token_*/call:*/data:*. The message
                # is forwarded to the recipient exactly as received — this
                # only changes what the AUTH check itself is allowed to
                # match against.
                if kind in ("sync:backup_offer", "sync:backup_accept", "sync:backup_push",
                            "sync:restore_ack", "sync:restore_push"):
                    frm_id, _frm_endpoint = parse_address(frm)
                    if frm_id is None:
                        warn_throttled("bad_from", "  %s with invalid 'from', dropped  peer=%s", kind, addr)
                        continue
                else:
                    frm_id = frm
                if frm_id not in client_ids:
                    warn_throttled("from_not_authed", "%-10s from=%s  not authed  peer=%s  dropped", kind.upper(), short_addr(frm), addr)
                    await reply_once(ws, "not_authenticated", {"type": "error", "reason": "not_authenticated"})
                    continue
                if to_endpoint:
                    reached = await deliver_to_endpoint(to_id, to_endpoint, raw, exclude=ws)
                else:
                    reached = await deliver(to_id, raw, exclude=ws)
                log.info("%-16s from=%s  to=%s  reached=%d",
                         kind.upper()[:16], short_addr(frm), short_addr(msg.get("to")), reached)
                # sync:backup_push is deliberately NOT buffered — live delivery
                # only, same as every other sync:*/call:*/data:* type in this
                # branch. History: 0.5.0 buffered it on a missed live
                # delivery so offline siblings would catch up on mini
                # backups. That was the wrong tool:
                #   - contact-path pushes answer a live offer/accept
                #     handshake and (0.5.1) may be wrapped under an
                #     ephemeral the receiver holds ~60s in memory. A
                #     buffered copy flushed on a later reconnect can never
                #     be unwrapped ("wrap present but no pending ephemeral"),
                #     and an unwrapped stale one could overwrite a newer
                #     stored peer backup.
                #   - the sibling-catch-up job moved to the "selfsync"
                #     app:message path (client: sendSelfSync/handleSelfSync),
                #     which gets per-endpoint buffering as an ordinary
                #     app:message — see route_or_buffer.
                # Self-sync full backups are therefore online-only again; a
                # sibling that was offline catches up via the next backup
                # cycle plus whatever selfsync copies were buffered for it.

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
                warn_throttled("unknown", "UNKNOWN    type=%.48r  peer=%s  dropped", kind, addr)

    except websockets.exceptions.ConnectionClosedOK:
        log.info("CLOSE OK   peer=%s  ids=%s", addr, client_ids)
    except websockets.exceptions.ConnectionClosedError as e:
        # A frame over the library's own cap (lowered before auth, see
        # set_max_frame) closes the connection with 1009 before handler()
        # ever sees it — count it with the other oversize rejections.
        sent = getattr(e, "sent", None)
        if sent is not None and getattr(sent, "code", None) == CLOSE_CODE_TOO_BIG:
            stats["frame_rejected"] += 1
        warn_throttled("close_err", "CLOSE ERR  peer=%s  ids=%s  reason=%s", addr, client_ids, e)
    except Exception as e:
        emit, suppressed = _log_throttle.ok("handler_ex")
        if emit:
            log.error("HANDLER EX peer=%s  ids=%s  error=%s%s", addr, client_ids, e,
                      "  (+%d similar suppressed)" % suppressed if suppressed else "")
    finally:
        # no more unauthenticated deadline, and out of the all-sockets table
        if st.deadline is not None:
            st.deadline.cancel()
            st.deadline = None
        st.closing = True
        sock_state.pop(ws, None)
        # release per-IP slot — and the shared limiters along with it, once
        # this address has no sockets left (otherwise ip_limiters grows
        # forever under normal IP churn, one entry per address ever seen).
        if ipk in ip_conns:
            ip_conns[ipk] -= 1
            if ip_conns[ipk] <= 0:
                del ip_conns[ipk]
                ip_limiters.pop(ipk, None)
                ip_byte_limiters.pop(ipk, None)
        # clean up any pending challenge if socket dropped mid-auth
        pending_auth.pop(id(ws), None)
        # unregister every identity this socket is REGISTERED under. The
        # authority is ws_to_ids (what auth_verify actually put in
        # `connected`), not client_ids: client_ids is only appended to AFTER
        # auth_verify returns, so a socket that dropped mid-auth_verify (e.g.
        # while its buffer flush was awaiting) is registered but not yet in
        # client_ids — walking client_ids alone left it in `connected` until
        # some later send_to() happened to fail on it. client_ids is kept in
        # the union only as a belt-and-braces fallback. A no_receive probe is
        # in client_ids but was never registered, so it's correctly skipped
        # here rather than logging a bogus session drop.
        registered = ws_to_ids.pop(ws, set())
        for cid in registered:
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
    log.info("Buffer fair share: regular packets use at most %d of %d slots (%d reserved for migrate/burn); overflow evicts the heaviest sender's oldest",
             max(1, BUF_MAX_MSGS - max(0, BUF_RESERVED_SLOTS)), BUF_MAX_MSGS, max(0, BUF_RESERVED_SLOTS))
    log.info("Global auth admission: %.1f/s  burst=%.0f  known-identity lane: %.1f/s burst=%.0f  per-address: %.1f/s burst=%.0f",
             GLOBAL_AUTH_RATE, GLOBAL_AUTH_BURST, AUTH_KNOWN_RATE, AUTH_KNOWN_BURST, AUTH_RATE_IP, AUTH_BURST_IP)
    log.info("Rate limits: per-socket=%d/s burst=%d  per-ip=%d/s burst=%d",
              RATE_LIMIT_RATE, RATE_LIMIT_BURST, IP_RATE_LIMIT_RATE, IP_RATE_LIMIT_BURST)
    log.info("Sockets: max=%d (all open sockets)  per_ip=%d (key: IPv4 / IPv6 /%d)  unauth_per_ip=%d  unauth_deadline=%.0fs  idle_evict=%.0fs  max_sessions_per_identity=%d  send_timeout=%.0fs",
             MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, IPV6_KEY_PREFIX, MAX_UNAUTH_PER_IP, UNAUTH_DEADLINE_S,
             WS_IDLE_EVICT_S, MAX_SESSIONS_PER_IDENTITY, SEND_TIMEOUT_S)
    log.info("Frame caps (bytes): pre-auth=%d  tiny=%d  handshake=%d  signal=%d  bulk=%d  message=%d  (library max=%d)",
             FRAME_CAP_PREAUTH, FRAME_CAP_TINY, FRAME_CAP_HANDSHAKE, FRAME_CAP_SIGNAL, FRAME_CAP_BULK, FRAME_CAP_MESSAGE, WS_MAX_SIZE)
    log.info("Byte budgets: per-socket=%.0f B/s burst=%.0f  per-ip=%.0f B/s burst=%.0f",
             BYTE_RATE_SOCKET, BYTE_BURST_SOCKET, BYTE_RATE_IP, BYTE_BURST_IP)
    log.info("Type budgets (rate/s, burst): %s",
             "  ".join(f"{c}={r:g}/{b:g}" for c, (r, b) in TYPE_LIMITS.items()))
    log.info("Strikes: close after >%.0f (one forgiven per %.0fs)  log_throttle=%.0fs", STRIKE_LIMIT, STRIKE_DECAY_S, LOG_THROTTLE_S)
    log.info("Push: cooldown=%.0fs  max_concurrent=%d  max_queue=%d  max_identities=%d",
             PUSH_COOLDOWN_S, PUSH_MAX_CONCURRENT, PUSH_MAX_QUEUE, MAX_PUSH_IDENTITIES)
    log.info("Trusted proxies: %s", ", ".join(str(n) for n in TRUSTED_PROXIES) or "(none)")
    if AUTH_HOSTS:
        log.info("Auth: v%d  bound to host(s): %s", AUTH_VERSION, ", ".join(sorted(AUTH_HOSTS)))
    else:
        log.error("Auth: v%d  NOT CONFIGURED — RELAY_WSS_URL is unset or invalid, so EVERY client auth is refused "
                  "(relay_not_configured). Set RELAY_WSS_URL (e.g. wss://yourrelay.example.com/ws/).", AUTH_VERSION)
    log.info("Push: subs_dir=%s  vapid_key=%s  vapid_pub=%s…  ttl=%ds  subject=%s",
             PUSH_SUBS_DIR, VAPID_KEY_FILE, VAPID_PUBLIC_KEY_B64[:16], PUSH_TTL_SECONDS, VAPID_SUBJECT)
    log.info("Push policy: allowed hosts=%s  max_subs_per_identity=%d",
             ", ".join(sorted(PUSH_ALLOWED_EXACT) + list(PUSH_ALLOWED_SUFFIXES)) or "(none — every push endpoint is rejected)",
             PUSH_MAX_SUBS_PER_IDENTITY)
    log.info("=" * 50)
    # prime the in-memory directory counts off the loop (one scandir each)
    await asyncio.to_thread(buf_recipient_count.resync)
    await asyncio.to_thread(push_identity_count.resync)
    # known-identity registry: open / create / rebuild, off the loop (it can
    # scan the data directories). Never fails — worst case it runs in memory.
    await asyncio.to_thread(known_registry.open)
    n_prob = await asyncio.to_thread(probation_pool.load)
    log.info("State dir: %s  registry=%s  (%s)", STATE_DIR, known_registry.mode, known_registry.note)
    log.info("Registry: ttl=%.0fd  max_identities=%d  max_endpoints=%d  grace=%ds   Probation: pool=%d (now %d)  max_bytes=%d  "
             "unseen_devices_per_recipient=%d  new_slots=%.1f/s burst=%.0f per address",
             REGISTRY_TTL_S / 86400, REGISTRY_MAX_IDENTITIES, REGISTRY_MAX_ENDPOINTS, REGISTRY_GRACE_S,
             MAX_PROBATION_RECIPIENTS, n_prob, PROBATION_MAX_BYTES, PROBATION_ENDPOINTS_PER_RECIPIENT,
             PROBATION_IP_RATE, PROBATION_IP_BURST)
    async with websockets.serve(handler, WS_HOST, WS_PORT, max_size=WS_MAX_SIZE):
        asyncio.create_task(log_stats())
        asyncio.create_task(buf_expire())
        asyncio.create_task(sweep_pending_auth())
        asyncio.create_task(registry_flush_loop())
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
        known_registry.close()   # last write-behind flush
        PUSH_EXECUTOR.shutdown(wait=False, cancel_futures=True)
        http_proc.terminate()
        http_proc.join()