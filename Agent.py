#!/usr/bin/env python3
"""
agent.py — MeshChat command agent (PoC)

A headless MeshChat identity that lives on a box, takes whitelisted shell
commands (ls / cd) from trusted contacts, and replies with the output —
same protocol, same crypto as script.js. Add its shareable key to your
real MeshChat client like any other contact.

Crypto is a line-for-line mirror of script.js:
  masterSecret = PBKDF2(passphrase, salt=SHA256("meshchat-v1:"+username), 100000, SHA-256, 32B)
  encKey / signSeed = HKDF-SHA256(master, salt=32 zero bytes, info="meshchat-v1:<label>", 32B)
  publicId = base64url( SHA256(encKey)[0:12] )
  message envelope: AES-256-GCM keyed on the RECIPIENT's encKey, Ed25519-signed
  own incoming messages are decrypted with OUR OWN encKey (symmetric-by-address design)

Auth handshake with the relay is identical to server.py's challenge-response.

Requirements:
    pip install websockets cryptography

Run:
    ./startagent.sh
    (sets the AGENT_* env vars below, then runs this file — see that
    script for the config format. Running `python3 agent.py` directly
    without those env vars set falls back to the placeholder defaults.)

The shareable key is printed on boot — exchange it with the contact(s)
listed in CONTACTS below (out of band, same as any MeshChat address).
"""

import asyncio
import base64
import fcntl
import hashlib
import json
import logging
import os
import pty
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid

import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# aiortc is only needed for the shell-escalation feature (see SHELL CONFIG
# below) — the bounded command whitelist works fine without it. Kept
# optional so this file still runs on a box where aiortc doesn't install
# cleanly (it pulls in native deps like libavcodec/libopus).
try:
    from aiortc import (
        RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription,
    )
    from aiortc.sdp import candidate_from_sdp
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False

# ══════════════════════════════════════════
#   LOGGING
#   Moved ahead of CONFIG (below) so env-var parsing can log warnings
#   on malformed AGENT_CONTACTS/AGENT_SHELL_CONTACTS entries instead of
#   silently dropping them or needing a bare print().
# ══════════════════════════════════════════

LOG_LEVEL = logging.INFO
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("agent")


def pid(s):
    return (s or "?")[:8] + "…"


# ══════════════════════════════════════════
#   CONFIG — loaded from AGENT_* environment variables, set by
#   startagent.sh. Falls back to the placeholder values below if a
#   given env var isn't set, so `python3 agent.py` run bare still boots
#   (and still warns about the placeholder key, same as before).
#
#   AGENT_CONTACTS format:      name=shareable_key,name2=shareable_key2
#   AGENT_SHELL_CONTACTS format: name,name2   (subset of the names above)
#   Shareable keys are base64url segments joined by '.' — they never
#   contain '=' or ',' themselves, so splitting on those characters is
#   unambiguous and needs no escaping/quoting.
# ══════════════════════════════════════════

def _parse_contacts(raw: str) -> dict:
    contacts = {}
    if not raw:
        return contacts
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            log.warning("CONFIG     AGENT_CONTACTS entry missing '=': %r — skipped", entry)
            continue
        name, key = entry.split("=", 1)
        name, key = name.strip(), key.strip()
        if not name or not key:
            log.warning("CONFIG     AGENT_CONTACTS entry has empty name/key: %r — skipped", entry)
            continue
        contacts[name] = key
    return contacts


def _parse_shell_contacts(raw: str) -> set:
    if not raw:
        return set()
    return {n.strip() for n in raw.split(",") if n.strip()}


USERNAME   = os.environ.get("AGENT_USERNAME", "agent-bot")                          # this agent's MeshChat username
PASSPHRASE = os.environ.get("AGENT_PASSPHRASE", "change-this-passphrase")           # this agent's MeshChat passphrase
RELAY_WSS  = os.environ.get("AGENT_RELAY_WSS", "wss://yourrelay.example.com/ws/")   # relay this agent connects to

# Who is allowed to send it commands. name -> shareable key
# ("encKey_b64url.signPubKey_b64url" or with a third ".relay_b64" segment —
# the relay segment is ignored here; see NOTE below).
CONTACTS = _parse_contacts(os.environ.get("AGENT_CONTACTS", "")) or {
    "admin": "PASTE_SHAREABLE_KEY_HERE",
}

# Whitelist — nothing outside this dict is executed. Each entry:
#   needs_arg     — must have at least one non-flag argument (blocks cat/head/
#                   tail/file from being invoked bare, which would otherwise
#                   sit reading stdin forever since nothing is piped to it)
#   no_args       — informational commands; any args the caller sent are
#                   dropped rather than passed through
#   blocked_flags — exact-match flags that would make the command not
#                   terminate on its own (tail -f and friends). This is a
#                   simple exact-token check, not a real arg parser — it
#                   won't catch a combined short flag like "-nf". Good
#                   enough for a whitelist of contacts you already trust;
#                   tighten if that assumption stops holding.
COMMAND_SPECS = {
    "ls":       {},
    "cd":       {},
    "pwd":      {"no_args": True},
    "cat":      {"needs_arg": True},
    "head":     {"needs_arg": True},
    "tail":     {"needs_arg": True, "blocked_flags": {"-f", "-F", "--follow", "--retry"}},
    "file":     {"needs_arg": True},
    "df":       {},
    "du":       {},
    "whoami":   {"no_args": True},
    "hostname": {"no_args": True},
    "uptime":   {"no_args": True},
}
MAX_OUTPUT_CHARS = 4000
COMMAND_TIMEOUT  = 10             # seconds, per command — also the cap on a
                                   # blocked-flag command's non-terminating
                                   # cousin slipping through some other way;
                                   # see the TimeoutExpired handling below
RECONNECT_DELAY  = 5              # seconds, on disconnect

# NOTE — single-relay assumption: replies are sent back over this agent's
# own authenticated socket to RELAY_WSS (the same fallback path script.js
# calls sendSignal). If a contact lives on a different relay than this
# agent, delivery depends on them also being reachable there (live or via
# that relay's offline buffer) — there's no outbound cross-relay connection
# here the way script.js's sendToRelay/getOrOpenRelayConn does. Fine for a
# same-relay PoC; extend later if that stops being true.

# ══════════════════════════════════════════
#   SHELL ESCALATION (WebRTC)
#   ---------------------------------------
#   Two data channels, opened by the human side (the offerer):
#     "shell-data" — raw pty bytes, ordered+reliable
#     "shell-ctrl" — JSON control messages, currently just
#                    {"type":"resize","cols":N,"rows":N}
#   No TURN — same permanent decision as audio calls. If ICE fails, there
#   is no escalation, full stop; the bounded command whitelist above is
#   the fallback and needs no WebRTC to work.
#
#   Trust tiers are DELIBERATELY separate: being in CONTACTS (bounded
#   command access) does NOT imply shell access. Only names also listed
#   in SHELL_CONTACTS can ever get a full pty.
# ══════════════════════════════════════════

# subset of CONTACTS names allowed to request a full shell — empty = disabled
SHELL_CONTACTS       = _parse_shell_contacts(os.environ.get("AGENT_SHELL_CONTACTS", ""))
SHELL_IDLE_TIMEOUT_S = 300       # ssh-style — no bytes either direction for this long, session dies
SHELL_IDLE_CHECK_S   = 5         # how often the watchdog checks

RTC_ICE_SERVERS = [
    RTCIceServer(urls="stun:stun.l.google.com:19302"),
    RTCIceServer(urls="stun:stun1.l.google.com:19302"),
    RTCIceServer(urls="stun:global.stun.twilio.com:3478"),
] if AIORTC_AVAILABLE else []

# contact public_id -> ShellSession — one active session per contact, enforced
# in handle_shell_invite. A second invite while one is already live is ignored,
# same rule as contact.call in script.js's state machine.
SHELL_SESSIONS = {}

# ══════════════════════════════════════════
#   CRYPTO — mirrors script.js exactly
# ══════════════════════════════════════════

def derive_master_secret(username: str, passphrase: str) -> bytes:
    salt = hashlib.sha256(("meshchat-v1:" + username.lower().strip()).encode()).digest()
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(passphrase.encode())


def hkdf_expand(master: bytes, label: str) -> bytes:
    return HKDF(
        algorithm=SHA256(), length=32, salt=b"\x00" * 32,
        info=("meshchat-v1:" + label).encode(),
    ).derive(master)


def derive_public_id(raw_key: bytes) -> str:
    digest = hashlib.sha256(raw_key).digest()[:12]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def raw_to_b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_to_raw(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def encrypt_message(recipient_aesgcm: AESGCM, payload: dict) -> dict:
    iv = os.urandom(12)
    pt = json.dumps(payload, separators=(",", ":")).encode()
    ct = recipient_aesgcm.encrypt(iv, pt, None)
    return {"v": 1, "iv": list(iv), "data": list(ct)}


def decrypt_message(own_aesgcm: AESGCM, blob: dict) -> dict:
    if blob.get("v", 1) > 1:
        raise ValueError(f"unsupported message version v{blob.get('v')}")
    iv, data = bytes(blob["iv"]), bytes(blob["data"])
    pt = own_aesgcm.decrypt(iv, data, None)
    return json.loads(pt.decode())


def sign_blob(sign_key: Ed25519PrivateKey, blob: dict) -> list:
    raw = json.dumps(blob, separators=(",", ":")).encode()
    return list(sign_key.sign(raw))


def verify_blob(blob: dict, sig: list, pubkey: Ed25519PublicKey) -> bool:
    try:
        raw = json.dumps(blob, separators=(",", ":")).encode()
        pubkey.verify(bytes(sig), raw)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════
#   IDENTITY
# ══════════════════════════════════════════

class Identity:
    def __init__(self, username, passphrase, relay_wss):
        master = derive_master_secret(username, passphrase)
        self.enc_key_bytes = hkdf_expand(master, "encryption")
        self.sign_seed     = hkdf_expand(master, "signing")
        self.sign_key      = Ed25519PrivateKey.from_private_bytes(self.sign_seed)

        sign_pub_bytes = self.sign_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        self.aesgcm        = AESGCM(self.enc_key_bytes)
        self.public_id     = derive_public_id(self.enc_key_bytes)
        self.shareable_key = (
            raw_to_b64url(self.enc_key_bytes) + "." +
            raw_to_b64url(sign_pub_bytes) + "." +
            base64.b64encode(relay_wss.encode()).decode()
        )


def parse_contact(name: str, shareable_key: str) -> dict:
    parts = shareable_key.split(".")
    if len(parts) < 2:
        raise ValueError(f"contact '{name}' has an invalid shareable key")
    enc_key_bytes  = b64url_to_raw(parts[0])
    sign_pub_bytes = b64url_to_raw(parts[1])
    return {
        "name":      name,
        "public_id": derive_public_id(enc_key_bytes),
        "aesgcm":    AESGCM(enc_key_bytes),      # used to encrypt OUR replies to them
        "sign_pub":  Ed25519PublicKey.from_public_bytes(sign_pub_bytes),
    }


# ══════════════════════════════════════════
#   COMMAND EXECUTION — ls / cd only
# ══════════════════════════════════════════

def run_command(text: str, cwd_holder: dict) -> str:
    try:
        parts = shlex.split(text)
    except ValueError as e:
        return f"error parsing command: {e}"
    if not parts:
        return "(empty command)"

    cmd = parts[0]
    if cmd not in COMMAND_SPECS:
        return f"command not allowed — whitelisted: {', '.join(sorted(COMMAND_SPECS))}"

    spec = COMMAND_SPECS[cmd]
    args = parts[1:]

    if spec.get("no_args"):
        args = []   # informational commands — drop whatever was passed rather than error

    blocked = spec.get("blocked_flags")
    if blocked:
        hit = blocked.intersection(args)
        if hit:
            return f"{cmd}: not allowed here — blocked flag(s): {', '.join(sorted(hit))} (would never terminate)"

    if spec.get("needs_arg") and not any(not a.startswith("-") for a in args):
        return f"{cmd}: requires at least one argument (a bare invocation would block reading stdin)"

    cwd = cwd_holder["cwd"]

    if cmd == "cd":
        target  = args[0] if args else os.path.expanduser("~")
        newpath = target if os.path.isabs(target) else os.path.join(cwd, target)
        newpath = os.path.normpath(newpath)
        if os.path.isdir(newpath):
            cwd_holder["cwd"] = newpath
            return newpath
        return f"cd: no such directory: {target}"

    # argv list, never shell=True — nothing in args can break out into shell
    # syntax, it's all literal arguments passed straight to the binary.
    # stdin is always /dev/null: with no pipe attached, a command that would
    # otherwise wait on stdin (e.g. a bare "cat") would hang until the
    # COMMAND_TIMEOUT kill instead of erroring immediately.
    timed_out = False
    try:
        proc = subprocess.run(
            [cmd] + args, cwd=cwd, capture_output=True, text=True,
            timeout=COMMAND_TIMEOUT, stdin=subprocess.DEVNULL,
        )
        out = proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
    except subprocess.TimeoutExpired as e:
        # Python still hands back whatever stdout/stderr had been read
        # before the kill — treat it as a snapshot rather than a failure.
        # This is what lets something like a slow `du` on a huge tree come
        # back with partial results instead of nothing.
        timed_out = True
        out = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
    except Exception as e:
        out = f"error: {e}"

    out = out.strip() or "(no output)"
    if len(out) > MAX_OUTPUT_CHARS:
        out = out[:MAX_OUTPUT_CHARS] + f"\n… truncated ({len(out)} chars total)"
    if timed_out:
        out += f"\n… [killed after {COMMAND_TIMEOUT}s — showing partial output]"
    return out


# ══════════════════════════════════════════
#   PTY PLUMBING — no aiortc dependency, testable standalone
#   (spawn a shell, read/write it, resize it)
# ══════════════════════════════════════════

def _set_winsize(fd: int, rows: int, cols: int):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def spawn_pty_shell(cols: int = 80, rows: int = 24):
    """Fork a pty-attached interactive shell. Returns (pid, master_fd) to
    the parent; never returns in the child (execs or exits)."""
    pid_, master_fd = pty.fork()
    if pid_ == 0:
        shell = os.environ.get("SHELL", "/bin/bash")
        os.execvp(shell, [shell, "-i"])
        os._exit(1)  # unreachable unless execvp itself fails
    _set_winsize(master_fd, rows, cols)
    return pid_, master_fd


class ShellSession:
    """One escalated shell for one contact.

    Lifecycle: created when an eligible shell:invite is accepted, torn
    down on shell:end/cancel, ICE failure, the pty's own process exiting,
    or SHELL_IDLE_TIMEOUT_S of silence in both directions (ssh-style —
    idle means no bytes crossing the data channel either way, not "tab
    not focused").

    aiortc's DataChannel API mirrors the browser's (on("message"),
    on("open"), .send()), so the channel-facing half of this class reads
    the same as script.js's RTC code once that side exists.
    """

    def __init__(self, contact: dict, session_id: str, loop: asyncio.AbstractEventLoop):
        self.contact       = contact
        self.session_id    = session_id
        self.loop          = loop
        self.pc            = None
        self.data_ch       = None   # raw pty bytes
        self.ctrl_ch       = None   # JSON control messages (resize, ...)
        self.master_fd     = None
        self.pid           = None
        self.last_activity = time.monotonic()
        self._idle_task    = None
        self._closed       = False

    def touch(self):
        self.last_activity = time.monotonic()

    async def start_pty(self, cols: int = 80, rows: int = 24):
        if self.master_fd is not None:
            return   # already started — data channel reopen/duplicate open event
        self.pid, self.master_fd = spawn_pty_shell(cols, rows)
        os.set_blocking(self.master_fd, False)
        self.loop.add_reader(self.master_fd, self._on_pty_readable)
        self._idle_task = self.loop.create_task(self._idle_watchdog())
        log.info("SHELL      pty started  contact=%s  pid=%d  session=%s",
                  self.contact["name"], self.pid, pid(self.session_id))

    def _on_pty_readable(self):
        try:
            data = os.read(self.master_fd, 4096)
        except BlockingIOError:
            return
        except OSError:
            data = b""   # pty closed out from under us — treat like EOF below
        if not data:
            self.loop.create_task(self.close("pty exited"))
            return
        self.touch()
        if self.data_ch is not None and getattr(self.data_ch, "readyState", None) == "open":
            self.data_ch.send(data)

    def write_input(self, data: bytes):
        if self.master_fd is None:
            return
        self.touch()
        try:
            os.write(self.master_fd, data)
        except OSError as e:
            log.warning("SHELL      write failed  contact=%s  err=%s", self.contact["name"], e)

    def resize(self, cols: int, rows: int):
        if self.master_fd is None or self.pid is None:
            return
        try:
            _set_winsize(self.master_fd, rows, cols)
            os.kill(self.pid, signal.SIGWINCH)
        except (OSError, ProcessLookupError):
            pass

    async def _idle_watchdog(self):
        try:
            while not self._closed:
                await asyncio.sleep(SHELL_IDLE_CHECK_S)
                if time.monotonic() - self.last_activity > SHELL_IDLE_TIMEOUT_S:
                    log.info("SHELL      idle timeout (%ds)  contact=%s",
                              SHELL_IDLE_TIMEOUT_S, self.contact["name"])
                    await self.close("idle timeout")
                    return
        except asyncio.CancelledError:
            pass

    async def close(self, reason: str = ""):
        if self._closed:
            return
        self._closed = True
        log.info("SHELL      closing  contact=%s  reason=%s", self.contact["name"], reason)

        if self._idle_task:
            self._idle_task.cancel()
        if self.master_fd is not None:
            try:
                self.loop.remove_reader(self.master_fd)
            except (ValueError, OSError):
                pass
            try:
                os.close(self.master_fd)
            except OSError:
                pass
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
        for ch in (self.data_ch, self.ctrl_ch):
            if ch is not None:
                try:
                    ch.close()
                except Exception:
                    pass
        if self.pc is not None:
            try:
                await self.pc.close()
            except Exception:
                pass
        SHELL_SESSIONS.pop(self.contact["public_id"], None)


# ══════════════════════════════════════════
#   SHELL SIGNALING — signed packets, mirrors signCallPacket/verifyCallPacket
# ══════════════════════════════════════════

def sign_shell_packet(identity: "Identity", obj: dict) -> list:
    payload = {
        "type": obj["type"], "from": obj["from"], "to": obj["to"],
        "sessionId": obj["sessionId"], "deviceId": obj.get("deviceId"),
        "ts": obj["ts"], "blob": obj.get("blob"),
    }
    return sign_blob(identity.sign_key, payload)


def verify_shell_packet(obj: dict, pubkey: Ed25519PublicKey) -> bool:
    if not obj.get("sig"):
        return False
    payload = {
        "type": obj["type"], "from": obj["from"], "to": obj["to"],
        "sessionId": obj["sessionId"], "deviceId": obj.get("deviceId"),
        "ts": obj["ts"], "blob": obj.get("blob"),
    }
    return verify_blob(payload, obj["sig"], pubkey)


async def handle_shell_invite(ws, identity: "Identity", contacts_by_id: dict, msg: dict):
    """Agent is always the callee here — only the human client escalates.
    Auto-accepts (no human on this end to click answer) iff the sender is
    both a known contact AND explicitly in SHELL_CONTACTS. Being whitelisted
    for bounded commands does NOT imply shell eligibility."""
    if not AIORTC_AVAILABLE:
        log.warning("SHELL      invite received but aiortc isn't installed — ignoring")
        return
    frm = msg.get("from")
    contact = contacts_by_id.get(frm)
    if not contact or contact["name"] not in SHELL_CONTACTS:
        log.warning("SHELL      invite from %s — not shell-eligible, ignored", pid(frm))
        return
    if not verify_shell_packet(msg, contact["sign_pub"]):
        log.warning("SHELL      invite from %s — bad signature, dropped", contact["name"])
        return
    if contact["public_id"] in SHELL_SESSIONS:
        log.info("SHELL      invite from %s — session already active, ignored (one per contact)", contact["name"])
        return

    session_id = msg["sessionId"]
    session = ShellSession(contact, session_id, asyncio.get_event_loop())
    SHELL_SESSIONS[contact["public_id"]] = session

    claim = {"type": "shell:claim", "from": identity.public_id, "to": frm,
             "sessionId": session_id, "ts": int(time.time() * 1000)}
    claim["sig"] = sign_shell_packet(identity, claim)
    await ws.send(json.dumps(claim))
    log.info("SHELL      invite accepted  contact=%s  session=%s", contact["name"], pid(session_id))
    # human side sends shell:offer next — see handle_shell_offer


async def handle_shell_offer(ws, identity: "Identity", contacts_by_id: dict, msg: dict):
    if not AIORTC_AVAILABLE:
        return
    frm = msg.get("from")
    contact = contacts_by_id.get(frm)
    session = SHELL_SESSIONS.get(contact["public_id"]) if contact else None
    if not contact or not session or session.session_id != msg.get("sessionId"):
        log.warning("SHELL      offer from %s — no matching session, dropped", pid(frm))
        return
    if not verify_shell_packet(msg, contact["sign_pub"]):
        log.warning("SHELL      offer from %s — bad signature, dropped", contact["name"])
        return

    try:
        plain = decrypt_message(identity.aesgcm, msg["blob"])
    except Exception as e:
        log.warning("SHELL      offer from %s — decrypt failed: %s", contact["name"], e)
        return

    pc = RTCPeerConnection(configuration=RTCConfiguration(iceServers=RTC_ICE_SERVERS))
    session.pc = pc

    @pc.on("datachannel")
    def on_datachannel(channel):
        if channel.label == "shell-data":
            session.data_ch = channel

            @channel.on("message")
            def on_data_message(data):
                session.write_input(data.encode() if isinstance(data, str) else data)

            @channel.on("open")
            def on_data_open():
                asyncio.ensure_future(session.start_pty())

            # RACE FIX — aiortc can deliver the datachannel event after the
            # channel has already transitioned to "open" (this happens
            # whenever the remote description is applied late enough that
            # the DCEP open handshake completes before Python gets around
            # to registering the "open" listener above). In that case the
            # "open" event has already fired with nobody listening, and
            # start_pty() would otherwise never run — pty never spawns,
            # nothing is ever written to the channel, and the client sees
            # a connected data channel with a permanently blank terminal.
            # start_pty() is idempotent (guards on self.master_fd), so
            # calling it here is always safe even if "open" also fires
            # normally right after this runs.
            if channel.readyState == "open":
                asyncio.ensure_future(session.start_pty())

        elif channel.label == "shell-ctrl":
            session.ctrl_ch = channel

            @channel.on("message")
            def on_ctrl_message(data):
                try:
                    ctrl = json.loads(data)
                    if ctrl.get("type") == "resize":
                        session.resize(int(ctrl.get("cols", 80)), int(ctrl.get("rows", 24)))
                except Exception:
                    pass

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        if pc.iceConnectionState in ("failed", "closed"):
            await session.close(f"ice {pc.iceConnectionState}")

    await pc.setRemoteDescription(RTCSessionDescription(sdp=plain["sdp"], type="offer"))
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    blob = encrypt_message(contact["aesgcm"], {"sdp": pc.localDescription.sdp})
    obj = {"type": "shell:answer", "from": identity.public_id, "to": frm,
           "sessionId": session.session_id, "ts": int(time.time() * 1000), "blob": blob}
    obj["sig"] = sign_shell_packet(identity, obj)
    await ws.send(json.dumps(obj))
    log.info("SHELL      answer sent  contact=%s", contact["name"])


async def handle_shell_ice(identity: "Identity", contacts_by_id: dict, msg: dict):
    if not AIORTC_AVAILABLE:
        return
    frm = msg.get("from")
    contact = contacts_by_id.get(frm)
    session = SHELL_SESSIONS.get(contact["public_id"]) if contact else None
    if not contact or not session or session.session_id != msg.get("sessionId") or session.pc is None:
        return
    if not verify_shell_packet(msg, contact["sign_pub"]):
        return
    try:
        plain = decrypt_message(identity.aesgcm, msg["blob"])
        if not plain.get("candidate"):
            return
        cand = candidate_from_sdp(plain["candidate"].split(":", 1)[1])
        cand.sdpMid        = plain.get("sdpMid")
        cand.sdpMLineIndex = plain.get("sdpMLineIndex")
        await session.pc.addIceCandidate(cand)
    except Exception as e:
        log.debug("SHELL      ice candidate error  contact=%s  err=%s", contact["name"], e)


async def handle_shell_end(contacts_by_id: dict, msg: dict):
    frm = msg.get("from")
    contact = contacts_by_id.get(frm)
    session = SHELL_SESSIONS.get(contact["public_id"]) if contact else None
    if session and session.session_id == msg.get("sessionId"):
        await session.close("shell:end/cancel received")


# ══════════════════════════════════════════
#   PROTOCOL — auth handshake + message loop
# ══════════════════════════════════════════

async def do_auth(ws, identity: Identity):
    await ws.send(json.dumps({"type": "sig:auth_init", "enc_key": list(identity.enc_key_bytes)}))
    while True:
        msg = json.loads(await ws.recv())
        kind = msg.get("type")
        if kind == "sig:auth_challenge":
            iv, data = bytes(msg["iv"]), bytes(msg["data"])
            nonce = identity.aesgcm.decrypt(iv, data, None)
            await ws.send(json.dumps({"type": "sig:auth_proof", "nonce": list(nonce)}))
        elif kind == "sig:auth_ok":
            log.info("AUTH OK    id=%s", pid(msg.get("public_id")))
            return
        elif kind == "sig:auth_fail":
            raise RuntimeError(f"auth failed: {msg.get('reason')}")
        # anything else during handshake is ignored


async def send_reply(ws, identity: Identity, contact: dict, text: str):
    await asyncio.sleep(0.5)
    payload = {"id": str(uuid.uuid4()), "type": "text", "text": text, "ts": int(time.time() * 1000)}
    blob    = encrypt_message(contact["aesgcm"], payload)
    sig     = sign_blob(identity.sign_key, blob)
    obj = {
        "type": "app:message", "from": identity.public_id, "to": contact["public_id"],
        "blob": blob, "sig": sig,
    }
    await ws.send(json.dumps(obj))
    log.info("→ REPLY    to=%s  (%d chars)", contact["name"], len(text))


async def handle_message(ws, identity: Identity, contacts_by_id: dict, cwd_holder: dict, msg: dict):
    frm, blob, sig = msg.get("from"), msg.get("blob"), msg.get("sig")
    if not frm or not blob or msg.get("to") != identity.public_id:
        return

    contact = contacts_by_id.get(frm)
    if not contact:
        log.debug("MSG        from unknown id=%s — ignored", pid(frm))
        return

    try:
        plain = decrypt_message(identity.aesgcm, blob)
    except Exception as e:
        log.warning("MSG        from %s — decrypt failed: %s", contact["name"], e)
        return

    if not (sig and verify_blob(blob, sig, contact["sign_pub"])):
        log.warning("MSG        from %s — invalid/missing signature, ignored", contact["name"])
        return

    if plain.get("type") not in (None, "text"):
        log.debug("MSG        from %s — non-text payload (%s), ignored", contact["name"], plain.get("type"))
        return

    text = (plain.get("text") or "").strip()
    log.info("← CMD      from=%s  \"%s\"", contact["name"], text)
    output = run_command(text, cwd_holder)
    await send_reply(ws, identity, contact, output)


async def run():
    identity = Identity(USERNAME, PASSPHRASE, RELAY_WSS)

    print("=" * 60)
    print(f" MeshChat Agent — {USERNAME}")
    print(f" publicId  : {identity.public_id}")
    print(f" shareable : {identity.shareable_key}")
    print("=" * 60)

    contacts_by_id = {}
    for name, key in CONTACTS.items():
        if key == "PASTE_SHAREABLE_KEY_HERE":
            log.warning("CONTACT    '%s' still has a placeholder key — set AGENT_CONTACTS (see startagent.sh)", name)
            continue
        c = parse_contact(name, key)
        contacts_by_id[c["public_id"]] = c
        log.info("CONTACT    %-12s → %s", name, pid(c["public_id"]))

    if SHELL_CONTACTS:
        unknown = SHELL_CONTACTS - set(CONTACTS)
        if unknown:
            log.warning("SHELL      AGENT_SHELL_CONTACTS references unknown name(s): %s", ", ".join(sorted(unknown)))
        if not AIORTC_AVAILABLE:
            log.warning("SHELL      AGENT_SHELL_CONTACTS is set but aiortc isn't installed — shell escalation disabled")
        else:
            log.info("SHELL      escalation enabled for: %s", ", ".join(sorted(SHELL_CONTACTS)))

    cwd_holder = {"cwd": os.path.expanduser("~")}

    while True:
        try:
            async with websockets.connect(RELAY_WSS) as ws:
                log.info("WS         connected  %s", RELAY_WSS)
                await do_auth(ws, identity)
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    kind = msg.get("type")
                    if kind == "app:message":
                        await handle_message(ws, identity, contacts_by_id, cwd_holder, msg)
                    elif kind == "sig:auth_fail":
                        log.warning("relay rejected traffic: %s", msg.get("reason"))
                    elif kind == "shell:invite":
                        await handle_shell_invite(ws, identity, contacts_by_id, msg)
                    elif kind == "shell:offer":
                        await handle_shell_offer(ws, identity, contacts_by_id, msg)
                    elif kind == "shell:ice":
                        await handle_shell_ice(identity, contacts_by_id, msg)
                    elif kind in ("shell:end", "shell:cancel"):
                        await handle_shell_end(contacts_by_id, msg)
                    # calls / sync / migrate etc. — not implemented, ignored silently
        except (websockets.exceptions.ConnectionClosed, OSError) as e:
            log.warning("WS         disconnected (%s) — retrying in %ds", e, RECONNECT_DELAY)
        except Exception as e:
            log.error("error: %s — retrying in %ds", e, RECONNECT_DELAY)
        await asyncio.sleep(RECONNECT_DELAY)


async def _shutdown():
    for session in list(SHELL_SESSIONS.values()):
        await session.close("agent shutting down")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nshutting down")
        if SHELL_SESSIONS:
            asyncio.run(_shutdown())
        sys.exit(0)