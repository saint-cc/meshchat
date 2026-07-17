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
    python3 agent.py
The shareable key is printed on boot — exchange it with the contact(s)
listed in CONTACTS below (out of band, same as any MeshChat address).
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import shlex
import subprocess
import sys
import time
import uuid

import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# ══════════════════════════════════════════
#   CONFIG — edit before running
# ══════════════════════════════════════════

USERNAME   = "agent-bot"                               # this agent's MeshChat username
PASSPHRASE = "change-this-passphrase"          # this agent's MeshChat passphrase
RELAY_WSS  = "wss://meshchat.somedomain.com/ws/"       # relay this agent connects to

# Who is allowed to send it commands. name -> shareable key
# ("encKey_b64url.signPubKey_b64url" or with a third ".relay_b64" segment —
# the relay segment is ignored here; see NOTE below).
CONTACTS = {
    "admin1": "",
}

ALLOWED_COMMANDS = {
    "ls",
    "cd",
    "pwd",
    "cat",

}   # PoC whitelist — nothing else is executed
MAX_OUTPUT_CHARS = 4000
COMMAND_TIMEOUT  = 10             # seconds, per command
RECONNECT_DELAY  = 5              # seconds, on disconnect
LOG_LEVEL        = logging.INFO

# NOTE — single-relay assumption: replies are sent back over this agent's
# own authenticated socket to RELAY_WSS (the same fallback path script.js
# calls sendSignal). If a contact lives on a different relay than this
# agent, delivery depends on them also being reachable there (live or via
# that relay's offline buffer) — there's no outbound cross-relay connection
# here the way script.js's sendToRelay/getOrOpenRelayConn does. Fine for a
# same-relay PoC; extend later if that stops being true.

# ══════════════════════════════════════════
#   LOGGING
# ══════════════════════════════════════════

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("agent")


def pid(s):
    return (s or "?")[:8] + "…"


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

    if cmd not in ALLOWED_COMMANDS:
        return f"command not allowed — whitelisted: {', '.join(sorted(ALLOWED_COMMANDS))}"

    cwd = os.path.abspath(cwd_holder["cwd"])

    # ──────────────────────────────────────
    # cd
    # ──────────────────────────────────────
    if cmd == "cd":
        target = parts[1] if len(parts) > 1 else os.path.expanduser("~")

        newpath = target if os.path.isabs(target) else os.path.join(cwd, target)
        newpath = os.path.abspath(os.path.normpath(newpath))

        if os.path.isdir(newpath):
            cwd_holder["cwd"] = newpath
            return newpath

        return f"cd: no such directory: {target}"

    # ──────────────────────────────────────
    # pwd
    # ──────────────────────────────────────
    if cmd == "pwd":
        return cwd

    # ──────────────────────────────────────
    # cat
    # ──────────────────────────────────────
    if cmd == "cat":
        if len(parts) < 2:
            return "cat: missing filename"

        filename = os.path.abspath(
            os.path.join(cwd, parts[1])
        )

        # prevent escaping current directory
        if not filename.startswith(cwd + os.sep):
            return "cat: access denied"

        try:
            with open(filename, "r", errors="replace") as f:
                out = f.read()

        except FileNotFoundError:
            return f"cat: file not found: {parts[1]}"

        except IsADirectoryError:
            return f"cat: {parts[1]} is a directory"

        except Exception as e:
            return f"cat: {e}"

        return out

    # ──────────────────────────────────────
    # ls
    # ──────────────────────────────────────
    if cmd == "ls":
        try:
            proc = subprocess.run(
                ["ls"] + parts[1:],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )

            out = proc.stdout
            if proc.stderr:
                out += "\n" + proc.stderr

        except subprocess.TimeoutExpired:
            out = "error: command timed out"

        except Exception as e:
            out = f"error: {e}"

        out = out.strip() or "(no output)"
        return out

    return "command implemented but no handler found"


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
    await asyncio.sleep(0.3)
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
            log.warning("CONTACT    '%s' still has a placeholder key — edit CONTACTS in the config", name)
            continue
        c = parse_contact(name, key)
        contacts_by_id[c["public_id"]] = c
        log.info("CONTACT    %-12s → %s", name, pid(c["public_id"]))

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
                    if msg.get("type") == "app:message":
                        await handle_message(ws, identity, contacts_by_id, cwd_holder, msg)
                    elif msg.get("type") == "sig:auth_fail":
                        log.warning("relay rejected traffic: %s", msg.get("reason"))
                    # calls / sync / migrate etc. — not implemented, ignored silently
        except (websockets.exceptions.ConnectionClosed, OSError) as e:
            log.warning("WS         disconnected (%s) — retrying in %ds", e, RECONNECT_DELAY)
        except Exception as e:
            log.error("error: %s — retrying in %ds", e, RECONNECT_DELAY)
        await asyncio.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nshutting down")
        sys.exit(0)