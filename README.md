# MeshChat

Decentralised, end-to-end encrypted messaging built around cryptographic identities rather than accounts.

No registration. No central identity provider. No plaintext.

Messages are encrypted in the browser before they leave your device. Relay servers transport and 
temporarily buffer ciphertext, but never possess your private keys or message contents.

---

## How it works

Your identity is derived locally from your username and passphrase using PBKDF2 + HKDF. The same 
credentials always produce the same cryptographic identity.

There are no accounts to create and no passwords stored on any server. Your passphrase **is** your identity.

Contacts are added by exchanging a shareable address (QR code or copy-paste). This contains your X25519 
public key (used for key agreement), your Ed25519 public key (used for signing), and your current relay address. No registration or central directory is required.

Message content is encrypted with AES-256-GCM under a per-device-pair session key agreed through X4DH (see `X4DH.md`), and every message is signed with Ed25519 before it leaves your device. The static key derived from your two identity keys is used only for the content-free HELLO and a few signalling blobs, never for message content.

---

## Features

- End-to-end encrypted text, image and audio messages
- Per-message Ed25519 signatures, verified on receipt (an unverified message is shown with a warning, not hidden)
- Per-device session establishment (X4DH) with partial forward secrecy. Message content is session-only: there is no fallback to the static identity key, and a message to a device without a ready session is held on your device and sent automatically once one exists. See `known-limitations.md` for exactly what this does and doesn't cover
- Held outbox: messages wait locally (up to 24 hours) for a secure session instead of being sent under a weaker key
- Peer-to-peer voice calling over WebRTC (STUN only, no TURN, by design — see `known-limitations.md`)
- Agent contacts: a bounded command whitelist over ordinary encrypted messages, plus interactive shell access over a WebRTC data channel for contacts on a separate, stricter allowlist
- No accounts, email addresses or phone numbers
- Roaming identities — move freely between relay servers
- No central directory or identity provider
- Direct client-to-relay delivery across different relays
- Offline delivery through temporary encrypted relay buffers
- Multi-device synchronization
- Peer backup of encrypted data
- QR code contact exchange, including a one-way live QR (one scan is enough; single use, valid for about 2 minutes while you stay online)
- Encrypted backup export / import
- Optional auto login on a device you trust, and a logout that keeps your data on the device
- Settings panel for per-device options (push, theme, backup, relay override, migrate, burn)
- Progressive Web App (PWA)
- Installable and offline-capable for reading conversations
- Opt-in push notifications (per device, content-free — a push only ever means "open the app and check")

---

## Built for humans and agents

MeshChat identities are derived from a name and passphrase — no registration, API key, or phone number required. That statelessness is what makes the protocol a natural fit for AI agents, not just people.

Agent contacts already work today: a contact can be given a bounded command whitelist over ordinary encrypted messages, or — on a separate, stricter allowlist — an interactive shell over a WebRTC data channel. Looking further ahead, an agent doesn't need any of that client machinery to talk to MeshChat at all — just the ability to run the same handshake a human client does (derive keys, authenticate, encrypt, send). A lightweight skill/tool (e.g. a `SKILL.md`) that lets an agent join as a MeshChat contact this way — talking to a human, or in principle to another agent, since the protocol itself draws no distinction between the two — is planned but not yet built; see `Roadmap.md`.

---

## Running a relay server

### Requirements

- Python 3.11+
- `websockets`
- `flask`
- `cryptography`

```bash
pip install websockets flask cryptography
```

### Configuration

Example:

```bash
export RELAY_WSS_URL="wss://yourrelay.example.com/ws/"
export HTTP_PORT=8000
export WS_PORT=8888
export BUF_DIR="./relay_buf"
export BUF_MAX_MSGS=100
export BUF_MAX_AGE=86400
export BUF_MAX_MB=10

python3 server.py
```

`RELAY_WSS_URL` is required. It is the relay address clients distribute when sharing their identity, and its host is what clients' authentication proofs are bound to. Without a valid value the relay refuses every client with `relay_not_configured`.

Push notifications are only sent to push services on an allowlist, `PUSH_ALLOWED_HOSTS`. The defaults cover the services used by Chrome, Edge, Brave, Opera, Firefox and Safari. Setting the variable replaces the defaults; see `protocol.md` for the full configuration table.

### Nginx reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name yourrelay.example.com;

    ssl_certificate     /etc/letsencrypt/live/yourrelay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourrelay.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;


    ## General protection

    client_max_body_size 5m;

    client_header_timeout 10s;
    client_body_timeout   10s;
    send_timeout          30s;

    keepalive_timeout     30s;

    limit_conn conn_limit 20;

    ## Security headers

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;

    ## Logging

    access_log /var/log/nginx/meshchat_access.log;
    error_log  /var/log/nginx/meshchat_error.log;


    location / {

        limit_req zone=req_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:8000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /ws/ {
        limit_req zone=req_limit burst=10 nodelay;
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Static files

The client files are inside a `static/` 
directory next to `server.py`:

* `index.html`, `style.css`, `style_local.css` (themes), `manifest.json`, `sw.js`
* `meshchat-lib.js`, `meshchat-gui.js`, `meshchat.js`, `meshchat-identity.js`, `statemachine.js`, `meshchat-boot.js`
* `vendor/` with the three bundled libraries (`qrcode.min.js`, `html5-qrcode.min.js`, `noble-ed25519.js`)

The page runs entirely from its own origin: the libraries are bundled rather than loaded from a CDN, and the Content-Security-Policy in `index.html` allows scripts from `'self'` only, with no inline scripts or event-handler attributes.

---

## Relay authentication

When a client connects, the relay authenticates the session by checking a signature that proves possession of the presented keys, made over a challenge it issues.

The signature is bound to the relay: it covers a fixed label, the relay's own host name (the one the client dialed), the challenge, both public keys and the device's routing id. A relay therefore cannot be used as a signing oracle for your identity key, and a proof made for one relay is useless at another. The relay checks the proof against the host names in its own configuration, never against anything the connecting party claims.

This lets the relay associate active connections and offline message buffers with authenticated identities without ever learning private keys or passphrases.

Relay authentication protects against identity spoofing while preserving end-to-end encryption.

---

## Design philosophy

MeshChat separates **transport** from **trust**.

Relay servers are intentionally simple transport nodes. They forward ciphertext, temporarily buffer encrypted 
messages for offline users, and authenticate ownership of public identities during connection.

Trust resides entirely in cryptographic identities generated locally by each client.

There is no global directory, no relay-to-relay communication and no central authority coordinating the network. 
Contacts learn each other's current relay location directly, allowing identities to migrate between relays 
while remaining reachable.

---

## Security model

### Relay operators can see

* sender public ID
* recipient public ID
* message timing
* approximate message size
* relay currently used by connected clients
* a per-device routing id (it cannot be linked to the device id your contacts see)

### Relay operators cannot see

* plaintext messages
* attachments
* private keys
* passphrases
* contact names
* encrypted backups

### Important limitations

* Passphrase security is everything.
* Forward secrecy is **partial**: message content only ever travels under per-device-pair X4DH session keys, and a session that has completed its live upgrade also protects against a later compromise of your identity keys (see `X4DH.md`). There is no per-message ratchet yet: one key is used for every message under a session. A device pair without a session cannot exchange content at all; messages are held until one is established. See `known-limitations.md` for the complete picture.
* Relay operators can observe IP addresses.
* **Auto login is a convenience with a cost.** When ticked, the browser keeps your identity's master secret (not your passphrase) encrypted under a key stored beside it. Anyone with access to that browser profile can open your identity. Leave it off on shared or untrusted devices. Logout and BURN remove it.
* MeshChat is **not** an anonymity network and is not a replacement for Tor.

See `known-limitations.md` for a complete discussion.

---

## Routing

Messages are delivered directly to the recipient's current relay.

1. Alice shares her MeshChat address.
2. Bob stores Alice's current relay information.
3. Bob's client opens a temporary connection directly to Alice's relay.
4. Alice's relay immediately delivers the message if she is connected.
5. Otherwise the encrypted message is buffered until Alice reconnects.
6. When Alice migrates to another relay, her contacts automatically learn her new location through normal protocol traffic.

Relay servers never communicate with one another.

---

## Privacy tips

* Choose a unique username.
* Use a strong passphrase.
* Verify contacts out-of-band when first exchanging identities.
* Treat your passphrase as your private key.
* Share your MeshChat address only with people you trust.

---

## Protocol

See `protocol.md` for the complete protocol specification, packet formats, routing rules, synchronization protocol and backup protocol.

---

## Status

MeshChat is an experimental research project exploring decentralised, roaming, end-to-end encrypted messaging.

The protocol is still evolving and should not yet be considered stable.

```
```